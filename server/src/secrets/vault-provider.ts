import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import type { DeploymentMode } from "@paperclipai/shared";
import { unprocessable } from "../errors.js";
import type {
  PreparedSecretVersion,
  SecretProviderClientErrorCode,
  SecretProviderHealthCheck,
  SecretProviderModule,
  SecretProviderValidationResult,
  SecretProviderVaultRuntimeConfig,
  StoredSecretVersionMaterial,
} from "./types.js";
import { SecretProviderClientError } from "./types.js";

const VAULT_EXTERNAL_REFERENCE_SCHEME = "vault_external_reference_v1";
const DEFAULT_MOUNT_PATH = "secret";
const DEFAULT_SECRET_PATH_PREFIX = "paperclip";
const REQUEST_TIMEOUT_MS = 15_000;
const TOKEN_EXPIRATION_SKEW_MS = 30_000;

interface VaultExternalReferenceMaterial extends StoredSecretVersionMaterial {
  scheme: typeof VAULT_EXTERNAL_REFERENCE_SCHEME;
  path: string;
  field: string;
  version: number | null;
}

interface VaultRuntimeConfig {
  address: string;
  namespace: string | null;
  mountPath: string;
  secretPathPrefix: string;
  roleIdFile: string;
  secretIdFile: string;
}

interface VaultTokenCacheEntry {
  token: string;
  expiresAt: number;
  pending: Promise<string> | null;
}

const tokenCache = new Map<string, VaultTokenCacheEntry>();

function sha256Hex(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function optionalString(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

function normalizePath(value: string, label: string): string {
  if (value.includes("%") || value.includes("\\")) {
    throw unprocessable(`${label} cannot contain percent escapes or backslashes`);
  }
  const normalized = value.trim().replace(/^\/+|\/+$/g, "").replace(/\/+/g, "/");
  if (!normalized || normalized.split("/").some((segment) => segment === "." || segment === "..")) {
    throw unprocessable(`${label} must be a non-empty relative path without traversal segments`);
  }
  return normalized;
}

function loadConfig(providerConfig?: SecretProviderVaultRuntimeConfig | null): VaultRuntimeConfig {
  if (!providerConfig || providerConfig.provider !== "vault") {
    throw unprocessable("Vault provider requires a selected provider vault");
  }
  if (providerConfig.status === "disabled" || providerConfig.status === "coming_soon") {
    throw unprocessable(`Vault provider vault is ${providerConfig.status}`);
  }
  const address = optionalString(providerConfig.config.address);
  if (!address) throw unprocessable("Vault provider vault requires non-secret config: address");
  const parsedAddress = new URL(address);
  const allowedOrigin = process.env.PAPERCLIP_SECRETS_VAULT_ALLOWED_ORIGIN?.trim();
  if (!allowedOrigin) {
    throw unprocessable("Vault provider requires PAPERCLIP_SECRETS_VAULT_ALLOWED_ORIGIN");
  }
  const parsedAllowedOrigin = new URL(allowedOrigin);
  if (parsedAllowedOrigin.protocol !== "https:" || parsedAllowedOrigin.origin !== allowedOrigin) {
    throw unprocessable("PAPERCLIP_SECRETS_VAULT_ALLOWED_ORIGIN must be an origin-only HTTPS URL");
  }
  if (parsedAddress.protocol !== "https:" || parsedAddress.origin !== parsedAllowedOrigin.origin) {
    throw unprocessable("Vault provider address must match the server-controlled HTTPS origin");
  }
  const roleIdFile = process.env.PAPERCLIP_SECRETS_VAULT_ROLE_ID_FILE?.trim();
  const secretIdFile = process.env.PAPERCLIP_SECRETS_VAULT_SECRET_ID_FILE?.trim();
  if (!roleIdFile || !secretIdFile) {
    throw unprocessable(
      "Vault provider requires PAPERCLIP_SECRETS_VAULT_ROLE_ID_FILE and PAPERCLIP_SECRETS_VAULT_SECRET_ID_FILE",
    );
  }
  return {
    address: parsedAddress.origin,
    namespace: optionalString(providerConfig.config.namespace),
    mountPath: normalizePath(optionalString(providerConfig.config.mountPath) ?? DEFAULT_MOUNT_PATH, "Vault mountPath"),
    secretPathPrefix: normalizePath(
      optionalString(providerConfig.config.secretPathPrefix) ?? DEFAULT_SECRET_PATH_PREFIX,
      "Vault secretPathPrefix",
    ),
    roleIdFile,
    secretIdFile,
  };
}

function parseExternalReference(externalRef: string, providerVersionRef?: string | null) {
  const [rawPath, rawField] = externalRef.trim().split("#", 2);
  const path = normalizePath(rawPath ?? "", "Vault externalRef");
  const field = rawField?.trim() || "value";
  if (!/^[A-Za-z0-9_.-]+$/.test(field)) {
    throw unprocessable("Vault externalRef field must contain only letters, numbers, dot, underscore, or hyphen");
  }
  const versionText = providerVersionRef?.trim();
  if (versionText && !/^[1-9][0-9]*$/.test(versionText)) {
    throw unprocessable("Vault providerVersionRef must be a positive KV-v2 version number");
  }
  const version = versionText ? Number(versionText) : null;
  if (version !== null && !Number.isSafeInteger(version)) {
    throw unprocessable("Vault providerVersionRef must be a safe positive KV-v2 version number");
  }
  return { path, field, version };
}

function prepareExternalReference(externalRef: string, providerVersionRef?: string | null): PreparedSecretVersion {
  const parsed = parseExternalReference(externalRef, providerVersionRef);
  const fingerprint = sha256Hex(
    `${VAULT_EXTERNAL_REFERENCE_SCHEME}:${parsed.path}:${parsed.field}:${parsed.version ?? "latest"}`,
  );
  return {
    material: {
      scheme: VAULT_EXTERNAL_REFERENCE_SCHEME,
      path: parsed.path,
      field: parsed.field,
      version: parsed.version,
    },
    valueSha256: fingerprint,
    fingerprintSha256: fingerprint,
    externalRef: `${parsed.path}#${parsed.field}`,
    providerVersionRef: parsed.version === null ? null : String(parsed.version),
  };
}

function asMaterial(value: StoredSecretVersionMaterial): VaultExternalReferenceMaterial {
  if (
    value &&
    typeof value === "object" &&
    value.scheme === VAULT_EXTERNAL_REFERENCE_SCHEME &&
    typeof value.path === "string" &&
    typeof value.field === "string" &&
    (value.version === null ||
      (typeof value.version === "number" && Number.isSafeInteger(value.version) && value.version > 0))
  ) {
    return value as VaultExternalReferenceMaterial;
  }
  throw unprocessable("Invalid Vault external-reference material");
}

function classifyError(status: number, message: string): SecretProviderClientErrorCode {
  if (status === 403) return "access_denied";
  if (status === 404) return "not_found";
  if (status === 429) return "throttled";
  if (status >= 500) return "provider_unavailable";
  if (status >= 400) return "invalid_request";
  if (/fetch failed|ECONN|ENOTFOUND|ETIMEDOUT|network|timeout/i.test(message)) return "provider_unavailable";
  return "provider_error";
}

function safeMessage(code: SecretProviderClientErrorCode): string {
  switch (code) {
    case "access_denied": return "Vault denied the request. Check the Paperclip broker policy and AppRole.";
    case "not_found": return "Vault could not find the requested secret or version.";
    case "throttled": return "Vault throttled the request. Wait and try again.";
    case "invalid_request": return "Vault rejected the request.";
    case "provider_unavailable": return "Vault is unavailable right now.";
    default: return "Vault request failed.";
  }
}

async function vaultRequest<T>(input: {
  config: VaultRuntimeConfig;
  path: string;
  method?: "GET" | "POST";
  token?: string;
  body?: Record<string, unknown>;
}): Promise<T> {
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (input.config.namespace) headers["x-vault-namespace"] = input.config.namespace;
  if (input.token) headers["x-vault-token"] = input.token;
  try {
    const response = await fetch(`${input.config.address}/v1/${input.path.replace(/^\/+/, "")}`, {
      method: input.method ?? "GET",
      headers,
      body: input.body ? JSON.stringify(input.body) : undefined,
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      redirect: "error",
    });
    const text = await response.text();
    const parsed = text ? JSON.parse(text) as T & { errors?: string[] } : {} as T & { errors?: string[] };
    if (!response.ok) {
      const rawMessage = Array.isArray(parsed.errors) ? parsed.errors.join("; ") : response.statusText;
      const code = classifyError(response.status, rawMessage);
      throw new SecretProviderClientError({
        code,
        provider: "vault",
        operation: input.path,
        message: safeMessage(code),
        rawMessage,
      });
    }
    return parsed;
  } catch (error) {
    if (error instanceof SecretProviderClientError) throw error;
    const rawMessage = error instanceof Error ? error.message : String(error);
    const code = classifyError(0, rawMessage);
    throw new SecretProviderClientError({
      code,
      provider: "vault",
      operation: input.path,
      message: safeMessage(code),
      rawMessage,
      cause: error,
    });
  }
}

async function readCredentialFile(path: string, label: string): Promise<string> {
  const value = (await readFile(path, "utf8")).trim();
  if (!value) throw unprocessable(`${label} file is empty`);
  return value;
}

async function login(config: VaultRuntimeConfig): Promise<string> {
  const cacheKey = `${config.address}|${config.namespace ?? ""}|${config.roleIdFile}|${config.secretIdFile}`;
  const now = Date.now();
  let cached = tokenCache.get(cacheKey);
  if (cached?.token && cached.expiresAt > now) return cached.token;
  if (cached?.pending) return cached.pending;
  if (!cached) {
    cached = { token: "", expiresAt: 0, pending: null };
    tokenCache.set(cacheKey, cached);
  }
  cached.pending = (async () => {
    const [roleId, secretId] = await Promise.all([
      readCredentialFile(config.roleIdFile, "Vault RoleID"),
      readCredentialFile(config.secretIdFile, "Vault SecretID"),
    ]);
    const response = await vaultRequest<{
      auth?: { client_token?: string; lease_duration?: number };
    }>({
      config,
      path: "auth/approle/login",
      method: "POST",
      body: { role_id: roleId, secret_id: secretId },
    });
    const token = response.auth?.client_token;
    if (!token) throw unprocessable("Vault AppRole login returned no client token");
    const leaseSeconds = Math.max(response.auth?.lease_duration ?? 60, 1);
    cached!.token = token;
    cached!.expiresAt = Date.now() + Math.max(leaseSeconds * 1000 - TOKEN_EXPIRATION_SKEW_MS, 1_000);
    return token;
  })().finally(() => {
    if (cached) cached.pending = null;
  });
  return cached.pending;
}

function invalidateToken(config: VaultRuntimeConfig): void {
  const cacheKey = `${config.address}|${config.namespace ?? ""}|${config.roleIdFile}|${config.secretIdFile}`;
  tokenCache.delete(cacheKey);
}

function assertConsumerPath(
  path: string,
  context: { consumerType?: string | null; consumerId?: string | null } | undefined,
): void {
  if (!context?.consumerId || !context.consumerType) {
    throw unprocessable("Vault resolution requires a bound consumer context");
  }
  if (path === "shared/common" || path.startsWith("shared/common/")) return;
  if (path === "shared/device-lifecycle" || path.startsWith("shared/device-lifecycle/")) return;
  if (
    (context.consumerType === "agent" || context.consumerType === "agent_api") &&
    (path === `agents/${context.consumerId}` || path.startsWith(`agents/${context.consumerId}/`))
  ) return;
  throw unprocessable("Vault external reference is outside the bound consumer namespace");
}

export function createVaultProvider(): SecretProviderModule {
  async function validateConfig(input?: {
    deploymentMode?: DeploymentMode;
    strictMode?: boolean;
    providerConfig?: SecretProviderVaultRuntimeConfig | null;
  }): Promise<SecretProviderValidationResult> {
    const warnings: string[] = [];
    if (input?.deploymentMode === "authenticated" && input.strictMode !== true) {
      warnings.push("Strict secret mode should be enabled for authenticated deployments");
    }
    loadConfig(input?.providerConfig);
    return { ok: true, warnings };
  }

  async function healthCheck(input?: {
    deploymentMode?: DeploymentMode;
    strictMode?: boolean;
    providerConfig?: SecretProviderVaultRuntimeConfig | null;
  }): Promise<SecretProviderHealthCheck> {
    try {
      const config = loadConfig(input?.providerConfig);
      const validation = await validateConfig(input);
      await login(config);
      return {
        provider: "vault",
        status: validation.warnings.length ? "warn" : "ok",
        message: "Vault provider authenticated with the server runtime AppRole.",
        warnings: validation.warnings,
        details: {
          address: config.address,
          namespaceConfigured: Boolean(config.namespace),
          mountPath: config.mountPath,
          secretPathPrefix: config.secretPathPrefix,
          credentialSource: "AppRole RoleID/SecretID files",
        },
        backupGuidance: [
          "Back up Paperclip metadata and retain the OpenBao namespace independently.",
          "Restore the broker RoleID/SecretID files before reconciling provider config and bindings.",
        ],
      };
    } catch (error) {
      return {
        provider: "vault",
        status: "warn",
        message: "Vault provider health check failed.",
        warnings: ["Vault resolution remains unavailable until provider config and AppRole custody files are valid."],
      };
    }
  }

  return {
    id: "vault",
    descriptor() {
      return {
        id: "vault",
        label: "HashiCorp Vault / OpenBao",
        requiresExternalRef: true,
        supportsManagedValues: false,
        supportsExternalReferences: true,
        configured: Boolean(
          process.env.PAPERCLIP_SECRETS_VAULT_ALLOWED_ORIGIN?.trim() &&
          process.env.PAPERCLIP_SECRETS_VAULT_ROLE_ID_FILE?.trim() &&
          process.env.PAPERCLIP_SECRETS_VAULT_SECRET_ID_FILE?.trim(),
        ),
      };
    },
    validateConfig,
    async createSecret() {
      throw unprocessable("Vault provider supports read-only external references, not Paperclip-managed values");
    },
    async createVersion() {
      throw unprocessable("Vault provider supports read-only external references, not Paperclip-managed values");
    },
    async linkExternalSecret(input) {
      loadConfig(input.providerConfig);
      return prepareExternalReference(input.externalRef, input.providerVersionRef);
    },
    async resolveVersion(input) {
      const config = loadConfig(input.providerConfig);
      const material = asMaterial(input.material);
      const requested = parseExternalReference(input.externalRef ?? `${material.path}#${material.field}`, input.providerVersionRef);
      if (
        requested.path !== material.path ||
        requested.field !== material.field ||
        requested.version !== material.version
      ) {
        throw unprocessable("Vault external-reference material does not match the requested path, field, and version");
      }
      assertConsumerPath(requested.path, input.context);
      const fullPath = `${config.secretPathPrefix}/${requested.path}`;
      const query = requested.version ? `?version=${requested.version}` : "";
      let response: { data?: { data?: Record<string, unknown> } };
      for (let attempt = 0; ; attempt += 1) {
        const token = await login(config);
        try {
          response = await vaultRequest<{ data?: { data?: Record<string, unknown> } }>({
            config,
            token,
            path: `${config.mountPath}/data/${fullPath}${query}`,
          });
          break;
        } catch (error) {
          if (!(error instanceof SecretProviderClientError) || error.code !== "access_denied" || attempt > 0) {
            throw error;
          }
          invalidateToken(config);
        }
      }
      const value = response.data?.data?.[requested.field];
      if (typeof value !== "string") {
        throw unprocessable(`Vault secret field ${requested.field} is missing or is not a string`);
      }
      return value;
    },
    async deleteOrArchive() {
      // External references are metadata-only; Paperclip never deletes OpenBao values.
    },
    healthCheck,
  };
}

export const vaultProvider = createVaultProvider();
