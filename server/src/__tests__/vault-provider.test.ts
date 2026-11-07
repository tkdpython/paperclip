import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createVaultProvider } from "../secrets/vault-provider.js";

const originalRoleFile = process.env.PAPERCLIP_SECRETS_VAULT_ROLE_ID_FILE;
const originalSecretFile = process.env.PAPERCLIP_SECRETS_VAULT_SECRET_ID_FILE;
const originalAllowedOrigin = process.env.PAPERCLIP_SECRETS_VAULT_ALLOWED_ORIGIN;

async function credentialFiles() {
  const directory = await mkdtemp(join(tmpdir(), "paperclip-vault-test-"));
  const roleIdFile = join(directory, "role-id");
  const secretIdFile = join(directory, "secret-id");
  await writeFile(roleIdFile, "role-id\n", { mode: 0o600 });
  await writeFile(secretIdFile, "secret-id\n", { mode: 0o600 });
  process.env.PAPERCLIP_SECRETS_VAULT_ROLE_ID_FILE = roleIdFile;
  process.env.PAPERCLIP_SECRETS_VAULT_SECRET_ID_FILE = secretIdFile;
  process.env.PAPERCLIP_SECRETS_VAULT_ALLOWED_ORIGIN = "https://openbao.example.test";
  return directory;
}

const providerConfig = {
  id: "vault-config-1",
  provider: "vault" as const,
  status: "ready",
  config: {
    address: "https://openbao.example.test",
    namespace: null,
    mountPath: "secret",
    secretPathPrefix: "paperclip",
  },
};

afterEach(() => {
  vi.restoreAllMocks();
  if (originalRoleFile === undefined) delete process.env.PAPERCLIP_SECRETS_VAULT_ROLE_ID_FILE;
  else process.env.PAPERCLIP_SECRETS_VAULT_ROLE_ID_FILE = originalRoleFile;
  if (originalSecretFile === undefined) delete process.env.PAPERCLIP_SECRETS_VAULT_SECRET_ID_FILE;
  else process.env.PAPERCLIP_SECRETS_VAULT_SECRET_ID_FILE = originalSecretFile;
  if (originalAllowedOrigin === undefined) delete process.env.PAPERCLIP_SECRETS_VAULT_ALLOWED_ORIGIN;
  else process.env.PAPERCLIP_SECRETS_VAULT_ALLOWED_ORIGIN = originalAllowedOrigin;
});

describe("vaultProvider", () => {
  it("links an external reference without storing a secret value", async () => {
    const directory = await credentialFiles();
    try {
      const prepared = await createVaultProvider().linkExternalSecret({
        externalRef: "agents/agent-1/github#token",
        providerConfig,
      });
      expect(prepared.externalRef).toBe("agents/agent-1/github#token");
      expect(prepared.material).toMatchObject({
        scheme: "vault_external_reference_v1",
        path: "agents/agent-1/github",
        field: "token",
        version: null,
      });
      expect(JSON.stringify(prepared)).not.toContain("role-id");
      expect(JSON.stringify(prepared)).not.toContain("secret-id");
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("authenticates with AppRole and resolves a KV-v2 string field", async () => {
    const directory = await credentialFiles();
    const fetchMock = vi.spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(new Response(JSON.stringify({
        auth: { client_token: "ephemeral-token", lease_duration: 900 },
      }), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({
        data: { data: { token: "resolved-secret" }, metadata: { version: 3 } },
      }), { status: 200 }));
    try {
      const provider = createVaultProvider();
      const prepared = await provider.linkExternalSecret({
        externalRef: "agents/agent-1/github#token",
        providerConfig,
      });
      const value = await provider.resolveVersion({
        material: prepared.material,
        externalRef: prepared.externalRef,
        providerConfig,
        context: {
          companyId: "company-1",
          secretId: "secret-1",
          secretKey: "github-token",
          version: 1,
          consumerType: "agent_api",
          consumerId: "agent-1",
        },
      });
      expect(value).toBe("resolved-secret");
      expect(fetchMock).toHaveBeenNthCalledWith(
        1,
        "https://openbao.example.test/v1/auth/approle/login",
        expect.objectContaining({ method: "POST", redirect: "error" }),
      );
      expect(fetchMock).toHaveBeenNthCalledWith(
        2,
        "https://openbao.example.test/v1/secret/data/paperclip/agents/agent-1/github",
        expect.objectContaining({
          method: "GET",
          headers: expect.objectContaining({ "x-vault-token": "ephemeral-token" }),
        }),
      );
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("rejects traversal and non-string values", async () => {
    const directory = await credentialFiles();
    try {
      const provider = createVaultProvider();
      await expect(provider.linkExternalSecret({
        externalRef: "../sibling/secret#value",
        providerConfig,
      })).rejects.toThrow(/traversal/);
      await expect(provider.linkExternalSecret({
        externalRef: "%2e%2e/sibling/secret#value",
        providerConfig,
      })).rejects.toThrow(/percent escapes/);

      vi.spyOn(globalThis, "fetch")
        .mockResolvedValueOnce(new Response(JSON.stringify({
          auth: { client_token: "ephemeral-token-2", lease_duration: 900 },
        }), { status: 200 }))
        .mockResolvedValueOnce(new Response(JSON.stringify({
          data: { data: { value: { nested: true } } },
        }), { status: 200 }));
      const prepared = await provider.linkExternalSecret({
        externalRef: "agents/agent-2/structured#value",
        providerConfig,
      });
      await expect(provider.resolveVersion({
        material: prepared.material,
        externalRef: prepared.externalRef,
        providerConfig,
        context: {
          companyId: "company-1",
          secretId: "secret-2",
          secretKey: "structured",
          version: 1,
          consumerType: "agent_api",
          consumerId: "agent-2",
        },
      })).rejects.toThrow(/not a string/);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("rejects an unpinned origin, cross-agent paths, and version drift", async () => {
    const directory = await credentialFiles();
    try {
      const provider = createVaultProvider();
      process.env.PAPERCLIP_SECRETS_VAULT_ALLOWED_ORIGIN = "https://approved.example.test";
      await expect(provider.linkExternalSecret({
        externalRef: "agents/agent-1/github#token",
        providerConfig,
      })).rejects.toThrow(/server-controlled HTTPS origin/);

      process.env.PAPERCLIP_SECRETS_VAULT_ALLOWED_ORIGIN = "https://openbao.example.test";
      const prepared = await provider.linkExternalSecret({
        externalRef: "agents/agent-1/github#token",
        providerVersionRef: "3",
        providerConfig,
      });
      await expect(provider.resolveVersion({
        material: prepared.material,
        externalRef: prepared.externalRef,
        providerVersionRef: "2",
        providerConfig,
        context: {
          companyId: "company-1",
          secretId: "secret-3",
          secretKey: "github-token",
          version: 1,
          consumerType: "agent_api",
          consumerId: "agent-1",
        },
      })).rejects.toThrow(/path, field, and version/);
      await expect(provider.resolveVersion({
        material: prepared.material,
        externalRef: prepared.externalRef,
        providerVersionRef: "3",
        providerConfig,
        context: {
          companyId: "company-1",
          secretId: "secret-3",
          secretKey: "github-token",
          version: 1,
          consumerType: "agent_api",
          consumerId: "agent-2",
        },
      })).rejects.toThrow(/bound consumer namespace/);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("requires canonical safe KV-v2 version numbers", async () => {
    const directory = await credentialFiles();
    try {
      const provider = createVaultProvider();
      for (const providerVersionRef of ["03", "+3", "3.0", "1e3", "9007199254740992"]) {
        await expect(provider.linkExternalSecret({
          externalRef: "agents/agent-1/github#token",
          providerVersionRef,
          providerConfig,
        })).rejects.toThrow(/KV-v2 version number/);
      }
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("reauthenticates once when a cached token is rejected", async () => {
    const directory = await credentialFiles();
    const fetchMock = vi.spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(new Response(JSON.stringify({ auth: { client_token: "spent-token", lease_duration: 900 } }), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ errors: ["permission denied"] }), { status: 403 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ auth: { client_token: "fresh-token", lease_duration: 900 } }), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ data: { data: { token: "resolved-after-refresh" } } }), { status: 200 }));
    try {
      const provider = createVaultProvider();
      const prepared = await provider.linkExternalSecret({
        externalRef: "agents/agent-1/github#token",
        providerConfig,
      });
      const value = await provider.resolveVersion({
        material: prepared.material,
        externalRef: prepared.externalRef,
        providerConfig,
        context: {
          companyId: "company-1",
          secretId: "secret-4",
          secretKey: "github-token",
          version: 1,
          consumerType: "agent_api",
          consumerId: "agent-1",
        },
      });
      expect(value).toBe("resolved-after-refresh");
      expect(fetchMock).toHaveBeenCalledTimes(4);
      expect(fetchMock).toHaveBeenNthCalledWith(4, expect.any(String), expect.objectContaining({
        headers: expect.objectContaining({ "x-vault-token": "fresh-token" }),
      }));
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("keeps hostile health-check errors out of persisted health output", async () => {
    const directory = await credentialFiles();
    vi.spyOn(globalThis, "fetch").mockRejectedValueOnce(new Error("hostile /private/custody/path credential detail"));
    try {
      const health = await createVaultProvider().healthCheck({ providerConfig });
      expect(health.status).toBe("warn");
      expect(health.message).toBe("Vault provider health check failed.");
      expect(JSON.stringify(health)).not.toContain("/private/custody/path");
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });
});
