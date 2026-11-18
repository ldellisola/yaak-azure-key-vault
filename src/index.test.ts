import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";

const execFileMock = vi.hoisted(() => vi.fn());
vi.mock("node:child_process", () => ({ execFile: execFileMock }));

import { plugin } from "./index";
import { clearCache, getSecret, parseArgs, resolveVaultUrl, scopeForVault } from "./keyvault";

function cliReturnsToken(token = "cli-token") {
  execFileMock.mockImplementation((_cmd, _args, _opts, cb) => {
    cb(null, JSON.stringify({ accessToken: token, expires_on: Math.floor(Date.now() / 1000) + 3600 }), "");
  });
}

function jsonResponse(status: number, body: unknown) {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

const fetchMock = vi.fn<typeof fetch>();

beforeEach(() => {
  clearCache();
  execFileMock.mockReset();
  fetchMock.mockReset();
  vi.stubGlobal("fetch", fetchMock);
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
});

describe("plugin", () => {
  test("exposes the azure_keyvault.secret template function", () => {
    expect(plugin.templateFunctions?.map((f) => f.name)).toEqual(["azure_keyvault.secret"]);
  });
});

describe("resolveVaultUrl", () => {
  test("expands a bare vault name", () => {
    expect(resolveVaultUrl("my-vault")).toBe("https://my-vault.vault.azure.net");
  });

  test("normalises a full URL", () => {
    expect(resolveVaultUrl("https://my-vault.vault.azure.net/secrets/x")).toBe("https://my-vault.vault.azure.net");
  });

  test("rejects garbage", () => {
    expect(() => resolveVaultUrl("not a vault")).toThrow(/not a valid/);
    expect(() => resolveVaultUrl("")).toThrow(/required/);
  });

  test("derives the scope from the vault's cloud", () => {
    expect(scopeForVault("https://v.vault.usgovcloudapi.net")).toBe("https://vault.usgovcloudapi.net/.default");
  });
});

describe("parseArgs", () => {
  test("defaults to Azure CLI auth", () => {
    expect(parseArgs({ vault: "vault1", secret: "s" }).auth).toBe("cli");
  });

  test("requires service principal fields", () => {
    expect(() => parseArgs({ vault: "vault1", secret: "s", auth: "client_secret" })).toThrow(/required/);
  });

  test("falls back to AZURE_* env vars for service principal", () => {
    vi.stubEnv("AZURE_TENANT_ID", "t");
    vi.stubEnv("AZURE_CLIENT_ID", "c");
    vi.stubEnv("AZURE_CLIENT_SECRET", "x");
    const r = parseArgs({ vault: "vault1", secret: "s", auth: "client_secret" });
    expect([r.tenantId, r.clientId, r.clientSecret]).toEqual(["t", "c", "x"]);
  });
});

describe("getSecret", () => {
  test("reads a secret with an Azure CLI token and caches it", async () => {
    cliReturnsToken();
    fetchMock.mockResolvedValue(jsonResponse(200, { value: "hunter2" }));

    const req = parseArgs({ vault: "my-vault", secret: "db-password", version: "abc", tenantId: "t1" });
    expect(await getSecret(req)).toBe("hunter2");
    expect(await getSecret(req)).toBe("hunter2");

    expect(execFileMock).toHaveBeenCalledTimes(1);
    const [cmd, args] = execFileMock.mock.calls[0]!;
    expect(cmd).toMatch(/^az/);
    expect(args).toEqual([
      "account", "get-access-token", "--scope", "https://vault.azure.net/.default", "--output", "json", "--tenant", "t1",
    ]);

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0]!;
    expect(url).toBe("https://my-vault.vault.azure.net/secrets/db-password/abc?api-version=7.5");
    expect((init?.headers as Record<string, string>).Authorization).toBe("Bearer cli-token");
  });

  test("dedupes concurrent requests", async () => {
    cliReturnsToken();
    fetchMock.mockImplementation(async () => jsonResponse(200, { value: "v" }));
    const req = parseArgs({ vault: "my-vault", secret: "s" });
    await Promise.all([getSecret(req), getSecret(req), getSecret(req)]);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  test("uses client credentials for service principal auth", async () => {
    fetchMock
      .mockResolvedValueOnce(jsonResponse(200, { access_token: "sp-token", expires_in: 3600 }))
      .mockResolvedValueOnce(jsonResponse(200, { value: "sp-secret" }));

    const req = parseArgs({
      vault: "my-vault", secret: "s", auth: "client_secret", tenantId: "t", clientId: "c", clientSecret: "x",
    });
    expect(await getSecret(req)).toBe("sp-secret");
    expect(execFileMock).not.toHaveBeenCalled();

    const [tokenUrl, tokenInit] = fetchMock.mock.calls[0]!;
    expect(tokenUrl).toBe("https://login.microsoftonline.com/t/oauth2/v2.0/token");
    expect(String(tokenInit?.body)).toContain("scope=https%3A%2F%2Fvault.azure.net%2F.default");
    const [, secretInit] = fetchMock.mock.calls[1]!;
    expect((secretInit?.headers as Record<string, string>).Authorization).toBe("Bearer sp-token");
  });

  test("surfaces Key Vault errors and does not cache them", async () => {
    cliReturnsToken();
    fetchMock.mockResolvedValue(
      jsonResponse(404, { error: { code: "SecretNotFound", message: "A secret with (name/id) nope was not found" } }),
    );
    const req = parseArgs({ vault: "my-vault", secret: "nope" });
    await expect(getSecret(req)).rejects.toThrow(/SecretNotFound: A secret with/);
    await expect(getSecret(req)).rejects.toThrow();
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  test("explains a missing Azure CLI", async () => {
    execFileMock.mockImplementation((_cmd, _args, _opts, cb) => {
      cb(Object.assign(new Error("spawn az ENOENT"), { code: "ENOENT" }), "", "");
    });
    await expect(getSecret(parseArgs({ vault: "my-vault", secret: "s" }))).rejects.toThrow(/Azure CLI \(az\) not found/);
  });

  test("explains an expired Azure CLI login", async () => {
    execFileMock.mockImplementation((_cmd, _args, _opts, cb) => {
      cb(Object.assign(new Error("Command failed"), { code: 1 }), "", "ERROR: AADSTS700082: The refresh token has expired.\n");
    });
    await expect(getSecret(parseArgs({ vault: "my-vault", secret: "s" }))).rejects.toThrow(/AADSTS700082.*az login/);
  });
});
