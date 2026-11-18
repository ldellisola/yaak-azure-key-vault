import { execFile } from "node:child_process";

export type AuthMethod = "cli" | "client_secret";

export interface SecretRequest {
  vaultUrl: string;
  secretName: string;
  version?: string;
  auth: AuthMethod;
  tenantId?: string;
  clientId?: string;
  clientSecret?: string;
}

interface AccessToken {
  token: string;
  expiresAt: number;
}

const KEY_VAULT_API_VERSION = "7.5";
const SECRET_CACHE_TTL_MS = 5 * 60 * 1000;
/** Refresh tokens this long before they actually expire. */
const TOKEN_EXPIRY_MARGIN_MS = 2 * 60 * 1000;
const CLI_TIMEOUT_MS = 30_000;

/** Key Vault DNS suffix -> Entra ID authority, for sovereign clouds. */
const AUTHORITIES: Record<string, string> = {
  "vault.azure.net": "https://login.microsoftonline.com",
  "vault.usgovcloudapi.net": "https://login.microsoftonline.us",
  "vault.azure.cn": "https://login.chinacloudapi.cn",
};

const tokenCache = new Map<string, AccessToken>();
const secretCache = new Map<string, { value: string; expiresAt: number }>();
// Concurrent renders of the same tag (or token) share one in-flight request.
const inFlight = new Map<string, Promise<unknown>>();

export function clearCache(): void {
  tokenCache.clear();
  secretCache.clear();
  inFlight.clear();
}

/**
 * Accepts a bare vault name ("my-vault") or a full vault URL
 * ("https://my-vault.vault.azure.net", sovereign clouds included).
 */
export function resolveVaultUrl(vault: string): string {
  const trimmed = vault.trim();
  if (!trimmed) throw new Error("Vault name or URL is required");
  if (/^https?:\/\//i.test(trimmed)) {
    const url = new URL(trimmed);
    return `https://${url.host}`;
  }
  if (!/^[a-zA-Z0-9-]{3,24}$/.test(trimmed)) {
    throw new Error(`"${trimmed}" is not a valid Key Vault name or URL`);
  }
  return `https://${trimmed}.vault.azure.net`;
}

/** "https://my-vault.vault.azure.net" -> "vault.azure.net" */
function vaultSuffix(vaultUrl: string): string {
  return new URL(vaultUrl).host.split(".").slice(1).join(".");
}

export function scopeForVault(vaultUrl: string): string {
  return `https://${vaultSuffix(vaultUrl)}/.default`;
}

function str(value: unknown): string | undefined {
  if (value == null) return undefined;
  const s = String(value).trim();
  return s === "" ? undefined : s;
}

export function parseArgs(values: Record<string, unknown>): SecretRequest {
  const secretName = str(values.secret);
  if (!secretName) throw new Error("Secret name is required");

  const auth: AuthMethod = values.auth === "client_secret" ? "client_secret" : "cli";
  const request: SecretRequest = {
    vaultUrl: resolveVaultUrl(str(values.vault) ?? ""),
    secretName,
    version: str(values.version),
    auth,
    tenantId: str(values.tenantId),
  };

  if (auth === "client_secret") {
    // Fall back to the same environment variables the Azure SDKs use.
    request.tenantId ??= str(process.env.AZURE_TENANT_ID);
    request.clientId = str(values.clientId) ?? str(process.env.AZURE_CLIENT_ID);
    request.clientSecret = str(values.clientSecret) ?? str(process.env.AZURE_CLIENT_SECRET);
    if (!request.tenantId || !request.clientId || !request.clientSecret) {
      throw new Error("Tenant ID, Client ID and Client Secret are required for service principal auth");
    }
  }
  return request;
}

function dedupe<T>(key: string, fn: () => Promise<T>): Promise<T> {
  const pending = inFlight.get(key);
  if (pending) return pending as Promise<T>;
  const promise = fn().finally(() => inFlight.delete(key));
  inFlight.set(key, promise);
  return promise;
}

function credentialKey(r: SecretRequest): string {
  return r.auth === "client_secret"
    ? `client_secret|${r.tenantId}|${r.clientId}|${r.clientSecret}`
    : `cli|${r.tenantId ?? ""}`;
}

async function getAccessToken(r: SecretRequest): Promise<string> {
  const scope = scopeForVault(r.vaultUrl);
  const key = `token|${credentialKey(r)}|${scope}`;

  const cached = tokenCache.get(key);
  if (cached && cached.expiresAt - TOKEN_EXPIRY_MARGIN_MS > Date.now()) return cached.token;

  const token = await dedupe(key, () =>
    r.auth === "client_secret" ? clientSecretToken(r, scope) : azureCliToken(r, scope),
  );
  tokenCache.set(key, token);
  return token.token;
}

function azureCliToken(r: SecretRequest, scope: string): Promise<AccessToken> {
  const args = ["account", "get-access-token", "--scope", scope, "--output", "json"];
  if (r.tenantId) args.push("--tenant", r.tenantId);

  const isWindows = process.platform === "win32";
  return new Promise((resolve, reject) => {
    execFile(
      isWindows ? "az.cmd" : "az",
      args,
      { timeout: CLI_TIMEOUT_MS, shell: isWindows, windowsHide: true },
      (err, stdout, stderr) => {
        if (err) {
          const code = (err as NodeJS.ErrnoException).code;
          if (code === "ENOENT") {
            return reject(new Error("Azure CLI (az) not found. Install it and run `az login`."));
          }
          const detail = String(stderr).trim().split("\n").filter(Boolean).slice(0, 2).join(" ");
          return reject(new Error(`Azure CLI failed: ${detail || err.message}. Try \`az login\`.`));
        }
        try {
          const json = JSON.parse(String(stdout)) as {
            accessToken: string;
            expires_on?: number;
            expiresOn?: string;
          };
          const expiresAt = json.expires_on
            ? json.expires_on * 1000
            : json.expiresOn
              ? new Date(json.expiresOn).getTime()
              : Date.now() + 5 * 60 * 1000;
          resolve({ token: json.accessToken, expiresAt });
        } catch {
          reject(new Error("Could not parse Azure CLI token output"));
        }
      },
    );
  });
}

async function clientSecretToken(r: SecretRequest, scope: string): Promise<AccessToken> {
  const authority = AUTHORITIES[vaultSuffix(r.vaultUrl)] ?? AUTHORITIES["vault.azure.net"];
  const url = `${authority}/${encodeURIComponent(r.tenantId!)}/oauth2/v2.0/token`;
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "client_credentials",
      client_id: r.clientId!,
      client_secret: r.clientSecret!,
      scope,
    }),
  });
  const json = (await res.json().catch(() => ({}))) as {
    access_token?: string;
    expires_in?: number;
    error?: string;
    error_description?: string;
  };
  if (!res.ok || !json.access_token) {
    const detail = json.error_description?.split("\n")[0] ?? json.error ?? `HTTP ${res.status}`;
    throw new Error(`Service principal sign-in failed: ${detail}`);
  }
  return { token: json.access_token, expiresAt: Date.now() + (json.expires_in ?? 3600) * 1000 };
}

export async function getSecret(r: SecretRequest): Promise<string> {
  const key = `secret|${r.vaultUrl}|${r.secretName}|${r.version ?? ""}|${credentialKey(r)}`;

  const cached = secretCache.get(key);
  if (cached && cached.expiresAt > Date.now()) return cached.value;

  return dedupe(key, async () => {
    try {
      const value = await fetchSecret(r);
      secretCache.set(key, { value, expiresAt: Date.now() + SECRET_CACHE_TTL_MS });
      return value;
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      throw new Error(`Azure Key Vault: "${r.secretName}" in ${r.vaultUrl}: ${message}`);
    }
  });
}

async function fetchSecret(r: SecretRequest): Promise<string> {
  const token = await getAccessToken(r);
  const path = [r.secretName, r.version].filter(Boolean).map((s) => encodeURIComponent(s!));
  const url = `${r.vaultUrl}/secrets/${path.join("/")}?api-version=${KEY_VAULT_API_VERSION}`;

  const res = await fetch(url, { headers: { Authorization: `Bearer ${token}` } });
  const json = (await res.json().catch(() => ({}))) as {
    value?: string;
    error?: { code?: string; message?: string };
  };
  if (!res.ok) {
    const { code, message } = json.error ?? {};
    throw new Error([code ?? `HTTP ${res.status}`, message].filter(Boolean).join(": "));
  }
  return json.value ?? "";
}
