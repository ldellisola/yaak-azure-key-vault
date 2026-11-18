import type { CallTemplateFunctionArgs, PluginDefinition } from "@yaakapp/api";
import { clearCache, getSecret, parseArgs } from "./keyvault";

/**
 * Apps launched from the macOS Dock/Finder get a minimal PATH, so the Azure CLI
 * (installed via Homebrew or the official installer) wouldn't be found.
 */
function ensureCliOnPath(): void {
  if (process.platform === "win32") return;
  const extra = ["/opt/homebrew/bin", "/usr/local/bin", "/home/linuxbrew/.linuxbrew/bin"];
  const parts = (process.env.PATH ?? "").split(":").filter(Boolean);
  for (const dir of extra) {
    if (!parts.includes(dir)) parts.push(dir);
  }
  process.env.PATH = parts.join(":");
}

const hiddenUnlessClientSecret = (_ctx: unknown, args: CallTemplateFunctionArgs) => ({
  hidden: args.values.auth !== "client_secret",
});

export const plugin: PluginDefinition = {
  init() {
    ensureCliOnPath();
  },

  dispose() {
    clearCache();
  },

  templateFunctions: [
    {
      name: "azure_keyvault.secret",
      description: "Read a secret from Azure Key Vault",
      previewType: "click",
      previewArgs: ["vault", "secret"],
      args: [
        {
          type: "text",
          name: "vault",
          label: "Vault",
          placeholder: "my-vault or https://my-vault.vault.azure.net",
          description: "Key Vault name, or its full URL (needed for sovereign clouds)",
        },
        {
          type: "text",
          name: "secret",
          label: "Secret Name",
          placeholder: "my-secret",
        },
        {
          type: "text",
          name: "version",
          label: "Version",
          optional: true,
          placeholder: "latest",
          description: "Leave empty for the latest version",
        },
        {
          type: "select",
          name: "auth",
          label: "Authentication",
          defaultValue: "cli",
          options: [
            { label: "Azure CLI (az login)", value: "cli" },
            { label: "Service Principal (client secret)", value: "client_secret" },
          ],
        },
        {
          type: "text",
          name: "tenantId",
          label: "Tenant ID",
          optional: true,
          description: "Optional for Azure CLI. For Service Principal, falls back to AZURE_TENANT_ID",
        },
        {
          type: "text",
          name: "clientId",
          label: "Client ID",
          optional: true,
          description: "Falls back to AZURE_CLIENT_ID",
          dynamic: hiddenUnlessClientSecret,
        },
        {
          type: "text",
          name: "clientSecret",
          label: "Client Secret",
          optional: true,
          password: true,
          description: "Falls back to AZURE_CLIENT_SECRET. Prefer a variable over pasting the secret here",
          dynamic: hiddenUnlessClientSecret,
        },
      ],
      async onRender(_ctx, args) {
        return getSecret(parseArgs(args.values));
      },
    },
  ],

  httpRequestActions: [
    {
      label: "Clear Azure Key Vault cache",
      icon: "trash",
      async onSelect(ctx) {
        clearCache();
        await ctx.toast.show({ color: "success", message: "Azure Key Vault cache cleared" });
      },
    },
  ],
};
