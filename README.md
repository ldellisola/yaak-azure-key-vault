# Yaak Azure Key Vault

A [Yaak](https://yaak.app) plugin that adds an `azure_keyvault.secret` template function,
so requests can pull secrets straight from Azure Key Vault instead of storing them in Yaak.

```
Authorization: Bearer ${[ azure_keyvault.secret(vault='my-vault', secret='api-token') ]}
```

Insert it like any other template function (type `azure` in a field, or use the template
function picker) and fill in the form.

## Arguments

| Argument       | Description                                                                                  |
| -------------- | -------------------------------------------------------------------------------------------- |
| Vault          | Vault name (`my-vault`) or full URL (`https://my-vault.vault.azure.net`, for sovereign clouds) |
| Secret Name    | Name of the secret                                                                           |
| Version        | Optional. Empty means the latest version                                                    |
| Authentication | `Azure CLI` (default) or `Service Principal`                                                 |
| Tenant ID      | Optional for Azure CLI (selects a tenant); required for Service Principal                    |
| Client ID      | Service Principal only                                                                       |
| Client Secret  | Service Principal only                                                                       |

Every argument can itself use Yaak variables, e.g. `vault='${[ KEY_VAULT ]}'`, which lets
each environment point at a different vault.

## Authentication

- **Azure CLI**: uses your `az login` session (`az account get-access-token`). Requires the
  [Azure CLI](https://learn.microsoft.com/cli/azure/install-azure-cli).
- **Service Principal**: client-credentials flow. Empty fields fall back to the
  `AZURE_TENANT_ID`, `AZURE_CLIENT_ID` and `AZURE_CLIENT_SECRET` environment variables of the
  Yaak process. Avoid pasting the client secret directly into a request, because it would be
  saved (and possibly synced) with the workspace.

The identity needs the **Key Vault Secrets User** role (RBAC vaults) or a `get` secret
permission (access-policy vaults).

## Caching

Secret values are cached in memory for 5 minutes and access tokens until shortly before they
expire, so previews don't hit Key Vault on every keystroke. Errors are never cached. To force
a refresh after rotating a secret, use the **Clear Azure Key Vault cache** request action
(right-click a request).

The inline preview is click-to-reveal and only shows the vault and secret name.

## Development

```sh
npm install
npm run dev        # rebuild on change (Yaak reloads the plugin automatically)
npm run build      # one-off build to build/index.js
npm test
npm run typecheck
```

Install it in Yaak via **Settings → Plugins** and point it at this directory.

The plugin has no runtime dependencies. It calls the Key Vault REST API directly rather than
using `@azure/identity`, because that package's lazy `import("open")` can't be bundled into
Yaak's single-file plugin build.
