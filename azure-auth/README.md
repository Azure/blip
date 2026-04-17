# azure-auth

An Azure Function that bridges Entra ID (Azure AD) authentication with the blip SSH gateway's device-flow login.

## How it works

1. A user initiates SSH gateway device-flow authentication, which produces a pubkey JWT and directs the user's browser to this function.
2. Azure App Service Authentication (EasyAuth) intercepts the request and requires the user to sign in with Entra ID. After sign-in, EasyAuth injects the user's ID token in the `X-MS-TOKEN-AAD-ID-TOKEN` header.
3. The function reads the pubkey JWT from the `u` query parameter and the Entra ID token from the EasyAuth header.
4. It fetches the gateway's TLS certificate and hostname from the `gateway-tls-certs` ConfigMap in `kube-public` via the Kubernetes API.
5. It POSTs the Entra ID token and pubkey JWT to the gateway's `/auth/user` endpoint over HTTPS, using the gateway's self-signed certificate as the trusted CA.
6. The user sees a success or failure page and can return to their terminal.

## Configuration

| Environment variable | Required | Description |
|---|---|---|
| `APISERVER_URL` | Yes | URL of the Kubernetes API server (e.g. `https://my-cluster.example.com:6443`) |

Entra ID authentication must be configured on the Function App (EasyAuth) so that unauthenticated requests are redirected to sign-in.

## Build

```sh
npm install
npm run build
```

## Run locally

Requires [Azure Functions Core Tools](https://learn.microsoft.com/en-us/azure/azure-functions/functions-run-local) (`func` CLI).

```sh
npm start
```

## Deploy

1. Create an Azure Function App (Node.js 20+, Linux, Consumption or App Service plan).
2. Enable **Authentication** on the Function App with Microsoft (Entra ID) as the identity provider. Configure it to require authentication.
3. Set the `APISERVER_URL` application setting to your Kubernetes API server URL.
4. Ensure the Function App has network access to both the Kubernetes API server and the SSH gateway.
5. Deploy using one of the methods below.

### Using Azure Functions Core Tools

```sh
func azure functionapp publish <function-app-name>
```

### Using a zip package

Build a deployment zip containing only the compiled code and production dependencies:

```sh
npm run build:zip
```

This produces `deploy.zip` in the project root. Deploy it using the Azure CLI:

```sh
az webapp deploy --resource-group <group-name> --name <app-name> --src-path deploy.zip --type zip
```

Or upload it to Azure Blob Storage and deploy from the URL:

```sh
az webapp deploy --resource-group <group-name> --name <app-name> --src-url <blob-url> --type zip
```
