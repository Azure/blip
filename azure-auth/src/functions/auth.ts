import { app, HttpRequest, HttpResponseInit, InvocationContext } from "@azure/functions";
import * as https from "node:https";

// Required configuration: the URL of the Kubernetes API server.
// The gateway's TLS certificate and hostname are discovered automatically
// from the gateway-tls-certs ConfigMap in kube-public.
const APISERVER_URL = process.env["APISERVER_URL"];

// Request timeouts in milliseconds.
const APISERVER_TIMEOUT_MS = 5_000;
const GATEWAY_TIMEOUT_MS = 5_000;

// Maximum sizes for response bodies to prevent memory exhaustion.
const MAX_APISERVER_RESPONSE = 256 * 1024; // 256 KiB (ConfigMap is small)
const MAX_GATEWAY_RESPONSE = 64 * 1024; // 64 KiB

// Maximum length of the pubkey JWT query parameter.
const MAX_PUBKEY_JWT_LENGTH = 4096;

interface GatewayConfig {
	hostname: string;
	ca: string;
}

/**
 * Fetches the gateway's TLS certificate and hostname from the
 * gateway-tls-certs ConfigMap in kube-public via the Kubernetes API.
 */
async function fetchGatewayConfig(): Promise<GatewayConfig> {
	if (!APISERVER_URL) {
		throw new Error("APISERVER_URL environment variable is not set");
	}

	const url = `${APISERVER_URL}/api/v1/namespaces/kube-public/configmaps/gateway-tls-certs`;
	const headers: Record<string, string> = {};

	const resp = await fetch(url, {
		headers,
		signal: AbortSignal.timeout(APISERVER_TIMEOUT_MS),
	});
	if (!resp.ok) {
		throw new Error(`Failed to fetch gateway-tls-certs: ${resp.status} ${resp.statusText}`);
	}

	// Read with size limit.
	const text = await readResponseWithLimit(resp, MAX_APISERVER_RESPONSE);

	const cm = JSON.parse(text) as {
		data?: { hostname?: string; "active.crt"?: string; "previous.crt"?: string };
	};

	const hostname = cm.data?.hostname;
	const activeCert = cm.data?.["active.crt"];
	if (!hostname || !activeCert) {
		throw new Error("gateway-tls-certs configmap missing hostname or active.crt");
	}

	// Validate hostname: must look like a DNS name (no slashes, spaces, etc.)
	if (!/^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$/.test(hostname)) {
		throw new Error("gateway-tls-certs configmap contains invalid hostname");
	}

	// Trust both active and previous certs for seamless rotation.
	let ca = activeCert;
	if (cm.data?.["previous.crt"]) {
		ca += "\n" + cm.data["previous.crt"];
	}

	return { hostname, ca };
}

/**
 * Reads a fetch Response body up to maxBytes. Throws if the limit is exceeded.
 */
async function readResponseWithLimit(resp: Response, maxBytes: number): Promise<string> {
	const reader = resp.body?.getReader();
	if (!reader) {
		throw new Error("Response has no body");
	}
	const chunks: Uint8Array[] = [];
	let totalBytes = 0;
	for (; ;) {
		const { done, value } = await reader.read();
		if (done) break;
		totalBytes += value.byteLength;
		if (totalBytes > maxBytes) {
			reader.cancel();
			throw new Error(`Response exceeded ${maxBytes} byte limit`);
		}
		chunks.push(value);
	}
	return Buffer.concat(chunks).toString("utf-8");
}

/**
 * POSTs the user's Entra ID token and the pubkey JWT to the gateway's
 * /auth/user endpoint, using the gateway's self-signed certificate as
 * the trusted CA.
 */
function postAuthUser(
	hostname: string,
	ca: string,
	bearerToken: string,
	pubkeyJWT: string,
): Promise<{ status: number; body: string }> {
	return new Promise((resolve, reject) => {
		const formBody = `pubkey=${encodeURIComponent(pubkeyJWT)}`;
		const req = https.request(
			{
				hostname,
				port: 443,
				path: "/auth/user",
				method: "POST",
				timeout: GATEWAY_TIMEOUT_MS,
				headers: {
					Authorization: `Bearer ${bearerToken}`,
					"Content-Type": "application/x-www-form-urlencoded",
					"Content-Length": Buffer.byteLength(formBody).toString(),
				},
				ca,
			},
			(res) => {
				let body = "";
				let bytes = 0;
				res.on("data", (chunk: Buffer) => {
					bytes += chunk.byteLength;
					if (bytes > MAX_GATEWAY_RESPONSE) {
						res.destroy(new Error("gateway response too large"));
						return;
					}
					body += chunk.toString();
				});
				res.on("end", () => resolve({ status: res.statusCode ?? 0, body }));
				res.on("error", reject);
			},
		);
		req.on("timeout", () => {
			req.destroy(new Error("gateway request timed out"));
		});
		req.on("error", reject);
		req.write(formBody);
		req.end();
	});
}

const HTML_SUCCESS = `<!DOCTYPE html>
<html><head><title>Authenticated</title></head>
<body style="font-family:system-ui;max-width:480px;margin:80px auto;text-align:center">
<h2>Authentication successful</h2>
<p>You may close this window and return to your terminal.</p>
</body></html>`;

const HTML_FAIL = `<!DOCTYPE html>
<html><head><title>Authentication Failed</title></head>
<body style="font-family:system-ui;max-width:480px;margin:80px auto;text-align:center">
<h2>Authentication failed</h2>
<p>The gateway rejected the request. Please try again.</p>
</body></html>`;

const HTML_ERROR = `<!DOCTYPE html>
<html><head><title>Error</title></head>
<body style="font-family:system-ui;max-width:480px;margin:80px auto;text-align:center">
<h2>Internal error</h2>
<p>Something went wrong. Please try again.</p>
</body></html>`;

/**
 * Azure Function HTTP trigger that completes the SSH gateway device-flow
 * authentication. Azure Functions built-in Entra ID authentication (EasyAuth)
 * handles user login; this function receives the authenticated request and
 * forwards the credentials to the SSH gateway.
 *
 * Query parameters:
 *   u - The pubkey JWT issued by the SSH gateway during device-flow auth.
 *
 * EasyAuth headers:
 *   X-MS-TOKEN-AAD-ID-TOKEN - The user's Entra ID token.
 *
 * Environment variables:
 *   APISERVER_URL   - (Required) Kubernetes API server URL.
 *   APISERVER_TOKEN - (Optional) Bearer token for K8s API authentication.
 */
async function handler(req: HttpRequest, context: InvocationContext): Promise<HttpResponseInit> {
	const pubkeyJWT = req.query.get("u");
	if (!pubkeyJWT || pubkeyJWT.length > MAX_PUBKEY_JWT_LENGTH) {
		return { status: 400, headers: { "Content-Type": "text/html" }, body: HTML_ERROR };
	}

	// EasyAuth injects the Entra ID token after authenticating the user.
	const idToken = req.headers.get("x-ms-token-aad-id-token");
	if (!idToken) {
		return {
			status: 401,
			body: "Not authenticated. Ensure Entra ID authentication is configured on this Function App.",
		};
	}

	try {
		const gw = await fetchGatewayConfig();
		const result = await postAuthUser(gw.hostname, gw.ca, idToken, pubkeyJWT);

		if (result.status === 200) {
			return { status: 200, headers: { "Content-Type": "text/html" }, body: HTML_SUCCESS };
		}

		context.error(`Gateway returned ${result.status}: ${result.body}`);
		return { status: 502, headers: { "Content-Type": "text/html" }, body: HTML_FAIL };
	} catch (err) {
		context.error(`Auth flow error: ${err}`);
		return { status: 500, headers: { "Content-Type": "text/html" }, body: HTML_ERROR };
	}
}

app.http("auth", {
	methods: ["GET"],
	authLevel: "anonymous", // EasyAuth handles authentication at the platform level
	handler,
});
