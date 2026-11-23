<!-- Copyright (c) Microsoft Corporation.
Licensed under the MIT License. -->

# opencode browser E2E

This directory contains a browser test:

```
Playwright -> blipchat-auth -> blipchat -> Blip -> opencode acp
```

`blipchat-auth` is a test-only nginx shim. It injects
`X-Forwarded-User: e2e`; it is not a production authentication design.

The test uses the `opencode` BlipPool and a base state named
`e2e-opencode-base` created from the image built by `hack/opencode-image`. In
local real-model mode, the VM reaches the inference endpoint through the
logical Blip endpoint named `unbounded`, which is supplied by the local,
git-ignored `inference-proxy/` directory. That directory owns the upstream URL,
Azure token, TLS material, and bearer-token injection. Nothing in this tracked
directory contains those details.

CI uses `hack/e2e/opencode/mock-model/`, a deterministic HTTPS
OpenAI-compatible server that echoes the browser nonces and emits the
`spawn_agent` tool calls. It replaces `unbounded-proxy` in the kind cluster, so
CI needs no model credentials.

## Prerequisites

- A local kind cluster from `hack/kind-up.sh`, context `kind-blip-dev`.
- Playwright 1.65.1 and the cached chromium-1255 browser. Run `npm install`
  and `npx playwright install chromium` in this directory, or set `NODE_PATH`.
- Docker access to the Ubuntu archive and the opencode GitHub release, which
  the image build downloads.
- The local registry at `127.0.0.1:5001` (`blip-registry`).

For real-model mode only:

- The ignored `inference-proxy/` directory with `setup.sh`, or an already
  running `unbounded-proxy` service.

For mock mode only:

- `BLIP_E2E_MOCK_MODEL=1`; no `az` login or inference credentials are required.

The script refuses to run unless the current kubectl context is exactly
`kind-blip-dev`. It never touches a remote cluster.

## Run

```bash
./hack/e2e/opencode/run.sh
```

Useful environment variables:

- `KEEP=1` — keep the test session, artifacts, and cluster fixtures.
- `SKIP_BUILD=1` — reuse the already-pushed opencode image.
- `SKIP_BASE=1` — reuse an existing `e2e-opencode-base`.
- `SKIP_INFERENCE_PROXY=1` — use an already-running `unbounded-proxy`.
- `BLIP_E2E_MOCK_MODEL=1` — deploy the deterministic mock model instead of
  the real inference proxy.
- `REBUILD_BASE=1` — delete and re-import the base state.
- `BLIP_E2E_TIMEOUT=600` — per-wait timeout in seconds.
- `BLIP_E2E_CHAT_PORT=18080` — local auth-shim port.
- `BLIP_E2E_DIRECT_PORT=18081` — local direct-port for the unauthenticated
  `401` check.

The VM image is built from `hack/opencode-image`; no host `opencode` binary is
needed.

## What the test asserts

1. Direct `svc/blipchat` API access without a forwarded user returns `401`;
   access through the shim succeeds.
2. The browser creates a session with profile `opencode` and base
   `e2e-opencode-base`.
3. The first prompt returns the expected nonce from the configured model
   endpoint.
4. The first generation `<session>-g1` runs `/usr/local/bin/opencode acp` in
   the `opencode` pool and persists a non-empty `chat.blip.dev/acp-session`
   annotation.
5. After the first turn ends, a second prompt creates `<session>-g2` and
   resumes the same ACP session.
6. A third prompt asks the agent to spawn two children through the blipchat
   MCP tools, and the test verifies both child sessions and their parent/root/
   depth annotations.
7. In real-model mode, no inference credential appears in the Blip spec.

On success the test deletes only its session state and Blips. It keeps the
base state, pool, and auth shim for faster reruns, plus
`build/e2e-opencode/<timestamp>/` with the result and browser artifacts. On
failure it also keeps that directory, including cluster diagnostics.
