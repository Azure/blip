<!-- Copyright (c) Microsoft Corporation.
Licensed under the MIT License. -->

# opencode browser E2E

This directory contains a local-only browser test:

```
Playwright -> blipchat-auth -> blipchat -> Blip -> opencode acp
```

`blipchat-auth` is a test-only nginx shim. It injects
`X-Forwarded-User: e2e`; it is not a production authentication design.

The test uses the `opencode` BlipPool and a base state named
`e2e-opencode-base` created from the image built by `hack/opencode-image`. The
VM reaches the inference endpoint through the logical Blip endpoint named
`unbounded`, which is supplied by the local, git-ignored `inference-proxy/`
directory. That directory owns the upstream URL, Azure token, TLS material, and
bearer-token injection. Nothing in this tracked directory contains those
details.

## Prerequisites

- A local kind cluster from `hack/kind-up.sh`, context `kind-blip-dev`.
- The ignored `inference-proxy/` directory with `setup.sh`.
- Playwright 1.65.1 and the cached chromium-1255 browser. If Playwright is not
  installed in this directory, set `NODE_PATH` or set `PLAYWRIGHT_MODULE` to a
  module that resolves `playwright`.
- Docker access to the Ubuntu archive and the opencode GitHub release, which the
  image build downloads.
- The local registry at `127.0.0.1:5001` (`blip-registry`).

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
- `REBUILD_BASE=1` — delete and re-import the base state.
- `BLIP_E2E_TIMEOUT=600` — per-wait timeout in seconds.
- `BLIP_E2E_CHAT_PORT=18080` — local auth-shim port.

The VM image is built from `hack/opencode-image`; no host `opencode` binary is
needed.

## What the test asserts

1. Direct `svc/blipchat` API access without a forwarded user returns `401`;
   access through the shim succeeds.
2. The browser creates a session with profile `opencode` and base
   `e2e-opencode-base`.
3. The first prompt returns the expected nonce from the real model.
4. The first generation `<session>-g1` runs `/usr/local/bin/opencode acp` in
   the `opencode` pool and persists a non-empty `chat.blip.dev/acp-session`
   annotation.
5. After the first turn ends, a second prompt creates `<session>-g2` and
   resumes the same ACP session.
6. A third prompt asks the agent to spawn two children through the blipchat
   MCP tools, and the test verifies both child sessions and their parent/root/
   depth annotations.
7. No inference credential appears in the Blip spec.

On success the test deletes only its session state and Blips. It keeps the
base state, pool, and auth shim for faster reruns, plus
`build/e2e-opencode/<timestamp>/` with the result and browser artifacts. On
failure it also keeps that directory, including cluster diagnostics.
