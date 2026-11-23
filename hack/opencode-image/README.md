<!-- Copyright (c) Microsoft Corporation.
Licensed under the MIT License. -->

# opencode image

A reusable container image for running opencode in a Blip chat pool. It
provides the `opencode` binary plus a small, practical development tool set so
the agent can edit, build, and test a repository inside the VM.

## Build

From the repository root:

```bash
docker build -t localhost:5001/blip/opencode:dev hack/opencode-image
```

The image is based on Ubuntu 24.04, runs as the non-root user `dev` (UID 1000,
passwordless sudo), and starts a login shell by default. The build needs access
to the Ubuntu archive and the opencode GitHub release.

## Contents

- `opencode` v2.4.1 from the anomalyco release, installed to
  `/usr/local/bin/opencode`. The build maps `amd64` to `x64` and `arm64` to
  `arm64`, and verifies the release archive against a pinned SHA-256.
- Common tooling: `git`, `curl`, `wget`, `ripgrep`, `fd` (from `fd-find`), `jq`,
  Python 3 with `pip` and `venv`, Node.js and `npm`, `build-essential`, and
  basic editors.
- `/etc/opencode/opencode.json` with the GitHub MCP configuration.
- `/etc/opencode/plugins/blipchat-codemode`, a local opencode plugin.

## Configuration

`/etc/opencode/opencode.json` configures a remote MCP server named `github` at
`http://github` with `oauth` disabled. The `blipchat` MCP server is not listed
here: ACP supplies it at session start, and the plugin below adjusts it.

Both `/etc/opencode/opencode.json` and `/etc/opencode/plugins/` are loaded
automatically for every user. A chat profile does not need to set
`OPENCODE_CONFIG`. Because `/etc/opencode` is managed configuration, it has
higher precedence than global and project config; a deployment that needs a
different GitHub server must change the image.

GitHub tools use opencode's default Code Mode. Only the blipchat server is
switched to direct tools, because ACP delivers it after startup and the agent
needs `spawn_agent` as a first-class tool.

If the pool has no `github` endpoint, the connection fails and opencode logs a
warning but continues.

## blipchat-codemode plugin

ACP sends the `blipchat` MCP server to opencode as part of each new or resumed
session. opencode applies its default Code Mode setting to that server, which
hides the server's tools behind a single code-execution tool. The
`blipchat.codemode` plugin runs in `ctx.mcp.transform`, finds the ACP-provided
`blipchat` entry, and sets `codemode = false` so the tools stay directly
available to the agent.

The plugin does not add or remove servers. It only changes the Code Mode flag
on a server that ACP already provided.

## GitHub MCP endpoint

Blip pool endpoint URLs are origin-only: the configured URL cannot contain a
path. The api-proxy still forwards the guest's request path and query to the
upstream, so the path opencode uses matters.

The image points at `http://github`, which assumes a proxy that maps the root to
the real GitHub MCP endpoint. If the pool endpoint points directly at
`https://api.githubcopilot.com`, configure opencode with
`http://github/mcp/` instead.

In both cases the proxy must supply GitHub authentication. The sidecar strips
caller `Authorization` and identity headers; a Blip projected token is a
Kubernetes service-account token, not a GitHub credential.
