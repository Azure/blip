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
- `/etc/opencode/plugins/blipchat-codemode`, a local opencode plugin.

## Configuration

`/etc/opencode/plugins/` is loaded automatically for every user. The image does
not ship an opencode configuration file and defines no MCP servers of its own.
A chat profile or deployment supplies MCP servers through its own opencode
configuration, for example `OPENCODE_CONFIG_CONTENT` or a config file in the
base state at `/opencode.json` or `$XDG_CONFIG_HOME/opencode/opencode.json`. If
a deployment adds `/etc/opencode/opencode.json`, that managed configuration has
higher precedence than global and project config. A deployment that relied on
the image's former `github` server must now declare it in its profile's opencode
configuration.

The `blipchat` MCP server is not part of the image's configuration: ACP supplies
it at session start, and the plugin below adjusts it.

MCP servers delivered by ACP use opencode's default Code Mode. Only the blipchat
server is switched to direct tools, because the agent needs `spawn_agent` as a
first-class tool.

## blipchat-codemode plugin

ACP sends the `blipchat` MCP server to opencode as part of each new or resumed
session. opencode applies its default Code Mode setting to that server, which
hides the server's tools behind a single code-execution tool. The
`blipchat.codemode` plugin runs in `ctx.mcp.transform`, finds the ACP-provided
`blipchat` entry, and sets `codemode = false` so the tools stay directly
available to the agent.

The plugin does not add or remove servers. It only changes the Code Mode flag
on a server that ACP already provided.

## MCP endpoints

Blip pool endpoint URLs are origin-only: the configured URL cannot contain a
path. The Envoy sidecar still forwards the guest's request path and query to
the upstream, so the path a profile configures for an MCP server matters.

The sidecar supplies the upstream authentication it is configured for. It
strips caller `Authorization` and identity headers, and a Blip token is a
Kubernetes service-account token, not a third-party credential.
