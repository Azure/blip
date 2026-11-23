<!-- Copyright (c) Microsoft Corporation.
Licensed under the MIT License. -->

# State build recipes

`spec.build` turns a BlipState into a build recipe. The recipe is not a
filesystem: it periodically runs a command and produces new BlipStates. Use it
for periodic artifacts such as a git cache (see
[Shared git repository caches](git-cache.md)) or a preinstalled development
image.

The recipe holds no data and is never committed, so a selector that waits for a
committed version skips it. Consumers select an output by label or name.

## Fields

| Field | Meaning |
| --- | --- |
| `from` | State each build starts from. Empty starts from an empty filesystem; a build recipe means its newest successful output. |
| `incremental` | Start each build from the newest output instead of `from`. The first build still uses `from`. |
| `builder` | State to boot the build in. The output is mounted writable at `path`. |
| `path` | Absolute mount path for the output inside `builder`. Required with `builder`. |
| `intervalSeconds` | Time between build starts. Minimum 60. Also the deadline for one build. |
| `pool` | Pool that runs the build. Default `default`. |
| `command` | Command that produces the output. At least one element. |
| `env` | Environment for the command. |
| `user` | User that runs the command. Default `root`. |
| `workingDir` | Working directory for the command. Default `/`. |

## Output states

Each build creates an output named `<recipe>-<timestamp>`, for example
`gitcache-blip-20261123t030000`. An output is an ordinary BlipState. It is
created with a copy of the recipe's `runtime`, `size`, `replicas`,
`nodeSelector`, and `imagePullSecrets`. It starts from `from`; with
`incremental`, later builds start from the previous output. An empty `from`
starts from an empty filesystem.

Outputs are owned by the recipe. Deleting the recipe deletes its outputs, any
builder copies, and the build Blips.

The recipe's labels and annotations are applied to an output only after the
build command exits successfully. A failed or incomplete build therefore
carries no publishing labels. Put `blip.dev/shared: "true"` and any consumer
selector, such as `chat.blip.dev/base`, on the recipe to publish every
successful output.

`status.build` reports `latest` (newest successful output), `output` and `blip`
(the last attempt), `builder` (its builder copy), `lastBuild`,
`observedGeneration`, and `message`. Inspect a failed attempt with
`kubectl -n dev get blipstate dev-image -o jsonpath='{.status.build}'` and
`blip logs` on `.status.build.blip`.

## Scheduling and failure

A build starts when no build is running and one of these is true:

- The recipe has not started a build yet.
- `intervalSeconds` has elapsed since the last build started.
- The recipe's spec changed.

Changing any spec field starts a build immediately, which is the manual "build
now". On failure the output stays unpublished; the next build deletes it and
its build Blip before starting. A failed build is retried at the next interval.

`intervalSeconds` is also the build deadline. A build still running when the
next start is due is stopped and fails.

`historyLimit` is required for a recipe and must be 1 through 32. It keeps the
newest N successful outputs and deletes older ones. Failed outputs do not count
as successful.

Size, `replicas`, and `nodeSelector` are mutable on a recipe; changing one
starts a build immediately. A recipe cannot set `image`, `copyFrom`, or
`mounts`, the presence of `build` is immutable, and `builder` and `path` must
be set together.

## Inputs and builders

Without `builder`, the command runs in the output itself, so `from` must name a
state that contains an operating system. With `builder` and `path`, the command
runs in a throwaway copy of the builder state's newest output, with the new
output mounted writable at `path`. The output can then hold only the build
artifact and start from an empty filesystem (`from` empty).

`from` and `builder` may name another build recipe; its newest successful
output is used. If that recipe has no successful output yet, the build waits.

Use no `incremental` for a clean rebuild from `from` each interval,
`incremental` to refresh the newest output in place, and an empty `from` with
`builder` when the builder supplies the operating system.

## Example

This recipe refreshes a development image nightly. `ubuntu` is an imported
image state with `spec.image: ubuntu:24.04`; the first build starts from it, and
later builds start from the previous output and reinstall the tool packages.

```yaml
apiVersion: blip.dev/v1alpha1
kind: BlipState
metadata:
  name: dev-image
  namespace: dev
  labels:
    blip.dev/shared: "true"
spec:
  size: 48Gi
  replicas: 2
  historyLimit: 2
  runtime:
    user: "1000"
    workingDir: /src
  build:
    from: ubuntu
    incremental: true
    intervalSeconds: 86400
    command:
      - sh
      - -ec
      - |
        set -eu
        apt-get update
        DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
          build-essential git
        rm -rf /var/lib/apt/lists/*
        mkdir -p /src
        chown 1000:1000 /src
```

The build runs as `root` by default so it can install packages; `runtime.user`
sets the user for consumers of the output. The recipe's `replicas: 2` is copied
to every output.

Image states and build outputs are replicated like any other state.
`spec.replicas` sets how many nodes hold each committed version, default 3.
Nodes that do not hold a version fetch it on demand when they need it. A node
keeps previously used committed versions as a local cache and evicts the least
recently used versions when its pool falls below about 25 percent free. A
recipe's `replicas` applies to its outputs.
