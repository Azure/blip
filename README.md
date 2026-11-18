# Blip

> NOTE: this project is in active development, not ready for serious use

Blip runs workloads in VMs backed by durable **BlipStates**. A **Blip** is one
execution; deleting it saves and releases its writable filesystems. States remain
until you explicitly delete them.

## Pull, fork, and reuse

With Blip installed on your cluster and `kubectl-blip` on your `PATH`:

```sh
# Import an OCI image once as a read-only template.
kubectl blip pull base ubuntu:24.04

# Fork a private root state named workspace and run a command in it.
kubectl blip run workspace --fork base -- sh -c 'echo kept > /root/notes.txt'

# Delete the execution, then use the same root in a differently named execution.
kubectl delete blip workspace
kubectl blip run next --state workspace -- cat /root/notes.txt

# Explicit cleanup when the workspace is no longer needed.
kubectl delete blip next
kubectl delete blipstate workspace base
```

Every run selects either `--fork SOURCE_STATE` to create a private workspace named
after the new Blip, or `--state WORKSPACE` to reuse an existing writable root.
Import OCI images with `blip pull BASE OCI_REF`; imported image states are
read-only templates and must be copied before use as a root or writable mount.
Only one execution can write a given state at a time.

## Durable workspace configuration

Store auxiliary mounts in the root **BlipState's `spec.mounts`** and execution
defaults in **`spec.runtime`**:

```yaml
apiVersion: blip.dev/v1alpha1
kind: BlipState
metadata:
  name: workspace
spec:
  copyFrom: base
  mounts:
    - state: data # Create this state first, e.g. blip create blipstate data.
      path: /work
      writable: true
  runtime:
    env:
      - name: PROJECT
        value: demo
    workingDir: /work
    user: "0:0"
    idleTimeout: 10m
    network: {} # Deny outbound traffic; omit to inherit the pool policy.
```

`blip mount data workspace --path /work --write` adds a persistent mount;
`blip unmount data workspace` removes it. Mounts follow the root state into later
executions, including differently named Blips. Runtime
defaults override imported image metadata; per-execution overrides take
precedence. `network` narrows the pool's egress policy.

Forking a workspace copies its root, runtime defaults, and writable auxiliary
states, and shares read-only auxiliary states. These states also survive deletion
of the fork's execution. A Blip manifest selects its root with `spec.state`.

## Local development

`hack/kind-up.sh` builds and installs a local kind cluster and prints connection
examples. `hack/e2e.sh` exercises durable workspace reuse, forks, collection, and
SSH-user isolation against that cluster. Tear it down with `hack/kind-down.sh`
(`--purge` also discards local storage).
