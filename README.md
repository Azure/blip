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

## Implementation outline

Blip is a Kubernetes controller plus a privileged per-node agent. Workloads run
in Cloud Hypervisor/KVM VMs inside ordinary Pods; durable data lives outside the
Pod as node-local, replicated, encrypted block storage.

### API (`blip.dev/v1alpha1`)

- **`BlipPool`** — VM shape (CPUs, memory), `warmCount`/`maxCount`, node selector,
  service account, egress policy, and optional gateway sidecar.
- **`BlipState`** — one durable ext4 filesystem. Provisioning is immutable:
  `image` (OCI image converted to ext4), `copyFrom`, `size`, `replicas` (default
  3), `nodeSelector`. `mounts` and `runtime` persist across executions.
  Image states are read-only templates held by every eligible node.
- **`Blip`** — one VM lifetime: root `state`, command, env, workdir, user, TTY,
  idle timeout, `stop` flag, and per-execution network narrowing.
- **`BlipNode`** — cluster-scoped node inventory: endpoint, hypervisors,
  incarnation, heartbeat, drain and safe-to-remove state.

Users write `spec`. The controller writes `Blip`/`BlipPool` status and most of
`BlipState` status; each node agent server-side-applies only its own
`BlipNode.status` and `BlipState.status.nodes` entry.

### Control plane (`blip-controller`)

- Five reconcilers: enrollment, node, pool, state, and blip.
- **Enrollment** labels Kubernetes nodes matching a pool selector with
  `blip.dev/enrolled=true` and `blip.dev/hypervisor-kvm=true`. The node agent
  DaemonSet self-registers a `BlipNode` and heartbeats every 20s. Removing a
  node from every pool drains it: writers are asked to stop, replicas move, and
  its `BlipNode` is deleted once safe.
- **Pools** keep `warmCount` booted vacant VMs, cap total VMs at `maxCount`, and
  pin/relocate warm VMs to follow where a pending Blip's data lives.
- **Blips** acquire the single writer slot for each writable state in sorted
  order (avoiding deadlocks), publish attachment IDs, then claim a warm VM with
  an optimistic-lock patch that transfers pod ownership. On stop the VM is
  fenced, writable disks are sealed, and the Blip finishes only after every
  replica reports the new version.
- **States** build image filesystems per node, resolve `copyFrom` to a committed
  version or a live snapshot of a running writer, replicate pending versions to
  `replicas` nodes, and use finalizers to block deletion while writers or
  dependent copies exist. Newly eligible nodes receive existing image states.
- There is no admission webhook. A CEL `ValidatingAdmissionPolicy` plus a
  controller-maintained ConfigMap (`blip-vm-owners`) restrict pod-bound service
  account tokens to the owning Blip, its pool, and owner-prefixed resources.

### Node agent (`blip-node` DaemonSet)

- Privileged, host-network agent mounting `/var/lib/blip`, `/dev`,
  `/lib/modules`, and `/sys/kernel/config`.
- **Storage** is a device-mapper thin pool on sparse loop files, with an
  AES-256-XTS dm-crypt layer above it. A commit is a dm-thin snapshot over
  64 KiB blocks, not a file. Sealing fences the writable device, checks the ext4
  journal is clean, flushes, and snapshots; content identity is a digest over
  mapped ciphertext blocks.
- **Replication** is node-to-node NVMe/TCP: a kernel `nvmet` target exports a
  throwaway snapshot, and the reader uses the kernel initiator with
  DH-HMAC-CHAP credentials derived from the cluster disk key. `dm-clone` copies
  only the delta regions computed with `thin_delta`/`thin_dump`.
- **Peer control** is mutually authenticated TLS on port 7890, keyed to Ed25519
  node identities published in `BlipNode`. nftables admits only registered
  node addresses to ports 7890 and 4420.
- The agent prepares `desired.json` and block-device nodes for each attachment,
  imports/caches OCI images, builds commits, runs background transfers, and
  garbage-collects volumes that are no longer referenced.

### VM runtime (`blip-runtime`)

- Runs in the Pod's privileged `vm` container and starts Cloud Hypervisor with a
  kernel/initramfs, a read-only JSON config disk, virtio-vsock, and a TAP NIC.
  State disks are hot-added as virtio-blk devices; changing read-only/writable
  mode replaces the attachment rather than toggling the disk.
- **Networking** uses a routed `/30` private link inside `169.254.0.0/16`,
  chosen to avoid existing pod, CNI, and DNS routes, with NAT to the pod IP. A
  default-drop nftables gate applies the compiled egress policy: layers are
  ANDed, rules within a layer are ORed. The default pool policy allows public
  internet plus cluster DNS and denies private/LAN ranges and metadata.
- Writes complete `desired.json`/`observed.json` snapshots and reconciles guest
  claims, mounts, freeze requests, and shutdown.
- The `api-proxy` native sidecar holds the projected service-account token (and
  optional gateway token) and proxies the guest's loopback ports 8001
  (Kubernetes API) and 8002 (gateway) over vsock to HTTPS upstreams. It strips
  caller identity headers and scopes reads to the Blip's owner.

### Guest (`blip-guest`)

- PID 1 in the initramfs: reads its config disk, mounts pseudo-filesystems, loads
  modules, configures `eth0` over rtnetlink, and serves the framed vsock
  protocol on port 1024 (control) and 1025 (sessions), with loopback relays to
  the API and gateway proxies.
- Claims the root ext4 filesystem, chroots into it, resolves users/groups from
  the image's `/etc/passwd` and `/etc/group`, runs processes in a cgroup, and
  supports PTYs, multiple sessions, signals, window resize, and detach without
  killing the process. Each session keeps a 1 MiB output replay ring.
- Uses `FIFREEZE`/`FITHAW` with a 90s auto-thaw for live snapshots and stops
  interactive sandboxes after the idle timeout with no clients or processes.
- Writes `/run/blip/kubeconfig` pointing at the loopback API proxy; the proxy
  injects the real token, so no credential enters the workload filesystem.

### Gateway and CLI

- `blip-gateway` serves SSH on 2222 with public keys or CA-signed user
  certificates. The key determines the owner and the SSH user name selects a
  sandbox within it; resources are named `owner.name`. The gateway forks the
  configured base state and creates its Blip on demand. Interactive shells
  without a command enter a Bubble Tea menu for listing, creating, forking,
  connecting to, and deleting sandboxes. `direct-tcpip` forwarding is supported;
  remote forwarding is not. An mTLS certificate API on 8443 (behind Envoy)
  issues short-lived user certificates from a trusted identity header.
- `kubectl-blip` provides `run`, `exec`, `attach`, `sessions`, `wait`, `pull`,
  `create blipstate`, `mount`, `unmount`, and `collect`. It reaches a VM through
  Kubernetes pod exec (`blip-runtime bridge 1025`, WebSocket with SPDY
  fallback), then the framed vsock protocol; guest exit codes propagate and
  Ctrl-] detaches.
- `blip-controller` and `blip-gateway` share one image; the node agent, VM
  runtime, and dev sandbox are separate images.

## Local development

`hack/kind-up.sh` builds and installs a local kind cluster and prints connection
examples. `hack/e2e.sh` exercises durable workspace reuse, forks, collection, and
SSH-user isolation against that cluster. Tear it down with `hack/kind-down.sh`
(`--purge` also discards local storage).