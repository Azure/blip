# Blip

> NOTE: this project is in active development, not ready for serious use

Blip runs workloads in VMs backed by durable **BlipStates**. A **Blip** is one
execution of one required command; deleting it saves and releases its writable
filesystems. States remain until you delete them, or are removed with the Blip
that owns them.

## Run, gather, and reuse

With Blip installed on your cluster and `kubectl-blip` on your `PATH`:

```sh
# Import an OCI image once as a read-only template.
kubectl blip pull base ubuntu:24.04

# Start a command in a fork of base. run returns at once with the blip's name.
kubectl blip run --name hello --from base -- sh -c 'echo kept > /root/notes.txt'

# Wait for it, report its exit code, collect results, and delete it with its
# workspace.
kubectl blip gather hello

# Keep a durable workspace instead: --keep leaves the fork behind.
kubectl blip run --name workspace --from base --keep -- sleep infinity
kubectl delete blip workspace    # the workspace state survives
kubectl blip run --name next --state workspace -- cat /root/notes.txt
kubectl blip gather next

# Explicit cleanup when the workspace is no longer needed.
kubectl delete blipstate workspace base
```

`run` selects `--from SOURCE` to create a private workspace named after the new
Blip, or `--state WORKSPACE` to reuse an existing writable root. Import OCI
images with `blip pull BASE OCI_REF`; imported image states are read-only
templates and must be copied before use as a root or writable mount. Only one
execution can write a given state at a time.

A Blip owns the workspace it forks, so deleting the Blip frees it. `--keep`
leaves the workspace in place. Inside a blip, `--timeout` (default 2h) stops a
command whose caller disappeared, and `--ttl` (default 1h after it finishes)
deletes a blip nobody gathered.

## Fanning out from a blip

Inside a blip, `run` needs no source: it forks the caller's own root, keeps the
caller's working directory and pool, and names the blip after the caller.
`gather` with no arguments then targets the forks that blip started:

```sh
for i in 1 2 3; do
  blip run --name "w$i" --from / -w "$PWD" -- sh -c "./task $i"
done
blip gather --collect "git:$PWD:{name}" --collect "$PWD/out:./out/{name}"
```

Each `run` returns as soon as its fork's snapshot is committed, each fork sees
the same starting files, and changes stay private to their fork. `gather`
waits for all of them, prints `blip/NAME Phase (exit N)` for each, fetches each
blip's branch or files, and deletes each blip with its workspace. `git:`
collection fetches commits only: uncommitted and untracked changes are not
collected, and gather prints a warning when it finds them. `-f` streams
a running fork's output; `--any` returns on the first finish; `--wait` bounds
the wait; a fork whose command failed or whose results could not be collected
is kept for inspection until its TTL (1h by default) deletes it.

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
    - state: data # Create it first, e.g. blip mount --new data:/work:rw --size 20Gi.
      path: /work
      writable: true
  runtime:
    env:
      - name: PROJECT
        value: demo
    workingDir: /work
    user: "0:0"
    network: {} # Deny outbound traffic; omit to inherit the pool policy.
```

`blip mount data:/work:rw --root workspace` adds a persistent mount;
`blip mount --rm data --root workspace` removes it. `blip mount
--new cache:/cache:rw --size 20Gi --root workspace` creates a state and mounts
it, and `blip mount --root workspace` lists the mounts. Inside a blip, `--root`
defaults to that blip's own root. Mounts follow the root state into later
executions, including differently named Blips. Runtime defaults override
imported image metadata; per-execution overrides take precedence. `network`
narrows the pool's egress policy.

Forking a workspace copies its root, runtime defaults, and writable auxiliary
states, and shares read-only auxiliary states. These states are owned by the
fork's Blip, so they are removed with it. A Blip manifest selects its root with
`spec.state`.

## Implementation outline

Blip is a Kubernetes controller plus a privileged per-node agent. Workloads run
in Cloud Hypervisor/KVM VMs inside ordinary Pods; durable data lives outside the
Pod as node-local, replicated, encrypted block storage.

### API (`blip.dev/v1alpha1`)

- **`BlipPool`** — VM shape (CPUs, memory), `warmCount`/`maxCount`, node selector,
  service account, egress policy, and `endpoints` (guest-visible names proxied
  to fixed HTTPS URLs).
- **`BlipState`** — one durable ext4 filesystem. Provisioning is immutable:
  `image` (OCI image converted to ext4), `copyFrom`, `size`, `replicas` (default
  3), `nodeSelector`. `mounts` and `runtime` persist across executions.
  Image states are read-only templates held by every eligible node.
- **`Blip`** — one VM lifetime: root `state`, one required command, env, workdir,
  user, TTY, `stop` flag, `activeDeadlineSeconds` and `ttlSecondsAfterFinished`
  expiry, and per-execution network narrowing.
- **`BlipNode`** — cluster-scoped node inventory: endpoint, hypervisors,
  incarnation, heartbeat, drain and safe-to-remove state.
- **`BlipThread`** — one project's long-running coordinator. Administrators
  write the system prompt, charter, pool, base state, concurrency cap, model,
  daily token budget, heartbeat, and retention. An empty system prompt uses
  blipchat's built-in coordinator prompt; the charter is always appended.
  Blipchat writes status: turn sequence, rolling summary, timers, task board,
  token spend, and pause state.
- **`BlipTurn`** — one event in a thread: a user message, a blip report, a
  finished blip, or a coordinator step. Turns are immutable, carry a bounded
  text and free-form attributes, and blipchat stamps `status.seq` to put all
  turns in one order. In-cluster producers create turns; the API server
  validates that only the `blip-system/blipchat` service account may author a
  turn as someone else, and every other producer names its own service account.

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
- The `api-proxy` native sidecar holds projected service-account tokens and
  proxies the guest's loopback HTTP names over vsock. It routes by `Host`
  header: `kube-apiserver` goes to the API server with reads scoped to the
  Blip's owner; each `spec.endpoints` name goes to its configured HTTPS URL
  (optionally with its own token audience and CA). It strips caller identity
  headers, rejects `CONNECT`, and answers unknown hosts with `421`.

### Guest (`blip-guest`)

- PID 1 in the initramfs: reads its config disk, mounts pseudo-filesystems, loads
  modules, configures `eth0` over rtnetlink, and serves the framed vsock
  protocol on port 1024 (control) and 1025 (sessions). A second loopback
  listener on `127.0.2.2:80` raw-forwards to the API-proxy sidecar, and
  `/etc/hosts` maps `kube-apiserver` and the pool's endpoint names to it.
- Claims the root ext4 filesystem, chroots into it, resolves users/groups from
  the image's `/etc/passwd` and `/etc/group`, runs processes in a cgroup, and
  supports PTYs, multiple command sessions, signals, and window resize. Each
  session keeps a 1 MiB output replay ring.
- Uses `FIFREEZE`/`FITHAW` with a 90s auto-thaw for live snapshots.
- Writes `/run/blip/kubeconfig` pointing at `http://kube-apiserver`; the proxy
  injects the real token, so no credential enters the workload filesystem.
- Serves a report endpoint at `http://blip/report` (`127.0.2.1:80`), exposed to
  the command as `BLIP_REPORT_URL`. A workload POSTs up to 1 KiB of UTF-8 text
  and receives `{"seq": n}`; the text becomes `status.report` on the Blip and
  survives the pod. Reports are spaced at least 10 seconds apart and are never
  coalesced.

### Coordinator (`blipchat`, `cmd/blipchat` and `internal/blipchat`)

Blipchat is a stateless Deployment with one elected leader. The leader
sequences turns, turns blip reports and finished blips into turns, and runs
coordinator steps; every replica serves the engineer chat. Steps are driven by
`wake=Now` turns, a short debounce for `wake=Batch`, status timers, and a
heartbeat while tasks are open. A step reads its system prompt (the thread's
`spec.systemPrompt`, or the built-in default) and charter, a compact task board,
the rolling summary and new turns, may call asynchronous tools (start, watch,
exec and stop blips; manage tasks and timers), and then writes its turns and
one status update. One worker per thread serializes status writes. The model
is any OpenAI-compatible endpoint selected with `--llm-base-url`; the chat
front end authenticates users and blipchat reads the identity from
`X-Forwarded-User`. The chat is stateless: the browser sends its transcript and
`POST /chat?namespace=NS` names the thread (a valid DNS-1123 namespace label;
the default is `default`).

**Trust boundary:** blipchat has no authentication of its own. It believes
`X-Forwarded-User` from any caller and authorizes the namespace in the query
string with its own cluster-wide credentials. It must only be reachable through
a front end that authenticates users, overwrites `X-Forwarded-User`, and
restricts which namespaces each user may reach (a NetworkPolicy or an
authenticating proxy). Do not expose the Service directly. Requests with zero
or multiple `X-Forwarded-User` headers are rejected.

The chat endpoint accepts at most 1 MiB of JSON, an 8000-character message, 40
history messages, and 32000 characters of total history; larger requests get
`400`. The HTTP server bounds read, write, and idle time and closes unused
keep-alive connections, so a slow client cannot pin a handler. Chat inspection
is read-only:
running blips accept a small allowlist (`git status|log|diff|show`, `ls`,
`cat`, `head`, `tail`, `wc`, `grep`, `rg`, `find`, `pwd`) and finished blips
report their last report.

### CLI

- `kubectl-blip run` creates a Blip and returns its name as soon as its
  workspace snapshot is committed; `gather` waits for blips, reports their exit
  codes, collects files and git commits, and deletes them. `exec` runs
  additional commands in a running Blip, `mount` manages states and mounts, and
  `pull` imports images. It reaches a VM through Kubernetes pod exec
  (`blip-runtime bridge 1025`, WebSocket with SPDY fallback), then the framed
  vsock protocol.
- `gather -f` tails a running command's output, and the guest mirrors the
  primary command's output to the VM serial console, so `kubectl logs` shows it
  too. Output is not retained beyond the 1 MiB replay ring.
- A finished Blip is kept as Succeeded or Failed so its status and exit code
  remain visible, and `gather` reports the command's exit code. The controller
  deletes a Blip `spec.ttlSecondsAfterFinished` after it finishes and
  garbage-collects old finished Blips past a count threshold (1000 by default),
  oldest `status.finishTime` first; states remain until you delete them or their
  owning Blip is deleted.
- `spec.activeDeadlineSeconds` stops a command that has run too long, as if
  `spec.stop` were set. `blip run` sets it from `--timeout`.
- `blip-controller` is its own image; the node agent, VM runtime, and dev
  sandbox are separate images.

## Local development

`hack/kind-up.sh` builds and installs a local kind cluster and prints connection
examples. `hack/e2e.sh` exercises durable workspace reuse, concurrent forks,
gathering, deadlines, and command exit codes against that cluster. Tear it down with `hack/kind-down.sh`
(`--purge` also discards local storage).