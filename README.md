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
collected, and gather prints a warning when it finds them. A gather whose
operations resolve two blips to the same destination is rejected; use `{name}`
so each blip writes somewhere different. `--collect` splits SRC and DEST at the
last `:`, so neither may contain one. `blip mount` accepts paths with `:` (for
example `/a:b`), but such a mount cannot be collected: mount that data at a
colon-free path if you need to gather it. `-f` streams
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
  dependent copies exist. A copy waits for an in-flight source save and pins
  the new committed version; it does not capture the version current when the
  copy object was created. Newly eligible nodes receive existing image states.
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
  internet plus cluster DNS and denies private/LAN ranges and metadata. New
  inbound connections are admitted only from an explicitly named egress peer,
  matched on the rule's protocol and destination port; a broad `0.0.0.0/0`
  egress rule grants no new inbound connections. Replies to allowed flows and
  related ICMP errors (including PMTUD) remain allowed.
- Writes complete `desired.json`/`observed.json` snapshots and reconciles guest
  claims, mounts, freeze requests, and shutdown.
- The vsock socket lives in the pod directory (`sock/vsock.sock`), so the node
  agent dials the guest's stdio port directly. A bind-mounted `sock`
  subdirectory lets the non-root API-proxy sidecar share the same socket
  directory without access to the rest of the pod directory.
- The `api-proxy` native sidecar holds projected service-account tokens and
  proxies the guest's loopback HTTP names over vsock. It routes by `Host`
  header: `kube-apiserver` goes to the API server with reads scoped to the
  Blip's owner; each `spec.endpoints` name goes to its configured HTTPS URL
  (optionally with its own token audience and CA). It strips caller identity
  headers, rejects `CONNECT`, and answers unknown hosts with `421`. Endpoint
  tokens are projected only for the configured audience, and the controller
  rejects an audience the cluster API server accepts: the default
  `kubernetes.default.svc[.cluster.local]` names and the service-account
  issuer discovered from the API server's OpenID configuration. A cluster
  that overrides `--api-audiences` with an unrelated value is not covered by
  that check, so keep endpoint URLs off the API server on such clusters.

### Guest (`blip-guest`)

- PID 1 in the initramfs: reads its config disk, mounts pseudo-filesystems, loads
  modules, configures `eth0` over rtnetlink, and serves the framed vsock
  protocol on port 1024 (control) and 1026 (stdio). A loopback listener on
  `127.0.2.2:80` raw-forwards to the API-proxy sidecar, and `/etc/hosts` maps
  `kube-apiserver` and the pool's endpoint names to it.
- Claims the root ext4 filesystem, chroots into it, resolves users/groups from
  the image's `/etc/passwd` and `/etc/group`, runs the one required command in a
  cgroup, and wires its stdin/stdout/stderr to the stdio port. There is no
  exec, no TTY, and no second command. The guest buffers the last 256 KiB of
  each output stream so a reconnecting node agent resumes from byte offsets
  instead of losing output.
- Uses `FIFREEZE`/`FITHAW` with a 90s auto-thaw for live snapshots.
- Writes `/run/blip/kubeconfig` pointing at `http://kube-apiserver`; the proxy
  injects the real token, so no credential enters the workload filesystem.

### Stream API (`internal/streamapi`)

Node agents serve an aggregated API for trajectories at
`stream.blip.dev/v1alpha1`:

```
GET  /apis/stream.blip.dev/v1alpha1/namespaces/NS/blipstreams/STATE/log?offset=N&follow=true&raw=false
POST /apis/stream.blip.dev/v1alpha1/namespaces/NS/blipstreams/STATE/stdin?eof=true
```

The log is newline-delimited JSON (`o` offset, `g` generation, `t` type,
`d` base64 data); `raw=1` emits only stdout bytes. The node agent owns the
ring: it records stdin before forwarding it to the guest, records output as it
arrives, and closes the device before a seal. Reads of a running blip come from
the writer's node; reads of a stopped blip come from a committed placement
through a short-lived read-only view, so the API keeps working after the pod is
gone. Requests for another node's writer are forwarded over the existing peer
mTLS mesh. Authentication uses the kube-apiserver front-proxy identity
headers, and authorization is a delegated SubjectAccessReview on
`blipstreams/log` (get) or `blipstreams/stdin` (create). Node agents listen on
port 7891. If the front-proxy CA is not present on workers, the listener trusts
`X-Remote-User`; anyone who can reach port 7891 could then impersonate a user.
Restrict that port to the control plane (a host firewall, or a cluster that
makes the front-proxy CA available) before exposing a cluster beyond a trusted
team. The controller creates
the serving certificate Secret and the `v1alpha1.stream.blip.dev` APIService;
node agents load the certificate from that Secret.

### Chat (`blipchat`, `cmd/blipchat` and `internal/blipchat`)

Blipchat is a small, stateless web app for talking to ACP agents that run in
blips. A chat session is a `BlipState` with the label
`chat.blip.dev/session=true`. The state's trajectory ring is the conversation:
forking the state with `spec.copyFrom` gives the new chat the parent's history,
and each turn's stdin/stdout is recorded there. The title, profile, ACP session
id, and last read log offset live in annotations
(`chat.blip.dev/title`, `chat.blip.dev/profile`, `chat.blip.dev/acp-session`,
`chat.blip.dev/offset`).

A turn starts a Blip named `<state>-g<generation>` in the same namespace with
`spec.state` set to the chat state, the profile's command, env, pool, and idle
timeout (default one hour). Blipchat reads the aggregated stream API
(`/apis/stream.blip.dev/v1alpha1/namespaces/NS/blipstreams/STATE`) to write raw
stdin and to follow the NDJSON trajectory log. A `409` means no agent is
running: blipchat starts the next generation, waits for it to reach `Running`,
sends ACP `initialize`, then `session/load` (or `session/resume` when the agent
advertises it) with the stored id, and retries the prompt. ACP is JSON-RPC 2.0
over newline-delimited stdin/stdout; blipchat implements `initialize`,
`session/new`, `session/load`, `session/resume`, `session/prompt`,
`session/cancel`, `session/update`, and `session/request_permission`. When a
prompt response arrives and no other request is pending, blipchat sends
`stdin?eof=true`; the agent exits and the blip stops and saves the state. The
next message starts a new generation.

Profiles are read from the `blip-chat-profiles` ConfigMap (override with
`--profiles-configmap NAMESPACE/NAME`) and optionally `--profiles-file`. Each
key is a profile name whose JSON value is
`{"pool":"default","command":["npx","-y","@zed-industries/claude-code-acp"],
"env":{"K":"V"},"idleTimeoutSeconds":3600,"title":"Claude Code"}`. The example
command is documentation, not a bundled install: use a base state whose
filesystem already has the agent, or configure another profile. The built-in
`default` profile uses that command and `--default-pool`.

The HTTP API is under `/api`, and `/` serves a dependency-free single-page UI:

- `GET /api/sessions?namespace=NS` lists chat states with title, running
  state, generation, and ACP session id.
- `POST /api/sessions {namespace, profile, title, base?}` creates a state
  (copying `base` when given) and starts generation 1.
- `GET /api/sessions/NAME?namespace=NS` returns details and the in-memory
  transcript tail.
- `GET /api/sessions/NAME/events?namespace=NS&offset=N` is SSE. Events are
  `{type:"acp",message:{...}}`, `{type:"status",status:{...}}`, and
  `{type:"gap"}`.
- `POST /api/sessions/NAME/message {text}` prompts or steers the agent,
  restarting it when stopped. `.../cancel` sends ACP `session/cancel`, and
  `.../stop` patches `spec.stop` on the current blip.
- `GET /healthz` and `GET /readyz` are probes.

**Trust boundary:** blipchat has no authentication of its own. It believes
`X-Forwarded-User` from any caller and authorizes the namespace in the query
string with its own cluster-wide credentials. It must only be reachable through
a front end that authenticates users, overwrites `X-Forwarded-User`, and
restricts which namespaces each user may reach (a NetworkPolicy or an
authenticating proxy). Do not expose the Service directly. Every `/api` request
must carry exactly one non-empty `X-Forwarded-User` header, and a namespace
must be a valid DNS label. Requests with zero or multiple headers get `401`;
an invalid namespace gets `400`.

The HTTP server bounds header, read, and idle time and caps request bodies at
1 MiB. SSE clears the write deadline for its own connection and uses a 20-second
heartbeat, so a quiet agent does not look like a stalled handler.

### CLI

- `kubectl-blip run` creates a Blip and returns its name as soon as its
  workspace snapshot is committed; `gather` waits for blips, reports their exit
  codes, collects files and git commits, and deletes them. `mount` manages
  states and mounts, `pull` imports images, and `stop` stops a running blip.
  `run` closes the command's stdin once the blip exists unless `--interactive`
  is set.
- `logs` prints a command's trajectory (stdout, stderr, stdin, and lifecycle
  records), and `send` writes stdin. Both use the aggregated stream API, so they
  work while the command runs (with `-f`) and after its pod is gone, as long as
  the state retains its trajectory. `gather -f` is a thin wrapper over `logs
  -f`; there is no serial-console scraping and no `status.output` tail.
- `exec` no longer exists. A blip runs exactly one command; start another blip
  on the same state to run a second command, and fork from it for parallel work.
- Every blip's stdin, stdout, stderr, and exit are recorded in a trajectory ring
  at a fixed offset inside the state's volume, after the ext4 filesystem. The
  ring defaults to 64 MiB (`BlipState.spec.streamSize`) and overwrites its
  oldest whole records when full, so a chatty agent never blocks. Because the
  ring is part of the state, forking a state copies the conversation history.
- `spec.idleTimeoutSeconds` stops a command that has been silent for that long.
  The node agent enforces it; the blip saves its root and finishes as
  succeeded with reason `Idle`. Batch commands rely on
  `spec.activeDeadlineSeconds` instead.
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
examples. `hack/e2e.sh` runs the end-to-end scenarios in `hack/e2e/` against that
cluster. They cover the CLI lifecycle, durable workspaces, mounts, concurrent
forks, trajectories and stdin, the endpoint proxy, in-guest Kubernetes access,
network policy, state serialization and finalizers, cluster scheduling, and a
blipchat HTTP smoke test. The slow drain and node-restart scenarios
run only with `BLIP_E2E_RESILIENCE=1` (nightly in CI). Set `BLIP_E2E_SCENARIOS`
to a space-separated list of scenario number prefixes (for example `20 40`) to
run a subset while developing. Tear the cluster down with `hack/kind-down.sh`
(`--purge` also discards local storage).
