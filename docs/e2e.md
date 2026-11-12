# End-to-end test on kind

`hack/e2e/run.sh` tests the whole system on the local kind cluster: real
microVMs with agentless guests, multi-volume Blips with live attach and
forced detach, shutdown and interval snapshots written to storage nodes,
derive,
storage over NVMe/TCP with TLS, pod IP networking over DHCP, guest exit
classification (poweroff, reboot, panic, PID 1 exit, boot failure), graceful
stop with the power button and port forwarding over vsock. Design: `docs/design.md`.

## Run it

```sh
make kind-up                         # once: cluster, loop devices, host tlshd
make guest images kind-load deploy   # build and deploy Blip (deploy restarts the pods)
make e2e                             # or: hack/e2e/run.sh [check...]
```

Inner loop after a change to Go code:

```sh
make redeploy                        # about 20-60s
hack/e2e/run.sh chain                # one check: about 30s plus the check
hack/e2e/run.sh                      # all checks, 4 at a time: about 7.5 minutes
```

`make redeploy` rebuilds `bin/blipd` and the blipd and slot images, loads
only images whose ID changed into the kind nodes (in parallel), applies the
manifests, restarts the controller and node pods and waits until the
controller has a session with every node daemon (`hack/kind/ready.sh`).
Run `make guest` once first. `KIND_LOAD_FORCE=1` loads images even if they
look unchanged. A restart of the node pods can take a node away for longer
than the kind node-lost timeout, so Blips running during `make redeploy`
may fail with `NodeLost`.

Go builds use a private build cache, `.cache/go-build` in the repository
(`BLIP_GOCACHE` to change it), through `hack/go.sh`. On a shared host other
jobs clean `~/.cache/go-build` while builds run, which made builds fail
with `no such file or directory` under `go-build` or `package os is not in
std`. `hack/go.sh` retries such a build once.

The script needs `jq`, `kind`, `kubectl`, `docker` and `go`. It writes the kubeconfig of the kind cluster `$KIND_CLUSTER` (default `blip`) to `/tmp/opencode/e2e-<cluster>.kubeconfig` and exports `KUBECONFIG`, so the current kubectl context does not matter. Set `E2E_KUBECONFIG` to use a given kubeconfig instead. `make deploy` uses `--context kind-$(KIND_CLUSTER)`. The `tls`
check also needs passwordless `sudo` (it reads nvmet configfs and NVMe sysfs
on the host). The guest kernel needs `CONFIG_VFAT_FS` (workloads format
their own data volumes) and `CONFIG_MAGIC_SYSRQ` (the `panic` check).

## The kind cluster

- `hack/kind/up.sh` creates a kind cluster with one control-plane node and 3 workers. Each worker is both a storage node and a compute node, so the 3 workers form group `sg-1`.
- Backing files live under `BLIP_DATA_DIR` (default `/mnt/nvme2/blip/kind`). Each worker gets two loop devices: one for its VG `blip-<node>`, one for its compute pool. The script creates the device nodes inside the kind node and writes `/etc/blip/node.yaml`.
- All kind nodes share the host kernel. This is why names include the node name (design 7.1), each replica has its own NQN (design 7.2), and VGs use `--setautoactivation n`.
- The node daemon mounts configfs in the kind node if it is missing. nvmet ports listen in the kind node's network namespace.
- NVMe/TCP reconnects run in the host's initial network namespace. The host must run `tlshd` (package `ktls-utils`) and reach the kind node addresses. `hack/kind/up.sh` installs and starts it if needed. The host side passes the key serial, so the stock host config works.
- `/dev/kvm` comes from the host. MSHV is not tested locally.
- The kind overlay runs the controller with `--snapshot-interval-scale=60`, so a 5m interval runs every 5s; it also shortens `--heartbeat` (3s) and `--node-lost-timeout` (40s).
- `hack/e2e/run.sh` (`make e2e`) runs end-to-end tests against this cluster.
- `make kind-load` imports images with `ctr import`, because `kind load` fails with recent Docker versions.
- The kind node `/sys` is read-only; the node daemon remounts it read-write in its own mount namespace.

## Guest image

The root image is `images/blip-e2e`: Alpine with `blip-meta`, `curl`, `jq`,
`socat` and `dosfstools`, and no init system. Unless `E2E_IMAGE` is set, the
script builds `bin/blip-meta` and the image, pushes it to the local
registry (`hack/registry/up.sh`, also `make e2e-image`) and imports it by
digest. Every Blip boots it with

```yaml
init: [/sbin/blip-e2e-init, MODE, ARGS...]
```

`blip-e2e-init` is a shell script running as PID 1. It mounts `/proc`,
`/sys`, `/dev`, `/run` and `/tmp`, keeps `/dev/disk/by-id/virtio-<serial>`
links for the virtio disks (there is no udev), runs `udhcpc` on the first
Ethernet NIC (renewing in the background), runs `blip-meta creds --watch`
into `/run/secrets/kubernetes.io/serviceaccount` and waits for the ACPI
power button on its input device. Then it runs MODE:

| Mode | Behaviour |
|---|---|
| `ok` / `fail CODE` | exit 0 / CODE |
| `sh SCRIPT` | run SCRIPT with busybox `sh` and `lib.sh` (helpers `w`, `r`, `dev`, `waitdev`, `net_report`, `creds_check`) |
| `sleep [SECS]` | sleep (forever by default) |
| `panic` | `echo c > /proc/sysrq-trigger` |
| `initexit CODE` | PID 1 exits with CODE |
| `reboot [N]` | `reboot -f` until this is boot N (default 2, counter on the root fs), then exit 0 |
| `net`, `creds` | network and credential checks from `lib.sh` |
| `vsock PORT [SECS]` | answer `PONG <hostname>` on AF_VSOCK PORT |

When MODE ends, the init records its exit code with `blip-meta exit CODE`,
remounts the root read-only and runs `poweroff -f`. A power button press
writes `/e2e-power.txt`, records exit code 0 and powers off the same way.
Console lines from the image start with `E2E `, `NET ` or `CREDS `.

Expected outcomes: poweroff with exit code 0 is `Complete`; a nonzero code is
`Failed`/`Error` with `lastExitCode`; a kernel panic is `Failed`/`GuestPanic`;
PID 1 exiting is `Failed`/`InitExited`; a root that cannot be mounted is
`Failed`/`BootFailed` (message with `RootMountFailed`); `maxTTLSeconds` is
`Failed`/`TTLExceeded`. `status.restartCount` counts guest reboots.

The kind overlay runs the controller with short timers, so the checks
wait less:

| Flag | Kind | Default | Why |
|---|---|---|---|
| `--snapshot-interval-scale` | 60 | 1 | The 5m minimum `snapshotPolicy.interval` runs every 5s (`periodic`, `compact`, `nodeloss`) |
| `--heartbeat` | 3s | 10s | Both sides drop a silent session after 3 heartbeats (9s) |
| `--node-lost-timeout` | 40s | 2m | `nodeloss` waits for it. It must stay above the node daemon's longest reconnect backoff (30s), or a controller restart could mark connected nodes lost |

`nodeloss` needs `docker` access to the
kind node containers. It pauses nodes instead of stopping them: `docker
stop` (and sometimes `docker restart`, which `nodeloss` retries) can fail
with "did not receive an exit event" when the host is slow to write back
the node's overlay file systems, leaving the node half torn down. Deleting
the Node object is not covered (the kubelet re-registers it without the
labels `hack/kind/up.sh` set); the controller treats NotFound like the
taint, which envtest covers.

Options (environment):

| Variable | Effect |
|---|---|
| `E2E_ONLY=a,b` | Run only these checks (same as `hack/e2e/run.sh a b`) |
| `E2E_KEEP=1` | Keep the namespaces after the run |
| `E2E_FAILFAST=1` | Stop at the first failing check |
| `E2E_DIAG_DIR` | Where diagnostics go (default `/tmp/opencode/blip-e2e-diag`) |
| `E2E_IMAGE` | Use this guest image (built from `images/blip-e2e`) instead of building and pushing one |
| `E2E_UBUNTU_IMAGE` | For the `plugin` and `nested` checks: use this SSH image (built from `images/blip-ubuntu`) instead of building and pushing one |
| `E2E_PARALLEL=N` | Run up to N checks at a time (default 4, the size of the pool; 1 runs one at a time) |
| `E2E_LOG_DIR` | Where per-check logs go (default `/tmp/opencode/blip-e2e-logs/<time>`) |

Checks run in three phases. `health` and `image` run first, alone. Then
the other checks run up to `E2E_PARALLEL` at a time, longest first;
`plugin` and `nested` run one after the other, since they share the
`img-<hash>` BlipVol, the sessions and the `blip-ssh` RBAC objects.
`pool` (it checks the pool's free count) and `nodeloss` (it takes nodes
away) run last, alone. The parallel checks share namespace `blip-e2e` and
its pool of at most 4 slots, with unique Blip and BlipVol names; when all
slots are in use a Blip waits for one. Each check writes
`<log dir>/<check>.log`; stdout gets the same lines prefixed with the
check name.

It uses the namespaces `blip-e2e` and `blip-e2e-quota` and deletes them
before and after the run, so it is safe to run again. Each namespace is
its own pool: after creating a namespace the script applies the kind slots
(`config/overlays/kind/slots/common`, a BlipPool with 2 to 3 free slots and at most 4 slots) into it. `make deploy`
also installs slots into `blip-e2e`, `blip-e2e-quota` (1 slot) and the demo
namespace `blip-demo` (1 slot); kind has 6 hypervisor devices in total. One image BlipVol
`base` is imported once; each check clones its own root from it, so checks
never compete for a root volume claim. Each check runs in a subshell: a
failure ends only that check and writes a diagnostics file (Blips,
BlipVols with their snapshot history, describe output, controller and node log
tails). After every check its Blips (label `e2e-check=<check>`) are deleted
so slots and claims are free. A summary table ends the run; the exit code is
nonzero if any check failed.

Guest workloads find data volumes at `/dev/disk/by-id/virtio-<name>`
(`waitdev` waits for the device and checks its virtio serial) and treat them
as raw block devices: markers are written to sector 0 with `dd
conv=sync,fsync` and read back with `head`; some checks run `mkfs.vfat` and
`mount` themselves. Blip itself only mounts the root volume.

## Checks

| Check | What it proves |
|---|---|
| `health` | Controller, node DaemonSet and the BlipPool in `blip-e2e` are ready, every node advertises slots, all 3 nodes have a session, the Blip, BlipVol and BlipPool CRDs exist and no BlipSnapshotSeries CRD |
| `image` | A BlipVol imported from an OCI image becomes Ready; its history is snapshot 1 (`Initial`, current) with at least 2 sealed replicas |
| `chain` | A Blip writes a file to its root and completes; `status.volumes[root].shutdownSnapshot` is `Ready`/`Completed` and names a sequence; the root BlipVol's `status.current` moved to it (reason `Shutdown`, `writer` = the Blip). A second Blip on the same BlipVol reads the file and appends another; the vol advances again. With `snapshotPolicy.skipShutdown: true` the state is `Skipped` and `current` does not move |
| `net` | The guest NIC got the slot pod IP from the slot's DHCP server with a 24h lease (86400s) and has the pod's MAC, `status.podIP` is the pod IP, cluster DNS answers, and `kubectl logs` of the slot pod shows the console |
| `tls` | Every nvmet port requires TLS 1.3, every NVMe/TCP path of a running Blip has a TLS key, a plain connect is refused, and `tlshd` logged handshakes |
| `datavols` | Image root plus two empty 64Mi BlipVols: the guest sees each at `/dev/disk/by-id/virtio-<name>` with virtio serial `<name>` (distinct, zero-filled); the workload formats one (vfat) and writes raw bytes to the other; `status.volumes[].devicePath` is `/dev/disk/by-id/virtio-a`; three shutdown snapshots are `Ready`/`Completed`; a Blip on the same BlipVols sees the root file, the vfat file and the raw bytes |
| `hotplug` | On a running Blip, adding a `spec.volumes` entry reaches `Attached` and claims the BlipVol; the workload (polling for the device) writes to it; removing the entry reaches `Released`, the claim is gone, the Blip keeps running, the shutdown snapshot is `Ready`/`Detach` and has the bytes |
| `forcedetach` | The workload mounts a vfat data volume and syncs a file; removing the entry detaches it at once (forced, no `DetachBlocked`): `Released` with a `Detach` snapshot while the Blip keeps running; the snapshot has the file |
| `never` | Guest exit code 3 (`blip-meta exit 3`, then poweroff) gives phase `Failed`, `Failed`/`Error`, `lastExitCode` 3 and a message with the code; the root and data shutdown snapshots are still `Ready` with reason `Failed`, and the data snapshot has the bytes |
| `ttl` | `maxTTLSeconds` gives `Failed`/`TTLExceeded` and a `DeadlineExceeded` shutdown snapshot |
| `cancel` | Deleting a running Blip stops it, deletes its slot pod, releases the claim and publishes one `Ready` root snapshot that has the file written before the delete |
| `poweroff` | Deleting a running Blip presses the ACPI power button: the guest's handler writes `/e2e-power.txt` and powers off; the `Deleted` snapshot has the file |
| `reboot` | The guest runs `reboot -f` once: the VM boots again from the same root (boot counter on the root fs), then completes; `status.restartCount` is 1 |
| `panic` | A kernel panic (`sysrq c`) gives `Failed`/`GuestPanic`; the root shutdown snapshot is `Ready`/`Failed` |
| `initexit` | PID 1 exiting with 7 gives `Failed`/`InitExited` and `lastExitCode` 7 |
| `move` | The same root BlipVol boots in one slot, is released, and boots in another slot pod: each time the guest gets that pod's IP by DHCP, resolves cluster DNS, and authenticates to the API server with the token from `blip-meta creds` (SelfSubjectReview as `system:serviceaccount:<ns>:default`) |
| `portfwd` | With `ports: [{port: 8080}]`, `kubectl port-forward` to the slot pod reaches a guest AF_VSOCK listener on port 8080 (`socat VSOCK-LISTEN`) |
| `periodic` | Two volumes with `snapshotPolicy: {interval: 5m, limit: 2}` and a counter written to both every second: each BlipVol gets `Interval` snapshots while attached; after at least 4 of them compaction keeps at most 2 Ready ones (plus the claim's `snapshot` and `baseline`); sequences only grow. After the Blip is deleted each vol has a `Shutdown` snapshot as `current`, and a new Blip on both sees the counters |
| `exclusive` | While one Blip holds a BlipVol, a second Blip using it is `Pending` with `Scheduled=False/VolumeInUse` and `status.claim` names the first; the second runs after the first finishes and starts from the first one's shutdown snapshot |
| `delblock` | Deleting a BlipVol attached to a running Blip leaves it with a `deletionTimestamp` and `Ready` reason `DeletionBlocked`; it is gone after the Blip finishes |
| `blankroot` | A Blip whose root volume is an empty BlipVol fails with `Failed`/`BootFailed` (message with `RootMountFailed`) and releases the claim |
| `quota` | With `quota.blip.example.com/default: "1"`, a second Blip waits with `QuotaExceeded` and runs when the first is gone |
| `pool` | A claimed slot pod loses its BlipPool owner reference and keeps the `pool` label, the pool refills to `minFree` free slots, and after the Blip is deleted its pod is gone and the pool is Ready |
| `plugin` | `kubectl blip` (`bin/kubectl-blip` first on `PATH`, `BLIP_HOME` in a temporary directory) with the `images/blip-ubuntu` SSH image: `setup` creates and then keeps the `blip-ssh` RBAC objects; `shell --image REF --ttl 15m -- CMD` creates `img-<hash>` and a session whose root is a clone owned by it, prints the remote output, leaves the key and `known_hosts` with mode 600; `-- exit 7` exits 7; a second `shell` reuses the session without prompts; `list` shows it Running with an owner; `ssh -F <ssh-config output> blip-<s>` connects through `kubectl blip proxy`; `create --volume img-<hash> --wait` runs a second session from the same image at the same time; after `poweroff` a finished session is refused without a terminal and replaced with `--recreate`; `delete` refuses a Blip without the session label unless `--force`; `delete --wait` removes the sessions and their root clones |
| `resched` | `spec.reschedule` with a connected node: the first attempt writes markers to data volumes `d` and `s` (`s` has `skipShutdown: true`) and to the root, then panics (`GuestPanic`). Every attached volume, `s` included, gets a `Ready` `Reschedule` snapshot written by the Blip; the second attempt starts from it (`status.volumes[].snapshot`, no `resumedFrom`), sees all markers and completes; `rescheduleCount` 1, `lastFailure.reason` `GuestPanic`, `Rescheduling` reason `Rescheduled`; `s` skips its final snapshot |
| `derive` | `kubectl blip derive` on a BlipVol with two Shutdown snapshots (GEN1, GEN2): from the idle vol (`status.origin.snapshot` = newest), with `--snapshot N` (the older one), `--snapshot 99` is refused by the plugin and a BlipVol with `spec.parent.snapshot: 99` waits with `Ready=False/SnapshotNotYetTaken`; while a running Blip has the vol attached and wrote GEN3, `derive` makes a live `Derive` capture (written by that Blip, which keeps running) and clones it; `kubectl blip volumes` lists the capture and the pins; a Blip on the three derived vols reads GEN2, GEN1 and GEN3 |
| `compact` | `snapshotPolicy: {interval: 5m, limit: 2}` (5s scaled): an old `Interval` snapshot pinned by a derived BlipVol survives while the snapshots after it are compacted, with `RetentionLimitExceeded=True/Pinned`; after the derived vol is deleted the pinned snapshot is compacted and the reason becomes `Held` (the claim's start snapshot 1 is still kept, so 3 Ready exceed the limit) |
| `nodeloss` | Disruptive, runs last and alone: takes kind node containers away and restores them on exit (unpause/start, out-of-service taint removed, uncordon, nodes Ready, kindnet pod routes, node DaemonSet rolled out, every node daemon has a controller session). If the controller runs on the node to be taken away it is first moved off it (cordon, delete the pod, uncordon). Each Blip has `spec.reschedule`, a volume `k` with interval snapshots (KEEP written once, so every Interval snapshot has it) and a volume `d` without (LOST, never snapshotted). **reboot**: `docker restart` of the Blip's node: `/run` (allocation records) is a tmpfs and the VM is gone, so the node returns without the allocation (it still reports the leftover overlay devices, record-less); the attempt ends `SlotLost`, the overlays are `Unavailable`, the next attempt resumes `d` from snapshot 1 and `k` from an `Interval` snapshot (`resumedFrom`), `Rescheduling` reason `ResumedFromOlderSnapshot`; the guest sees KEEP and a blank `d`. **fence**: `docker pause` (all node processes frozen) with `salvageTimeout: 5s`, `nodeLoss: Fence`: after the node-lost timeout (40s on kind) and the salvage window the Blip waits (checked for 10s) in `Saving` with `Rescheduling=False/NodeUnreachable`; the `node.kubernetes.io/out-of-service` taint lets it resume from older snapshots; when the node is unpaused it gets an `OverlayDiscarded` event. **abandon**: the same with `nodeLoss: Abandon`: it resumes without fencing, and the returning node gets `OverlayDiscarded` |
| `nested` | `kubectl` and `kubectl blip` inside a Blip, after `setup --nested` (creates `role/blip-ssh-nested` and its binding). In session `pn1` the guest runs as `system:serviceaccount:blip-e2e:blip-ssh` and `kubectl` completes `kubectl blip de` to `derive`, then: `kubectl blip derive --volume root --wait` triggers a live capture (reason `Derive`) of its own root and prints a new BlipVol with `status.origin`; `create pn-task --volume <derived> --wait`; a shell in `pn-task` sees the parent's file, has its own hostname and SSH host key, and writes a result; `kubectl blip derive <task root> --wait` (a live `Derive` capture of the running task) keeps it in a new BlipVol whose `status.origin` is the task's root; `delete pn-task --wait`; `attach <result> --name out --mount /mnt/out` prints `/dev/disk/by-id/virtio-out`; the result is copied off; `detach out --delete` unmounts, detaches and deletes the BlipVol; `shell pn-fresh --image REF` starts a Blip that does not have the parent's files. From the host: the first derived BlipVol is `Ready`, its `status.origin` names `pn1`'s root (uid and sequence) and that sequence is a `Ready` `Derive` snapshot of the root. After that `pn1` has only its root volume and still has the copied file; `pn1` and the derived BlipVol are deleted |

Run single checks by name, for example `hack/e2e/run.sh chain periodic` or
`E2E_ONLY=hotplug,forcedetach make e2e`. Every check except `health` first imports
`base` if it is missing. When `plugin` or `nested` is selected the script also builds
and pushes `images/blip-ubuntu` (unless `E2E_UBUNTU_IMAGE` is set); these
checks need `ssh` on the host.

## Timing

Every wait has a timeout and polls every second. Measured on kind on a
shared host (Nov 2026):

| Step | Time |
|---|---|
| `make redeploy` after a Go change | 20-60s (build 1-30s, images 2s, load 5s, rollout and node sessions the rest) |
| `make guest images` with nothing changed | about 10s |
| One quick check (`hack/e2e/run.sh chain`) | about 45s: 30s of setup (namespaces, image push, `base` import) plus the check |
| Full run, `E2E_PARALLEL=4` | about 7.5 minutes: `health` and `image` 5s, the parallel phase about 3 minutes, `pool` and `nodeloss` about 4 minutes |
| Full run, `E2E_PARALLEL=3` | about 9 minutes |
| Full run, one check at a time, before the kind timers were shortened | about 28 minutes |

The longest check is `nodeloss` (about 4 minutes, alone). Its fence and
abandon cases each wait about 55s for the node to be lost (9s until the
session drops, the 40s node-lost timeout, the 5s salvage timeout) and
then for a new attempt to boot; the reboot case waits for the node
container to restart. In the parallel phase `nested` and `plugin` (about
1-1.5 minutes each, one after the other) and checks that wait for a Blip
to finish (`exclusive`, `delblock`, 40-60s) take longest; with 4 slots in
the pool the checks also wait for each other's slots. `make e2e` stops a
run after 60 minutes.
