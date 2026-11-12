# Spike: guest, agent and slot

**Historical.** Blip no longer has a guest agent. This spike is superseded by `docs/spikes/agentless.md` and design section 8. The agent, its vsock protocol and the command model below no longer exist.

Status: done. Everything below was run on the dev host (kernel 7.0, `/dev/kvm`, no MSHV).

Later changes: the NAT network (`10.0.2.0/30`, nftables, IPv4 forwarding) was replaced by giving the pod IP to the guest (design section 9), and the agent no longer streams logs; command output goes to the guest console (design section 10). The single `/dev/blip-root` disk and the `Sealed` event were also replaced: VMs now boot with no disks, every volume is hot-plugged, and the agent reports `Released` (design sections 4.3 and 8).

## Artifacts

`hack/guest/fetch.sh` downloads these into `_output/guest/` and checks their sha256. Downloads are cached in `/mnt/nvme2/blip/guest/dl`.

| Artifact | Version | Source |
|---|---|---|
| Cloud Hypervisor | v54.0, `cloud-hypervisor-static` | GitHub release asset |
| Guest kernel | 7.2.8, tag `ch-release-v7.2.8-20261009`, `bzImage-x86_64` | `cloud-hypervisor/linux` release |
| Kernel config | `arch/x86/configs/ch_defconfig` at the same tag | used only for the config check |

**MSHV.** The official static release is built with `--features mshv` on top of the default `kvm` feature (see `.github/workflows/release.yaml` at v54.0). The binary contains the MSHV code (`/dev/mshv` and the MSHV emulator strings). So one binary serves both, and we pin the release binary. Only KVM was tested; this host has no `/dev/mshv`.

**Kernel config.** The release kernel has no `IKCONFIG`, so we check the defconfig it is built from (the release workflow runs `make ch_defconfig`). `hack/guest/check-kernel-config.sh` requires these as built-in (`=y`): initrd with gzip, devtmpfs, virtio-pci, virtio-blk, virtio-net, vsock with the virtio transport, ext4, virtio-balloon, page reporting, ACPI PCI hotplug, cgroups with memory and pids, Unix98 ptys, tmpfs, inet, packet, serial console. All are present, so no custom kernel is needed. Netfilter and IPv6 are off in the guest, which we do not need.

**Initramfs.** `hack/guest/mkinitramfs.sh` builds a static `blip-agent` and writes `_output/guest/initramfs.cpio.gz` with a small Go tool (`hack/guest/mkinitramfs`). The tool writes the `newc` format itself, so `/dev/console` and `/dev/null` can be created without root. The archive holds only `/init` (the agent) and empty mount points. Size: about 5 MiB compressed.

Build all: `make -f hack/guest/Makefile guest` (fetch, initramfs, `slotdev`). Test rootfs: `make -f hack/guest/Makefile rootfs` exports `alpine:3.22` into `/mnt/nvme2/blip/guest/rootfs-alpine`.

## Boot time

From starting `blipd slot` (TAP and nftables setup, capability drop, Cloud Hypervisor start) to the first successful `Hello` over vsock: **280 to 350 ms** (1 vCPU, 512 MiB, 5 runs). The guest kernel reports about 0.12 s of uptime when the agent starts listening.

A full successful run (boot, hot-plug, mount, run a short command, seal, power off, Cloud Hypervisor exit) takes about 0.6 s.

## Agent

- PID 1. It mounts `/proc`, `/sys` and `/dev`, then listens on vsock port 1024. A reaper collects every child with `wait4(-1)` and hands the status of the workload process to the run loop.
- **Root switch.** The design said `pivot_root`. That does not work from an initramfs (the root is `rootfs`, which cannot be pivoted). The agent instead stays in the initramfs and runs the command with `chroot` into the mounted disk at `/mnt/root`. This also makes unmounting simple, because the agent never holds the disk. Isolation inside the guest is not a goal, so `chroot` is enough.
- Mounts in the new root: `proc`, `sys`, `sys/fs/cgroup` (cgroup2), `dev` (devtmpfs), `dev/pts`, `dev/shm`, `run`. `/etc/resolv.conf` and `/etc/hosts` are bind-mounted from tmpfs files when they are regular files on the disk, so the saved disk keeps its own copies. A missing file or a symlink is replaced on the disk.
- **Disk.** The agent waits up to 30 s for a block device whose `/sys/block/*/serial` equals the allocation ID. virtio-blk serials are at most 20 bytes, so it compares with the first 20 bytes (`agent.SerialFor`). **Allocation IDs should be at most 20 bytes, or at least unique in their first 20 bytes.**
- **Network.** (Replaced since: the guest now owns the pod IP; see design section 9.) Guest `eth0` was `10.0.2.2/30` with gateway `10.0.2.1` (the TAP device in the pod). Both can be changed in `Start`. The subnet is private to each pod network namespace, so every slot uses the same one.
- **Cgroups.** Each attempt runs in a new cgroup `/sys/fs/cgroup/workload/attempt-N`, killed with `cgroup.kill` and removed after the attempt. Reusing one cgroup after `cgroup.kill` made every later process in it die with SIGKILL at once (seen on the 7.2 guest kernel), so a fresh cgroup per attempt is required.
- **Logs.** stdout and stderr are read line by line (lines over 16 KiB are split). Each event has a sequence number, the guest time and the attempt number. The agent keeps the newest 20000 events or 4 MiB, whichever is smaller. All logs of an attempt are sent before its `Exited` event (2 s limit for pipes held open by leftovers).
- **Retries.** OnFailure: 10 s, doubling to 5 min, back to 10 s after a run of 10 min or more. `Start` can override these for tests. A command that cannot be started counts as exit code 127.
- **Success.** Kill the attempt cgroup, `sync`, unmount everything (remount read-only if the disk stays busy), send `Sealed`, wait for the node's `Ack` (20 s limit), power off. A failed unmount is reported as `STATE_START_FAILED` with a message and no `Sealed`.
- **Failure with Never, setup failure.** The agent stays up in a terminal state. The node kills the VM.

## Protocol (formerly `internal/proto/agentpb`, removed)

gRPC over vsock. Calls: `Hello`, `Start`, `Events` (server stream from a sequence number), `Ack`. Every request carries the protocol version (`VERSION_1`) and the allocation ID. The first `Start` binds the guest to its allocation; later calls with another ID get `PermissionDenied`. A repeated `Start` is a no-op that returns the status.

**Reconnect.** A node that restarts calls `Hello` (current state, attempt, last exit code, first and last buffered sequence numbers) and then `Events(after = last seq it stored)`. If the first event it gets has `seq > after+1`, events were dropped from the buffer.

**Why `Ack`.** Without it, power off can race the delivery of `Sealed`, and the node cannot tell a clean shutdown from a guest that powered off for another reason. The client acks `Sealed` on its own.

The node reaches the agent through the Cloud Hypervisor hybrid vsock socket: connect to `/run/blip/vsock.sock`, send `CONNECT 1024\n`, read `OK <port>\n`, then speak gRPC.

## Slot (`blipd slot`)

1. Refuse to start if `/run/blip/assigned` exists. Remove `ready`, `kill`, `exit.json` and sockets left by an earlier container.
2. Pick the hypervisor: the one of `/dev/kvm` and `/dev/mshv` that exists (both is an error), or the one set with `--hypervisor`.
3. Network: create a persistent TAP `blip0` owned by the current uid and gid, with flags `IFF_TAP | IFF_NO_PI | IFF_VNET_HDR` (what Cloud Hypervisor asks for with one queue pair). Give it `10.0.2.1/30` and bring it up. Cloud Hypervisor then opens it without `CAP_NET_ADMIN` and skips `SIOCSIFFLAGS` because it is already up. nftables (`github.com/google/nftables`), table `ip blip`: masquerade `10.0.2.0/30` out of the default-route interface, and drop all input from the TAP, so the guest cannot reach anything listening in the pod network namespace.
4. Drop capabilities in all threads (`AllThreadsSyscall`): bounding set, ambient set, then effective, permitted and inheritable, and set `no_new_privs`. This needs `CAP_SETPCAP`, which containers have by default. The test checks that Cloud Hypervisor runs with `CapEff`, `CapPrm` and `CapBnd` all zero.
5. Start Cloud Hypervisor: kernel, initramfs, `--cpus boot=VM_CPUS`, `--memory size=VM_MEMORY`, `--net tap=blip0,mac=52:54:00:00:00:02`, `--vsock cid=3,socket=/run/blip/vsock.sock`, `--api-socket path=/run/blip/ch.sock`, `--serial file=/run/blip/serial.log`, `--console off`, `--balloon size=0,free_page_reporting=on`, no disk. Kernel command line `console=ttyS0 loglevel=4 panic=0`; a kernel panic halts the guest and the deadline or the node ends it.
6. **Backend check.** Within 10 s, `/proc/<pid>/fd` of Cloud Hypervisor must show `/dev/kvm` or `kvm-vm` (or `mshv` for MSHV) matching the chosen device. Otherwise it is killed with reason `backend`.
7. Every 250 ms: kill Cloud Hypervisor if `/run/blip/kill` exists (reason `killed`) or the deadline in `assignment.json` has passed (reason `deadline`). SIGTERM to `blipd slot` kills it too (reason `stopped`).
8. When Cloud Hypervisor exits, write `exit.json` (`exitCode`, `signal`, `reason`, `time`). `slot.Main` returns nil for a clean exit 0, else `*slot.ExitError`; `cmd/blipd` should exit with `ExitError.ExitCode()`.

Guest power off makes Cloud Hypervisor exit 0.

**IPv4 forwarding.** A new network namespace copies `net.ipv4.ip_forward` (and the `all` and `default` device settings) from the host namespace when `net.core.devconf_inherit_init_net` is 0, the default. Kubernetes nodes always have forwarding on, so pod namespaces start with `ip_forward=1`. Checked on this host: a fresh `ip netns add` namespace reads 1. `blipd slot` checks the value; if it is 0 it tries to write it (works only with a writable `/proc/sys`) and otherwise fails with a message. If a cluster ever needs it, the alternative is the pod sysctl `net.ipv4.ip_forward`, which kubelet must allow as an unsafe sysctl.

## Disk hot-plug (`internal/slot/chapi`)

`AddBlipDisk(path, serial)` sends `vm.add-disk` with `direct=true`, `image_type=Raw` (v54 rejects a disk without it), `sparse=false`, the serial and id `blip-root`.

**Discard and write-zeroes.** With the default `sparse=true`, Cloud Hypervisor advertises discard to the guest. With `sparse=false` it does not (checked in the guest: `discard_max_bytes` is 0). It still advertises write-zeroes, with `write_zeroes_may_unmap=0`. For a block device it serves that with `BLKZEROOUT`, which writes zeros (no unmap). So zeroed ranges become normal mapped writes in the local thin device, and the dirty set stays correct. The storage spike should confirm this on dm-thin.

## Tests

- Unit tests: backoff, event buffer, `lookPath`, serial cut, memory parsing, hypervisor pick, slot files, CH API client, and the full protocol through a fake hybrid vsock socket with a fake guest (logs, success with Ack and power off, OnFailure retries, Never, command not found, allocation binding, version check, resume after reconnect).
- Root integration tests (`hack/guest/itest.sh`, needs `BLIP_ROOT_TESTS=1`, run with sudo by the script): each test makes a network namespace with a veth to the host, runs `slotdev` in it with the real kernel, initramfs and Cloud Hypervisor on `/dev/kvm`, hot-plugs an ext4 image made with `mkfs.ext4 -d` from the Alpine rootfs, and drives the agent with the client.
  - Success: logs from stdout and stderr, hostname, resolv.conf, outbound HTTP to the host arrives from the pod IP (masquerade works), no discard, balloon with free page reporting, Cloud Hypervisor has no capabilities, `Sealed`, clean power off, `exit.json` code 0, the written file is on the image, `e2fsck -fn` is clean.
  - OnFailure: 3 attempts in the same guest, a counter file persists across attempts and is on the image afterward; the first client disconnects after attempt 1 and a new client resumes from its last sequence number without gaps.
  - Never: exit 3 gives `STATE_FAILED`; the kill file then kills Cloud Hypervisor.
  - Deadline: Cloud Hypervisor is killed about 2.05 s after a 2 s deadline.
  - Assigned marker: `blipd slot` exits with an error and never starts Cloud Hypervisor.

The tests copy the artifacts into `/mnt/nvme2/blip/guest/itest/<pid>`, because root without capabilities cannot read files in a home directory. They remove that directory and their network namespaces when done.

## Problems and open points

- MSHV is untested (no hardware here). The backend check for MSHV looks for any fd path containing `mshv`; confirm the exact names on an MSHV host.
- Allocation IDs longer than 20 bytes are cut for the disk serial.
- `assignment.json` format is defined here (`slot.Assignment`: `allocationID`, `deadline`). The node daemon should write it with `slot.WriteAssignment`.
- A guest kernel panic halts the guest (`panic=0`); the node notices the agent is gone and the deadline ends it. Cloud Hypervisor's pvpanic device could report this sooner.
- Write-zeroes stays advertised (see above).
