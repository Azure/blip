# Storage spike results

Kernel 7.0.0 (Ubuntu 24.04, azure), lvm2 2.03.16, thin-provisioning-tools 0.9.0, ktls-utils 0.9 (`tlshd`), e2fsprogs 1.47.0.

Setup: network namespaces for 3 storage nodes and 1 compute node, joined by a bridge in the initial namespace, plus loop devices. A privileged `kindest/node` container was used to check what changes inside a kind node. The same claims are proved again, through the library, by the root integration test `TestStorageEndToEnd` (see "How to run").

## Results

| Claim | Result |
|---|---|
| Netns of an nvmet port | The port listens in the netns of the process that links the first subsystem into `ports/<id>/subsystems`. Port settings are written before that and are global. |
| configfs in kind | Not mounted in a kind node. A privileged container can `mount -t configfs none /sys/kernel/config`. The library does this when needed. |
| Port IDs | configfs port names must be numbers (u16), so a port cannot carry the node name. The library hashes node, address and TCP port into a number. |
| TLS key type and keyring | Type `psk`, keyring `.nvme` (owned by root, created by the `nvme-keyring` module). |
| Identity of a configured PSK (SHA-256) | `NVMe0R01 <hostnqn> <subnqn>`. The kernel looks for this when no `tls_key=` is given. With `tls_key=<serial>`, the host's tlshd sends the description of that key as the identity. |
| Target lookup | tlshd (server side) runs `keyctl_search(session keyring, "psk", identity)`. `.nvme` must be linked into tlshd's session keyring with `keyrings=.nvme` in `tlshd.conf`, and tlshd needs its own session keyring (`keyctl session -` in tests; runc gives each container one). Without it: "failed to search key". |
| Match rule | The `psk` key type matches by prefix: a key is found if its description starts with the identity. Key net domains are ignored by this search. |
| PSK payload | Used as is by tlshd on both sides. We insert the 32 bytes of HMAC-SHA256(clusterKey, hostNQN) on both sides. |
| Where tlshd runs | The handshake request goes to the tlshd of the netns of the socket. Target: netns of the port. Host: netns of the thread that writes to `/dev/nvme-fabrics`. No tlshd there: "failed to start TLS, err=-3". |
| Reconnects | Kernel 7.0 creates reconnect sockets from a kernel worker, so they are in the **initial** netns and their handshakes go to the tlshd of the initial netns. Proved by removing the bridge address of the initial netns: the reconnect then times out, and with the address back it succeeds and its TCP connection shows up in the initial netns. |
| TLS required | Port with `addr_tsas=tls1.3`, `addr_treq=required`. A plain connect fails with "connection reset by peer" (tlshd: "unexpected TLS packet"). With `required`, the target never peeks for a plain ICReq. |
| Host IDs | Each host NQN needs its own `hostid=`; the kernel rejects a second host NQN with the same host ID. The library derives a UUID from the host NQN. |
| Multipath | Native NVMe multipath is on, so each subsystem has a bio-based head device (`nvmeXnY`). A dm `multipath` table over them needs `queue_mode bio`; without it: "unable to determine table type". |
| Failover | With one or two of three targets removed, reads continue through the rest. Paths are marked failed. |
| All paths gone | Reads fail with EIO. With `fast_io_fail_tmo=2` this took 3s in the test; without `fast_io_fail_tmo` it takes `ctrl_loss_tmo`. |
| Path return | Without multipathd, a failed path stays failed. If the controller came back (within `ctrl_loss_tmo`), `reinstate_path` fixes it. If it was removed, the host must connect again and reload the table with the new device. |
| Namespace identity | nvmet picks a random namespace UUID. After a re-export the host refuses the namespace ("identifiers changed for nsid 1"). The library sets `device_uuid` and `device_nguid` derived from the subsystem NQN. |
| Read-only export | nvmet has no read-only namespace option and cannot open a read-only device (EACCES on enable). Read-only is enforced on the host, by creating the multipath device with `--readonly`. |
| Dirty set | dm-thin pool (64KiB blocks, `ignore_discard`, `error_if_no_space`) on a loop device, thin device with external origin. After writes (including partial blocks) and a flush, the mapped blocks from `thin_dump -m` on a metadata snapshot equal exactly the set of touched 64KiB blocks. |
| Reload without origin | Works after a flush (suspend with flush, load, resume). |
| Save | After all read paths are gone, writing the mapped ranges into the seed over a read-write NVMe/TCP TLS export gives a seed whose block hashes equal the guest view, on all 3 replicas. |
| Discard and write-zeroes | The thin device and the slot device report `discard_max_bytes=0` and `write_zeroes_max_bytes=0`. |
| LVM | VG per node with `pvcreate --metadatasize 64m`, `vgcreate --setautoactivation n`, thin pool with 64KiB chunks. `--errorwhenfull y` must be set with `lvchange` after `lvcreate` (lvcreate rejects it for thin pools). Snapshots with `lvcreate -s` skip activation and are activated with `-K`. Tags work. |
| Parent delete | Removing a parent LV leaves its snapshot unchanged (same hashes). |
| thin_delta | `thin_delta -m --snap1 A --snap2 B` on a metadata snapshot of the `-tpool` device lists `same`, `different`, `left_only` and `right_only` ranges. Repair from a base with it gives identical replicas that still share blocks with the base. |
| LVM without udev | `--config` with `global_filter` (accept only the PVs, reject the rest), `use_devicesfile=0`, `obtain_device_list_from_udev=0`, `udev_sync=0`, `udev_rules=0`, plus `DM_DISABLE_UDEV=1`. LVM then creates its own `/dev/<vg>/<lv>` nodes. |
| Device nodes | New NVMe and dm devices do not appear in a container's `/dev`. The library reads `major:minor` from sysfs or `dmsetup info` and runs `mknod` in a private directory. Tables use `major:minor`. |
| Slot device | A dm device created as `0 1 error` and later reloaded to `linear` onto the thin device: a process that opens it after the reload sees the full size (an fd opened before also sees it). Reloading back to `error` gives 1 sector again. |

## Notes

- **Shared kernel (kind).** Host keys and target keys for the same (host, subsystem) pair can exist at the same time. Target keys get the suffix `" target"` after the identity (allowed by the prefix match), so each side removes only its own keys.
- **Reconnects in kind.** Kind nodes have their own netns, but reconnect sockets are created in the initial netns. For them to work, the initial netns must reach the node addresses (true for the docker bridge) and the host must run `tlshd` (the `ktls-utils` systemd service). In production, `hostNetwork` is the initial netns, so the sidecar serves reconnects too.
- **TLS identity is not bound to the host NQN.** nvmet in 7.0 does not compare the TLS identity with the host NQN in the Connect command, and skips DH-HMAC-CHAP when TLS is on. A host that holds a valid PSK for any export on a storage node can complete TLS there and then claim another host NQN. Together with the prefix match, TLS proves "some node this storage node exports to", not "this node". Guests cannot reach the storage network (section 9), so this only matters if a node daemon is compromised. Open problem.
- **LVM must stay confined.** One test run started `vgchange` without a filter; it scanned all host disks and hung in `bdev_open` (D state) on a device of another user. Every LVM call in the library passes the filter.
- **Shared-kernel tlshd.** The host has a systemd `tlshd` in the initial netns, and tests start one per test netns. Both work side by side.

## Library choices that follow

- `fast_io_fail_tmo=5` (new default) next to `ctrl_loss_tmo=60`, so a dead path fails I/O quickly and multipath moves on. The guest sees errors only when every path has failed.
- `ComputeNode.RefreshPaths` reconnects to replicas and reloads the multipath table; the node daemon should call it periodically while a blip runs.
- Device-mapper names use `_` between parts (`blip_<node>_thin_<id>_<alloc>`), because node names contain `-`.
- The compute pool reserves 1MiB at the start of the disk for a header with the boot ID. If the pool device exists, it was made in this boot and is reused. If not, the disk is wiped and a new pool is made.
- `Export` refuses a read-write export while a read-only export of the same content exists, and refuses read-write on sealed content. `ComputeNode.WriteExtents` refuses while the thin device still has its origin or the multipath device exists.

## Changes to docs/design.md

- 7.1 Compute nodes: pool reuse rule (an existing pool device is from this boot) and the 1MiB header with the boot ID, instead of only "compare the boot ID". Device-mapper names use `_`.
- 7.1 Naming rule: nvmet ports are numbers, so the port number is a hash of node name and address.
- 7.2: multipath needs `queue_mode bio`; paths must be refreshed by the node daemon (no multipathd); read-only is enforced by the host because nvmet has none; stable namespace IDs; `fast_io_fail_tmo`.
- 7.3: the exact identity format, `tls_key=`, the ` target` suffix, host IDs, `keyrings=.nvme` for tlshd, the netns rule for handshakes and reconnects, and the identity binding limit.
- 12: storage path loss now uses `fast_io_fail_tmo` for failover.
- 14: `fast_io_fail_tmo` default 5s.
- 16: configfs mount in kind nodes, and host `tlshd` for reconnects.

## How to run

```sh
cd <worktree>
GOFLAGS=-mod=mod go test ./internal/storage/...             # unit tests
GOFLAGS=-mod=mod go test -c -o /tmp/opencode/storage.test ./internal/storage/
sudo BLIP_ROOT_TESTS=1 timeout -s TERM 600 /tmp/opencode/storage.test -test.v -test.run TestStorageEndToEnd
```

The test needs `tlshd`, `keyctl`, lvm2, thin-provisioning-tools and e2fsprogs. It uses `/mnt/nvme2/blip/storage/itest` (`BLIP_TEST_DIR` overrides), netns `blipt-*`, bridge `blipt0` (10.98.0.0/24) and VGs `blipt-ts*`, and removes all of them at the end, also after a failure. The reconnect check needs the systemd `tlshd` in the initial netns and is skipped otherwise. `BLIP_NET_TESTS=1` enables an image pull test in `internal/storage/image`.
