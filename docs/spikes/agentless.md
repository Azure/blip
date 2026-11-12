# Spike: Cloud Hypervisor v54 behaviour for the agentless guest

Host: this dev VM, /dev/kvm, Cloud Hypervisor v54.0 (`_output/guest/cloud-hypervisor`), blip guest kernel
(`_output/guest/vmlinuz`). Guest PID 1 is a small static Go program packed with
`hack/guest/mkinitramfs`. The spike code (`hack/spikes/agentless/`) has been removed; this file is the record.
Launch flags were:

    cloud-hypervisor --api-socket path=$D/api.sock --kernel vmlinuz --initramfs initrd.gz \
      --cmdline "console=ttyS0 loglevel=4 panic=0 spike=<mode>" --cpus boot=1 --memory size=256M \
      --disk path=$D/meta.img,serial=blip-meta,id=blip-meta,direct=off,image_type=raw \
      --vsock cid=3,socket=$D/vsock.sock --serial file=$D/serial.log --console off \
      --event-monitor path=$D/events.json [--pvpanic]

Note: v54 refuses `--disk` without `image_type=raw` ("Image type required for disk"). The API needs
`"image_type":"Raw"` too.

Host timings below come from polling the meta disk backing file every 1 ms for records the guest writes with
O_DIRECT|O_DSYNC, so they include the host side delay.

## 1. Meta disk at launch

- The guest sees `/sys/block/vda/serial` = `blip-meta`.
- Guest O_DIRECT|O_DSYNC write of a 4 KiB block lands in `meta.img` right away (host reads it in the same poll).
  Time from CH start to the host seeing the guest WAITING record: 217 ms.
- inotify IN_MODIFY on `meta.img` fires for every guest write, with both `direct=off` and `direct=on`.
  The 1 ms poll saw the same change 0.3 to 0.8 ms later. inotify is enough; keep a slow poll (for example 1 s)
  only as a safety net.

## 2. Hot-plug via API

- `PUT vm.add-disk {"path":...,"serial":"...","id":"...","image_type":"Raw"}` returns in 7 to 10 ms.
- From the API call to the guest getting the NETLINK_KOBJECT_UEVENT block add, reading the serial from sysfs, and the
  host seeing the guest record: 15 to 28 ms (9 runs: 15, 15, 18, 19, 19, 21, 23, 24, 28 ms). The serial is
  readable when the uevent arrives.
- The 20 byte limit is real and checked by CH: a 20 char serial works and shows in full in the guest; 21 chars
  fails with "Block device serial length (21) exceeds maximum allowed length (20)".

## 3. Guest reboot

- `reboot(LINUX_REBOOT_CMD_RESTART)` from PID 1: CH resets and reruns the same kernel and initramfs. The process
  keeps running. Hot-plugged disks stay attached (`vm.info` lists them, and the guest sees `vdb serial=hotdisk` at
  boot 2 without a uevent, so the stub must scan /sys/block at start, not only wait for uevents).
- The meta disk keeps its contents: the guest read bootCount 1 and wrote 2.
- Events: `virtio-device reset` for each device, then `vm rebooting`, `vm rebooted`, then `activated` again.
- **The serial file is truncated on reboot.** After the reboot `serial.log` held only boot 2 output. Anything that
  parses the serial log must read it continuously (or use `--serial socket=`) and must handle the file shrinking.

## 4. Event monitor

The file is a stream of pretty printed JSON objects separated by blank lines (not one per line). Each has
`timestamp {secs,nanos}` (since CH start), `source`, `event`, `properties`. Seen sequences (ignoring
`virtio-device activated {id}` lines):

| Case | Events |
| --- | --- |
| boot | vmm starting, vmm started, vm booting, vm booted |
| guest reboot | virtio-device reset {id} x N, vm rebooting, vm rebooted |
| guest poweroff | virtio-device reset x N, vm shutdown, vm deleted, vmm shutdown; CH exits 0 |
| power button | nothing in the event file |
| panic (pvpanic) | guest panic {"event":"panic"} |
| SIGTERM to CH | vm shutdown, vm deleted, vmm shutdown (no device resets first) |

Guest poweroff and SIGTERM look almost the same in events. The slot knows when it sent the signal, and a guest
poweroff makes CH exit 0 on its own, so use that.

## 5. Panic and PID 1 exit (with --pvpanic)

| Cmdline | Trigger | Result |
| --- | --- | --- |
| panic=0 | sysrq c | `guest panic` event about 170 ms after the panic line; VM hangs; CH keeps running |
| panic=-1 | sysrq c | `guest panic`, then `vm rebooting`/`rebooted`; boot loop; CH keeps running |
| panic=1 | sysrq c | same as -1 with a 1 s delay |
| panic=0 | PID 1 exits 3 | serial: `Kernel panic - not syncing: Attempted to kill init! exitcode=0x00000300`, `guest panic` event, hang |
| panic=-1 | PID 1 exits 3 | `guest panic` then reboot loop |

CH never exits on its own after a panic. With panic=-1 or 1 the serial log is truncated by the reboot, so the
panic text (and the init exit code) is lost. The exit code is `exitcode >> 8` (0x300 means 3).

## 6. Power button

- `/proc/bus/input/devices` shows `N: Name="Power Button"`, `P: Phys=PNP0C0C/button/input0`, `H: Handlers=kbd event0`.
- `PUT vm.power-button` returns at once. A PID 1 that does not read the input device: nothing happens, the VM keeps
  running. A PID 1 that reads `/dev/input/event0` gets EV_KEY code 116 (KEY_POWER) value 1 then 0. Host saw the
  guest's reaction 7 to 9 ms after the API call.
- systemd-logind handles KEY_POWER from input devices tagged `power-switch` (default HandlePowerKey=poweroff), so
  systemd guests need logind running. busybox init does not read input devices; Alpine needs acpid (busybox acpid
  reads /dev/input/event*) or similar.

## 7. Hybrid vsock

Guest listening on AF_VSOCK ports 22 and 8080. `printf 'CONNECT 22\n' | nc -U vsock.sock` gives
`OK 1073741824` then the guest data; same for 8080. A port with no listener closes without output. Any port works.

## 8. AF_PACKET with tc ingress redirect

Test script (removed with the spike code; sudo, two netns, a veth pair stands in for the tap; tc ingress on `blip0`
with `matchall action mirred egress redirect dev eth0`, as in internal/slot/net.go). Sent 3 broadcast UDP 68->67
frames from the guest side.

- Packet socket on blip0 bound to ETH_P_ALL: got all 3.
- Packet socket on blip0 bound to ETH_P_IP: got 0.

This matches `__netif_receive_skb_core`: ptype_all taps run before `sch_handle_ingress`, protocol specific handlers
run after it, and the redirect steals the packet. With an extra `flower ip_proto udp dst_port 67 action drop` at
prio 1 the ETH_P_ALL socket still got all 3, and the frames no longer leave through eth0.

So no tc exception is needed for receive, if the socket binds ETH_P_ALL (add a socket BPF filter for udp dport 67).
Adding the drop filter is still worth it so guest DHCP broadcasts do not leak into the pod network.

## 9. switch_root on a hot-plugged disk

Alpine rootfs from hack/guest/mkrootfs.sh, packed with `mkfs.ext4 -d`, with an inittab that prints a marker, shows
/proc/mounts and powers off. The stub: on uevent with serial `root`, mount ext4 at /newroot, MS_MOVE /dev /proc /sys
into it, write EXEC to the meta disk, remove /init, chdir /newroot, `mount --move . /`, chroot ., exec /sbin/init.
Busybox init ran (`ALPINE-INIT-RUNNING`), `/proc/mounts` showed devtmpfs, proc, sysfs and `/dev/vdb / ext4`, and
the guest powered off; CH exited 0. 5 of 5 runs.

## 10. add-disk to exec

From the add-disk call to the host seeing the EXEC record (written just before exec): 77, 96, 82, 70, 76 ms (5 runs).
Of that, about 20 ms is hot-plug plus uevent and about 55 ms is the ext4 mount.

## Recommendations

- Kernel cmdline: keep `panic=0` and run CH with `--pvpanic`. On the `guest panic` event the slot reads the serial log
  (intact because no reboot), classifies `Attempted to kill init! exitcode=0x...` as InitExited (code = value >> 8)
  else Panic, then kills CH. panic=-1 would loop and lose the serial text.
- Reboot: let CH handle it. Count `vm rebooting` events (or bootCount in the meta guest area). The stub must scan
  /sys/block at start because disks attached before the reboot give no uevent. Serial readers must cope with
  truncation on reboot.
- Readiness and EXEC detection: inotify IN_MODIFY on meta.img, with a 1 s poll as backup. Works with direct=off.
- Exit: guest poweroff is CH exiting 0 by itself (events end with vm shutdown without a prior signal).
- Graceful stop: `vm.power-button` works only if the guest listens on the Power Button input device (logind, acpid).
  Hard kill after the timeout is required.
- DHCP: no tc exception needed to receive; bind the packet socket with ETH_P_ALL. Add a prio 1 flower filter that
  drops udp dport 67 on blip0 ingress so DHCP does not leak into the pod network.
- Volume serial limit 20 bytes is enforced by CH; keep MaxLength 20.
