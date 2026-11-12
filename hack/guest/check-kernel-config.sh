#!/bin/sh
# Check that a kernel config has every option the guest needs built in.
# EXT4_FS/JBD2: the root volume. HOTPLUG_PCI(_ACPI): Cloud Hypervisor hot-adds
# and hot-removes virtio-blk volumes through ACPI PCI hotplug. ACPI_BUTTON: the
# power button for graceful shutdown. PVPANIC(_PCI): Cloud Hypervisor's
# --pvpanic PCI device, so a guest panic is reported to the host.
set -eu
cfg=$1
fail=0
for opt in BLK_DEV_INITRD RD_GZIP DEVTMPFS VIRTIO_PCI BLK_DEV VIRTIO_BLK VIRTIO_NET \
	VSOCKETS VIRTIO_VSOCKETS EXT4_FS JBD2 VIRTIO_BALLOON PAGE_REPORTING \
	HOTPLUG_PCI HOTPLUG_PCI_ACPI ACPI CGROUPS MEMCG CGROUP_PIDS UNIX98_PTYS \
	TMPFS INET PACKET SERIAL_8250_CONSOLE ACPI_BUTTON PVPANIC PVPANIC_PCI; do
	if ! grep -qx "CONFIG_$opt=y" "$cfg"; then
		echo "missing CONFIG_$opt=y" >&2
		fail=1
	fi
done
exit $fail
