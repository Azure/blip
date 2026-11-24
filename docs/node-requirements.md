<!-- Copyright (c) Microsoft Corporation.
Licensed under the MIT License. -->

# Node kernel requirements

blip-node loads the kernel modules it needs with `modprobe` when it starts, so
a node does not need to load them beforehand. A module whose `/sys/module`
entry already exists is treated as loaded or built in and is skipped. If a
module fails to load, the agent logs a warning with the kernel release and
continues; the feature that needs the module fails when it is used. The node
image includes `kmod`, and the DaemonSet mounts the host's `/lib/modules`
read-only.

| Module | Needed for |
| --- | --- |
| `configfs` | Configuring the nvmet target. |
| `loop` | Block devices backed by files. |
| `tun` | TAP devices for VM networking. |
| `nvmet`, `nvmet_tcp` | Exporting state replicas over NVMe/TCP. |
| `nvmet_rdma` | Exporting state replicas over NVMe/RDMA (optional). |
| `nvme_fabrics`, `nvme_tcp` | Importing state replicas over NVMe/TCP. |
| `nvme_rdma` | Importing state replicas over NVMe/RDMA (optional). |
| `dm_thin_pool` | Thin-pool volumes and snapshots. |
| `dm_clone` | Hydrating a state replica on another node. |
| `dm_crypt` | Encrypted volume mappings. |

## dm-clone

Moving a BlipState between nodes hydrates its replica with dm-clone. The Azure
Linux 3 kernel used by AKS (6.6.*.azl3) does not ship dm-clone, so moving a
state between nodes fails on those nodes. Pools that run blip-node must use a
kernel that provides dm_clone, for example Ubuntu.

Check a candidate node with:

```sh
modinfo dm_clone
```

A missing module reports `modinfo: ERROR: Module dm_clone not found.`

## NVMe/RDMA (optional)

`blip-node --nvme-transport=tcp|auto|rdma` is opt-in and defaults to `tcp`.
When enabled, every lease's subsystem is exported over both NVMe/TCP at port
4420 and NVMe/RDMA at port 4421, and the RDMA modules above load at startup.
The host connects TCP first, then adds RDMA as an NVMe native-multipath path,
which requires `nvme_core.multipath=Y`; TCP is marked ANA non-optimized so
RDMA is preferred. RDMA is best effort: the node detects support at runtime
and the connection falls back to TCP when it is missing or breaks.

Azure Guest RDMA (public preview) needs a NIC with `enableGuestRdma: true` and
accelerated networking (`Microsoft.Network/networkInterfaces` apiVersion
`2026-07-01`) in the same VNet and region as its peer, on Ubuntu 24.04 with
kernel 6.8.0-1044-azure or later. Kernel NVMe/RDMA on MANA additionally
needs the rdma-next "RDMA/mana_ib: Add kernel RC and fast registration
support" series, which is not yet mainline, so blip uses TCP until the running
kernel provides it. The preview supports no load balancers, user-defined
routes, or VNet encryption.

RoCEv2 uses UDP 4791 in the NIC port space and bypasses nftables; nftables
still admits TCP 4420/4421 for iWARP. Any RDMA-enabled VM in the VNet can
reach the RDMA port, so access control rests on mandatory DH-HMAC-CHAP
authentication, per-subsystem allowed hosts, and dm-crypt ciphertext.
Live migration and NIC servicing can disrupt RDMA connections, which is why
the TCP path remains.
