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
| `nvme_fabrics`, `nvme_tcp` | Importing state replicas over NVMe/TCP. |
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
