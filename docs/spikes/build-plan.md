# Build plan (history)

The phases used to build Blip v1. Kept for reference; it is not maintained.

| Phase | Deliverables | Must prove |
|---|---|---|
| 1. Spikes | Cloud Hypervisor on KVM (MSHV where hardware exists); hot-plug, vsock, TAP, serial, metadata disk, event monitor, pvpanic, power button, clean exit (`docs/spikes/agentless.md`); external-origin thin over multipath NVMe/TCP with TLS | Changed set equals mapped blocks; deleting a source keeps derived volumes; no discard or write-zeroes leaks; multipath failover between replicas; TLS is required on every path |
| 2. Single node | CRDs, policies, RBAC, controller, slot, `blip-boot`, `blip-meta`, DHCP server, guest images | Conditions and `kubectl wait` work, including very short runs; reboot, panic and boot failure; deadline; graceful stop and cancel by delete; a root volume boots again in another slot |
| 3. Replicated storage | LVM replicas, import, clone, delete, orphan cleanup, repair, scrub, full-copy clones | No duplicate snapshots after a controller crash at any step; pool-full and replica-loss behavior |
| 4. Volumes and snapshots | Multi-disk slots, live attach and detach, claims and holds, capture loop, snapshot save, shutdown and interval snapshots, derive, compaction | Capture stays within the suspend budget under load; deltas write only changed blocks; claim and deletion races; stale generations refused; shutdown snapshot on every terminal path; compaction respects holds and pins; reschedule salvage rules |
| 5. User access | NetworkPolicy, metrics, docs | Tenant RBAC; guests cannot reach storage, nodes or the metadata service; upgrade without killing running blips |

**Release criteria:**
- Every shutdown snapshot ends `Ready`, `Skipped`, `Unavailable` or `Failed`, and the Blip finishes only after that.
- At most one attachment writes over a BlipVol at a time.
- No leaked overlays, local snapshots, exports, pods or claims after chaos tests.
- Any source volume or snapshot can be deleted safely. Data with a claim or hold is never deleted.
- No storage byte crosses the network without TLS.
