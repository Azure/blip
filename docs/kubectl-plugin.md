# kubectl blip: SSH sessions

`kubectl-blip` is a kubectl plugin that creates SSH-enabled Blips and connects
to them. It keeps a client key, sets the authorized-keys annotation, waits
for the guest's host key, trusts it, port-forwards to the slot pod and runs
`ssh`. Nothing is exposed outside the cluster: access goes through the
Kubernetes API and needs `pods/portforward` on the Blip's slot pod.

## Sessions

A **session** is a Blip that the plugin created and manages. It has:

- the label `blip.example.com/session: "true"`;
- the annotation `blip.example.com/session-owner` with the Kubernetes user
  name of its creator (from a SelfSubjectReview; empty if the API server
  does not allow it). The plugin does not enforce ownership;
- the annotation `blip.example.com/ssh-authorized-keys` with your public key;
- the spec of [examples/ssh/blip.yaml](../examples/ssh/blip.yaml):
  `serviceAccountName: blip-ssh`, root volume `root`, and
  `ports: [{port: 22, name: ssh}]`;
- its own root BlipVol `<session>-<5 random characters>`, a clone
  (`spec.parent`) of the `--volume` or `--image` BlipVol with an owner
  reference to the session, so deleting the session deletes it. A BlipVol is
  used by one Blip at a time; the clone lets several sessions boot the same
  image or volume at once, and leaves the source unchanged.

A session is an ordinary Blip: it ends at its deadline
(`spec.maxTTLSeconds`, set from `--ttl`) and is then deleted after
`ttlSecondsAfterFinished`. Session names are DNS labels of at most 57
characters.

Do not confuse sessions with the gRPC session between blipd and the
controller (`internal/node/session.go`).

## Install

```sh
make build                     # builds bin/kubectl-blip with the other commands
cp bin/kubectl-blip ~/.local/bin/   # any directory on PATH
kubectl blip version
```

kubectl finds the plugin as `kubectl blip`. You also need an OpenSSH client
(`ssh`) on PATH.

For tab completion of `kubectl blip ...` in bash or zsh with kubectl
completion set up, also copy `images/blip-ubuntu/kubectl_complete-blip` to a
directory on PATH.

## Prerequisites

- An image with the `blip-ssh-bootstrap` service, such as
  `images/blip-ubuntu` (see [The SSH image](#the-ssh-image)), either imported as a BlipVol or
  in a registry the cluster can pull from.
- The `blip-ssh` ServiceAccount, Role and RoleBinding in the namespace. A
  user who may manage RBAC there runs:

  ```sh
  kubectl blip setup -n blip-demo   # same objects as examples/ssh/rbac.yaml
  ```

  Without them the Blip waits with reason `ServiceAccountNotFound`, and the
  plugin prints this hint.
- Your user needs the `blip-edit` role (create, get, list, delete Blips and
  BlipVols, and `pods/portforward`).

## Usage

All commands accept the kubeconfig flags `--kubeconfig`, `--context` and
`-n`/`--namespace`.

```sh
# Create the session if needed, wait, then log in.
kubectl blip shell dev --image 172.18.0.5:5000/blip-ubuntu:dev
kubectl blip shell dev --volume ubuntu-ssh --ttl 8h --sku default
kubectl blip shell dev -- uname -a     # run a command; its exit code is returned

kubectl blip create dev --volume ubuntu-ssh --wait
kubectl blip list                      # NAME PHASE AGE DEADLINE OWNER
kubectl blip list -A
kubectl blip delete dev                # only sessions; --force for other Blips
```

`shell`:

1. creates `~/.blip/id_ed25519` if it does not exist;
2. creates the session if the Blip does not exist. `--image REF` first
   creates (or reuses) the BlipVol `img-<first 12 hex of sha256(REF)>` that
   imports REF and waits for it to be Ready. `--volume NAME` uses an
   existing BlipVol. Either way the session boots its own clone of it;
3. if the Blip has finished (Succeeded or Failed), asks whether to delete
   and recreate it. `--recreate` (`-y`) skips the question. Without a
   terminal the command fails instead;
4. waits (`--timeout`, default 15m, which also covers a first-time image
   import) until the Blip is Running and the guest has published `blip.example.com/ssh-host-key`;
5. runs `ssh blip-<name>` with the options that `ssh-config` prints (see
   below) and a ProxyCommand that runs `kubectl-blip proxy` with the same
   kubeconfig flags. The proxy writes the host key to `~/.blip/known_hosts`
   under the name `blip-<name>`, port-forwards to port 22 of the slot pod
   and relays the connection.

If the session already exists and your key is not in its authorized-keys
annotation, `shell` prints a warning: the guest reads the annotation only
once per boot, so recreate the session (or edit
`/root/.ssh/authorized_keys` in the guest) to change the keys.

### Plain ssh, scp and rsync

`kubectl blip ssh-config` prints a stanza for `~/.ssh/config`:

```sh
kubectl blip ssh-config --context kind-blip -n blip-demo >> ~/.ssh/config
kubectl blip create dev --volume ubuntu-ssh -n blip-demo
ssh blip-dev
scp file blip-dev:/tmp/
```

```
Host blip-*
  User root
  ProxyCommand kubectl blip proxy --context kind-blip --namespace blip-demo %n
  IdentityFile /home/you/.blip/id_ed25519
  IdentitiesOnly yes
  UserKnownHostsFile /home/you/.blip/known_hosts
  StrictHostKeyChecking yes
```

`kubectl blip proxy blip-dev` strips the `blip-` prefix, waits for the
session, records its host key under the host name `blip-dev`, port-forwards
and relays stdin/stdout to sshd. It logs only to stderr. It does not create
sessions. The kubeconfig flags given to `ssh-config` are fixed in the
ProxyCommand, so the `blip-dev` known_hosts entry belongs to that context and
namespace; print one stanza per cluster with a different `Host` pattern if
you need several. `shell` uses the same `blip-<name>` entries, so `shell` and
`ssh blip-<name>` share known_hosts entries; use them with the same context
and namespace.

## The SSH image

`images/blip-ubuntu` is Ubuntu 24.04 with systemd and openssh-server,
booted with the default `spec.init` (`/sbin/init`). The guest OS owns
everything after the boot stub mounts the root:

- systemd-networkd runs DHCP on any Ethernet NIC (matched by type, not by
  MAC) and gets the slot pod IP; systemd-resolved writes the DNS servers and
  search domains to `/etc/resolv.conf`.
- systemd-logind powers off on the ACPI power button, which is how Blip
  stops a guest gracefully.
- `blip-creds.service` runs `blip-meta creds --dir
  /run/secrets/kubernetes.io/serviceaccount --watch`.
- `blip-identity.service` writes `/run/blip/identity.json` (and `name`,
  `namespace`, `uid`), sets the hostname and derives `/etc/machine-id` from
  the Blip UID, so a root cloned for another Blip gets its own machine-id.
- sshd listens on TCP 22 and, via `blip-sshd-vsock.socket`
  (`ListenStream=vsock::22`), on vsock port 22 for port forwarding.
- `/etc/fstab` refers to volumes by `/dev/disk/by-id/virtio-<name>` or
  UUID, never `/dev/vdX`.
- `blip-ssh-bootstrap.service` runs once at boot, before `ssh.service`. It
  uses the Blip's service account token to read the annotation
  `blip.example.com/ssh-authorized-keys` and write it to
  `/root/.ssh/authorized_keys`, generate host keys, and write the ed25519
  host public key to the annotation `blip.example.com/ssh-host-key`. sshd
  does not start if this fails.

The image has no host keys. Gettys, timesyncd and apt timers are masked.
`blip-meta` is copied from `bin/` (`make build`), so build the image from
the repository root: `docker build -f images/blip-ubuntu/Dockerfile .`
(`make registry-up ubuntu-image` builds and pushes it to the local
registry).

[examples/ssh](../examples/ssh) has the RBAC (`rbac.yaml`,
`nested-rbac.yaml`; `setup` applies the same files) and a BlipVol and Blip
for use without the plugin.

### How it works

- Port-forward: kubectl connects to `localhost:22` in the slot pod. `blipd
  slot` listens there for each port in `spec.ports` and connects to the
  guest's AF_VSOCK port with the same number (22), where systemd accepts it
  and starts `sshd -i`.
- Credentials: the controller requests a token for `spec.serviceAccountName`;
  the node writes it, with the cluster CA and namespace, to the Blip's
  metadata disk (virtio serial `blip-meta`) and rewrites it before it
  expires. `blip-meta creds --watch` in the guest copies it to
  `/run/secrets/kubernetes.io/serviceaccount` (tmpfs). The token is bound to
  a Secret that the controller deletes when the allocation ends, so it stops
  working then.
- The guest reaches the API server at `https://kubernetes.default.svc`. The
  slot NetworkPolicy must allow egress to the API server.

## Volumes and snapshots

These commands work on any Blip, not only sessions. They print one name
per line on stdout, so scripts can capture the result.

```sh
kubectl blip derive ws                       # new BlipVol from ws; prints its name
kubectl blip derive ws --snapshot 12 --name ws-old --wait
kubectl blip volumes                         # BlipVols: phase, current sequence, snapshots, pins
kubectl blip volumes ws                      # snapshot history of ws
kubectl blip attach VOL --to dev --name out  # prints /dev/disk/by-id/virtio-out
kubectl blip detach out --from dev --delete  # detach, then delete the BlipVol
```

- `derive SOURCE` creates a BlipVol with `spec.parent` set to the BlipVol
  SOURCE (design 7.10). `--snapshot N` uses snapshot N of SOURCE; without
  it the newest Ready snapshot is used, or, if SOURCE is attached to a
  running Blip, a new capture taken now. `--name NAME` names the new
  BlipVol; without it the name is `SOURCE-` plus 5 random characters
  (`generateName`). `--skip-shutdown`, `--interval` (at least 5m) and
  `--limit` set its `snapshotPolicy`. `--wait` waits (`--timeout`, default
  15m) until it is Ready, printing each `Ready` reason it waits on (such as
  `WaitingForCapture`, `SourceUnreachable`, `ParentNotReady` or
  `SnapshotNotYetTaken`), and fails at once if the BlipVol fails. A live capture is crash-consistent. The new BlipVol is
  independent of SOURCE: it pins only the source snapshot against
  compaction, and does not block deleting SOURCE.
- `volumes` (alias `vols`, `-A` for all namespaces) lists BlipVols with
  their phase, current sequence, number of snapshots and pins.
  `volumes BLIPVOL` shows its snapshot history (sequence, reason, state,
  capture time, writer Blip) and what pins its snapshots or blocks its
  deletion: derived BlipVols, holds, and the snapshot its attachment
  started from and is based on.
- `attach` adds a `spec.volumes` entry (`--name`, default: the BlipVol name,
  at most 20 characters) and waits until it is Attached. The guest sees a
  private writable copy of the BlipVol's current snapshot at
  `/dev/disk/by-id/virtio-<name>`. Its writes become a new snapshot of the
  BlipVol when it is detached (unless `snapshotPolicy.skipShutdown`).
- `detach` removes the entry and waits until it is Released, including the
  shutdown snapshot. Unmount it first: detach is forced. The root volume
  cannot be detached. `--delete` then deletes the BlipVol and waits until it
  is gone. If the BlipVol is still claimed or held (for example a derive
  from it is running), `--delete` does not wait and prints
  `blipvol/NAME deletion pending: blocked by ...` instead.

## Inside a Blip

The `images/blip-ubuntu` image contains `kubectl` (v1.33) and
`kubectl-blip` with bash completion, and git, vim, less and rsync. In the
guest, kubectl and the plugin use the Blip's ServiceAccount token
(`/run/secrets/kubernetes.io/serviceaccount`, written by `blip-meta creds`)
and the API server at `kubernetes.default.svc` (set in `/etc/environment`;
the plugin also sets it itself when `KUBECONFIG` is unset). With no Blip
name, `attach` and `detach` act on the Blip they run in, found from
`$BLIP_NAME`, `/run/blip/name` or the metadata disk, in its own namespace
unless you pass `-n`. On their own Blip they also:

- `derive --volume ATTACHMENT`: derive from the BlipVol attached to this
  Blip as ATTACHMENT (for example `root`). It runs `sync` first, so that
  written data is in the capture;
- `attach --mount DIR`: wait for the device and mount it at DIR
  (`--read-only` for `-o ro`);
- `detach`: unmount every mount of the device first.

The default `blip-ssh` Role only allows the guest to read and patch Blips.
To let guests use the plugin, also run:

```sh
kubectl blip setup --nested -n blip-demo   # same as examples/ssh/nested-rbac.yaml
```

This adds the Role and RoleBinding `blip-ssh-nested`: Blips (all verbs but
deletecollection), BlipVols (create, get, list, watch, delete, so guests can
derive), pods (read) and `pods/portforward`. Every guest in the namespace that
uses `blip-ssh` gets it, so it can delete any Blip or BlipVol in the
namespace. Only use it in a namespace whose guests you trust equally.

### Example: run a task in a copy of this Blip

Inside the parent Blip (`kubectl blip shell parent`):

```sh
snap=$(kubectl blip derive --volume root --wait)     # this Blip's root, now
kubectl blip create task --volume "$snap" --wait     # boots a clone of it
kubectl blip shell task -- 'make -C /src && sync'    # the task
root=$(kubectl get blip task -o jsonpath='{.spec.volumes[0].blipVolRef.name}')
out=$(kubectl blip derive "$root" --wait)            # keep the result (live capture)
kubectl blip delete task --wait                      # also deletes the task's root
kubectl blip attach "$out" --name out --mount /mnt/out
cp -r /mnt/out/src/build ./artifacts
kubectl blip detach out --delete                     # unmount, detach, delete
kubectl delete blipvol "$snap"
```

The task Blip starts from the parent's disk as it was at the capture, but
with its own name, machine ID and SSH host keys. Use
`kubectl blip create task --image REF` instead for a fresh Blip that does not
share the parent's disk. Sessions created in a guest use the guest's own
`~/.blip` key, so only the parent can log in to them.

## Local state

`~/.blip` (or `$BLIP_HOME`), mode 0700:

| File | |
|---|---|
| `id_ed25519` | client private key, OpenSSH format, mode 0600 |
| `id_ed25519.pub` | public key, comment `blip@<hostname>` |
| `known_hosts` | guest host keys, one line per alias, rewritten atomically |
| `config.yaml` | optional defaults |

`config.yaml`:

```yaml
volume: ubuntu-ssh            # or: image: registry/blip-ubuntu@sha256:...
sku: default
ttl: 8h
```

Flags override the config file, which overrides the built-in defaults (SKU
`default`, TTL 1h). `--volume` or `--image` on the command line replaces both
`volume` and `image` from the file. Creating a session without a volume or an
image is an error.

## Security notes

- The `blip-ssh` Role lets every guest in the namespace get and patch any
  Blip there, including the `ssh-host-key` and `ssh-authorized-keys`
  annotations of other sessions. A compromised guest can therefore replace
  another session's published host key before you first connect, or its
  authorized keys before it boots. Use one namespace per trust boundary.
- The plugin trusts the host key annotation: each time it connects, it
  overwrites the known_hosts entry with the key the annotation holds then.
  The protection is only as strong as the RBAC on the namespace's Blips.
- Authorized keys are read once, when the guest boots.
- The private key never leaves `~/.blip`; only the public key is stored on
  the Blip.
- Anyone who can create Blips with `serviceAccountName: X` gets a token for
  X. Grant Blip create only where that is acceptable.
- With `setup --nested`, a guest can create, change and delete Blips and
  BlipVols in its namespace. See [Inside a Blip](#inside-a-blip).
- A Blip started from a derived BlipVol holds a copy of everything on the parent's
  disk at that time, including `~/.blip/id_ed25519` and any other secrets.
