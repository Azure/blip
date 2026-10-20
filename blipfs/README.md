# blipfs

> CAUTION: this is a PoC, it probably only barely works!

blipfs is a copy-on-write FUSE filesystem for AI agents. It stores its data in
one Azure storage account. Every file close makes a new revision. You can fork
branches instantly, and merge, cherry-pick and revert between them with a
git-like CLI.

## Getting started

You need Linux with `/dev/fuse` and `fusermount3`, Go, and a standard (GPv2)
Azure storage account. One volume is one blob container.

```sh
go build -o bin/ ./cmd/...        # builds bin/blipfsd (daemon) and bin/blipfs (CLI)
```

Start the daemon. It signs in with the default Azure credential, such as the
VM's managed identity, which needs the *Storage Blob Data Contributor* role.
You can use `--conn "<connection string>"` instead of `--account-url`.

```sh
sudo bin/blipfsd --account-url https://ACCOUNT.blob.core.windows.net \
  --container vol1 --standalone
```

The daemon starts with no mounts. Use the CLI to mount a branch:

```sh
sudo bin/blipfs mount main /mnt/main
echo hello > /mnt/main/a.txt
sudo bin/blipfs log main
```

The CLI talks to the daemon over a unix socket, `/run/blipfs.sock` by default.
Set `--socket` on the daemon and `$BLIPFS_SOCKET` for the CLI to change it.
Running as root is not required, but then you must choose a socket path you can
write to. Data of files that are open for writing is kept in `--tmp-dir` until
they are closed.

## Standalone and cluster mode

Every write gets a log position from a sequencer.

With `--standalone`, the daemon runs the sequencer itself. This is the fastest
setup for one host. Other hosts that try to open the volume fail with
`EBUSY: volume held in standalone mode by <host>`.

To share a volume between hosts, run the same command on each host without
`--standalone`:

```sh
blipfsd --account-url https://ACCOUNT.blob.core.windows.net --container vol1 \
  --listen :7070 --advertise 10.0.0.4:7070
```

One daemon takes a lease on the volume and becomes the sequencer. It publishes
its `--advertise` address in the volume, and the other daemons send their
sequencer requests there over gRPC. Make sure that address is reachable from
the other hosts. Data never goes through the sequencer; every host reads and
writes Azure directly.

If the sequencer host dies, another daemon takes over the lease within about
a minute. Writes wait during that time and then complete. A host sees changes
from other hosts when it opens a file (close-to-open consistency).

## Using blipfs from an agent

A simple pattern is one branch per agent or task:

```sh
blipfs fork main agent-1
blipfs mount agent-1 /work/agent-1
# the agent works in /work/agent-1
blipfs diff main agent-1                # review the changes
blipfs merge agent-1 --into main
```

Rules worth telling the agent:

* A file is saved as a new revision when it is closed. Write errors are
  returned by `close()`, so check it.
* `fsync` makes data durable but other readers do not see it until close.
* Creating, renaming and deleting files and directories each take effect
  right away.
* If two writers change the same file at once, the last write to each byte
  wins and `blipfs log` marks the revision `[concurrent-writer]`.

Revisions are written `<branch>@<number>`. A plain `<branch>` means its latest
revision. Inside a mount, commands use the mounted branch by default.

```sh
blipfs log [<branch>] [-n N] [-- <path>]
blipfs show main@42
blipfs diff <rev> <rev>
blipfs cherry-pick agent-1@50..agent-1@57 --onto main
blipfs revert main@57
blipfs branches [-a]
blipfs umount /work/agent-1
```

Old revisions are readable at `<mount>/.blipfs/rev/<branch>@<number>/`.

If a merge has conflicts, blipfs creates a workspace at
`<mount>/.blipfs/merge/<id>/`. Fix files in `work/` (`base/`, `ours/` and
`theirs/` are read-only references), then:

```sh
blipfs resolve <path>...
blipfs merge --continue --into main     # or: blipfs merge --abort --into main
```

Text conflicts get `<<<<<<<` markers. Binary conflicts, and two different files
added with the same name, produce a second file named `<name>~theirs`.
