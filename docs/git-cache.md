<!-- Copyright (c) Microsoft Corporation.
Licensed under the MIT License. -->

# Shared git repository caches

A shared state is an ownerless BlipState that every blip in its namespace may
read or copy. Imported image states already worked this way. A state labelled
`blip.dev/shared: "true"` joins them, provided it has no `blip.dev/owner`
label.

A git cache is a shared state whose filesystem root holds a complete, non-bare
clone of one repository with its default branch checked out. A consumer copies
the cache into its own writable state and runs `git fetch`. The copy moves
filesystem blocks, not git objects.

An owner may mount a shared state read-only. The controller rejects a writable
mount of a shared state with
`state "NAME" is shared read-only; copy it into a new state instead`. An
ownerless blip may write a shared state, which is how a warm job publishes a
generation.

## Copy the filesystem instead of the git objects

`spec.copyFrom` pins the source's committed version and builds the destination
from it. On a node that already holds the source, storage takes a thin
snapshot. No repository data crosses the network, and the claim starts with a
full working tree and `.git` directory. When the copy is placed on another
node, it streams the filesystem from a node that holds the cache instead of
fetching history from the git remote.

Git's own shortcuts keep a dependency on the cache. `git clone --reference` and
an `objects/info/alternates` file borrow objects from another repository, so a
claim breaks when the cache generation is pruned. `blip gather --collect git:`
also rejects any repository whose alternates resolve outside the state. A
`git clone --dissociate` removes that dependency by copying every object, which
costs as much as a full clone. A plain `git clone` from the remote pays network
and server time per claim.

Copying the filesystem makes cache lifetime irrelevant. The claim owns its
blocks and objects, and deleting the cache generation does not touch it.

## Cache state contract

A generation is a BlipState named `gitcache-<repo>-<timestamp>`, for example
`gitcache-blip-20261123t0300`. Keep the timestamp lowercase so the whole name
is a legal DNS label.

| Metadata | Value |
| --- | --- |
| `blip.dev/shared` label | `"true"` |
| `blip.dev/owner` label | absent |
| `git.blip.dev/repo` label | repository name, for example `blip` |
| `git.blip.dev/url` annotation | clone URL |
| `git.blip.dev/branch` annotation | branch checked out in the cache |

Publish only a state that is Ready, has a committed version, and has no
writer. `claim_repo` selects the newest Ready generation by
`status.committed.time`, so the labels go on after the warm blip finishes and
the state saves. A published generation is never written again, which keeps a
consumer from copying a half-finished fetch and keeps the controller from
taking a live snapshot of a moving filesystem.

The filesystem root is the clone itself. `.git` sits next to the working tree,
and the branch named in `git.blip.dev/branch` is checked out at `HEAD`, so
build scripts, `git status`, and `git log -1` work on a fresh claim without
setup.

Every ext4 filesystem has a `lost+found` directory at its root. Add it to
`.git/info/exclude` in the cache; otherwise every consumer sees it as an
untracked file and `git status --porcelain` never comes back empty.

Write the commit graph, a multi-pack index, and pack bitmaps before publishing.
They let `git log`, `git status`, and reachability checks answer from indexes
instead of walking packs. The warm command in the worked example writes all
three.

The files must belong to the uid that consumer blips run as, often `1000`. Git
refuses to operate on a repository owned by another user and reports
`detected dubious ownership in repository`. The guest gives an empty filesystem
to the blip's user, but a cache is not empty, so the warmer has to `chown` the
clone or every consumer needs a `safe.directory` entry.

Set two config values in the cache repository before publishing:

```sh
git -C /cache config gc.auto 0
git -C /cache config maintenance.auto false
```

Copies inherit `.git/config`. Without these, a consumer's first fetch, commit,
or merge can trigger automatic gc or maintenance. That repack rewrites the
packs inherited from the cache, so the consumer's first save stores a full copy
of the repository instead of a thin layer over the cache.

Refresh packs with a geometric repack:

```sh
git -C /cache repack --geometric=2 -d --write-midx --write-bitmap-index
```

Geometric repacking folds small packs into larger ones only when their sizes
pass a ratio. Each generation adds one pack for the fetched commits and folds
only small packs, so most inherited packs stay unchanged. A full
`git repack -adb` rewrites every object on every run, so consecutive
generations have almost no pack data in common and the thin layer between them
grows toward the size of the repository.

Give each generation a generous `spec.size`. The size is immutable, and a copy
inherits it unless its creator asks for a larger one. A claim created with a
larger size grows the copied filesystem at creation with `e2fsck` and
`resize2fs`. Set enough room for the repository plus the build output a
consumer is likely to make, so claims rarely need to grow.

## Trust and credentials

Treat a cache as executable input. A consumer mounts a copy writable and runs
git commands in it.

The cache must contain no credentials. Every blip in the namespace can copy it,
and a claim carries `.git/config` into a workspace that `blip gather` may
export. Pass tokens in the environment or in a credential helper that reads the
environment, never in a remote URL or a config file inside the state.

The cache must contain no hooks and no configured hook or fsmonitor program.
Git runs hooks from `.git/hooks` or `core.hooksPath` during commands such as
commit, merge, and checkout, and `core.fsmonitor` runs a program on
`git status`, so a cache can execute code inside every consumer. The warmer
should remove `.git/hooks`, unset `core.hooksPath` and `core.fsmonitor`, and
publish only from a trusted pipeline.

Only a trusted warmer writes a cache. An ownerless blip may write a shared
state, so anyone who can create an ownerless blip in the namespace can replace
a cache's contents. The namespace is the trust boundary: anything that can copy
shared states in the namespace can read every cache in it.

A claim still catches up with `git fetch`, so the consumer's pool needs egress
to the git remote. When the remote needs credentials, route the fetch through a
proxy instead of editing the repository. Git reads `GIT_CONFIG_COUNT` and the
numbered `GIT_CONFIG_KEY_n` and `GIT_CONFIG_VALUE_n` entries as extra config:

```sh
GIT_CONFIG_COUNT=1
GIT_CONFIG_KEY_0=url.https://git-proxy.internal/github.com/.insteadOf
GIT_CONFIG_VALUE_0=https://github.com/
```

With those three variables in `spec.env`, a fetch of
`https://github.com/Azure/blip.git` goes to
`https://git-proxy.internal/github.com/Azure/blip.git`, where the proxy holds
the credential. The rewrite lives in the environment and never reaches the
cache.

## Worked example

Blip does not schedule the warm job; the operator runs it on a timer. The
manifests use the namespace `dev` and an illustrative image name.

### Create the warm state

The warm blip needs git, CA certificates, and a writable root. A blip cannot run
directly on a state that has `spec.image`, so the job copies the imported image
state into an ownerless state it reuses. Neither state has a `blip.dev/owner`
label, and the Blip manifest below has none either, so the warm run is
ownerless and may write the shared generation.

```yaml
apiVersion: blip.dev/v1alpha1
kind: BlipState
metadata:
  name: git-image
  namespace: dev
spec:
  image: ghcr.io/example/blip-git:1.2
---
apiVersion: blip.dev/v1alpha1
kind: BlipState
metadata:
  name: git-warmer
  namespace: dev
spec:
  copyFrom: git-image
  size: 10Gi
  mounts:
    - state: gitcache-blip-20261123t0300
      path: /cache
      writable: true
```

The mount goes on the root state, not on the Blip. Each run points it at the
new generation name before starting the warm blip.

### Run the warmer

Create the generation, then start the blip. The first run has no `copyFrom`
and starts empty; set `size: 40Gi` on it to leave room for the repository.
Later runs copy the previous generation and inherit its size, which turns the
`git fetch` into an incremental update.

```yaml
apiVersion: blip.dev/v1alpha1
kind: BlipState
metadata:
  name: gitcache-blip-20261123t0300
  namespace: dev
spec:
  copyFrom: gitcache-blip-20261122t0300  # omit on the first run
---
apiVersion: blip.dev/v1alpha1
kind: Blip
metadata:
  name: gitcache-blip-20261123t0300
  namespace: dev
spec:
  state: git-warmer
  command:
    - sh
    - -ec
    - |
      set -eu
      url=https://github.com/Azure/blip.git
      branch=main
      if [ -d /cache/.git ]; then
        git -C /cache fetch --prune origin
        git -C /cache reset --hard "origin/$branch"
      else
        git -C /cache init -b "$branch"
        git -C /cache remote add origin "$url"
        git -C /cache config remote.origin.fetch \
          '+refs/heads/*:refs/remotes/origin/*'
        git -C /cache fetch --prune origin
        git -C /cache reset --hard "origin/$branch"
      fi
      git -C /cache config gc.auto 0
      git -C /cache config maintenance.auto false
      git -C /cache config --unset core.hooksPath || true
      git -C /cache config --unset core.fsmonitor || true
      rm -rf /cache/.git/hooks
      grep -qxF lost+found /cache/.git/info/exclude ||
        echo lost+found >> /cache/.git/info/exclude
      git -C /cache repack --geometric=2 -d --write-midx --write-bitmap-index
      git -C /cache commit-graph write --reachable
      chown -R 1000:1000 /cache
```

The final `chown` needs a root warm blip or a privileged step. Without it,
consumers fail the ownership check unless they pass `safe.directory`.

### Publish the generation

Wait for the command to exit and the state to save, then add the labels and
annotations.

```sh
kubectl -n dev wait --for=jsonpath='{.status.phase}'=Succeeded \
  blip/gitcache-blip-20261123t0300 --timeout=30m
kubectl -n dev wait --for=jsonpath='{.status.phase}'=Ready \
  blipstate/gitcache-blip-20261123t0300 --timeout=10m

kubectl -n dev label blipstate gitcache-blip-20261123t0300 \
  git.blip.dev/repo=blip blip.dev/shared=true --overwrite
kubectl -n dev annotate blipstate gitcache-blip-20261123t0300 \
  git.blip.dev/url=https://github.com/Azure/blip.git \
  git.blip.dev/branch=main --overwrite
```

Keep the two newest generations and delete the rest:

```sh
kubectl -n dev get blipstate -l git.blip.dev/repo=blip,blip.dev/shared=true \
  --sort-by=.status.committed.time -o name |
  head -n -2 | xargs -r kubectl -n dev delete
```

The controller blocks deletion of a state that a root state mounts
persistently. The warm job points `git-warmer` at the new generation before it
starts the blip, so the generations this command deletes are no longer
mounted.

### Claim the cache

A claim is an ordinary owned state with `copyFrom` set to the generation. The
controller accepts a copy of a shared state from an owner.

```yaml
apiVersion: blip.dev/v1alpha1
kind: BlipState
metadata:
  name: alice.repo
  namespace: dev
  labels:
    blip.dev/owner: alice
spec:
  copyFrom: gitcache-blip-20261123t0300
```

Inside alice's blip, `blip mount alice.repo:/src/blip:rw` mounts the claim created
above. Or skip the manifest and create plus mount it in one step:

```sh
blip mount --new alice.repo:/src/blip:rw --from gitcache-blip-20261123t0300
```

The copy is writable, saves with alice's workspace, replicates like any other
state, and is deleted with its owner. Inside the blip, run
`git -C /src/blip fetch --prune origin` to pick up commits newer than the
cache. A forked workspace copies the writable mount into the fork and keeps the
`git.blip.dev/repo` label and the `git.blip.dev/source` annotation. The fork
keeps using the repository without claiming it again.

`blip gather --collect git:` still works on the claim:

```sh
blip gather --collect "git:/src/blip:alice-fix"
```

That fetches commits from the mounted worktree into the caller's repository,
not uncommitted changes. It rejects alternates outside the state, one more
reason the cache must hold a self-contained clone.

## Repositories in blipchat

blipchat exposes `claim_repo` as an MCP tool. A call names a repository and an
optional path:

```json
{"repo": "blip", "path": "/src/blip"}
```

The path defaults to `/src/<repo>`. The tool returns the claim as JSON:

```json
{
  "repo": "blip",
  "path": "/src/blip",
  "state": "chat-7f3a-r-blip",
  "url": "https://github.com/Azure/blip.git",
  "branch": "main",
  "cachedAt": "2026-11-23T03:00:12Z",
  "mounted": true,
  "next": "git -C /src/blip fetch --prune origin; git -C /src/blip merge --ff-only origin/main"
}
```

`cachedAt` is the commit time of the generation the claim was copied from, so a
reused claim reports its own snapshot and not a newer generation. `next` is the
catch-up command; a cache without a branch annotation returns only the
`fetch --prune` half. When the copy is ready but has not attached to the running
blip yet, `mounted` is `false` and a `note` says so. The mount is already
desired intent on the chat root and attaches when the controller next
reconciles.

The tool picks the newest Ready cache for the repository. A cache that is still
copying or has failed is ignored, so a newer complete generation wins. It then
creates a claim state named `<session>-r-<repo>`, or a hashed name when that
would exceed 63 characters, copies the cache into it, and mounts it writable on
the chat's root state. The tool waits up to a minute for the mount to attach and
reports the result. Repeated calls are idempotent: an existing mount at the
requested path is reused if it holds the same repository, otherwise any mount
of that repository is reused. A path already mounted from another repository
is an error.

A claim carries `chat.blip.dev/session: "true"`, `blip.dev/owner`, and
`git.blip.dev/repo`, plus an owner reference to the chat state. It is an owned
state, not a shared one. It has none of the chat annotations
(`chat.blip.dev/profile`, `chat.blip.dev/parent`, `chat.blip.dev/root`,
`chat.blip.dev/title`), so blipchat does not list it as a chat. Deleting the
chat deletes its claims.

A child chat started with the fork workspace mode inherits the parent's claims:
the fork copies each writable mount, including the repository claim. The child
can use the repository without calling `claim_repo`, and a call there reuses
the inherited mount.

## Verify a cache

Check the worktree and the checked-out commit:

```sh
git -C /src/blip status --porcelain
git -C /src/blip rev-parse --abbrev-ref HEAD
git -C /src/blip log -1 --format='%H %s'
```

Empty output from `git status --porcelain` means the worktree matches the
checked-out commit. The cache was reset to its branch before it was published,
so a fresh claim has no tracked changes and any tracked change came from the
consumer's work. `git log -1` should match the commit of the branch recorded in
`git.blip.dev/branch`; after the catch-up command the claim can be ahead of it.

Read the cache time from the generation state:

```sh
kubectl -n dev get blipstate gitcache-blip-20261123t0300 \
  -o jsonpath='{.status.committed.time}{"\n"}'
```

That timestamp is the same value `claim_repo` returns as `cachedAt` for a claim
copied from this generation, and it is what the newest-generation selection
compares.
