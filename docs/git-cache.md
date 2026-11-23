<!-- Copyright (c) Microsoft Corporation.
Licensed under the MIT License. -->

# Shared git repository caches

A git cache is a shared BlipState whose filesystem root holds a complete,
non-bare clone of one repository, with its default branch checked out. A
consumer copies the cache into a private writable state and runs `git fetch`.
The copy moves filesystem blocks, not git objects, so a claim starts with a full
worktree and `.git` directory and does not depend on the cache's lifetime.

`spec.build` maintains the cache: a recipe periodically runs a command and
publishes each successful result, replacing the warm job and its timer.

Image states and build outputs are replicated like any other state.
`spec.replicas` sets how many nodes hold each committed version, default 3.
Nodes that do not hold a version fetch it on demand. A node keeps previously
used committed versions as a local cache and evicts the least recently used
versions when its pool falls below about 25 percent free.

## Cache contract

A generation is an ownerless shared state: it carries `blip.dev/shared: "true"`,
has no `blip.dev/owner` label, and is not written after publication. It also
carries the label `git.blip.dev/repo` and the annotations `git.blip.dev/url`
and `git.blip.dev/branch`. The recipe copies its labels and annotations onto an
output only after the build command succeeds, so a selector never sees a failed
or incomplete build. A blipchat profile mount selects the newest Ready
generation by `status.committed.time`, with the state name breaking a tie.

The filesystem root is the clone. `.git` sits next to the worktree, and the
branch in `git.blip.dev/branch` is checked out at `HEAD`. Add `lost+found` to
`.git/info/exclude` so consumers do not see it as untracked. Write the commit
graph, a multi-pack index, and pack bitmaps. Set `gc.auto` to `0` and
`maintenance.auto` to `false`: copies inherit `.git/config`, and an automatic
repack would rewrite the inherited packs. A geometric repack folds only small
packs; the recipe below runs one.

The files must belong to the uid consumers run as, often `1000`. Git refuses a
repository owned by another user with `detected dubious ownership in
repository`, so the build command chowns `/cache`.

## Recipe

The builder is an imported OS image. The first build starts from an empty
output; `incremental: true` makes later builds start from the previous output,
which turns the fetch into an update. The output holds only the clone and is
mounted at `/cache` during the build.

```yaml
apiVersion: blip.dev/v1alpha1
kind: BlipState
metadata:
  name: git-image
  namespace: dev
spec:
  image: ghcr.io/example/blip-git:1.2
  size: 10Gi
---
apiVersion: blip.dev/v1alpha1
kind: BlipState
metadata:
  name: gitcache-blip
  namespace: dev
  labels:
    blip.dev/shared: "true"
    git.blip.dev/repo: blip
  annotations:
    git.blip.dev/url: https://github.com/Azure/blip.git
    git.blip.dev/branch: main
spec:
  size: 40Gi
  historyLimit: 2
  runtime:
    user: "1000"
  build:
    builder: git-image
    path: /cache
    incremental: true
    intervalSeconds: 86400
    command:
      - sh
      - -ec
      - |
        set -eu
        if [ -d /cache/.git ]; then
          git -C /cache fetch --prune origin
        else
          git -C /cache init -b main
          git -C /cache remote add origin https://github.com/Azure/blip.git
          git -C /cache fetch --prune origin
        fi
        git -C /cache reset --hard origin/main
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

`incremental: true` makes the first build start from an empty output and every
later build start from the newest output. The command runs as `root` by default
so it can create `/cache/.git` and chown the result; `runtime.user` sets the
default user for consumers. Without a builder, set `from` to an OS image and
clone into the output root instead; the output then contains the OS as well.

## Updates and retention

A build starts when no build is running and the recipe has not started one yet,
`intervalSeconds` has elapsed since the last start, or the recipe's spec
changed. A failed build is retried at the next interval. The interval is also the deadline: a build still running when the next
start is due is stopped and fails.

With `incremental`, each successful build creates a new output copied from the
previous one. Consumers keep private copies, so retiring an old generation does
not affect them. On failure the output stays unpublished; the next build
deletes it and its build Blip.

`historyLimit: 2` keeps the newest two successful outputs and deletes older
ones; the value is required, from 1 through 32. Outputs are owned by the recipe,
so deleting the recipe deletes its outputs, builder copies, and build Blips.

To force a rebuild, edit the spec; any change starts a build immediately. For
example, bump `intervalSeconds` or add a variable to `build.env`.

Inspect a failed build through `status.build`; `latest` is the newest successful
output, and `output`, `blip`, and `message` describe the last attempt.

```sh
kubectl -n dev get blipstate gitcache-blip -o jsonpath='{.status.build}{"\n"}'
blip logs "$(kubectl -n dev get blipstate gitcache-blip -o jsonpath='{.status.build.blip}')"
```

## Consumers

A claim is an ordinary owned state with `copyFrom` set to a published
generation; for example, `alice.repo` sets
`spec.copyFrom: gitcache-blip-20261123t030000` and carries
`blip.dev/owner: alice`. The copy is writable, saves with the owner's workspace,
and is deleted with its owner.

Mount it with `blip mount alice.repo:/src/blip:rw`, or create and mount it in
one step with `blip mount --new alice.repo:/src/blip:rw --from
gitcache-blip-20261123t030000`. Run `git -C /src/blip fetch --prune origin` to
catch up. A forked workspace copies the writable mount, so the fork keeps using
the repository without a new claim.

A blipchat profile can select caches by label; set the mount's selector to
`blip.dev/shared: "true"` and `git.blip.dev/repo: blip`. Blipchat copies the
newest matching Ready state into a private writable state when the chat is
created; later generations do not change the chat.

## Trust and credentials

Treat a cache as executable input. The cache must contain no hooks, no
configured `core.hooksPath` or `core.fsmonitor` program, and no credentials;
the build removes `.git/hooks`, unsets both config values, and stores no token
in a remote URL or a config file inside the state. Publish only from a trusted
pipeline.

The namespace is the trust boundary: anything that can copy shared states can
read every cache in it, and anything that can edit the recipe or create an
ownerless blip that writes a shared state can replace a cache.

Consumers still need egress to the git remote. When the remote needs
credentials, route through a proxy so no token reaches the cache.

## Verify a generation

```sh
git -C /src/blip status --porcelain
git -C /src/blip log -1 --format='%H %s'
```

Empty `git status --porcelain` means the worktree matches the checked-out
commit. A blipchat profile mount compares `status.committed.time` to select the
newest generation.
