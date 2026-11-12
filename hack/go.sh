#!/usr/bin/env bash
# go with a private build cache, retried once on a corrupted cache or GOROOT.
#
# This host is shared: other workloads clean the shared ~/.cache/go-build
# (go clean -cache, disk cleanup) while builds run, and go then fails with
# "open .../go-build/..: no such file or directory" or, when the cached
# std package index vanishes, "package os is not in std". Builds of this
# repository use their own cache (BLIP_GOCACHE, default .cache/go-build
# in the repository, gitignored). If one still fails like that (for
# example a snap refresh of Go replaced GOROOT), the build is retried once.
# Usage: hack/go.sh build|test|vet ARGS...
set -uo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
export GOCACHE=${BLIP_GOCACHE:-$root/.cache/go-build}
mkdir -p "$GOCACHE"
err=$(mktemp "${TMPDIR:-/tmp}/blip-go.XXXXXX")
trap 'rm -f "$err"' EXIT
for try in 1 2; do
	"${GO:-go}" "$@" 2>"$err"
	rc=$?
	cat "$err" >&2
	[[ $rc -ne 0 && $try == 1 ]] || exit $rc
	grep -qE 'is not in std|go-build/.*no such file or directory|cannot find GOROOT|GOROOT.*(not found|no such file)' "$err" || exit $rc
	echo "hack/go.sh: the Go build cache ($GOCACHE) or GOROOT ($("${GO:-go}" env GOROOT 2>/dev/null)) changed during the build; retrying once" >&2
	sleep 2
done
