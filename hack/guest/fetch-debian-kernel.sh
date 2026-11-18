#!/usr/bin/env bash
# Download a Debian cloud kernel and matching modules for ARCH, extract them
# under DEST, and print KVER/KERNEL/MODDIR assignments for hack/guest/build.sh:
#
#   eval "$(hack/guest/fetch-debian-kernel.sh amd64 build/guest/kernel)"
#   make guest
#
# DEBIAN_SUITE (default: trixie) and DEBIAN_MIRROR (default:
# https://deb.debian.org/debian) select the source. The package is resolved
# from the suite's Packages index and its SHA256 is verified before extraction,
# so the guest kernel does not depend on the build host's kernel.
set -euo pipefail

ARCH="${1:-$(go env GOARCH)}"
DEST="${2:-build/guest/kernel-$ARCH}"
SUITE="${DEBIAN_SUITE:-trixie}"
MIRROR="${DEBIAN_MIRROR:-https://deb.debian.org/debian}"

case "$ARCH" in
  amd64|arm64) ;;
  *) echo "unsupported architecture: $ARCH" >&2; exit 1 ;;
esac
for tool in curl dpkg-deb depmod sha256sum xz; do
  command -v "$tool" >/dev/null || { echo "missing $tool" >&2; exit 1; }
done

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

index="$tmp/Packages"
url="$MIRROR/dists/$SUITE/main/binary-$ARCH/Packages.xz"
echo "fetching $url" >&2
curl -fsSL --retry 5 "$url" | xz -d > "$index"

# field prints one field from the stanza with the exact package name.
field() {
  awk -v RS= -v pkg="$1" -v key="$2" '
    {
      n = split($0, lines, "\n")
      if (n == 0 || lines[1] != "Package: " pkg) next
      for (i = 1; i <= n; i++) {
        if (index(lines[i], key ": ") == 1) {
          print substr(lines[i], length(key) + 3)
          exit
        }
      }
    }' "$index"
}

# linux-image-cloud-$ARCH is a metapackage; resolve its concrete kernel.
meta="linux-image-cloud-$ARCH"
depends="$(field "$meta" Depends)"
pkg="$(printf '%s\n' "$depends" | tr ',|' ' ' | tr -s ' ' | tr ' ' '\n' |
  grep -E '^linux-image-[0-9]' | head -n1)"
[[ -n "$pkg" ]] || { echo "no $meta dependency in $SUITE/$ARCH" >&2; exit 1; }

filename="$(field "$pkg" Filename)"
sha256="$(field "$pkg" SHA256)"
[[ -n "$filename" && -n "$sha256" ]] ||
  { echo "missing $pkg metadata in $SUITE/$ARCH" >&2; exit 1; }

deb="$tmp/$pkg.deb"
echo "downloading $pkg ($SUITE/$ARCH)" >&2
curl -fsSL --retry 5 "$MIRROR/$filename" -o "$deb"
printf '%s  %s\n' "$sha256" "$deb" | sha256sum -c - >&2

rm -rf "$DEST"
mkdir -p "$DEST"
dpkg-deb -x "$deb" "$DEST"
if [[ -d "$DEST/usr/lib/modules" ]]; then
  mkdir -p "$DEST/lib"
  mv "$DEST/usr/lib/modules" "$DEST/lib/modules"
fi

kver="$(find "$DEST/lib/modules" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' |
  head -n1)"
[[ -n "$kver" ]] || { echo "no modules in $pkg" >&2; exit 1; }
kernel="$DEST/boot/vmlinuz-$kver"
[[ -r "$kernel" ]] || { echo "no $kernel in $pkg" >&2; exit 1; }

# The package ships module files but not modules.dep; modinfo and the
# dependency walk in build.sh need the generated index.
depmod -b "$DEST" "$kver"

printf 'KVER=%q\n' "$kver"
printf 'KERNEL=%q\n' "$kernel"
printf 'MODDIR=%q\n' "$DEST/lib/modules/$kver"
