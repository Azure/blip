# Guest artifacts. Run from the repo root: make -f hack/guest/Makefile guest
.PHONY: guest fetch initramfs rootfs slotdev

guest: fetch initramfs slotdev

# initramfs also builds _output/guest/blip-boot and _output/guest/blip-meta.

fetch:
	hack/guest/fetch.sh

initramfs:
	hack/guest/mkinitramfs.sh

slotdev:
	CGO_ENABLED=0 timeout -s TERM 300 hack/go.sh build -o _output/guest/slotdev ./hack/guest/slotdev

rootfs:
	hack/guest/mkrootfs.sh
