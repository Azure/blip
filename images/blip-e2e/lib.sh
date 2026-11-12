# Shell helpers for the e2e guest (busybox sh). Sourced by blip-e2e-init and
# by the scripts it runs in `sh` mode (hack/e2e/run.sh).
# shellcheck shell=sh

SA=/run/secrets/kubernetes.io/serviceaccount

log() { echo "E2E $*"; }

# w DEV TEXT: write TEXT as one line to sector 0 of DEV (fsync).
w() { printf '%s\n' "$2" | dd of="$1" bs=512 count=1 conv=sync,fsync 2>/dev/null; }
# r DEV: the first line of sector 0 of DEV (zero padding removed).
r() { head -c 512 "$1" | tr -d '\000' | head -n1; }

# dev NAME: guest path of the Blip volume NAME (virtio serial = name).
dev() { echo "/dev/disk/by-id/virtio-$1"; }

# link_disks: create /dev/disk/by-id/virtio-<serial> for every virtio disk
# and drop links whose device is gone (there is no udev in this image).
link_disks() {
	mkdir -p /dev/disk/by-id
	for b in /sys/block/vd*; do
		[ -e "$b/serial" ] || continue
		s=$(cat "$b/serial" 2>/dev/null)
		[ -n "$s" ] || continue
		l=/dev/disk/by-id/virtio-$s
		[ "$(readlink "$l" 2>/dev/null)" = "../../${b##*/}" ] || ln -sfn "../../${b##*/}" "$l"
	done
	for l in /dev/disk/by-id/virtio-*; do
		[ -L "$l" ] && [ ! -e "$l" ] && rm -f "$l"
	done
	return 0
}

# waitdev NAME [SECS]: wait for the volume NAME to appear and check that its
# virtio serial is NAME.
waitdev() {
	n=0
	while [ ! -b "$(dev "$1")" ]; do
		n=$((n + 1))
		[ "$n" -lt "${2:-120}" ] || { log "no device for volume $1"; return 1; }
		link_disks
		sleep 1
	done
	d=$(readlink -f "$(dev "$1")")
	[ "$(cat "/sys/block/${d##*/}/serial")" = "$1" ] || { log "serial of $d is not $1"; return 1; }
}

# iface: the first Ethernet interface (matched by type, never by MAC).
iface() {
	for i in /sys/class/net/*; do
		[ "$(cat "$i/type" 2>/dev/null)" = 1 ] && [ "${i##*/}" != lo ] && { echo "${i##*/}"; return 0; }
	done
	return 1
}

# net_report: print "NET ip=<ip> mac=<mac>" and check cluster DNS.
net_report() {
	i=$(iface) || { log "no ethernet interface"; return 4; }
	ip=$(ip -4 -o addr show dev "$i" | awk '{print $4}' | cut -d/ -f1 | head -n1)
	echo "NET ip=$ip mac=$(cat "/sys/class/net/$i/address")"
	nslookup kubernetes.default.svc.cluster.local >/tmp/dns 2>&1 || { cat /tmp/dns; return 4; }
	echo "NET dns-ok"
}

# creds_check: wait for the service account files and authenticate to the
# API server with the token (SelfSubjectReview is allowed for everyone).
creds_check() {
	n=0
	until [ -s $SA/token ] && [ -s $SA/ca.crt ] && [ -s $SA/namespace ]; do
		n=$((n + 1))
		[ $n -lt 60 ] || { log "no credentials in $SA"; return 5; }
		sleep 1
	done
	out=$(curl -sS --max-time 10 --cacert $SA/ca.crt -H "Authorization: Bearer $(cat $SA/token)" \
		-H 'Content-Type: application/json' -X POST \
		-d '{"apiVersion":"authentication.k8s.io/v1","kind":"SelfSubjectReview"}' \
		https://kubernetes.default.svc/apis/authentication.k8s.io/v1/selfsubjectreviews 2>&1)
	user=$(printf '%s' "$out" | jq -r '.status.userInfo.username // empty' 2>/dev/null)
	case $user in
	system:serviceaccount:*) echo "CREDS ok user=$user" ;;
	*) log "creds check failed: $out"; return 5 ;;
	esac
}
