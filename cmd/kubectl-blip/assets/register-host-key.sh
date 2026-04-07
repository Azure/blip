#!/bin/bash

set -euo pipefail

readonly SA_DIR="/var/run/secrets/kubernetes.io/serviceaccount"

main() {
	local token ns ca vm_name api_url host_key patch
	token="$(cat "$SA_DIR/token")"
	ns="$(cat "$SA_DIR/namespace")"
	ca="$SA_DIR/ca.crt"
	vm_name="$(hostname)"
	api_url="https://kubernetes.default.svc/apis/kubevirt.io/v1/namespaces/${ns}/virtualmachines/${vm_name}"

	host_key="$(awk '{print $1, $2}' /etc/ssh/ssh_host_ed25519_key.pub)"
	patch=$(printf '{"metadata":{"annotations":{"blip.io/host-key":"%s"}}}' "$host_key")

	local ok=false code
	for _retry in $(seq 1 10); do
		code=$(curl --silent --output /dev/null --write-out "%{http_code}" \
			--cacert "$ca" \
			-X PATCH \
			-H "Authorization: Bearer ${token}" \
			-H "Content-Type: application/merge-patch+json" \
			-d "$patch" \
			"$api_url")
		if [ "$code" -ge 200 ] && [ "$code" -lt 300 ]; then
			ok=true
			break
		fi
		sleep 2
	done

	if [ "$ok" != "true" ]; then
		echo "FATAL: failed to store host key annotation after retries (last HTTP $code)" >&2
		exit 1
	fi

	# sshd may already be running (Ubuntu 24.04 starts it via socket
	# activation). Restart to ensure it is running and picks up any
	# configuration changes.
	systemctl enable ssh
	systemctl restart ssh
}

main "$@"
