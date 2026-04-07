#!/bin/bash

set -euo pipefail

readonly SA_DIR="/var/run/secrets/kubernetes.io/serviceaccount"

main() {
	local token ns ca_cert cm_url
	token="$(cat "$SA_DIR/token")"
	ns="$(cat "$SA_DIR/namespace")"
	ca_cert="$SA_DIR/ca.crt"
	cm_url="https://kubernetes.default.svc/api/v1/namespaces/${ns}/configmaps/ssh-ca-pubkey"

	local ca_pub="" body
	for _retry in $(seq 1 10); do
		if body=$(curl --silent --fail \
			--cacert "$ca_cert" \
			-H "Authorization: Bearer ${token}" \
			"$cm_url"); then
			ca_pub=$(printf '%s' "$body" |
				grep -oP '"ca\.pub"\s*:\s*"[^"]*"' |
				head -1 |
				cut -d'"' -f4 |
				sed 's/\\n$//')
			if [ -n "$ca_pub" ]; then
				break
			fi
		fi
		sleep 2
	done

	if [ -z "$ca_pub" ]; then
		echo "FATAL: failed to fetch SSH CA public key after retries" >&2
		exit 1
	fi

	printf '%s\n' "$ca_pub" >/etc/ssh/trusted_user_ca_keys
	chmod 644 /etc/ssh/trusted_user_ca_keys
	printf '\nTrustedUserCAKeys /etc/ssh/trusted_user_ca_keys\n' >>/etc/ssh/sshd_config
}

main "$@"
