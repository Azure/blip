#!/bin/bash
set -euo pipefail

readonly SA_DIR="/var/run/secrets/kubernetes.io/serviceaccount"

# Build the KubeVirt VM API URL for this VM.
_vm_api_url() {
	local token ns ca vm_name
	token="$(cat "$SA_DIR/token")"
	ns="$(cat "$SA_DIR/namespace")"
	ca="$SA_DIR/ca.crt"
	vm_name="$(hostname)"

	# Export for caller use.
	VM_TOKEN="$token"
	VM_CA="$ca"
	VM_NAME="$vm_name"
	VM_API_URL="https://kubernetes.default.svc/apis/kubevirt.io/v1/namespaces/${ns}/virtualmachines/${vm_name}"
}

# Extract a JSON string value by key from flat JSON.  Handles simple
# single-line objects only (no jq dependency in the VM image).
_json_field() {
	local body="$1" key="$2"
	printf '%s' "$body" |
		grep -oP "\"${key}\"\\s*:\\s*\"[^\"]*\"" |
		head -1 |
		cut -d'"' -f4
}

# Parse a duration string like "5m", "2h", "1h30m" into total seconds.
# Supports hours (h) and minutes (m).
_parse_duration() {
	local input="$1"
	local total=0 num=""

	# Validate: only digits, 'h', and 'm' allowed.
	if ! printf '%s' "$input" | grep -qE '^[0-9]+[hm]([0-9]+[hm])?$'; then
		echo "Invalid duration format: $input (use e.g. 5m, 2h, 1h30m)" >&2
		return 1
	fi

	while [ -n "$input" ]; do
		# Extract leading digits.
		num=$(printf '%s' "$input" | grep -oE '^[0-9]+')
		if [ -z "$num" ]; then
			echo "Invalid duration format" >&2
			return 1
		fi
		# Remove the digits from input.
		input="${input#"$num"}"
		# Read the unit character.
		local unit="${input:0:1}"
		input="${input:1}"
		case "$unit" in
		h) total=$((total + num * 3600)) ;;
		m) total=$((total + num * 60)) ;;
		*)
			echo "Unknown duration unit: $unit" >&2
			return 1
			;;
		esac
	done

	printf '%d' "$total"
}

usage() {
	echo "Usage: blip <command>"
	echo ""
	echo "Commands:"
	echo "  retain [--ttl]  Preserve this blip across disconnects"
	exit 1
}

cmd_retain() {
	_vm_api_url

	local ttl_flag=""
	local new_ttl_sec=""

	# Parse arguments.
	while [ $# -gt 0 ]; do
		case "$1" in
		--ttl)
			if [ $# -lt 2 ]; then
				echo "Error: --ttl requires a duration value (e.g. 5m, 2h)" >&2
				exit 1
			fi
			ttl_flag="$2"
			shift 2
			;;
		--ttl=*)
			ttl_flag="${1#--ttl=}"
			shift
			;;
		*)
			echo "Unknown argument: $1" >&2
			echo "Usage: blip retain [--ttl <duration>]" >&2
			exit 1
			;;
		esac
	done

	# Build the patch: always set ephemeral=false.
	local patch
	if [ -n "$ttl_flag" ]; then
		new_ttl_sec=$(_parse_duration "$ttl_flag") || exit 1

		# Cap at 12 hours (43200 seconds).
		if [ "$new_ttl_sec" -gt 43200 ]; then
			echo "Warning: TTL capped to 12h (maximum total lifespan)" >&2
			new_ttl_sec=43200
		fi

		patch=$(printf '{"metadata":{"annotations":{"blip.io/ephemeral":"false","blip.io/max-duration":"%d"}}}' "$new_ttl_sec")
	else
		patch='{"metadata":{"annotations":{"blip.io/ephemeral":"false"}}}'
	fi

	local code response
	response=$(curl --silent --write-out "\n%{http_code}" \
		--cacert "$VM_CA" \
		-X PATCH \
		-H "Authorization: Bearer ${VM_TOKEN}" \
		-H "Content-Type: application/merge-patch+json" \
		-d "$patch" \
		"$VM_API_URL")

	code=$(printf '%s' "$response" | tail -1)
	local body
	body=$(printf '%s' "$response" | sed '$d')

	if [ "$code" -ge 200 ] && [ "$code" -lt 300 ]; then
		local session_id
		session_id=$(_json_field "$body" 'blip\.io/session-id')

		echo "Blip retained successfully."
		if [ -n "$session_id" ]; then
			echo ""
			echo "  Session ID: $session_id"
			echo ""
			echo "  Reconnect with: ssh $session_id@<gateway-host>"
		fi
		if [ -n "$ttl_flag" ]; then
			echo "  TTL updated to: $ttl_flag"
		fi

		# Allow output to flush through the SSH channel before exiting.
		sleep 0.1
	else
		echo "Failed to retain blip (HTTP $code)" >&2
		exit 1
	fi
}

if [ $# -lt 1 ]; then
	usage
fi

case "$1" in
retain)
	shift
	cmd_retain "$@"
	;;
*) usage ;;
esac
