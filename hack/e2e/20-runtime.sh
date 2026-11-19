# shellcheck shell=bash
# shellcheck disable=SC2016,SC2154
# Runtime contracts: per-execution overrides, image defaults, trajectory
# stdout/stderr, stdin, and retained output after the pod is gone.

cleanup_20() {
	k delete blip --ignore-not-found --wait=false \
		"$P-runtime" "$P-defaults" "$P-stream" "$P-retained" >/dev/null 2>&1 || true
	k delete blipstate --ignore-not-found --wait=false \
		"$P-runtime" "$P-defaults" "$P-stream" "$P-retained" >/dev/null 2>&1 || true
}
cleanup_register cleanup_20

step "run honors per-execution env, working directory, and user"
r20_run_env="run-env-$P"
test "$(blip run --name "$P-runtime" --from "$P-base" \
	-e RT_ENV="$r20_run_env" -e EXPECT_RUN="$r20_run_env" \
	-w /tmp -u 0:0 -- sh -ec '
	test "$RT_ENV" = "$EXPECT_RUN"
	test "$PWD" = /tmp
	test "$(id -u):$(id -g)" = 0:0
	echo "primary:$RT_ENV"
')" = "$P-runtime"
wait_blip_phase "$P-runtime" Succeeded "$T"
expect_ok_grep "trajectory has the command output" "primary:$r20_run_env" blip logs "$P-runtime"

step "the dev image metadata supplies runtime defaults"
test "$(blip run --name "$P-defaults" --from "$P-base" -- sh -ec '
	test "$(id -u)" = 1000
	test "$PWD" = /home/dev
	test "$LANG" = C.UTF-8
')" = "$P-defaults"
wait_blip_phase "$P-defaults" Succeeded "$T"
expect_ok_grep "gather the defaults blip" \
	"blip/$P-defaults Succeeded" blip gather "$P-defaults"

step "stdout and stderr are recorded separately and the exit code is kept"
test "$(blip run --name "$P-stream" --from "$P-base" -- sh -ec '
	echo out-line
	echo err-line >&2
	exit 3
')" = "$P-stream"
wait_blip_phase "$P-stream" Failed "$T"
test "$(blip_field "$P-stream" '{.status.exitCode}')" = 3
expect_ok_grep "stdout record" "out-line" blip logs "$P-stream"
expect_ok_grep "stderr record" "err-line" blip logs "$P-stream"
# The trajectory outlives the pod: the blip has finished and its pod is gone.
r20_pod=$(blip_pod "$P-stream")
test -n "$r20_pod"
wait_for "$T" "stream pod $r20_pod to be deleted" pod_gone_20 "$r20_pod"
expect_ok_grep "retained stdout after the pod is gone" "out-line" blip logs "$P-stream"

step "stdin reaches a running command"
blip run --name "$P-retained" --from "$P-base" --interactive -- sh -ec '
	read -r line
	echo "got:$line"
' >/dev/null
wait_blip_phase "$P-retained" Running "$T"
blip send "$P-retained" --text $'hello-stdin\n'
wait_blip_phase "$P-retained" Succeeded "$T"
expect_ok_grep "stdin was delivered" "got:hello-stdin" blip logs "$P-retained"
