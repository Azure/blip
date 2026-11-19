# shellcheck shell=bash
# shellcheck disable=SC2016,SC2154
# Runtime contracts: workload reports, per-execution overrides, image defaults,
# exec exit codes and concurrency, and serial console mirroring.

cleanup_20() {
	k delete blip --ignore-not-found --wait=false \
		"$P-report" "$P-big-report" "$P-runtime" "$P-defaults" \
		"$P-exec" "$P-concurrent" "$P-console" >/dev/null 2>&1 || true
	k delete blipstate --ignore-not-found --wait=false \
		"$P-report" "$P-big-report" "$P-runtime" "$P-defaults" \
		"$P-exec" "$P-concurrent" "$P-console" >/dev/null 2>&1 || true
}
cleanup_register cleanup_20

pod_gone_20() {
	! k get pod "$1" >/dev/null 2>&1
}

step "a workload report lands in status and outlives its pod"
r20_report="report-$P-round-trip"
test "$(blip run --name "$P-report" --from "$P-base" \
	-e REPORT_TEXT="$r20_report" -- sh -ec '
	curl -fsS -X POST --data-binary "$REPORT_TEXT" "$BLIP_REPORT_URL" >/dev/null
	sleep 1
')" = "$P-report"
wait_blip_phase "$P-report" Succeeded "$T"
r20_pod=$(blip_pod "$P-report")
test -n "$r20_pod"
test "$(blip_field "$P-report" '{.status.report.text}')" = "$r20_report"
test -n "$(blip_field "$P-report" '{.status.report.seq}')"
# The VM pod is deleted when the blip finishes, but its report stays in status.
wait_for "$T" "report pod $r20_pod to be deleted" pod_gone_20 "$r20_pod"
test "$(blip_field "$P-report" '{.status.pod}')" = "$r20_pod"
test "$(blip_field "$P-report" '{.status.report.text}')" = "$r20_report"
expect_ok_grep "gather prints the report" "report: $r20_report" blip gather "$P-report"

step "an oversized workload report is rejected with 413"
blip run --name "$P-big-report" --from "$P-base" -- sh -ec '
	code=$(head -c 1025 /dev/zero | tr "\000" x |
		curl -sS -o /dev/null -w "%{http_code}" --data-binary @- "$BLIP_REPORT_URL")
	test "$code" = 413
' >/dev/null
expect_ok_grep "gather the oversized-report blip" \
	"blip/$P-big-report Succeeded" blip gather "$P-big-report"

step "run and exec honor per-execution env, working directory, and user"
r20_run_env="run-env-$P"
r20_exec_env="exec-env-$P"
test "$(blip run --name "$P-runtime" --from "$P-base" \
	-e RT_ENV="$r20_run_env" -e EXPECT_RUN="$r20_run_env" \
	-w /tmp -u 0:0 -- sh -ec '
	test "$RT_ENV" = "$EXPECT_RUN"
	test "$PWD" = /tmp
	test "$(id -u):$(id -g)" = 0:0
	echo "primary:$RT_ENV" > /tmp/runtime-primary.txt
	sleep infinity
')" = "$P-runtime"
wait_blip_phase "$P-runtime" Running "$T"
expect_ok_grep "exec applies its own runtime overrides" "exec overrides applied" \
	blip exec "$P-runtime" \
	-e RT_ENV="$r20_exec_env" -e EXPECT_EXEC="$r20_exec_env" \
	-e EXPECT_RUN="$r20_run_env" \
	-w /var/tmp -u 0:0 -- sh -ec '
	test "$RT_ENV" = "$EXPECT_EXEC"
	test "$PWD" = /var/tmp
	test "$(id -u):$(id -g)" = 0:0
	# The primary command may still be starting when this session opens.
	i=0
	while [ ! -s /tmp/runtime-primary.txt ] && [ "$i" -lt 100 ]; do
		sleep 0.1
		i=$((i + 1))
	done
	test "$(cat /tmp/runtime-primary.txt)" = "primary:$EXPECT_RUN"
	echo "exec overrides applied"
'
k delete blip "$P-runtime" >/dev/null
wait_blip_gone "$P-runtime" "$T"

step "the dev image metadata supplies runtime defaults"
test "$(blip run --name "$P-defaults" --from "$P-base" -- sh -ec '
	test "$(id -u)" = 1000
	test "$PWD" = /home/dev
	test "$LANG" = C.UTF-8
')" = "$P-defaults"
expect_ok_grep "gather the defaults blip" \
	"blip/$P-defaults Succeeded" blip gather "$P-defaults"

step "exec propagates the command exit status"
test "$(blip run --name "$P-exec" --from "$P-base" -- sleep infinity)" = "$P-exec"
wait_blip_phase "$P-exec" Running "$T"
if blip exec "$P-exec" -- sh -c 'exit 9' >"$work/exec-exit.out" 2>&1; then
	echo "expected exec to fail with exit 9" >&2
	cat "$work/exec-exit.out" >&2
	exit 1
else
	r20_rc=$?
fi
test "$r20_rc" = 9
k delete blip "$P-exec" >/dev/null
wait_blip_gone "$P-exec" "$T"

step "two exec sessions run concurrently in one blip"
test "$(blip run --name "$P-concurrent" --from "$P-base" -- sleep infinity)" = "$P-concurrent"
wait_blip_phase "$P-concurrent" Running "$T"
blip exec "$P-concurrent" -- sh -c '
	sleep 1
	echo concurrent-a
	echo a > /tmp/concurrent-a
' >"$work/concurrent-a.out" 2>&1 &
r20_a=$!
blip exec "$P-concurrent" -- sh -c '
	sleep 1
	echo concurrent-b
	echo b > /tmp/concurrent-b
' >"$work/concurrent-b.out" 2>&1 &
r20_b=$!
wait "$r20_a"
wait "$r20_b"
grep -q '^concurrent-a$' "$work/concurrent-a.out"
grep -q '^concurrent-b$' "$work/concurrent-b.out"
blip exec "$P-concurrent" -- sh -ec '
	test "$(cat /tmp/concurrent-a)" = a
	test "$(cat /tmp/concurrent-b)" = b
'
k delete blip "$P-concurrent" >/dev/null
wait_blip_gone "$P-concurrent" "$T"

step "primary command output is mirrored to the serial console"
r20_marker="serial-marker-$P"
test "$(blip run --name "$P-console" --from "$P-base" \
	-e MARKER="$r20_marker" -- sh -c 'echo "$MARKER"; sleep 30')" = "$P-console"
wait_blip_phase "$P-console" Running "$T"
r20_pod=$(blip_pod "$P-console")
test -n "$r20_pod"
# The runtime maps the VM serial console to the vm container's stdout.
serial_has_marker_20() {
	k logs "$r20_pod" -c vm --tail=2000 2>/dev/null | grep -q -- "blip: $r20_marker"
}
retry 30 serial_has_marker_20
k delete blip "$P-console" >/dev/null
wait_blip_gone "$P-console" "$T"
