// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package guest

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// TestWorkloadLimitsAllowMoreThanInitDefaults reproduces workloads inheriting
// init_task's NOFILE soft/hard 1024/4096: even `ulimit -n 5000` failed, and
// opening the 1022nd descriptor returned EMFILE. Raising the limits in the
// guest init must let a child shell see the new value and open more than 1024
// descriptors.
func TestWorkloadLimitsAllowMoreThanInitDefaults(t *testing.T) {
	if os.Getenv("BLIP_RLIMIT_HELPER") == "1" {
		workloadLimitHelper(t)
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestWorkloadLimitsAllowMoreThanInitDefaults$")
	cmd.Env = append(os.Environ(), "BLIP_RLIMIT_HELPER=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("workload limit helper: %v\n%s", err, out)
	}
	line := ""
	for _, l := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(l, "RESULT ") {
			line = l
			break
		}
	}
	var soft, hard uint64
	var opened int
	if _, err := fmt.Sscanf(line, "RESULT soft=%d hard=%d opened=%d", &soft, &hard, &opened); err != nil {
		t.Fatalf("parse helper output %q: %v\n%s", line, err, out)
	}
	if soft < 8192 || hard < soft {
		t.Fatalf("NOFILE limits soft=%d hard=%d, want at least 8192 and hard >= soft", soft, hard)
	}
	if opened <= 1024 {
		t.Fatalf("workload opened only %d descriptors", opened)
	}
}

func workloadLimitHelper(t *testing.T) {
	if err := raiseWorkloadLimits(); err != nil {
		t.Fatalf("raise workload limits: %v", err)
	}
	var lim unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &lim); err != nil {
		t.Fatal(err)
	}
	if lim.Cur < 8192 || lim.Max < lim.Cur {
		t.Fatalf("NOFILE limits soft=%d hard=%d", lim.Cur, lim.Max)
	}
	// A workload shell inherits the same soft/hard limits.
	out, err := exec.Command("sh", "-c", "ulimit -Sn; ulimit -Hn").CombinedOutput()
	if err != nil {
		t.Fatalf("read shell limits: %v: %s", err, out)
	}
	fields := strings.Fields(string(out))
	if len(fields) != 2 {
		t.Fatalf("shell limits output %q", out)
	}
	soft, err1 := strconv.ParseUint(fields[0], 10, 64)
	hard, err2 := strconv.ParseUint(fields[1], 10, 64)
	if err1 != nil || err2 != nil || soft != lim.Cur || hard != lim.Max {
		t.Fatalf("shell sees soft=%s hard=%s, want %d/%d", fields[0], fields[1], lim.Cur, lim.Max)
	}
	var fds []int
	defer func() {
		for _, fd := range fds {
			unix.Close(fd)
		}
	}()
	for i := 0; i < 1500; i++ {
		fd, err := unix.Open("/dev/null", unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			t.Fatalf("open descriptor %d: %v", i+1, err)
		}
		fds = append(fds, fd)
	}
	fmt.Printf("RESULT soft=%d hard=%d opened=%d\n", lim.Cur, lim.Max, len(fds))
}
