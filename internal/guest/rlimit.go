package guest

import (
	"errors"

	"golang.org/x/sys/unix"
)

// Workload limits. blip-guest is PID 1 and inherits the kernel init task's
// limits, whose NOFILE soft/hard of 1024/4096 is too low for builds and test
// suites. Raise both to a useful finite value (or the host's higher hard
// limit) before any workload starts; an inherited RLIM_INFINITY is capped so
// workloads cannot opt into unlimited resource use.
const (
	workloadNoFileFloor = 65536
	workloadNprocFloor  = 8192
	workloadLimitCeil   = 1 << 20
)

// raiseWorkloadLimits applies the workload limits to the guest init process so
// every child inherits them. It is best-effort: Main logs a failure and boots
// anyway, since a limit change must not prevent the VM from serving work.
func raiseWorkloadLimits() error {
	var errs []error
	if err := raiseWorkloadLimit(unix.RLIMIT_NOFILE, workloadNoFileFloor); err != nil {
		errs = append(errs, err)
	}
	if err := raiseWorkloadLimit(unix.RLIMIT_NPROC, workloadNprocFloor); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// raiseWorkloadLimit raises one resource to at least floor, capped at
// workloadLimitCeil and never below the current hard limit unless that limit
// is unlimited or above the cap. The soft limit is set to the hard limit so a
// workload can use and raise up to it.
func raiseWorkloadLimit(resource int, floor uint64) error {
	var cur unix.Rlimit
	if err := unix.Getrlimit(resource, &cur); err != nil {
		return err
	}
	hard := cur.Max
	if hard == unix.RLIM_INFINITY || hard > workloadLimitCeil {
		hard = workloadLimitCeil
	}
	if hard < floor {
		hard = floor
	}
	if cur.Cur == hard && cur.Max == hard {
		return nil
	}
	return unix.Setrlimit(resource, &unix.Rlimit{Cur: hard, Max: hard})
}
