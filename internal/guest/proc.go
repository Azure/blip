// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package guest

import (
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

// startError is a failure before the command ran, carrying the conventional
// shell status: 127 when the command was not found and 126 when it exists but
// cannot be executed (EACCES, ENOEXEC, a bad workdir, or another start-time
// configuration failure). Without it every start failure reported 127, which
// is indistinguishable from a command that ran and exited 1.
type startError struct {
	code int
	err  error
}

func (e *startError) Error() string { return e.err.Error() }
func (e *startError) Unwrap() error { return e.err }

func startFail(code int, err error) error { return &startError{code: code, err: err} }

// startExitCode returns the conventional status for a command that could not
// start. A failure that is not attributable to command lookup prevents
// execution, which is 126.
func startExitCode(err error) int {
	var se *startError
	if errors.As(err, &se) {
		return se.code
	}
	return 126
}

// classifyStart maps an error from os.StartProcess to 127 only when the
// command does not exist; execution errors are 126.
func classifyStart(err error) int {
	if errors.Is(err, unix.ENOENT) {
		return 127
	}
	return 126
}

// reaper reaps every child (as PID 1 it also inherits orphans) and delivers
// exit statuses to registered waiters. Processes are only started through
// reaper.start so a status can never arrive before its waiter exists.
type reaper struct {
	mu      sync.Mutex
	waiters map[int]chan unix.WaitStatus
}

func newReaper() *reaper {
	r := &reaper{waiters: map[int]chan unix.WaitStatus{}}
	sig := make(chan os.Signal, 16)
	signal.Notify(sig, unix.SIGCHLD)
	go func() {
		t := time.NewTicker(time.Second)
		for {
			select {
			case <-sig:
			case <-t.C:
			}
			r.reap()
		}
	}()
	return r
}

func (r *reaper) reap() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if os.Getpid() != 1 {
		// Only init inherits orphans. Reaping every child elsewhere would
		// steal the status of processes this reaper did not start, such as
		// a test subprocess.
		for pid := range r.waiters {
			var ws unix.WaitStatus
			got, err := unix.Wait4(pid, &ws, unix.WNOHANG, nil)
			if err != nil || got != pid {
				continue
			}
			r.waiters[pid] <- ws
			delete(r.waiters, pid)
		}
		return
	}
	for {
		var ws unix.WaitStatus
		pid, err := unix.Wait4(-1, &ws, unix.WNOHANG, nil)
		if err == unix.EINTR {
			continue
		}
		if pid <= 0 || err != nil {
			return
		}
		if ch, ok := r.waiters[pid]; ok {
			ch <- ws
			delete(r.waiters, pid)
		}
	}
}

func (r *reaper) start(argv0 string, argv []string, attr *os.ProcAttr) (int, <-chan unix.WaitStatus, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	p, err := os.StartProcess(argv0, argv, attr)
	if err != nil {
		return 0, nil, err
	}
	ch := make(chan unix.WaitStatus, 1)
	r.waiters[p.Pid] = ch
	pid := p.Pid
	_ = p.Release()
	return pid, ch, nil
}

// procSpec describes the primary workload command.
type procSpec struct {
	argv []string
	dir  string
	user string
}

// proc is a running workload process and the host side of its stdio.
type proc struct {
	wait   <-chan unix.WaitStatus
	stdin  *os.File // pipe the guest writes to
	stdout *os.File // pipe the guest reads from
	stderr *os.File
}

// workdirInRoot returns dir as an absolute path inside the workload root.
// os.StartProcess resolves ProcAttr.Dir relative to the guest init's cwd,
// which is outside the root after chroot, so a relative workdir has to be
// anchored at the root first. The path is deliberately not cleaned: chdir(2)
// follows symlinks before resolving "..", so cleaning "/tmp/link/../other"
// lexically would enter a different directory than the caller asked for. ".."
// still cannot escape the root because the process's root is the chroot.
func workdirInRoot(dir string) string {
	if dir == "" {
		return "/"
	}
	if !path.IsAbs(dir) {
		return "/" + dir
	}
	return dir
}

// checkDirAccess verifies that the target account can search every directory
// the kernel traverses to reach dir inside root. Without this, os.StartProcess
// fails in the child with "fork/exec <program>: permission denied", which
// makes an inaccessible working directory look like a missing or unexecutable
// program.
//
// The walk follows the path as written, resolving each cumulative prefix the
// way chdir(2) does. Checking only the canonical components is not enough: in
// "/locked/../real" the kernel must search /locked before ".." removes it from
// the canonical path, so an account can be denied even though the resolved
// workdir is searchable. Resolving each prefix also covers directories that a
// symlink points through, since every prefix is resolved before it is checked.
func checkDirAccess(root, dir string, acct *account) error {
	if acct.uid == 0 {
		return nil
	}
	prefixes := []string{"/"}
	var parts []string
	for _, part := range strings.Split(strings.TrimPrefix(dir, "/"), "/") {
		if part == "" || part == "." {
			continue
		}
		parts = append(parts, part)
		prefixes = append(prefixes, "/"+strings.Join(parts, "/"))
	}
	checked := map[string]bool{}
	for _, prefix := range prefixes {
		resolved, err := resolveInRoot(root, prefix)
		if err != nil {
			return fmt.Errorf("chdir %s: %w", dir, err)
		}
		for _, p := range resolvedDirs(resolved) {
			if checked[p] {
				continue
			}
			checked[p] = true
			if err := checkSearchable(root, p, acct); err != nil {
				return fmt.Errorf("chdir %s: %w", dir, err)
			}
		}
	}
	return nil
}

// resolvedDirs returns the canonical directory paths on resolved, starting at
// the root.
func resolvedDirs(resolved string) []string {
	dirs := []string{"/"}
	p := "/"
	for _, part := range strings.Split(strings.TrimPrefix(resolved, "/"), "/") {
		if part == "" {
			continue
		}
		p = path.Join(p, part)
		dirs = append(dirs, p)
	}
	return dirs
}

// checkSearchable verifies that acct may search directory p inside root.
func checkSearchable(root, p string, acct *account) error {
	fi, err := statInRoot(root, p)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return unix.ENOTDIR
	}
	err = checkAccess(root, p, unix.X_OK, acct)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, errAccessUnavailable):
		// Kernels without faccessat2 or a process that cannot switch to
		// acct's credentials: use the mode-bit approximation.
		if canSearchDir(fi, acct) {
			return nil
		}
	case !errors.Is(err, unix.EACCES):
		return err
	}
	return fmt.Errorf("%w for uid %d", unix.EACCES, acct.uid)
}

// canSearchDir reports whether acct has execute (search) permission on the
// directory under the owner/group/other rule. It is the fallback for kernels
// without faccessat2; checkAccess is authoritative because it also accounts
// for POSIX ACLs.
func canSearchDir(fi os.FileInfo, acct *account) bool {
	return canAccess(fi, acct, 0o100, 0o010, 0o001)
}

// canExecFile reports whether acct may execute the file under the
// owner/group/other rule. Root still needs at least one execute bit set, like
// the kernel. It is the fallback for kernels without faccessat2; checkAccess
// is authoritative because it also accounts for POSIX ACLs.
func canExecFile(fi os.FileInfo, acct *account) bool {
	if acct.uid == 0 {
		return fi.Mode().Perm()&0o111 != 0
	}
	return canAccess(fi, acct, 0o100, 0o010, 0o001)
}

// canAccess applies the owner/group/other rule with the given permission bits.
func canAccess(fi os.FileInfo, acct *account, owner, group, other os.FileMode) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		// Without ownership information, leave the decision to the kernel.
		return true
	}
	mode := fi.Mode().Perm()
	switch {
	case acct.uid == st.Uid:
		return mode&owner != 0
	case slices.Contains(acct.groups, st.Gid):
		return mode&group != 0
	default:
		return mode&other != 0
	}
}

// startProc starts the primary command chrooted in the root filesystem, as
// the requested user, in the work cgroup. Its stdin and both output streams
// are pipes owned by the guest.
func (g *Guest) startProc(s procSpec, base []string) (*proc, error) {
	acct, err := lookupAccount(g.root, s.user)
	if err != nil {
		return nil, startFail(126, err)
	}
	if len(s.argv) == 0 {
		return nil, startFail(126, errors.New("empty command"))
	}
	argv := s.argv
	env := g.procEnv(acct, base)
	// Validation and start failures below are not "command not found": the
	// command may be fine but the workdir, credentials, or process setup is
	// wrong, so they use the conventional 126 instead of the old 127.
	dir := s.dir
	if dir == "" {
		dir = "/"
		if fi, err := statInRoot(g.root, acct.home); err == nil && fi.IsDir() {
			dir = acct.home
		}
	}
	// The child chdirs after chrooting, but os.StartProcess applies Dir
	// relative to the guest init's cwd (outside the root). Anchor relative
	// workdirs at the root so "tmp" means "<root>/tmp" rather than the
	// initramfs /tmp, and so getcwd(3) works inside the workload.
	dir = workdirInRoot(dir)
	// Validate the working directory before starting: a failed chdir surfaces
	// from os.StartProcess as ENOENT on the program path, which reads as if
	// the executable were missing. Stat it inside the root, like the chdir
	// will happen after chroot.
	if fi, err := statInRoot(g.root, dir); err != nil {
		return nil, startFail(126, fmt.Errorf("chdir %s: %w", dir, err))
	} else if !fi.IsDir() {
		return nil, startFail(126, fmt.Errorf("chdir %s: %w", dir, unix.ENOTDIR))
	}
	if err := checkDirAccess(g.root, dir, acct); err != nil {
		return nil, startFail(126, err)
	}
	// Resolve the command after the workdir is known: a relative PATH entry
	// is relative to the command's working directory, as in execvp.
	argv0, err := lookPath(g.root, dir, argv[0], env, acct)
	if err != nil {
		return nil, err
	}

	p := &proc{}
	var child []*os.File
	attr := &syscall.SysProcAttr{
		Chroot:     g.root,
		Credential: &syscall.Credential{Uid: acct.uid, Gid: acct.gid, Groups: acct.groups},
	}
	if g.cgroupFD >= 0 {
		attr.UseCgroupFD = true
		attr.CgroupFD = g.cgroupFD
	}
	inR, inW, err := os.Pipe()
	if err != nil {
		return nil, startFail(126, err)
	}
	outR, outW, err := os.Pipe()
	if err != nil {
		inR.Close()
		inW.Close()
		return nil, startFail(126, err)
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		inR.Close()
		inW.Close()
		outR.Close()
		outW.Close()
		return nil, startFail(126, err)
	}
	p.stdin, p.stdout, p.stderr = inW, outR, errR
	child = []*os.File{inR, outW, errW}
	_, wait, err := g.reaper.start(argv0, argv, &os.ProcAttr{Dir: dir, Env: env, Files: child, Sys: attr})
	for _, f := range child {
		f.Close()
	}
	if err != nil {
		p.close()
		return nil, startFail(classifyStart(err), fmt.Errorf("start %s: %w", argv[0], err))
	}
	p.wait = wait
	return p, nil
}

// procEnv supplies the defaults for the primary command, regardless of its
// user. Explicit workload values take priority.
func (g *Guest) procEnv(acct *account, base []string) []string {
	env := []string{
		"PATH=" + defaultPath,
		"HOME=" + acct.home,
		"USER=" + acct.name,
		"LOGNAME=" + acct.name,
		"SHELL=" + acct.shell,
	}
	env = append(env, "KUBECONFIG="+kubeconfigPath)
	// Guest-local names are resolved through /etc/hosts and must not go
	// through a workload's HTTP proxy.
	noProxy := []string{"blip", "kube-apiserver"}
	noProxy = append(noProxy, g.endpoints...)
	// The proxy bypass is applied after every caller-supplied list, so a
	// workload proxy setting can add names but can never proxy a
	// guest-local one.
	return mergeEnv(env, base, proxyEnv(noProxy, base))
}

// proxyEnv merges the guest-local names with a workload's NO_PROXY/no_proxy
// and returns both spellings applied after every caller-supplied list, so a
// workload proxy setting can add bypasses but can never proxy blip or
// kube-apiserver. Go reads NO_PROXY while other tools merge both spellings;
// keeping them identical avoids the two disagreeing inside one shell.
func proxyEnv(reserved []string, lists ...[]string) []string {
	var names []string
	seen := map[string]bool{}
	add := func(value string) {
		for _, name := range strings.Split(value, ",") {
			name = strings.TrimSpace(name)
			if name == "" || seen[name] {
				continue
			}
			seen[name] = true
			names = append(names, name)
		}
	}
	for _, name := range reserved {
		add(name)
	}
	for _, list := range lists {
		for _, kv := range list {
			if key, value, ok := strings.Cut(kv, "="); ok && (key == "NO_PROXY" || key == "no_proxy") {
				add(value)
			}
		}
	}
	merged := strings.Join(names, ",")
	return []string{"NO_PROXY=" + merged, "no_proxy=" + merged}
}

func (p *proc) close() {
	for _, f := range []*os.File{p.stdin, p.stdout, p.stderr} {
		if f != nil {
			f.Close()
		}
	}
}

// exitOf converts a wait status into a wire exit.
func exitOf(ws unix.WaitStatus) (code int, sig string) {
	if ws.Signaled() {
		return 128 + int(ws.Signal()), signalName(ws.Signal())
	}
	return ws.ExitStatus(), ""
}

func signalName(s unix.Signal) string {
	n := unix.SignalName(s)
	if len(n) > 3 {
		return n[3:]
	}
	return fmt.Sprint(int(s))
}

// maxErrorText bounds start error text kept for the host. A single client
// argument can be enormous and JSON escapes control bytes, so the stderr
// report must not grow without bound.
const maxErrorText = 4 << 10

const truncatedMarker = "... (truncated)"

// boundErrorText shortens s to maxErrorText bytes without splitting a UTF-8
// sequence. Invalid bytes are replaced only here, in the human-readable error.
func boundErrorText(s string) string {
	s = strings.ToValidUTF8(s, "\uFFFD")
	if len(s) <= maxErrorText {
		return s
	}
	limit := maxErrorText - len(truncatedMarker)
	for limit > 0 && !utf8.RuneStart(s[limit]) {
		limit--
	}
	return s[:limit] + truncatedMarker
}
