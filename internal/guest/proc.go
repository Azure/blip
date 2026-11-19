package guest

import (
	"fmt"
	"os"
	"os/signal"
	"path"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/Azure/blip/internal/podapi"
)

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

// procSpec describes a workload process.
type procSpec struct {
	argv []string // empty: login shell
	env  []string
	dir  string
	user string
	tty  bool
	rows uint16
	cols uint16
	// stdinEOF gives a non-TTY process an immediately closed stdin instead
	// of a pipe that stays open for its whole lifetime. The primary command
	// has no client that could feed it or send EOF, so without this `cat`
	// waits forever. Exec sessions keep the pipe: their client uploads stdin
	// and forwards its own end of input.
	stdinEOF bool
}

// procStdin returns the child's stdin and the parent-side writer. For a
// non-interactive primary command both are /dev/null, so reads see EOF and
// stdin a client sends is discarded instead of blocking. Otherwise the child
// reads from a pipe whose write end the session owns.
func procStdin(stdinEOF bool) (child, parent *os.File, err error) {
	if stdinEOF {
		child, err = os.Open(os.DevNull)
		if err != nil {
			return nil, nil, err
		}
		parent, err = os.OpenFile(os.DevNull, os.O_WRONLY, 0)
		if err != nil {
			child.Close()
			return nil, nil, err
		}
		return child, parent, nil
	}
	child, parent, err = os.Pipe()
	return child, parent, err
}

// proc is a running workload process and the host side of its stdio.
type proc struct {
	pid    int
	wait   <-chan unix.WaitStatus
	tty    *os.File // PTY master when tty
	stdin  *os.File // pipe when !tty
	stdout *os.File
	stderr *os.File
}

// workdirInRoot returns dir as an absolute path inside the workload root.
// os.StartProcess resolves ProcAttr.Dir relative to the guest init's cwd,
// which is outside the root after chroot, so a relative workdir has to be
// anchored at the root first. path.Clean clamps ".." at "/", so a workdir can
// never escape the root.
func workdirInRoot(dir string) string {
	if dir == "" {
		return "/"
	}
	if !path.IsAbs(dir) {
		dir = "/" + dir
	}
	return path.Clean(dir)
}

// checkDirAccess verifies that the target account can search every component
// of dir inside root. Without this, os.StartProcess fails in the child with
// "fork/exec <program>: permission denied", which makes an inaccessible
// working directory look like a missing or unexecutable program.
func checkDirAccess(root, dir string, acct *account) error {
	if acct.uid == 0 {
		return nil
	}
	p := "/"
	for _, part := range strings.Split(strings.TrimPrefix(dir, "/"), "/") {
		if part == "" {
			continue
		}
		p = path.Join(p, part)
		fi, err := statInRoot(root, p)
		if err != nil {
			return fmt.Errorf("chdir %s: %w", dir, err)
		}
		if !fi.IsDir() {
			return fmt.Errorf("chdir %s: %w", dir, unix.ENOTDIR)
		}
		if !canSearchDir(fi, acct) {
			return fmt.Errorf("chdir %s: %w for uid %d", dir, unix.EACCES, acct.uid)
		}
	}
	return nil
}

// canSearchDir reports whether acct has execute (search) permission on the
// directory, matching the kernel's owner/group/other rule.
func canSearchDir(fi os.FileInfo, acct *account) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		// Without ownership information, leave the decision to the kernel.
		return true
	}
	mode := fi.Mode().Perm()
	switch {
	case acct.uid == st.Uid:
		return mode&0o100 != 0
	case slices.Contains(acct.groups, st.Gid):
		return mode&0o010 != 0
	default:
		return mode&0o001 != 0
	}
}

// startProc starts a process chrooted in the root filesystem, as the
// requested user, in the work cgroup, in a new session.
func (g *Guest) startProc(s procSpec, base []string) (*proc, []string, error) {
	acct, err := lookupAccount(g.root, s.user)
	if err != nil {
		return nil, nil, err
	}
	argv := s.argv
	argv0 := ""
	if len(argv) == 0 {
		argv = []string{"-" + path.Base(acct.shell)}
		argv0 = acct.shell
	}
	env := g.procEnv(acct, s, base)
	if argv0 == "" {
		if argv0, err = lookPath(g.root, argv[0], env); err != nil {
			return nil, nil, err
		}
	}
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
		return nil, nil, fmt.Errorf("chdir %s: %w", dir, err)
	} else if !fi.IsDir() {
		return nil, nil, fmt.Errorf("chdir %s: %w", dir, unix.ENOTDIR)
	}
	if err := checkDirAccess(g.root, dir, acct); err != nil {
		return nil, nil, err
	}

	p := &proc{}
	var child []*os.File
	attr := &syscall.SysProcAttr{
		Chroot:     g.root,
		Credential: &syscall.Credential{Uid: acct.uid, Gid: acct.gid, Groups: acct.groups},
		Setsid:     true,
	}
	if g.cgroupFD >= 0 {
		attr.UseCgroupFD = true
		attr.CgroupFD = g.cgroupFD
	}
	if s.tty {
		master, slave, err := openPTY()
		if err != nil {
			return nil, nil, err
		}
		_ = slave.Chown(int(acct.uid), int(acct.gid))
		rows, cols := s.rows, s.cols
		if rows == 0 || cols == 0 {
			rows, cols = 24, 80
		}
		setWinsize(master, rows, cols)
		p.tty = master
		child = []*os.File{slave, slave, slave}
		attr.Setctty = true
		attr.Ctty = 0
	} else {
		inR, inW, err := procStdin(s.stdinEOF)
		if err != nil {
			return nil, nil, err
		}
		outR, outW, _ := os.Pipe()
		errR, errW, _ := os.Pipe()
		p.stdin, p.stdout, p.stderr = inW, outR, errR
		child = []*os.File{inR, outW, errW}
	}
	pid, wait, err := g.reaper.start(argv0, argv, &os.ProcAttr{Dir: dir, Env: env, Files: child, Sys: attr})
	for _, f := range child {
		f.Close()
	}
	if err != nil {
		p.close()
		return nil, nil, fmt.Errorf("start %s: %w", argv[0], err)
	}
	p.pid, p.wait = pid, wait
	return p, argv, nil
}

// procEnv supplies the same defaults to the primary command and later exec
// sessions, regardless of their user. Explicit workload values take priority.
func (g *Guest) procEnv(acct *account, s procSpec, base []string) []string {
	env := []string{
		"PATH=" + defaultPath,
		"HOME=" + acct.home,
		"USER=" + acct.name,
		"LOGNAME=" + acct.name,
		"SHELL=" + acct.shell,
	}
	if s.tty {
		env = append(env, "TERM=xterm-256color")
	}
	if g.kubeNamespace != "" {
		env = append(env, "KUBECONFIG="+kubeconfigPath)
	}
	// Guest-local names are resolved through /etc/hosts and must not go
	// through a workload's HTTP proxy.
	noProxy := []string{"blip"}
	if g.kubeNamespace != "" {
		noProxy = append(noProxy, "kube-apiserver")
	}
	noProxy = append(noProxy, g.endpoints...)
	// Reserved variables are applied after every caller-supplied list, so an
	// exec caller's -e (s.env) cannot redirect a guest-owned service or drop
	// the guest-local proxy bypass.
	return mergeEnv(env, base, s.env, reservedEnv(), proxyEnv(noProxy, base, s.env))
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

// reservedEnv is the environment the guest owns. Callers, including exec -e,
// may not override it: BLIP_REPORT_URL must always point at the guest's
// loopback report endpoint.
func reservedEnv() []string {
	return []string{podapi.ReportEnv + "=" + podapi.ReportURL}
}

func (p *proc) close() {
	for _, f := range []*os.File{p.tty, p.stdin, p.stdout, p.stderr} {
		if f != nil {
			f.Close()
		}
	}
}

func openPTY() (*os.File, *os.File, error) {
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		return nil, nil, err
	}
	// Fd() would switch the master to blocking mode; use the raw conn.
	var n int
	err = withFD(master, func(fd int) error {
		if err := unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0); err != nil {
			return err
		}
		var err error
		n, err = unix.IoctlGetInt(fd, unix.TIOCGPTN)
		return err
	})
	if err != nil {
		master.Close()
		return nil, nil, err
	}
	slave, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		master.Close()
		return nil, nil, err
	}
	return master, slave, nil
}

func setWinsize(f *os.File, rows, cols uint16) {
	_ = withFD(f, func(fd int) error {
		return unix.IoctlSetWinsize(fd, unix.TIOCSWINSZ, &unix.Winsize{Row: rows, Col: cols})
	})
}

func withFD(f *os.File, fn func(fd int) error) error {
	rc, err := f.SyscallConn()
	if err != nil {
		return err
	}
	var ferr error
	if err := rc.Control(func(fd uintptr) { ferr = fn(int(fd)) }); err != nil {
		return err
	}
	return ferr
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

func parseSignal(name string) (unix.Signal, error) {
	if len(name) < 3 || name[:3] != "SIG" {
		name = "SIG" + name
	}
	s := unix.SignalNum(name)
	if s == 0 {
		return 0, fmt.Errorf("unknown signal %q", name)
	}
	return s, nil
}
