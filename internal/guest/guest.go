package guest

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Azure/blip/internal/wire"
	"golang.org/x/sys/unix"
)

const (
	// RootDir is where the claimed root filesystem is mounted.
	RootDir = "/mnt/root"
	// WorkCgroup holds every workload process.
	WorkCgroup = "/sys/fs/cgroup/work"
	// stopGrace is how long processes get between SIGTERM and cgroup.kill.
	stopGrace = 10 * time.Second
)

// Guest is the state of the VM's init process.
type Guest struct {
	root          string
	cgroup        string
	cgroupFD      int
	reaper        *reaper
	kubeNamespace string
	api           *apiForwarder
	gateway       *apiForwarder

	mu         sync.Mutex
	ctl        *wire.Conn
	ctlFile    *os.File
	ctlGone    chan struct{} // closed when ctl disconnects
	claim      *wire.Claim
	rootDev    string
	mounts     map[string]*mount // auxiliary mounts by ID
	sessions   map[string]*session
	clients    int
	lastActive time.Time // last client attach or session start; resets idle
	exit       *wire.Exit
	stopping   bool

	// fmu guards frozen. It is taken after mu, never before, and nothing
	// that can block on a frozen filesystem runs under it, so the
	// auto-thaw (which takes only fmu) cannot be blocked by a frozen fs.
	fmu    sync.Mutex
	frozen map[string]*frozenFS // frozen filesystems by disk ID
}

type mount struct {
	id     string
	path   string // path inside the root
	target string // guest path
}

func newGuest(root, cgroup string) *Guest {
	g := &Guest{
		root:     root,
		cgroup:   cgroup,
		cgroupFD: -1,
		reaper:   newReaper(),
		mounts:   map[string]*mount{},
		frozen:   map[string]*frozenFS{},
		sessions: map[string]*session{},
	}
	if fd, err := unix.Open(cgroup, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0); err == nil {
		g.cgroupFD = fd
	}
	return g
}

// Main runs blip-guest as PID 1. It never returns.
func Main() {
	log.SetFlags(log.Lmicroseconds)
	log.SetPrefix("blip-guest: ")
	if !isInit() {
		log.Fatal("blip-guest must run as PID 1")
	}
	bootMounts()
	loadModules("/lib/modules")
	cfg, err := readConfig()
	if err != nil {
		log.Printf("config: %v", err)
		powerOff()
	}
	if cfg.Hostname != "" {
		_ = unix.Sethostname([]byte(cfg.Hostname))
	}
	if err := setupNetwork(cfg); err != nil {
		log.Printf("network: %v", err)
		if cfg.KubeNamespace != "" {
			powerOff()
		}
	}
	g := newGuest(RootDir, WorkCgroup)
	g.kubeNamespace = cfg.KubeNamespace
	if cfg.KubeNamespace != "" {
		g.api, err = startAPIForwarder(8001, dialHostAPI)
		if err != nil {
			log.Printf("listen Kubernetes API: %v", err)
			powerOff()
		}
	}
	if cfg.GatewayLoopbackPort > 0 {
		g.gateway, err = startGatewayForwarder(cfg.GatewayLoopbackPort, dialHostGateway)
		if err != nil {
			log.Printf("listen gateway: %v", err)
			powerOff()
		}
	}
	ctl, err := listenVsock(wire.ControlPort)
	if err != nil {
		log.Printf("listen control port: %v", err)
		powerOff()
	}
	sess, err := listenVsock(wire.SessionPort)
	if err != nil {
		log.Printf("listen session port: %v", err)
		powerOff()
	}
	go g.accept(sess, g.serveSession)
	go g.idleLoop()
	log.Printf("ready")
	g.accept(ctl, g.serveControl)
	powerOff()
}

func (g *Guest) accept(lfd int, serve func(*os.File)) {
	for {
		f, err := acceptVsock(lfd)
		if err != nil {
			log.Printf("accept: %v", err)
			return
		}
		go serve(f)
	}
}

func (g *Guest) helloLocked() wire.Hello {
	h := wire.Hello{Version: wire.Version, Exit: g.exit}
	if g.claim != nil {
		h.ClaimID = g.claim.ID
	}
	for id := range g.mounts {
		h.Mounts = append(h.Mounts, id)
	}
	sort.Strings(h.Mounts)
	h.Frozen = g.frozenIDs()
	return h
}

// serveControl serves the runtime. A new connection replaces the previous
// one; Hello tells the runtime the current state.
func (g *Guest) serveControl(f *os.File) {
	c := wire.NewConn(f)
	gone := make(chan struct{})
	g.mu.Lock()
	if g.ctlFile != nil {
		g.ctlFile.Close()
	}
	g.ctl, g.ctlFile, g.ctlGone = c, f, gone
	hello := g.helloLocked()
	err := c.WriteJSON(wire.THello, hello)
	if err == nil {
		err = c.WriteJSON(wire.TStatus, wire.Status{Sessions: g.clients})
	}
	g.mu.Unlock()
	defer func() {
		g.mu.Lock()
		if g.ctl == c {
			g.ctl, g.ctlFile = nil, nil
		}
		g.mu.Unlock()
		f.Close()
		close(gone)
	}()
	if err != nil {
		return
	}
	for {
		t, payload, err := c.Read()
		if err != nil {
			return
		}
		switch t {
		case wire.TClaim:
			var m wire.Claim
			err := wire.Decode(payload, &m)
			if err == nil {
				err = g.doClaim(m)
			}
			_ = c.WriteJSON(wire.TClaimResult, wire.Result{ID: m.ID, Error: errString(err)})
			if err != nil {
				break
			}
			var failed error
			for _, mt := range m.Mounts {
				err := g.doMount(mt)
				_ = c.WriteJSON(wire.TMountResult, wire.Result{ID: mt.ID, Error: errString(err)})
				if err != nil && failed == nil {
					failed = fmt.Errorf("mount %s: %w", mt.Path, err)
				}
			}
			if failed != nil {
				g.failPrimary(failed)
			} else {
				g.startPrimary()
			}
		case wire.TMount:
			var m wire.Mount
			err := wire.Decode(payload, &m)
			if err == nil {
				err = g.doMount(m)
			}
			_ = c.WriteJSON(wire.TMountResult, wire.Result{ID: m.ID, Error: errString(err)})
		case wire.TUnmount:
			var m wire.Unmount
			err := wire.Decode(payload, &m)
			if err == nil {
				err = g.doUnmount(m.ID)
			}
			_ = c.WriteJSON(wire.TUnmountResult, wire.Result{ID: m.ID, Error: errString(err)})
		case wire.TFreeze, wire.TThaw:
			var m wire.Freeze
			err := wire.Decode(payload, &m)
			if err == nil {
				if t == wire.TFreeze {
					err = g.doFreeze(m.ID)
				} else {
					err = g.doThaw(m.ID)
				}
			}
			g.fmu.Lock()
			frozen := g.frozen[m.ID] != nil
			g.fmu.Unlock()
			_ = c.WriteJSON(wire.TFreezeResult, wire.FreezeResult{ID: m.ID, Frozen: frozen, Error: errString(err)})
		case wire.TShutdown:
			go g.shutdown()
		}
	}
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// send writes a control frame to the runtime if it is connected.
func (g *Guest) send(t wire.Type, v any) {
	g.mu.Lock()
	c := g.ctl
	g.mu.Unlock()
	if c != nil {
		if err := c.WriteJSON(t, v); err != nil {
			log.Printf("control write: %v", err)
		}
	}
}

func (g *Guest) addClients(n int) {
	g.mu.Lock()
	g.clients += n
	g.lastActive = time.Now()
	st := wire.Status{Sessions: g.clients}
	g.mu.Unlock()
	g.send(wire.TStatus, st)
}

func (g *Guest) sessionList() []wire.SessionInfo {
	g.mu.Lock()
	ss := make([]*session, 0, len(g.sessions))
	for _, s := range g.sessions {
		ss = append(ss, s)
	}
	g.mu.Unlock()
	out := make([]wire.SessionInfo, 0, len(ss))
	for _, s := range ss {
		out = append(out, s.info())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (g *Guest) doClaim(m wire.Claim) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.claim != nil {
		if g.claim.ID == m.ID {
			return nil
		}
		return fmt.Errorf("already claimed by %s", g.claim.ID)
	}
	if g.stopping {
		return errors.New("guest is stopping")
	}
	if g.kubeNamespace != "" && (g.api == nil || !g.api.ready()) {
		return errors.New("Kubernetes API forwarding is unavailable")
	}
	if g.gateway != nil && !g.gateway.ready() {
		return errors.New("gateway forwarding is unavailable")
	}
	if !isInit() {
		return errNotInit
	}
	start := time.Now()
	dev, err := findBlock(m.Serial, 10*time.Second)
	if err != nil {
		return err
	}
	found := time.Since(start)
	if err := unix.Mount(dev, g.root, "ext4", 0, ""); err != nil {
		return fmt.Errorf("mount root %s: %w", dev, err)
	}
	g.rootDev = dev
	if err := g.setupRootLocked(m); err != nil {
		g.unmountRootLocked()
		return err
	}
	if m.Hostname != "" {
		_ = unix.Sethostname([]byte(m.Hostname))
	}
	claim := m
	g.claim = &claim
	log.Printf("claimed %s (disk found after %v, ready after %v)", m.ID, found.Round(time.Millisecond), time.Since(start).Round(time.Millisecond))
	return nil
}

// setupRootLocked mounts the pseudo filesystems, resolv.conf and hosts inside
// the freshly mounted root.
func (g *Guest) setupRootLocked(m wire.Claim) error {
	type sysMount struct {
		src, dst, fstype string
		flags            uintptr
		data             string
	}
	for _, x := range []sysMount{
		{"proc", "/proc", "proc", unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC, ""},
		{"sysfs", "/sys", "sysfs", unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC, ""},
		{"/dev", "/dev", "", unix.MS_BIND, ""},
		{"/dev/pts", "/dev/pts", "", unix.MS_BIND, ""},
		{"/dev/shm", "/dev/shm", "", unix.MS_BIND, ""},
		{"tmpfs", "/run", "tmpfs", unix.MS_NOSUID | unix.MS_NODEV, "mode=0755"},
	} {
		if _, err := g.mountInRootLocked(x.src, x.dst, x.fstype, x.flags, x.data); err != nil {
			return err
		}
	}
	if fd, err := mkdirInRoot(g.root, "/tmp", true); err == nil {
		_ = unix.Fchmodat(fd, "", 0o1777, unix.AT_EMPTY_PATH)
		unix.Close(fd)
	}
	for _, f := range []string{"/etc/resolv.conf", "/etc/hosts"} {
		if err := g.bindFileLocked(f); err != nil {
			log.Printf("bind %s: %v", f, err)
		}
	}
	// Resolve the sandbox name locally. Without this, sudo (and anything else
	// that looks up the host name) prints "unable to resolve host" on every
	// command.
	if err := g.writeHostsLocked(m.Hostname); err != nil {
		log.Printf("write /etc/hosts: %v", err)
	}
	if err := g.installKubeConfigLocked(); err != nil {
		return fmt.Errorf("Kubernetes API config: %w", err)
	}
	return nil
}

// hostsFile is the /etc/hosts content for a claimed blip. The host entry uses
// 127.0.1.1 (the Debian convention) so name lookups resolve without a DNS
// round trip.
func hostsFile(hostname string) string {
	var b strings.Builder
	b.WriteString("127.0.0.1 localhost\n")
	if hostname != "" && !strings.ContainsAny(hostname, " \t\r\n") {
		fmt.Fprintf(&b, "127.0.1.1 %s\n", hostname)
	}
	b.WriteString("::1 localhost ip6-localhost ip6-loopback\n")
	return b.String()
}

// writeHostsLocked replaces the guest's /etc/hosts (a bind mount of the
// initramfs file) with content that resolves the blip's host name.
func (g *Guest) writeHostsLocked(hostname string) error {
	fd, err := openFileInRootWritable(g.root, "/etc/hosts")
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), "/etc/hosts")
	defer f.Close()
	if err := f.Truncate(0); err != nil {
		return err
	}
	_, err = f.WriteAt([]byte(hostsFile(hostname)), 0)
	return err
}

// mountInRootLocked mounts at dst inside the root (symlinks resolved inside
// the root) and returns the guest path of the mount point.
func (g *Guest) mountInRootLocked(src, dst, fstype string, flags uintptr, data string) (string, error) {
	fd, err := mkdirInRoot(g.root, dst, true)
	if err != nil {
		return "", err
	}
	defer unix.Close(fd)
	target, err := fdPath(fd)
	if err != nil {
		return "", err
	}
	if err := unix.Mount(src, fmt.Sprintf("/proc/self/fd/%d", fd), fstype, flags, data); err != nil {
		return "", fmt.Errorf("mount %s: %w", dst, err)
	}
	return target, nil
}

func (g *Guest) bindFileLocked(p string) error {
	fd, err := openFileInRoot(g.root, p)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	return unix.Mount(p, fmt.Sprintf("/proc/self/fd/%d", fd), "", unix.MS_BIND, "")
}

func (g *Guest) startPrimary() {
	g.mu.Lock()
	claim := g.claim
	_, started := g.sessions[wire.PrimarySession]
	g.mu.Unlock()
	if claim == nil || len(claim.Command) == 0 || started {
		return
	}
	spec := procSpec{argv: claim.Command, dir: claim.WorkingDir, user: claim.User, tty: claim.TTY}
	if _, err := g.startSession(wire.PrimarySession, spec, claim.Env, false); err != nil {
		log.Printf("start primary: %v", err)
		g.failedSession(wire.PrimarySession, claim.Command, err)
	}
}

// failPrimary records a primary command that could not start.
func (g *Guest) failPrimary(err error) {
	g.mu.Lock()
	claim := g.claim
	_, started := g.sessions[wire.PrimarySession]
	g.mu.Unlock()
	if claim == nil || len(claim.Command) == 0 || started {
		log.Printf("claim: %v", err)
		return
	}
	g.failedSession(wire.PrimarySession, claim.Command, err)
}

// sessionExited ends a command blip when its primary command exits.
func (g *Guest) sessionExited(s *session) {
	if s.id != wire.PrimarySession {
		return
	}
	g.mu.Lock()
	g.lastActive = time.Now()
	if g.stopping || g.exit != nil {
		g.mu.Unlock()
		return
	}
	st := s.status
	st.Reason = "Completed"
	if st.Code != 0 || st.Signal != "" {
		st.Output = s.tail(exitOutputMax)
	}
	g.exit = &st
	g.mu.Unlock()
	log.Printf("primary exited: code %d %s", st.Code, st.Signal)
	g.send(wire.TExit, st)
	go func() {
		// A caller can be delayed by the API watch while a very fast
		// command already ran. Keep the replay available so it can still
		// attach and read the output.
		s.waitDelivered(30*time.Second, 30*time.Second)
		g.shutdown()
	}()
}

// idleLoop ends an interactive blip when nothing is attached and the work
// cgroup is empty for the claim's idle timeout.
func (g *Guest) idleLoop() {
	for range time.Tick(time.Second) {
		g.mu.Lock()
		c := g.claim
		idle := c != nil && len(c.Command) == 0 && c.IdleTimeoutSeconds > 0 &&
			g.clients == 0 && !g.stopping && g.exit == nil && cgroupEmpty(g.cgroup)
		now := time.Now()
		if !idle {
			// Also refresh while busy: a command that starts and ends
			// between ticks still resets the idle clock.
			g.lastActive = now
			g.mu.Unlock()
			continue
		}
		if g.lastActive.IsZero() {
			g.lastActive = now
		}
		if now.Sub(g.lastActive) < time.Duration(c.IdleTimeoutSeconds)*time.Second {
			g.mu.Unlock()
			continue
		}
		g.exit = &wire.Exit{Reason: "Idle"}
		ex := *g.exit
		g.mu.Unlock()
		log.Printf("idle for %ds; shutting down", c.IdleTimeoutSeconds)
		g.send(wire.TExit, ex)
		g.shutdown()
		return
	}
}

func cgroupEmpty(cg string) bool {
	b, err := os.ReadFile(filepath.Join(cg, "cgroup.procs"))
	return err == nil && len(strings.TrimSpace(string(b))) == 0
}

// shutdown stops all work, unmounts everything, reports, and powers off.
func (g *Guest) shutdown() {
	g.mu.Lock()
	if g.stopping {
		g.mu.Unlock()
		return
	}
	g.stopping = true
	// Frozen filesystems would block the workload's exit and the unmounts.
	if err := g.thawAll(); err != nil {
		log.Printf("shutdown: %v", err)
	}
	g.mu.Unlock()
	log.Printf("shutting down")
	stopWork(g.cgroup, stopGrace)
	if g.api != nil {
		g.api.Close()
	}
	if g.gateway != nil {
		g.gateway.Close()
	}
	g.mu.Lock()
	err := g.unmountAllLocked()
	gone := g.ctlGone
	g.mu.Unlock()
	if isInit() {
		unix.Sync()
	}
	if err != nil {
		log.Printf("shutdown: %v", err)
	}
	g.send(wire.TShutdownDone, wire.ShutdownDone{Clean: err == nil, Error: errString(err)})
	// Give the runtime a moment to read ShutdownDone and hang up.
	if gone != nil {
		select {
		case <-gone:
		case <-time.After(2 * time.Second):
		}
	}
	powerOff()
}

// stopWork terminates every process in the work cgroup: SIGTERM, up to grace
// to exit, then cgroup.kill. It is a no-op unless this process is PID 1.
func stopWork(cg string, grace time.Duration) {
	if !isInit() {
		log.Printf("not PID 1; skipping stop of %s", cg)
		return
	}
	for _, pid := range cgroupPIDs(cg) {
		_ = unix.Kill(pid, unix.SIGTERM)
	}
	if waitEmpty(cg, grace) {
		return
	}
	if err := os.WriteFile(filepath.Join(cg, "cgroup.kill"), []byte("1"), 0); err != nil {
		log.Printf("cgroup.kill: %v", err)
	}
	if !waitEmpty(cg, 5*time.Second) {
		log.Printf("processes left in %s after cgroup.kill", cg)
	}
}

func waitEmpty(cg string, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for !cgroupEmpty(cg) {
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(20 * time.Millisecond)
	}
	return true
}

func cgroupPIDs(cg string) []int {
	b, _ := os.ReadFile(filepath.Join(cg, "cgroup.procs"))
	var pids []int
	for _, f := range strings.Fields(string(b)) {
		var pid int
		if _, err := fmt.Sscan(f, &pid); err == nil && pid > 1 {
			pids = append(pids, pid)
		}
	}
	return pids
}

// unmountAllLocked unmounts auxiliary mounts (deepest first), then the root
// and everything inside it. No lazy unmounts.
func (g *Guest) unmountAllLocked() error {
	if err := g.thawAll(); err != nil {
		return err
	}
	var errs []error
	aux := make([]*mount, 0, len(g.mounts))
	for _, m := range g.mounts {
		aux = append(aux, m)
	}
	sort.Slice(aux, func(i, j int) bool { return len(aux[i].path) > len(aux[j].path) })
	for _, m := range aux {
		if err := unmount(m.target, 25); err != nil {
			errs = append(errs, err)
			continue
		}
		delete(g.mounts, m.id)
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return g.unmountRootLocked()
}

// unmountRootLocked unmounts every mount at or below the root, newest first.
// This includes mounts made by workloads inside the VM.
func (g *Guest) unmountRootLocked() error {
	if g.rootDev == "" {
		return nil
	}
	targets := mountsUnder(g.root)
	for i := len(targets) - 1; i >= 0; i-- {
		if err := unmount(targets[i], 25); err != nil {
			return err
		}
	}
	g.rootDev = ""
	return nil
}

// mountsUnder returns the mount points at or below dir in mount order.
func mountsUnder(dir string) []string {
	b, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return nil
	}
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) < 5 {
			continue
		}
		mp := unescapeMountinfo(f[4])
		if mp == dir || strings.HasPrefix(mp, dir+"/") {
			out = append(out, mp)
		}
	}
	return out
}

func unescapeMountinfo(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			var v int
			if _, err := fmt.Sscanf(s[i+1:i+4], "%o", &v); err == nil {
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func (g *Guest) doMount(m wire.Mount) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if cur := g.mounts[m.ID]; cur != nil {
		if cur.path == filepath.Clean(m.Path) {
			return nil
		}
		return fmt.Errorf("%s is already mounted at %s", m.ID, cur.path)
	}
	if g.claim == nil || g.stopping {
		return errors.New("blip is not running")
	}
	// Creating the mount point would block on a frozen filesystem while
	// holding mu; freezes are brief and the runtime retries mounts.
	if g.anyFrozen() {
		return errors.New("a filesystem is frozen")
	}
	var existing []string
	for _, x := range g.mounts {
		existing = append(existing, x.path)
	}
	if err := checkMountPath(m.Path, existing); err != nil {
		return err
	}
	p := filepath.Clean(m.Path)
	if !isInit() {
		return errNotInit
	}
	dev, err := findBlock(m.Serial, 10*time.Second)
	if err != nil {
		return err
	}
	fd, err := mkdirInRoot(g.root, p, false)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	target, err := fdPath(fd)
	if err != nil {
		return err
	}
	var flags uintptr
	data := ""
	if m.ReadOnly {
		flags, data = unix.MS_RDONLY, "noload"
	}
	if err := unix.Mount(dev, fmt.Sprintf("/proc/self/fd/%d", fd), "ext4", flags, data); err != nil {
		return fmt.Errorf("mount %s at %s: %w", dev, p, err)
	}
	g.mounts[m.ID] = &mount{id: m.ID, path: p, target: target}
	if !m.ReadOnly {
		if a, err := lookupAccount(g.root, g.claim.User); err == nil {
			adoptEmpty(target, a.uid, a.gid)
		}
	}
	log.Printf("mounted %s at %s", m.ID, p)
	return nil
}

// adoptEmpty gives a new, empty filesystem to the blip's user so that
// non-root commands can write to it.
func adoptEmpty(dir string, uid, gid uint32) {
	var st unix.Stat_t
	if uid == 0 || unix.Stat(dir, &st) != nil || st.Uid != 0 {
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.Name() != "lost+found" {
			return
		}
	}
	_ = os.Chown(dir, int(uid), int(gid))
}

func (g *Guest) doUnmount(id string) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	m := g.mounts[id]
	if m == nil {
		return nil
	}
	if err := g.doThaw(id); err != nil {
		return err
	}
	if g.anyFrozen() {
		return errors.New("a filesystem is frozen")
	}
	if err := unmount(m.target, 1); err != nil {
		return err
	}
	delete(g.mounts, id)
	log.Printf("unmounted %s from %s", id, m.path)
	return nil
}
