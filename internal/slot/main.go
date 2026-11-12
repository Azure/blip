// Package slot implements `blipd slot`, the entrypoint of a pool pod. It
// gives the pod IP to the guest (TAP device, tc redirect and a DHCP
// server), drops capabilities, runs Cloud Hypervisor with the metadata
// disk, copies the guest console to its stdout, marks the slot ready when
// the boot stub waits, enforces the deadline and classifies the exit
// (design section 6.4).
package slot

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/example/blip/internal/api"
	"github.com/example/blip/internal/meta"
	"github.com/example/blip/internal/slot/chapi"
	"github.com/example/blip/internal/slot/dhcp"
)

// ExitError is returned by Main when Cloud Hypervisor did not exit 0.
// cmd/blipd should exit with ExitCode().
type ExitError struct {
	Record ExitRecord
}

func (e *ExitError) Error() string {
	if e.Record.Signal != "" {
		return fmt.Sprintf("cloud-hypervisor killed by %s (%s)", e.Record.Signal, e.Record.Cause)
	}
	return fmt.Sprintf("cloud-hypervisor exited with code %d (%s)", e.Record.ExitCode, e.Record.Cause)
}

// ExitCode is the process exit code for blipd slot.
func (e *ExitError) ExitCode() int {
	if e.Record.ExitCode > 0 {
		return e.Record.ExitCode
	}
	return 1
}

// Config holds the settings of blipd slot. Each has a flag, an
// environment variable and a default.
type Config struct {
	RunDir     string // BLIP_RUN_DIR, /run/blip
	CH         string // BLIP_CH, /usr/local/bin/cloud-hypervisor
	Kernel     string // BLIP_KERNEL, /usr/share/blip/vmlinuz
	Initramfs  string // BLIP_INITRAMFS, /usr/share/blip/initramfs.cpio.gz
	Hypervisor string // BLIP_HYPERVISOR: kvm, mshv or "" (from the device present)
	DevDir     string // BLIP_DEV_DIR, /dev
	Tap        string // BLIP_TAP, blip0
	PodIface   string // BLIP_POD_IFACE, eth0
	Cmdline    string // BLIP_CMDLINE, kernel command line
	CPUs       int    // VM_CPUS
	MemoryMiB  int64  // VM_MEMORY
	Poll       time.Duration
}

func env(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

func parseConfig(args []string) (*Config, error) {
	c := &Config{}
	fs := flag.NewFlagSet("blipd slot", flag.ContinueOnError)
	fs.StringVar(&c.RunDir, "run-dir", env("BLIP_RUN_DIR", "/run/blip"), "slot directory")
	fs.StringVar(&c.CH, "cloud-hypervisor", env("BLIP_CH", "/usr/local/bin/cloud-hypervisor"), "Cloud Hypervisor binary")
	fs.StringVar(&c.Kernel, "kernel", env("BLIP_KERNEL", "/usr/share/blip/vmlinuz"), "guest kernel")
	fs.StringVar(&c.Initramfs, "initramfs", env("BLIP_INITRAMFS", "/usr/share/blip/initramfs.cpio.gz"), "guest initramfs")
	fs.StringVar(&c.Hypervisor, "hypervisor", env("BLIP_HYPERVISOR", ""), "kvm or mshv; empty picks the device present")
	fs.StringVar(&c.DevDir, "dev-dir", env("BLIP_DEV_DIR", "/dev"), "where /dev/kvm or /dev/mshv is")
	fs.StringVar(&c.Tap, "tap", env("BLIP_TAP", "blip0"), "TAP device name")
	fs.StringVar(&c.PodIface, "pod-iface", env("BLIP_POD_IFACE", "eth0"), "pod interface whose IP and MAC the guest takes")
	fs.StringVar(&c.Cmdline, "cmdline", env("BLIP_CMDLINE", "console=ttyS0 loglevel=4 panic=0"), "kernel command line")
	fs.DurationVar(&c.Poll, "poll", 250*time.Millisecond, "how often to check deadline and kill files")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if fs.NArg() > 0 {
		return nil, fmt.Errorf("unexpected arguments %q", fs.Args())
	}
	var err error
	if c.CPUs, err = strconv.Atoi(env("VM_CPUS", "")); err != nil || c.CPUs < 1 {
		return nil, fmt.Errorf("VM_CPUS must be a positive integer, got %q", os.Getenv("VM_CPUS"))
	}
	if c.MemoryMiB, err = ParseMemory(env("VM_MEMORY", "")); err != nil {
		return nil, fmt.Errorf("VM_MEMORY: %w", err)
	}
	return c, nil
}

// Main runs `blipd slot`. args are the arguments after "slot". With
// args ["probe"] it is the readiness probe.
func Main(ctx context.Context, args []string) error {
	if len(args) > 0 && args[0] == "probe" {
		return Probe(env("BLIP_RUN_DIR", "/run/blip"))
	}
	c, err := parseConfig(args)
	if err != nil {
		return err
	}
	return Run(ctx, c)
}

// Probe succeeds iff the node daemon has marked the slot ready.
func Probe(runDir string) error {
	if _, err := os.Stat(filepath.Join(runDir, FileReady)); err != nil {
		return errors.New("slot not ready")
	}
	return nil
}

// pickHypervisor returns the backend to use, from the flag or from the one
// device present. Exactly one device must be present.
func pickHypervisor(devDir, want string) (string, error) {
	var found []string
	for _, h := range []string{"kvm", "mshv"} {
		if _, err := os.Stat(filepath.Join(devDir, h)); err == nil {
			found = append(found, h)
		}
	}
	switch {
	case want != "" && want != "kvm" && want != "mshv":
		return "", fmt.Errorf("unknown hypervisor %q", want)
	case want != "":
		for _, f := range found {
			if f == want {
				return want, nil
			}
		}
		return "", fmt.Errorf("hypervisor %s requested but %s/%s is missing", want, devDir, want)
	case len(found) == 1:
		return found[0], nil
	case len(found) == 0:
		return "", fmt.Errorf("neither %s/kvm nor %s/mshv exists", devDir, devDir)
	default:
		return "", fmt.Errorf("both %s/kvm and %s/mshv exist; set the hypervisor", devDir, devDir)
	}
}

// Run is blipd slot with an explicit config.
func Run(ctx context.Context, c *Config) error {
	if _, err := os.Stat(filepath.Join(c.RunDir, FileAssigned)); err == nil {
		return errors.New("slot was already assigned; refusing to boot a new guest")
	}
	// Files from a previous container in this pod.
	for _, f := range []string{FileReady, FileKill, FileExit, FileAPISocket, FileVsock, FileSerial, FileEvents} {
		_ = os.Remove(filepath.Join(c.RunDir, f))
	}
	hv, err := pickHypervisor(c.DevDir, c.Hypervisor)
	if err != nil {
		return err
	}
	metaPath := filepath.Join(c.RunDir, FileMeta)
	if err := meta.Create(metaPath); err != nil {
		return fmt.Errorf("create metadata disk: %w", err)
	}
	// The node daemon reads the pod's DNS settings from here for the guest.
	resolv, _ := os.ReadFile("/etc/resolv.conf")
	if resolv != nil {
		_ = writeAtomic(filepath.Join(c.RunDir, FileResolvConf), resolv)
	}
	pn, err := setupNetwork(netConfig{Tap: c.Tap, PodIface: c.PodIface, RunDir: c.RunDir})
	if err != nil {
		return err
	}
	logf("network: guest takes %v and MAC %s of %s, via tap %s", pn.Addresses, pn.MAC, c.PodIface, c.Tap)
	dcfg, err := DHCPConfig(pn, resolv, "")
	if err != nil {
		return fmt.Errorf("dhcp: %w", err)
	}
	// The packet socket needs CAP_NET_RAW: open it before dropping it.
	dconn, err := dhcp.Listen(c.Tap)
	if err != nil {
		return fmt.Errorf("dhcp: %w", err)
	}
	if err := dropCapabilities(); err != nil {
		dconn.Close()
		return err
	}
	dsrv := dhcp.New(dcfg)
	dctx, stopDHCP := context.WithCancel(context.Background())
	dhcpDone := make(chan struct{})
	go func() {
		defer close(dhcpDone)
		if err := dsrv.ServeConn(dctx, dconn); err != nil {
			logf("dhcp: %v", err)
		}
	}()
	defer func() {
		stopDHCP()
		<-dhcpDone
	}()
	// The forwarder listens on the pod loopback, which the guest does not
	// take, and lives until blipd slot ends.
	fctx, stopForward := context.WithCancel(context.Background())
	forwardDone := make(chan struct{})
	go func() {
		forwardPorts(fctx, c.RunDir, c.Poll)
		close(forwardDone)
	}()
	defer func() {
		stopForward()
		<-forwardDone
	}()
	cmd := exec.Command(c.CH,
		"--api-socket", "path="+filepath.Join(c.RunDir, FileAPISocket),
		"--kernel", c.Kernel,
		"--initramfs", c.Initramfs,
		"--cmdline", c.Cmdline,
		"--cpus", fmt.Sprintf("boot=%d", c.CPUs),
		"--memory", fmt.Sprintf("size=%dM", c.MemoryMiB),
		"--disk", fmt.Sprintf("path=%s,serial=%s,id=%s,image_type=raw", metaPath, meta.Serial, meta.Serial),
		"--net", fmt.Sprintf("tap=%s,mac=%s", c.Tap, pn.MAC),
		"--vsock", "cid=3,socket="+filepath.Join(c.RunDir, FileVsock),
		"--serial", "file="+filepath.Join(c.RunDir, FileSerial),
		"--console", "off",
		"--balloon", "size=0,free_page_reporting=on",
		"--pvpanic",
		"--event-monitor", "path="+filepath.Join(c.RunDir, FileEvents),
	)
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	start := time.Now()
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start cloud-hypervisor: %w", err)
	}
	logf("cloud-hypervisor pid %d started (%s, %d vCPU, %d MiB)", cmd.Process.Pid, hv, c.CPUs, c.MemoryMiB)
	waitCh := make(chan error, 1)
	go func() { waitCh <- cmd.Wait() }()
	s := &supervisor{
		c: c, cmd: cmd, hv: hv, start: start, metaPath: metaPath, dhcp: dsrv,
		con:    &console{path: filepath.Join(c.RunDir, FileSerial), w: os.Stdout},
		events: &eventReader{path: filepath.Join(c.RunDir, FileEvents)},
	}
	stopCopy := make(chan struct{})
	copied := make(chan struct{})
	go func() {
		defer close(copied)
		for {
			if s.con.poll() {
				logf("serial log truncated (guest reboot)")
			}
			select {
			case <-stopCopy:
				s.con.poll()
				return
			case <-time.After(100 * time.Millisecond):
			}
		}
	}()
	err = s.run(ctx, waitCh)
	close(stopCopy)
	<-copied
	s.con.close()
	return err
}

func logf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "blipd slot: "+format+"\n", args...)
}

// supervisor follows one Cloud Hypervisor run.
type supervisor struct {
	c        *Config
	cmd      *exec.Cmd
	hv       string
	start    time.Time
	metaPath string
	dhcp     *dhcp.Server
	con      *console
	events   *eventReader

	reason    string // why blipd slot killed CH, "" if it did not
	reboots   int
	panicLine string
	initCode  *int
	ready     bool
	hostname  string
}

func (s *supervisor) kill(r string) {
	if s.reason == "" {
		s.reason = r
		logf("killing cloud-hypervisor: %s", r)
		_ = s.cmd.Process.Kill()
	}
}

// checkEvents handles new event monitor events.
func (s *supervisor) checkEvents() {
	for _, e := range s.events.read() {
		switch e.String() {
		case "vm rebooting":
			s.reboots++
			logf("guest reboot %d", s.reboots)
		case "guest panic":
			s.onPanic()
		}
	}
}

// onPanic classifies a guest panic from the serial log and ends the VM.
// With panic=0 the guest hangs and the serial log is intact.
func (s *supervisor) onPanic() {
	if s.reason != "" {
		return
	}
	s.con.poll()
	line, code, found := parsePanic(s.con.text())
	if !found {
		// The panic line may still be on its way.
		time.Sleep(200 * time.Millisecond)
		s.con.poll()
		line, code, _ = parsePanic(s.con.text())
	}
	s.panicLine, s.initCode = line, code
	logf("guest panic: %s", line)
	s.kill("panic")
}

// checkMeta reads the guest area: it marks the slot ready on the first
// WAITING before assignment. It also gives the DHCP server the hostname
// from the host data once the node wrote it.
func (s *supervisor) checkMeta() {
	g, err := readGuestArea(s.metaPath)
	if err == nil {
		if !s.ready && g.State == meta.StateWaiting && !exists(filepath.Join(s.c.RunDir, FileAssigned)) {
			if err := os.WriteFile(filepath.Join(s.c.RunDir, FileReady), nil, 0o644); err != nil {
				logf("write %s: %v", FileReady, err)
			} else {
				s.ready = true
				logf("guest is waiting for an allocation (boot %d)", g.BootCount)
			}
		}
	}
	if s.dhcp == nil {
		return
	}
	if h := readHostArea(s.metaPath); h != nil {
		name := h.Hostname
		if name == "" {
			name = h.Identity.Name
		}
		if name != s.hostname {
			s.hostname = name
			cfg := s.dhcp.Config()
			cfg.Hostname = name
			s.dhcp.SetConfig(cfg)
		}
	}
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func (s *supervisor) run(ctx context.Context, waitCh <-chan error) error {
	c := s.c
	notify, stopNotify := metaNotify(s.metaPath)
	defer stopNotify()
	backendOK := false
	tick := time.NewTicker(c.Poll)
	defer tick.Stop()
	slow := time.NewTicker(time.Second)
	defer slow.Stop()
	var waitErr error
	done := ctx.Done()
loop:
	for {
		select {
		case waitErr = <-waitCh:
			break loop
		case <-done:
			done = nil
			s.kill("stopped")
		case <-notify:
			s.checkMeta()
		case <-slow.C:
			s.checkMeta()
		case <-tick.C:
			s.checkEvents()
			if !backendOK && s.reason == "" {
				got, err := backendOf(s.cmd.Process.Pid)
				switch {
				case err != nil && time.Since(s.start) > 10*time.Second:
					logf("cannot tell the hypervisor backend: %v", err)
					s.kill("backend")
				case err == nil && got != s.hv:
					logf("cloud-hypervisor uses %s, expected %s", got, s.hv)
					s.kill("backend")
				case err == nil:
					backendOK = true
					logf("cloud-hypervisor uses %s", got)
				}
			}
			if _, err := os.Stat(filepath.Join(c.RunDir, FileKill)); err == nil {
				s.kill("killed")
			}
			if a, err := readAssignment(c.RunDir); err == nil && !a.KillTime.IsZero() && time.Now().After(a.KillTime) {
				s.kill("deadline")
			}
		}
	}
	s.checkEvents()
	s.con.poll()
	rec := ExitRecord{Cause: s.reason, Time: time.Now().UTC()}
	if rec.Cause == "" {
		rec.Cause = "exited"
	}
	var ee *exec.ExitError
	switch {
	case waitErr == nil:
	case errors.As(waitErr, &ee):
		ws := ee.Sys().(syscall.WaitStatus)
		if ws.Signaled() {
			rec.ExitCode, rec.Signal = -1, ws.Signal().String()
		} else {
			rec.ExitCode = ws.ExitStatus()
		}
	default:
		rec.ExitCode = -1
		rec.Signal = waitErr.Error()
	}
	g, gerr := readGuestArea(s.metaPath)
	if gerr != nil {
		g = nil
	}
	Classify(&rec, g, s.reboots, s.panicLine, s.initCode)
	b, _ := json.Marshal(rec)
	if err := writeAtomic(filepath.Join(c.RunDir, FileExit), b); err != nil {
		logf("write %s: %v", FileExit, err)
	}
	logf("cloud-hypervisor exited: code %d %s (%s): %s: %s", rec.ExitCode, rec.Signal, rec.Cause, rec.Reason, rec.Message)
	if rec.ExitCode == 0 && rec.Signal == "" && rec.Cause == "exited" {
		return nil
	}
	return &ExitError{Record: rec}
}

// Classify fills rec.Reason, rec.Message, rec.GuestExitCode and
// rec.BootCount from how Cloud Hypervisor ended (rec.Cause, rec.ExitCode,
// rec.Signal), the final guest area (untrusted, may be nil), the reboot
// events and the panic seen in the serial log (initCode is set when
// init exited). This is the only place the end of a VM is classified.
func Classify(rec *ExitRecord, g *meta.GuestData, reboots int, panicLine string, initCode *int) {
	if reboots > 0 {
		rec.BootCount = reboots + 1
	}
	if g != nil {
		if g.BootCount > rec.BootCount && g.BootCount < 1<<20 {
			rec.BootCount = g.BootCount
		}
	}
	if rec.Cause == "panic" && initCode != nil {
		c := *initCode
		rec.GuestExitCode = &c
	}
	if g != nil && g.ExitCode != nil {
		c := *g.ExitCode
		if c < -1<<31 || c > 1<<31-1 {
			c = -1
		}
		rec.GuestExitCode = &c
	}
	detail := func(s, more string) string {
		if more != "" {
			return s + ": " + more
		}
		return s
	}
	clean := rec.Cause == "exited" && rec.ExitCode == 0 && rec.Signal == ""
	switch {
	case rec.Cause == "killed" || rec.Cause == "stopped":
		rec.Reason, rec.Message = api.ReasonHypervisorExited, fmt.Sprintf("the VM was killed (%s)", rec.Cause)
	case rec.Cause == "deadline":
		rec.Reason, rec.Message = api.ReasonTTLExceeded, "the deadline passed"
	case g != nil && g.State == meta.StateFail:
		m := "boot failed"
		if r := clip(g.Reason, 64); r != "" {
			m += " (" + r + ")"
		}
		rec.Reason, rec.Message = api.ReasonBootFailed, detail(m, clip(g.Message, 1024))
	case rec.Cause == "panic" && initCode != nil:
		rec.Reason, rec.Message = api.ReasonInitExited, detail(fmt.Sprintf("init exited with code %d", *rec.GuestExitCode), clip(panicLine, 1024))
	case rec.Cause == "panic":
		rec.Reason, rec.Message = api.ReasonGuestPanic, detail("the guest kernel panicked", clip(panicLine, 1024))
	case clean && (rec.GuestExitCode == nil || *rec.GuestExitCode == 0):
		rec.Reason, rec.Message = api.ReasonSucceeded, "the guest powered off"
	case clean:
		rec.Reason, rec.Message = api.ReasonError, fmt.Sprintf("the guest powered off with exit code %d", *rec.GuestExitCode)
	default:
		why := rec.Cause
		if why == "exited" {
			why = "crashed"
		}
		m := fmt.Sprintf("the VM exited (%s, status %d)", why, rec.ExitCode)
		if rec.Signal != "" {
			m = fmt.Sprintf("the VM exited (%s, %s)", why, rec.Signal)
		}
		rec.Reason, rec.Message = api.ReasonHypervisorExited, m
	}
}

// backendOf looks at the open files of Cloud Hypervisor to see which
// hypervisor device it uses: /dev/kvm and kvm-vm fds, or /dev/mshv and
// mshv partition fds.
func backendOf(pid int) (string, error) {
	dir := fmt.Sprintf("/proc/%d/fd", pid)
	ents, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	for _, e := range ents {
		l, err := os.Readlink(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		switch {
		case strings.Contains(l, "mshv"):
			return "mshv", nil
		case l == "/dev/kvm" || strings.HasPrefix(l, "anon_inode:kvm"):
			return "kvm", nil
		}
	}
	return "", errors.New("no hypervisor fd open yet")
}

// Client returns a Cloud Hypervisor API client for the slot directory.
func Client(runDir string) *chapi.Client {
	return chapi.New(filepath.Join(runDir, FileAPISocket))
}
