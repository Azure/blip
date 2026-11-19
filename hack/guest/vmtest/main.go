// Command vmtest boots real blip VMs through blip-runtime and checks the
// runtime and guest end to end. Run it through hack/guest/run-local.sh.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Azure/blip/internal/apiproxy"
	"github.com/Azure/blip/internal/network"
	"github.com/Azure/blip/internal/podapi"
	sessionpkg "github.com/Azure/blip/internal/session"
	"github.com/Azure/blip/internal/wire"
)

var (
	work   = os.Getenv("WORK")
	assets = os.Getenv("ASSETS")
	netns  = os.Getenv("NS")
)

func main() {
	log.SetFlags(log.Ltime | log.Lmicroseconds)
	only := flag.String("run", "", "run only this scenario (main, command)")
	flag.Parse()
	scenarios := []struct {
		name string
		fn   func()
	}{
		{"main", scenarioMain},
		{"command", scenarioCommand},
	}
	for _, s := range scenarios {
		if *only != "" && *only != s.name {
			continue
		}
		log.Printf("=== scenario %s", s.name)
		s.fn()
		log.Printf("=== scenario %s PASS", s.name)
	}
	log.Printf("ALL PASS")
}

func check(ok bool, format string, args ...any) {
	if !ok {
		log.Fatalf("FAIL: "+format, args...)
	}
	log.Printf("ok: "+format, args...)
}

func must(err error, what string) {
	if err != nil {
		log.Fatalf("FAIL: %s: %v", what, err)
	}
}

// ---- pod ----

type pod struct {
	dir  string
	cmd  *exec.Cmd
	done chan error
}

func startPod(name string, network bool) *pod {
	dir := filepath.Join(work, "pod-"+name)
	_ = os.RemoveAll(dir)
	must(os.MkdirAll(filepath.Join(dir, "dev"), 0o755), "mkdir pod")
	logf, err := os.Create(filepath.Join(dir, "runtime.log"))
	must(err, "log")
	args := []string{filepath.Join(work, "blip-runtime")}
	if network {
		args = append([]string{"ip", "netns", "exec", netns}, args...)
	}
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Env = append(os.Environ(),
		"BLIP_DIR="+dir,
		"BLIP_KERNEL="+filepath.Join(assets, "vmlinuz"),
		"BLIP_INITRAMFS="+filepath.Join(assets, "initramfs.gz"),
		"BLIP_CPUS=2",
		"BLIP_MEMORY_MB=1024",
	)
	if network {
		cmd.Env = append(cmd.Env, "BLIP_KUBE_NAMESPACE=vmtest-system")
	} else {
		cmd.Env = append(cmd.Env, "BLIP_SKIP_NETWORK=1")
	}
	cmd.Stdout, cmd.Stderr = logf, logf
	must(cmd.Start(), "start runtime")
	p := &pod{dir: dir, cmd: cmd, done: make(chan error, 1)}
	go func() { p.done <- cmd.Wait() }()
	return p
}

func (p *pod) path(n string) string { return filepath.Join(p.dir, n) }

func (p *pod) setDesired(d podapi.Desired) {
	must(podapi.WriteJSON(p.path(podapi.DesiredFile), d), "write desired")
}

func (p *pod) observed() podapi.Observed {
	var o podapi.Observed
	_ = podapi.ReadJSON(p.path(podapi.ObservedFile), &o)
	return o
}

func (p *pod) wait(what string, timeout time.Duration, pred func(podapi.Observed) bool) podapi.Observed {
	deadline := time.Now().Add(timeout)
	for {
		o := p.observed()
		if pred(o) {
			return o
		}
		if time.Now().After(deadline) {
			b, _ := json.Marshal(o)
			log.Fatalf("FAIL: timeout waiting for %s; observed %s\nconsole tail:\n%s", what, b, tail(p.path("runtime.log"), 3000))
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func (p *pod) waitExit(timeout time.Duration) {
	select {
	case err := <-p.done:
		check(err == nil, "runtime exited with status 0 (err=%v)", err)
	case <-time.After(timeout):
		_ = p.cmd.Process.Kill()
		log.Fatalf("FAIL: runtime did not exit")
	}
}

func diskStatus(o podapi.Observed, id string) podapi.DiskStatus {
	for _, m := range o.Mounts {
		if m.ID == id {
			return m
		}
	}
	return podapi.DiskStatus{}
}

func tail(path string, n int) string {
	b, _ := os.ReadFile(path)
	if len(b) > n {
		b = b[len(b)-n:]
	}
	return string(b)
}

// ---- disks ----

func freshRoot(name string) string {
	p := filepath.Join(work, name+"-root.ext4")
	out, err := exec.Command("cp", "--sparse=always", filepath.Join(work, "base.ext4"), p).CombinedOutput()
	must(err, "copy root: "+string(out))
	return p
}

func mkfs(name string, files map[string]string) string {
	p := filepath.Join(work, name+".ext4")
	_ = os.Remove(p)
	src := filepath.Join(work, name+"-src")
	_ = os.RemoveAll(src)
	must(os.MkdirAll(src, 0o755), "mkdir src")
	for f, data := range files {
		must(os.WriteFile(filepath.Join(src, f), []byte(data), 0o644), "write src")
	}
	out, err := exec.Command("mke2fs", "-q", "-t", "ext4", "-d", src, p, "64M").CombinedOutput()
	must(err, "mkfs: "+string(out))
	return p
}

func fsClean(img string) {
	out, err := exec.Command("dumpe2fs", "-h", img).CombinedOutput()
	must(err, "dumpe2fs")
	s := string(out)
	var features, state string
	for _, l := range strings.Split(s, "\n") {
		if strings.HasPrefix(l, "Filesystem features:") {
			features = l
		}
		if strings.HasPrefix(l, "Filesystem state:") {
			state = l
		}
	}
	check(!strings.Contains(features, "needs_recovery"), "%s: needs_recovery clear (%s)", filepath.Base(img), strings.TrimSpace(features))
	check(strings.Contains(state, "clean"), "%s: %s", filepath.Base(img), strings.TrimSpace(state))
}

func fsCat(img, path string) string {
	out, err := exec.Command("debugfs", "-R", "cat "+path, img).Output()
	must(err, "debugfs")
	return string(out)
}

// ---- sessions ----

// readDeadline is shared with deadlineConn so collect can bound a Recv that
// has no exposed deadline on session.Session.
type readDeadline struct {
	mu sync.Mutex
	at time.Time
}

func (d *readDeadline) set(at time.Time) {
	d.mu.Lock()
	d.at = at
	d.mu.Unlock()
}

func (d *readDeadline) get() time.Time {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.at
}

type deadlineConn struct {
	net.Conn
	d *readDeadline
}

func (c *deadlineConn) Read(p []byte) (int, error) {
	_ = c.Conn.SetReadDeadline(c.d.get())
	return c.Conn.Read(p)
}

type session struct {
	s        *sessionpkg.Session
	opened   wire.Opened
	deadline *readDeadline
}

func (s *session) Close() error { return s.s.Close() }

func writeStdin(s *session, data string) error {
	_, err := s.s.Write([]byte(data))
	return err
}

func dialPort(p *pod, port uint32) (net.Conn, error) {
	return wire.DialVsock(p.path(podapi.VsockSocket), port, 5*time.Second)
}

func open(p *pod, o wire.Open) (*session, error) {
	deadline := &readDeadline{}
	client := &sessionpkg.Client{Connect: func(ctx context.Context, _, _ string) (io.ReadWriteCloser, error) {
		conn, err := dialPort(p, wire.SessionPort)
		if err != nil {
			return nil, err
		}
		return &deadlineConn{Conn: conn, d: deadline}, nil
	}}
	s, err := client.Open(context.Background(), "", "", o)
	if err != nil {
		return nil, err
	}
	return &session{s: s, opened: s.Opened, deadline: deadline}, nil
}

type result struct {
	stdout, stderr string
	notices        []string
	exit           *wire.Exit
}

// collect reads until Exited or the connection closes. stop, if set, ends
// reading early when it returns true for the stdout seen so far.
func (s *session) collect(timeout time.Duration, stop func(string) bool) result {
	var r result
	var out, errb bytes.Buffer
	s.deadline.set(time.Now().Add(timeout))
	defer s.deadline.set(time.Time{})
	for {
		f, err := s.s.Recv()
		if err != nil {
			break
		}
		switch f.Type {
		case wire.TStdout:
			out.Write(f.Data)
		case wire.TStderr:
			errb.Write(f.Data)
		case wire.TNotice:
			r.notices = append(r.notices, f.Notice)
		case wire.TExited:
			r.exit = f.Exit
		}
		if r.exit != nil || (stop != nil && stop(out.String())) {
			break
		}
	}
	r.stdout, r.stderr = out.String(), errb.String()
	return r
}

func run(p *pod, o wire.Open, stdin string) result {
	o.Mode = wire.OpenExec
	s, err := open(p, o)
	must(err, fmt.Sprintf("exec %v", o.Argv))
	defer s.Close()
	if stdin != "" {
		_, err = s.s.Write([]byte(stdin))
		must(err, "stdin")
	}
	must(s.s.CloseStdin(), "stdin eof")
	r := s.collect(30*time.Second, nil)
	if r.exit == nil {
		log.Fatalf("FAIL: %v: no exit status (stdout %q stderr %q)", o.Argv, r.stdout, r.stderr)
	}
	return r
}

func sh(p *pod, script string) result {
	return run(p, wire.Open{Argv: []string{"sh", "-c", script}}, "")
}

func newID(n int) string {
	return fmt.Sprintf("%016x", time.Now().UnixNano()+int64(n))
}

// probeAPI exercises guest TCP -> guest-to-host vsock -> Unix sidecar -> TLS.
// The fake projected credential exists only in the host-side pod directory.
func probeAPI(p *pod) {
	const token = "vmtest-host-only-token"
	requests := make(chan http.Header, 1)
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/namespaces/vmtest-system/pods" {
			http.NotFound(w, r)
			return
		}
		requests <- r.Header.Clone()
		fmt.Fprintln(w, "api-vsock-ok")
	}))
	defer upstream.Close()
	tokenFile, caFile := p.path("api-token"), p.path("api-ca.crt")
	must(os.WriteFile(tokenFile, []byte(token), 0o600), "write host API token")
	must(os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: upstream.Certificate().Raw}), 0o600), "write host API CA")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	socket := p.path(podapi.VsockSocket) + fmt.Sprintf("_%d", wire.APIPort)
	go func() {
		done <- apiproxy.Run(ctx, apiproxy.Config{
			SocketPath: socket, APIAddress: strings.TrimPrefix(upstream.URL, "https://"), TokenFile: tokenFile, CAFile: caFile,
		})
	}()
	defer func() {
		cancel()
		must(<-done, "stop API proxy")
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		select {
		case err := <-done:
			log.Fatalf("FAIL: API proxy exited before ready: %v", err)
		default:
		}
		if _, err := os.Stat(socket); err == nil {
			break
		}
		if time.Now().After(deadline) {
			log.Fatal("FAIL: timeout waiting for API proxy socket")
		}
		time.Sleep(10 * time.Millisecond)
	}
	r := sh(p, `test "$KUBECONFIG" = /run/blip/kubeconfig &&
test ! -e /var/run/secrets/kubernetes.io/serviceaccount &&
cat /run/blip/kubeconfig && echo && cat /run/blip/namespace && echo && env`)
	check(r.exit.Code == 0 && strings.Contains(r.stdout, `"server":"http://127.0.0.1:8001"`) &&
		strings.Contains(r.stdout, `"namespace":"vmtest-system"`) && strings.Contains(r.stdout, "\nvmtest-system\n") &&
		!strings.Contains(r.stdout, token) && !strings.Contains(r.stdout, `"token"`),
		"guest has namespace/kubeconfig metadata and no service-account files or credential")
	r = run(p, wire.Open{Argv: []string{"timeout", "10", "bash", "-c", `exec 3<>/dev/tcp/127.0.0.1/8001
printf 'GET /api/v1/namespaces/vmtest-system/pods HTTP/1.1\r\nHost: guest.invalid\r\nAuthorization: Bearer guest-forged\r\nImpersonate-User: admin\r\nConnection: close\r\n\r\n' >&3
cat <&3`}}, "")
	check(r.exit.Code == 0 && strings.HasPrefix(r.stdout, "HTTP/1.1 200") && strings.Contains(r.stdout, "api-vsock-ok"),
		"guest localhost API works over vsock while direct egress is denied: %q (stderr %q)", r.stdout, r.stderr)
	select {
	case headers := <-requests:
		check(headers.Get("Authorization") == "Bearer "+token && headers.Get("Impersonate-User") == "",
			"host proxy injects its token and strips guest identity")
	default:
		log.Fatal("FAIL: fake TLS API received no request")
	}
}

// ---- scenarios ----

func scenarioMain() {
	rootImg := freshRoot("main")
	p := startPod("main", true)
	t0 := time.Now()
	p.wait("Booting", 5*time.Second, func(o podapi.Observed) bool { return o.Phase != "" })
	p.wait("Warm", 30*time.Second, func(o podapi.Observed) bool { return o.Phase == podapi.PhaseWarm })
	log.Printf("boot to Warm: %v", time.Since(t0).Round(time.Millisecond))

	rootID := newID(0)
	claim := &podapi.Claim{
		BlipName: "vmtest", BlipUID: "uid-1",
		Root: podapi.Disk{ID: rootID, Serial: rootID, Device: rootImg},
		Env:  []string{"IMAGE_ENV=from-image"},
	}
	p.setDesired(podapi.Desired{Claim: claim, Network: &network.Policy{Revision: "initial-deny"}})
	t1 := time.Now() // after the (fsynced) desired.json is in place
	o := p.wait("Running", 30*time.Second, func(o podapi.Observed) bool { return o.Phase == podapi.PhaseRunning })
	running := time.Since(t1)
	r := run(p, wire.Open{Argv: []string{"echo", "hello"}}, "")
	first := time.Since(t1)
	check(o.ClaimID == rootID, "observed claimID %s", o.ClaimID)
	check(r.stdout == "hello\n" && r.exit.Code == 0, "first command output %q", r.stdout)
	log.Printf("LATENCY claim->Running %v, claim->first command output %v", running.Round(time.Millisecond), first.Round(time.Millisecond))
	var lat []time.Duration
	for i := 0; i < 10; i++ {
		t := time.Now()
		run(p, wire.Open{Argv: []string{"true"}}, "")
		lat = append(lat, time.Since(t))
	}
	log.Printf("LATENCY exec round trip (true) x10: %v", lat)

	r = sh(p, "echo out; echo err >&2; exit 3")
	check(r.stdout == "out\n" && r.stderr == "err\n" && r.exit.Code == 3, "stdout/stderr/exit code: %q %q %d", r.stdout, r.stderr, r.exit.Code)

	r = run(p, wire.Open{Argv: []string{"sh", "-c", "id -u; id -g; pwd; echo $FOO $IMAGE_ENV $HOME"}, User: "nobody", WorkingDir: "/tmp", Env: []string{"FOO=bar"}}, "")
	check(r.stdout == "65534\n65534\n/tmp\nbar from-image /nonexistent\n", "user/workdir/env: %q", r.stdout)
	r = run(p, wire.Open{Argv: []string{"id"}, User: "1234:5678"}, "")
	check(strings.HasPrefix(r.stdout, "uid=1234 gid=5678"), "numeric user: %q", r.stdout)
	r = run(p, wire.Open{Argv: []string{"sh", "-c", "cat /proc/self/cgroup; test -f /etc/debian_version && echo debian; hostname"}}, "")
	check(r.stdout == "0::/work\ndebian\nvmtest\n", "cgroup, chroot, hostname: %q", r.stdout)

	// The same through `blip-runtime bridge 1025`, as pod exec would. Stdin
	// stays open until the session ends: stdin EOF means the client is gone.
	bridge := exec.Command(filepath.Join(work, "blip-runtime"), "bridge", "1025")
	bridge.Env = append(os.Environ(), "BLIP_DIR="+p.dir)
	bin, _ := bridge.StdinPipe()
	bout, _ := bridge.StdoutPipe()
	must(bridge.Start(), "bridge")
	bc := wire.NewConn(struct {
		io.Reader
		io.Writer
	}{bout, bin})
	_ = bc.WriteJSON(wire.TOpen, wire.Open{Mode: wire.OpenExec, Argv: []string{"echo", "bridged"}})
	var frames []string
	for {
		t, payload, err := bc.Read()
		if err != nil {
			break
		}
		frames = append(frames, fmt.Sprintf("%d:%s", t, payload))
		if t == wire.TExited {
			bin.Close()
		}
	}
	must(bridge.Wait(), "bridge exit")
	check(len(frames) == 3 && frames[1] == "46:bridged\n" && strings.HasPrefix(frames[2], "48:"), "bridge relays a session: %q", frames)
	r = run(p, wire.Open{Argv: []string{"cat"}}, "abc")
	check(r.stdout == "abc" && r.exit.Code == 0, "stdin + EOF: %q", r.stdout)
	if s, err := open(p, wire.Open{Mode: wire.OpenExec, Argv: []string{"no-such-command"}}); err == nil {
		s.Close()
		log.Fatalf("FAIL: missing command opened")
	} else {
		check(strings.Contains(err.Error(), "not found"), "missing command: %v", err)
	}

	// Routed network: the pod retains its IP, while the guest has a private
	// IPv4 link and inherits DNS. Missing policy denies direct egress.
	r = sh(p, "cat /etc/resolv.conf; cat /proc/net/route | awk 'NR>1{print $1}' | sort -u")
	check(strings.Contains(r.stdout, "nameserver 10.99.0.1") && strings.Contains(r.stdout, "options ndots:5") && strings.Contains(r.stdout, "eth0"), "guest resolv.conf/route: %q", r.stdout)
	r = sh(p, "hostname -I")
	guestIP := net.ParseIP(strings.TrimSpace(r.stdout))
	check(guestIP != nil && guestIP.To4() != nil && guestIP.IsLinkLocalUnicast(), "guest has private IPv4 link: %q", r.stdout)
	out, err := exec.Command("ip", "-n", netns, "-4", "addr", "show", "dev", "eth0").CombinedOutput()
	check(err == nil && strings.Contains(string(out), "10.99.0.2/24"), "pod retains IP 10.99.0.2")
	out, err = exec.Command("ping", "-c", "1", "-W", "2", "10.99.0.2").CombinedOutput()
	check(err == nil, "host pings guest through pod-IP DNAT (%s)", strings.TrimSpace(lastLine(string(out))))
	ln, err := net.Listen("tcp", "10.99.0.1:18080")
	must(err, "listen")
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				reader := bufio.NewReader(c)
				for {
					line, err := reader.ReadString('\n')
					if err != nil {
						return
					}
					fmt.Fprintf(c, "echo:%s", line)
					if line != "live-before\n" {
						return
					}
				}
			}()
		}
	}()
	defer ln.Close()
	denied := func(label string) {
		r := run(p, wire.Open{Argv: []string{"timeout", "2", "bash", "-c", "exec 3<>/dev/tcp/10.99.0.1/18080"}}, "")
		check(r.exit.Code == 124, "%s denies guest TCP egress (exit %d, stderr %q)", label, r.exit.Code, r.stderr)
	}
	denied("initial empty policy")
	p.setDesired(podapi.Desired{Claim: claim})
	p.wait("missing policy applied", 5*time.Second, func(o podapi.Observed) bool { return o.NetworkRevision == "" && o.NetworkError == "" })
	denied("missing policy")
	probeAPI(p)
	policy := &network.Policy{Revision: "allow-echo", Layers: [][]network.Rule{{{CIDR: "10.99.0.1/32", Protocol: "TCP", Port: 18080}}}}
	p.setDesired(podapi.Desired{Claim: claim, Network: policy})
	p.wait("allow-echo policy applied", 5*time.Second, func(o podapi.Observed) bool { return o.NetworkRevision == policy.Revision && o.NetworkError == "" })
	r = run(p, wire.Open{Argv: []string{"bash", "-c", "exec 3<>/dev/tcp/10.99.0.1/18080; echo from-guest >&3; cat <&3"}}, "")
	check(r.stdout == "echo:from-guest\n", "explicitly allowed guest TCP egress over routed TAP: %q", r.stdout)
	s, err := open(p, wire.Open{Mode: wire.OpenExec, Argv: []string{"bash", "-c", `exec 3<>/dev/tcp/10.99.0.1/18080
echo live-before >&3
IFS= read -r line <&3; echo "$line"
read -r trigger
echo live-after >&3
if IFS= read -r -t 2 line <&3; then echo "$line"; exit 1; fi
echo revoked`}})
	must(err, "open live connection")
	r = s.collect(5*time.Second, func(out string) bool { return strings.Contains(out, "echo:live-before\n") })
	check(r.stdout == "echo:live-before\n", "connection exchanges data before revocation")
	policy = &network.Policy{Revision: "revoke-echo"}
	p.setDesired(podapi.Desired{Claim: claim, Network: policy})
	p.wait("revoke-echo policy applied", 5*time.Second, func(o podapi.Observed) bool { return o.NetworkRevision == policy.Revision && o.NetworkError == "" })
	must(writeStdin(s, "continue\n"), "resume live connection")
	r = s.collect(5*time.Second, nil)
	s.Close()
	check(r.stdout == "revoked\n" && r.exit != nil && r.exit.Code == 0, "revocation blocks an established connection: %q", r.stdout)
	denied("revoked policy")
	ln.Close()

	// PTY shell (login shell of root from /etc/passwd).
	s, err = open(p, wire.Open{Mode: wire.OpenExec, TTY: true, Rows: 30, Cols: 100})
	must(err, "pty open")
	check(s.opened.TTY, "pty session opened (%s)", s.opened.Session)
	must(writeStdin(s, "stty size; tty; echo $0\n"), "pty write")
	r = s.collect(10*time.Second, func(out string) bool { return strings.Contains(out, "-bash") && strings.Contains(out, "/dev/pts/") })
	check(strings.Contains(r.stdout, "30 100"), "pty initial size 30x100")
	must(s.s.Resize(50, 132), "resize")
	must(writeStdin(s, "stty size\n"), "pty write")
	r = s.collect(10*time.Second, func(out string) bool { return strings.Contains(out, "50 132") })
	check(strings.Contains(r.stdout, "50 132"), "pty resize to 50x132")
	must(writeStdin(s, "exit 4\n"), "pty exit")
	r = s.collect(10*time.Second, nil)
	check(r.exit != nil && r.exit.Code == 4, "pty shell exit code 4")
	s.Close()

	// Disconnect and rejoin the session with replay.
	s, err = open(p, wire.Open{Mode: wire.OpenExec, Argv: []string{"sh", "-c", "for i in 1 2 3; do echo line$i; sleep 0.3; done; sleep 1; echo done"}})
	must(err, "replay exec")
	id := s.opened.Session
	r = s.collect(5*time.Second, func(out string) bool { return strings.Contains(out, "line1") })
	s.Close()
	time.Sleep(500 * time.Millisecond)
	s, err = open(p, wire.Open{Mode: wire.OpenAttach, Session: id})
	must(err, "attach")
	r = s.collect(10*time.Second, nil)
	s.Close()
	check(r.stdout == "line1\nline2\nline3\ndone\n" && r.exit != nil && r.exit.Code == 0, "rejoin replays all output then exit: %q", r.stdout)
	// Retirement follows the final client's disconnect asynchronously.
	retireBy := time.Now().Add(5 * time.Second)
	for {
		s, err = open(p, wire.Open{Mode: wire.OpenAttach, Session: id})
		if err != nil {
			check(strings.Contains(err.Error(), "no session"), "consumed finished non-primary session is retired: %v", err)
			break
		}
		s.Close()
		if time.Now().After(retireBy) {
			log.Fatal("FAIL: consumed finished non-primary session was not retired")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Ring overflow: a joiner gets a Notice and the last 1 MiB.
	s, err = open(p, wire.Open{Mode: wire.OpenExec, Argv: []string{"sh", "-c", "head -c 3000000 /dev/zero | tr '\\0' a; echo; echo tail-marker; sleep 1"}})
	must(err, "big exec")
	id = s.opened.Session
	s.Close()
	time.Sleep(700 * time.Millisecond)
	s, err = open(p, wire.Open{Mode: wire.OpenAttach, Session: id})
	must(err, "attach big")
	r = s.collect(10*time.Second, nil)
	s.Close()
	check(len(r.notices) == 1 && len(r.stdout) <= 1<<20+64<<10 && len(r.stdout) > 900<<10 && strings.HasSuffix(r.stdout, "tail-marker\n"), "gap notice %q, replay %d bytes", r.notices, len(r.stdout))

	// Signals by name.
	s, err = open(p, wire.Open{Mode: wire.OpenExec, Argv: []string{"sleep", "100"}})
	must(err, "sleep")
	must(s.s.Signal("TERM"), "signal")
	r = s.collect(5*time.Second, nil)
	s.Close()
	check(r.exit != nil && r.exit.Signal == "TERM" && r.exit.Code == 143, "signal TERM: %+v", r.exit)

	// Sessions count.
	s, err = open(p, wire.Open{Mode: wire.OpenExec, Argv: []string{"sleep", "100"}})
	must(err, "sleep")
	p.wait("sessions=1", 5*time.Second, func(o podapi.Observed) bool { return o.Sessions == 1 })
	must(s.s.Signal("KILL"), "kill")
	s.collect(5*time.Second, nil)
	s.Close()
	p.wait("sessions=0", 5*time.Second, func(o podapi.Observed) bool { return o.Sessions == 0 })
	check(true, "observed sessions follows attached clients")

	// Writable mount.
	dataImg := mkfs("data", nil)
	dataID := newID(1)
	data := podapi.Disk{ID: dataID, Serial: dataID, Device: dataImg, State: "data-state", Path: "/data"}
	desired := podapi.Desired{Claim: claim, Mounts: []podapi.Disk{data}}
	t := time.Now()
	p.setDesired(desired)
	p.wait("data Mounted", 20*time.Second, func(o podapi.Observed) bool { return diskStatus(o, dataID).Phase == podapi.DiskMounted })
	log.Printf("LATENCY hot-add + mount: %v", time.Since(t).Round(time.Millisecond))
	r = sh(p, "echo persisted > /data/file && echo root-data > /root/marker && grep ' /data ' /proc/mounts")
	check(r.exit.Code == 0 && strings.Contains(r.stdout, "rw"), "write to RW mount: %q", r.stdout)

	// A second control connection replaces the runtime's; the guest's Hello
	// reports the current state and the runtime reconnects.
	cc, err := dialPort(p, wire.ControlPort)
	must(err, "control dial")
	ctl := wire.NewConn(cc)
	typ, payload, err := ctl.Read()
	must(err, "hello")
	var hello wire.Hello
	_ = wire.Decode(payload, &hello)
	check(typ == wire.THello && hello.ClaimID == rootID && len(hello.Mounts) == 1 && hello.Mounts[0] == dataID, "hello on reconnect: %+v", hello)
	_ = cc.SetReadDeadline(time.Now().Add(10 * time.Second))
	for {
		if _, _, err := ctl.Read(); err != nil {
			break
		}
	}
	cc.Close()
	check(true, "runtime reconnected and took the control port back")

	// Busy unmount fails and is retried.
	busy, err := open(p, wire.Open{Mode: wire.OpenExec, Argv: []string{"sh", "-c", "cd /data && exec sleep 1000"}})
	must(err, "busy")
	time.Sleep(200 * time.Millisecond)
	desired.Mounts = nil
	p.setDesired(desired)
	o = p.wait("data Failed (busy)", 20*time.Second, func(o podapi.Observed) bool { return diskStatus(o, dataID).Phase == podapi.DiskFailed })
	check(strings.Contains(diskStatus(o, dataID).Message, "busy"), "busy unmount reported: %q", diskStatus(o, dataID).Message)
	r = sh(p, "cat /data/file")
	check(r.stdout == "persisted\n", "still mounted after failed unmount")
	must(busy.s.Signal("KILL"), "kill busy")
	busy.collect(5*time.Second, nil)
	busy.Close()
	t = time.Now()
	o = p.wait("data Detached", 30*time.Second, func(o podapi.Observed) bool { return diskStatus(o, dataID).Phase == podapi.DiskDetached })
	log.Printf("retry detached after %v", time.Since(t).Round(time.Millisecond))
	check(diskStatus(o, dataID).State == "data-state", "Detached after automatic retry")
	r = sh(p, "ls /sys/block; test -e /data/file && echo present || echo absent")
	check(strings.HasSuffix(r.stdout, "absent\n"), "unmounted in guest: %q", r.stdout)
	fsClean(dataImg)
	check(fsCat(dataImg, "/file") == "persisted\n", "data written in the guest is on the detached disk")

	// Read-only mount.
	roImg := mkfs("ro", map[string]string{"hello": "read-only data\n"})
	roID := newID(2)
	desired.Mounts = []podapi.Disk{{ID: roID, Serial: roID, Device: roImg, ReadOnly: true, State: "ro-state", Path: "/mnt/ro/x"}}
	p.setDesired(desired)
	p.wait("ro Mounted", 20*time.Second, func(o podapi.Observed) bool { return diskStatus(o, roID).Phase == podapi.DiskMounted })
	r = sh(p, "cat /mnt/ro/x/hello; touch /mnt/ro/x/new 2>&1; grep ' /mnt/ro/x ' /proc/mounts")
	check(strings.HasPrefix(r.stdout, "read-only data\n") && strings.Contains(r.stdout, "Read-only file system") && strings.Contains(r.stdout, " ro,"), "RO mount readable, writes fail: %q", r.stdout)

	// Path rules.
	sh(p, "ln -s /etc /evil")
	bad := []podapi.Disk{
		{ID: newID(3), Device: mkfs("bad1", nil), Path: "/evil/sub"},
		{ID: newID(4), Device: mkfs("bad2", nil), Path: "/mnt/ro"},
		{ID: newID(5), Device: mkfs("bad3", nil), Path: "/proc/x"},
		{ID: newID(6), Device: mkfs("bad4", nil), Path: "relative"},
	}
	for i := range bad {
		bad[i].Serial = bad[i].ID
	}
	desired.Mounts = append(desired.Mounts, bad...)
	p.setDesired(desired)
	for _, b := range bad {
		o = p.wait("bad mount Failed", 20*time.Second, func(o podapi.Observed) bool { return diskStatus(o, b.ID).Phase == podapi.DiskFailed })
		check(true, "mount at %q rejected: %s", b.Path, diskStatus(o, b.ID).Message)
	}
	desired.Mounts = desired.Mounts[:1]
	p.setDesired(desired)
	for _, b := range bad {
		p.wait("bad mount Detached", 20*time.Second, func(o podapi.Observed) bool { return diskStatus(o, b.ID).Phase == podapi.DiskDetached })
	}
	check(true, "failed mounts detach when removed")

	// Malformed desired keeps the last valid document.
	must(os.WriteFile(p.path(podapi.DesiredFile), []byte("{not json"), 0o644), "bad desired")
	_ = os.Remove(p.path(podapi.DesiredFile))
	time.Sleep(500 * time.Millisecond)
	o = p.observed()
	check(o.Phase == podapi.PhaseRunning && diskStatus(o, roID).Phase == podapi.DiskMounted, "missing/malformed desired keeps state")

	// Explicit stop with the RO mount still attached and a session running.
	keep, err := open(p, wire.Open{Mode: wire.OpenExec, Argv: []string{"sh", "-c", "trap '' TERM; sleep 1000"}})
	must(err, "trap TERM")
	desired.Stop = true
	t = time.Now()
	p.setDesired(desired)
	p.wait("Stopping", 5*time.Second, func(o podapi.Observed) bool { return o.Phase == podapi.PhaseStopping })
	o = p.wait("Exited", 60*time.Second, func(o podapi.Observed) bool { return o.Phase == podapi.PhaseExited })
	log.Printf("stop -> Exited: %v (includes 10s grace for a TERM-ignoring process)", time.Since(t).Round(time.Millisecond))
	keep.Close()
	check(o.Exit != nil && o.Exit.Reason == wire.ReasonStopped && o.Error == "", "observed exit %+v error %q", o.Exit, o.Error)
	p.waitExit(10 * time.Second)
	fsClean(rootImg)
	check(fsCat(rootImg, "/root/marker") == "root-data\n", "root data persisted")
	out, _ = exec.Command("ip", "netns", "exec", netns, "ip", "link", "show").CombinedOutput()
	check(!strings.Contains(string(out), "blip-tap0"), "TAP removed after exit")
}

func scenarioCommand() {
	rootImg := freshRoot("command")
	p := startPod("command", false)
	p.wait("Warm", 30*time.Second, func(o podapi.Observed) bool { return o.Phase == podapi.PhaseWarm })
	rootID := newID(20)
	p.setDesired(podapi.Desired{Claim: &podapi.Claim{
		BlipName: "command", Root: podapi.Disk{ID: rootID, Serial: rootID, Device: rootImg},
		Command: []string{"sh", "-c", "sleep 1; echo cmd-out; echo $CMD_ENV > /cmd; pwd; exit 7"},
		Env:     []string{"CMD_ENV=yes"}, WorkingDir: "/etc",
	}})
	p.wait("Running", 30*time.Second, func(o podapi.Observed) bool { return o.Phase == podapi.PhaseRunning })
	s, err := open(p, wire.Open{Mode: wire.OpenAttach})
	must(err, "attach main")
	r := s.collect(10*time.Second, nil)
	s.Close()
	check(r.stdout == "cmd-out\n/etc\n" && r.exit != nil && r.exit.Code == 7, "attach to main: %q %+v", r.stdout, r.exit)
	o := p.wait("Exited", 30*time.Second, func(o podapi.Observed) bool { return o.Phase == podapi.PhaseExited })
	check(o.Exit != nil && o.Exit.Code == 7 && o.Exit.Reason == wire.ReasonCompleted, "command exit %+v", o.Exit)
	p.waitExit(10 * time.Second)
	fsClean(rootImg)
	check(fsCat(rootImg, "/cmd") == "yes\n", "command output file persisted")
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	return lines[len(lines)-1]
}
