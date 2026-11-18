package gateway

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	kfake "k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/session"
	"github.com/Azure/blip/internal/session/fakeguest"
	"github.com/Azure/blip/internal/wire"
)

const ns = "gw"

func newKey(t *testing.T) (ssh.Signer, string) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s, string(ssh.MarshalAuthorizedKey(s.PublicKey()))
}

type env struct {
	t       *testing.T
	srv     *Server
	kube    client.WithWatch
	guest   *fakeguest.Guest
	userKey ssh.Signer
	started atomic.Bool // the fake controller runs blips once set
}

// withUIDs makes the fake client assign UIDs on create, as an API server does.
// Menu actions use them to reject a stale selection after replacement.
func withUIDs(c client.WithWatch) client.WithWatch {
	return interceptor.NewClient(c, interceptor.Funcs{
		Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			if obj.GetUID() == "" {
				obj.SetUID(types.UID(rand.Text()))
			}
			return c.Create(ctx, obj, opts...)
		},
	})
}

func newEnv(t *testing.T, objs ...client.Object) *env {
	objs = append(objs, gatewayBase())
	kube := withUIDs(catalogClient(t, objs...))
	hostKey, _ := newKey(t)
	userKey, line := newKey(t)
	users := &Users{}
	users.Set(map[string]string{"alice": "# alice\n" + line})
	e := &env{t: t, kube: kube, guest: &fakeguest.Guest{}, userKey: userKey}
	e.started.Store(true)
	e.srv = &Server{
		Config:   Config{Namespace: ns, BaseState: "gateway-base", Pool: "small", StateSize: resource.MustParse("20Gi"), IdleTimeout: 45 * time.Minute},
		Kube:     kube,
		Sessions: &session.Client{Connect: e.guest.Connect},
		Users:    users,
		HostKey:  hostKey,
		Log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	catalog := NewCatalog(kube, ns)
	if err := catalog.Start(ctx); err != nil {
		t.Fatal(err)
	}
	e.srv.Catalog = catalog
	go e.controller(ctx)
	return e
}

// controller marks new blips Running once e.started is set.
func (e *env) controller(ctx context.Context) {
	for ctx.Err() == nil {
		var list v1alpha1.BlipList
		e.kube.List(ctx, &list)
		for i := range list.Items {
			b := &list.Items[i]
			if b.Status.Phase == "" && e.started.Load() {
				b.Status.Phase, b.Status.Pod = v1alpha1.BlipRunning, "pod-"+b.Name
				e.kube.Update(ctx, b)
			}
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func (e *env) dial(user string, key ssh.Signer) (*ssh.Client, error) {
	// net.Pipe would deadlock: both sides send their version line first.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		e.t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	e.t.Cleanup(cancel)
	go e.srv.Serve(ctx, l)
	cfg := &ssh.ClientConfig{User: user, Auth: []ssh.AuthMethod{ssh.PublicKeys(key)}, HostKeyCallback: ssh.FixedHostKey(e.srv.HostKey.PublicKey())}
	c, err := ssh.Dial("tcp", l.Addr().String(), cfg)
	if err != nil {
		return nil, err
	}
	e.t.Cleanup(func() { c.Close() })
	return c, nil
}

func TestUsersSet(t *testing.T) {
	_, k1 := newKey(t)
	_, k2 := newKey(t)
	u := &Users{}
	errs := u.Set(map[string]string{
		"alice":      "# comment\n\n" + k1 + "not a key\n",
		"bob":        k1 + k2,
		"Bad_1":      k2,
		"u-reserved": k2,
	})
	if len(errs) != 4 {
		t.Fatalf("errs = %v", errs)
	}
	pk1, _, _, _, _ := ssh.ParseAuthorizedKey([]byte(k1))
	pk2, _, _, _, _ := ssh.ParseAuthorizedKey([]byte(k2))
	if o, ok := u.Owner(pk1); !ok || o != "alice" {
		t.Fatalf("k1 owner %q", o)
	}
	if o, ok := u.Owner(pk2); !ok || o != "bob" {
		t.Fatalf("k2 owner %q", o)
	}
}

func TestUsersRejectsAuthorizedKeyOptions(t *testing.T) {
	_, line := newKey(t)
	key := strings.TrimSpace(line)
	u := &Users{}
	errs := u.Set(map[string]string{
		"alice": `from="10.0.0.1" ` + key + "\ncommand=\"true\" " + key + "\nrestrict " + key + "\n",
	})
	if len(errs) != 3 {
		t.Fatalf("errs = %v", errs)
	}
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(key))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := u.Owner(pk); ok {
		t.Fatal("a key with options was accepted")
	}
}

func TestDeletedConfigMapUnwrapsTombstone(t *testing.T) {
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: UsersConfigMap, Namespace: ns}}
	if got, ok := deletedConfigMap(cache.DeletedFinalStateUnknown{Key: UsersConfigMap, Obj: cm}); !ok || got != cm {
		t.Fatalf("tombstone: %v %v", got, ok)
	}
	if _, ok := deletedConfigMap(cache.DeletedFinalStateUnknown{Key: "other", Obj: &corev1.Pod{}}); ok {
		t.Fatal("non-ConfigMap tombstone accepted")
	}
	if _, ok := deletedConfigMap(nil); ok {
		t.Fatal("nil object accepted")
	}
}

func TestUsersWatchReloads(t *testing.T) {
	_, k1 := newKey(t)
	pk1, _, _, _, _ := ssh.ParseAuthorizedKey([]byte(k1))
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: UsersConfigMap, Namespace: ns}, Data: map[string]string{"alice": k1}}
	cs := kfake.NewClientset(cm)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	u := &Users{}
	u.Watch(ctx, cs, ns, slog.New(slog.NewTextHandler(io.Discard, nil)))
	eventually(t, func() bool { o, _ := u.Owner(pk1); return o == "alice" })
	cm.Data = map[string]string{"carol": k1}
	if _, err := cs.CoreV1().ConfigMaps(ns).Update(ctx, cm, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	eventually(t, func() bool { o, _ := u.Owner(pk1); return o == "carol" })
	cs.CoreV1().ConfigMaps(ns).Delete(ctx, UsersConfigMap, metav1.DeleteOptions{})
	eventually(t, func() bool { _, ok := u.Owner(pk1); return !ok })
}

func eventually(t *testing.T, f func() bool) {
	t.Helper()
	for i := 0; i < 500; i++ {
		if f() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not met")
}

func TestSandboxName(t *testing.T) {
	for in, want := range map[string]string{"": "default", "dev": "dev", "a-1": "a-1", "Dev": "", "a_b": "", "-a": ""} {
		got, err := SandboxName(in)
		if got != want || (want == "") != (err != nil) {
			t.Errorf("%q: got %q err %v", in, got, err)
		}
	}
}

func TestLoadHostKeyCreatesOnce(t *testing.T) {
	cs := kfake.NewClientset()
	k1, err := LoadHostKey(context.Background(), cs, ns)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := LoadHostKey(context.Background(), cs, ns)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(k1.PublicKey().Marshal(), k2.PublicKey().Marshal()) || k1.PublicKey().Type() != ssh.KeyAlgoED25519 {
		t.Fatal("host key changed or wrong type")
	}
}

func TestEnsureSandboxIsIdempotentAndRecreatesFinished(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	pod, err := e.srv.ensureSandbox(ctx, "alice", "alice.dev")
	if err != nil || pod != "pod-alice.dev" {
		t.Fatalf("pod %q err %v", pod, err)
	}
	var st v1alpha1.BlipState
	if err := e.kube.Get(ctx, client.ObjectKey{Namespace: ns, Name: "alice.dev"}, &st); err != nil {
		t.Fatal(err)
	}
	if st.Spec.Image != "" || st.Spec.CopyFrom != e.srv.BaseState || st.Spec.Size.String() != "20Gi" || st.Labels[v1alpha1.LabelOwner] != "alice" || len(st.OwnerReferences) != 0 ||
		st.Spec.Runtime == nil || st.Spec.Runtime.IdleTimeout.Duration != 45*time.Minute {
		t.Fatalf("state spec %+v labels %v", st.Spec, st.Labels)
	}
	var b v1alpha1.Blip
	e.kube.Get(ctx, client.ObjectKey{Namespace: ns, Name: "alice.dev"}, &b)
	if b.Spec.State != "alice.dev" || b.Spec.Pool != "small" || len(b.Spec.Command) != 0 || b.Spec.IdleTimeout != nil || b.Labels[v1alpha1.LabelOwner] != "alice" {
		t.Fatalf("blip spec %+v labels %v", b.Spec, b.Labels)
	}
	if pod, err := e.srv.ensureSandbox(ctx, "alice", "alice.dev"); err != nil || pod != "pod-alice.dev" {
		t.Fatalf("second call: %q %v", pod, err)
	}

	b.Status.Phase = v1alpha1.BlipSucceeded
	b.Status.Pod = "old-pod"
	e.kube.Update(ctx, &b)
	pod, err = e.srv.ensureSandbox(ctx, "alice", "alice.dev")
	if err != nil || pod != "pod-alice.dev" {
		t.Fatalf("recreate: %q %v", pod, err)
	}
	var list v1alpha1.BlipList
	e.kube.List(ctx, &list)
	if len(list.Items) != 1 {
		t.Fatalf("blips %d", len(list.Items))
	}
}

func TestEnsureSandboxFailedState(t *testing.T) {
	st := &v1alpha1.BlipState{ObjectMeta: metav1.ObjectMeta{Name: "alice.dev", Namespace: ns, Labels: map[string]string{v1alpha1.LabelOwner: "alice"}}}
	st.Status.Phase, st.Status.Message = v1alpha1.StateFailed, "image not found"
	e := newEnv(t, st)
	_, err := e.srv.ensureSandbox(context.Background(), "alice", "alice.dev")
	if err == nil || !strings.Contains(err.Error(), "image not found") {
		t.Fatal(err)
	}
}

func TestFullSandboxNameIsUnambiguous(t *testing.T) {
	a, err := fullSandboxName("alice", "dev-default")
	if err != nil {
		t.Fatal(err)
	}
	b, err := fullSandboxName("alice-dev", "default")
	if err != nil {
		t.Fatal(err)
	}
	if a != "alice.dev-default" || b != "alice-dev.default" || a == b {
		t.Fatalf("names = %q and %q", a, b)
	}
	if n, err := fullSandboxName("u-0123456789abcdef0123456789abcdef", strings.Repeat("a", 28)); err != nil || len(n) != 63 {
		t.Fatalf("63-character name: %q %v", n, err)
	}
	if _, err := fullSandboxName("u-0123456789abcdef0123456789abcdef", strings.Repeat("a", 29)); err == nil {
		t.Fatal("64-character name accepted")
	}
}

func TestEnsureSandboxRejectsCrossOwner(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	if _, err := e.srv.ensureSandbox(ctx, "alice", "alice.dev"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.srv.ensureSandbox(ctx, "bob", "alice.dev"); err == nil || !strings.Contains(err.Error(), "not owned") {
		t.Fatalf("cross-owner state: %v", err)
	}

	// The State belongs to the caller, but the Blip is another owner's.
	st := &v1alpha1.BlipState{ObjectMeta: metav1.ObjectMeta{Name: "bob.dev", Namespace: ns, Labels: map[string]string{v1alpha1.LabelOwner: "bob"}}}
	b := &v1alpha1.Blip{ObjectMeta: metav1.ObjectMeta{Name: "bob.dev", Namespace: ns, Labels: map[string]string{v1alpha1.LabelOwner: "alice"}}}
	e2 := newEnv(t, st, b)
	if _, err := e2.srv.ensureSandbox(ctx, "bob", "bob.dev"); err == nil || !strings.Contains(err.Error(), "not owned") {
		t.Fatalf("cross-owner blip: %v", err)
	}

	// Objects without the label are not served either.
	unlabeled := &v1alpha1.BlipState{ObjectMeta: metav1.ObjectMeta{Name: "carol.dev", Namespace: ns}}
	e3 := newEnv(t, unlabeled)
	if _, err := e3.srv.ensureSandbox(ctx, "carol", "carol.dev"); err == nil || !strings.Contains(err.Error(), "not owned") {
		t.Fatalf("unlabeled state: %v", err)
	}
}

func TestSSHExecExitStatusAndEnv(t *testing.T) {
	e := newEnv(t)
	e.started.Store(false)
	e.guest.Run = func(s *fakeguest.Session) wire.Exit {
		s.Stdout("hi\n")
		s.Stderr("warn\n")
		return wire.Exit{Code: 7}
	}
	c, err := e.dial("", e.userKey)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := c.NewSession()
	if err := s.Setenv("LANG", "C.UTF-8"); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	s.Stdout, s.Stderr = &out, &errb
	go func() { time.Sleep(50 * time.Millisecond); e.started.Store(true) }()
	err = s.Run("echo hi")
	var exit *ssh.ExitError
	if !errors.As(err, &exit) || exit.ExitStatus() != 7 {
		t.Fatalf("err = %v", err)
	}
	if out.String() != "hi\n" || !strings.Contains(errb.String(), "warn") || strings.Contains(errb.String(), "still starting") || strings.Contains(errb.String(), "sandboxed") {
		t.Fatalf("out %q err %q", out.String(), errb.String())
	}
	o := e.guest.Opens()[0]
	if o.Pod != "pod-alice.default" || strings.Join(o.Open.Argv, "|") != "/bin/sh|-c|echo hi" || o.Open.TTY || o.Open.Env[0] != "LANG=C.UTF-8" {
		t.Fatalf("open = %+v", o)
	}
}

// EOF after the open request is written is how a sandbox that stopped
// between ensureSandbox and pod exec looks. The gateway must recreate it and
// retry rather than failing the user's command.
type eofConn struct{}

func (eofConn) Read([]byte) (int, error)    { return 0, io.EOF }
func (eofConn) Write(p []byte) (int, error) { return len(p), nil }
func (eofConn) Close() error                { return nil }

func TestSSHExecRetriesWhenSandboxDisappears(t *testing.T) {
	e := newEnv(t)
	e.guest.Run = func(s *fakeguest.Session) wire.Exit { return wire.Exit{} }
	orig := e.srv.Sessions.Connect
	var first atomic.Bool
	e.srv.Sessions.Connect = func(ctx context.Context, namespace, pod string) (io.ReadWriteCloser, error) {
		if first.CompareAndSwap(false, true) {
			return eofConn{}, nil
		}
		return orig(ctx, namespace, pod)
	}
	c, err := e.dial("", e.userKey)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := c.NewSession()
	if err := s.Run("echo hi"); err != nil {
		t.Fatal(err)
	}
	if n := len(e.guest.Opens()); n != 1 {
		t.Fatalf("guest opened %d sessions, want 1", n)
	}
}

func TestSSHShellWithoutPTYIsDirect(t *testing.T) {
	e := newEnv(t)
	e.guest.Run = func(s *fakeguest.Session) wire.Exit {
		s.Stdout("direct shell\n")
		return wire.Exit{Code: 7}
	}
	c, err := e.dial("dev", e.userKey)
	if err != nil {
		t.Fatal(err)
	}
	s, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	out := newSSHOutput()
	s.Stdout, s.Stderr = out, out
	done := make(chan error, 1)
	go func() {
		if err := s.Shell(); err != nil {
			done <- err
			return
		}
		done <- s.Wait()
	}()
	select {
	case err := <-done:
		var exit *ssh.ExitError
		if !errors.As(err, &exit) || exit.ExitStatus() != 7 {
			t.Fatalf("non-PTY shell exit = %v", err)
		}
	case <-time.After(sshTestTimeout):
		t.Fatalf("non-PTY shell did not exit:\n%s", out.String())
	}
	if out.String() != "direct shell\n" {
		t.Fatalf("non-PTY shell output = %q", out.String())
	}
	opens := e.guest.Opens()
	if len(opens) != 1 || opens[0].Pod != "pod-alice.dev" || opens[0].Open.TTY || opens[0].Open.Argv != nil {
		t.Fatalf("non-PTY shell opens = %+v", opens)
	}
}

func TestSSHSlowStartNotice(t *testing.T) {
	e := newEnv(t)
	e.srv.StartNoticeDelay = 10 * time.Millisecond
	e.started.Store(false)
	e.guest.Run = func(s *fakeguest.Session) wire.Exit { return wire.Exit{} }
	c, err := e.dial("dev", e.userKey)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := c.NewSession()
	var errb bytes.Buffer
	s.Stderr = &errb
	if err := s.RequestPty("xterm-256color", 40, 80, ssh.TerminalModes{}); err != nil {
		t.Fatal(err)
	}
	go func() { time.Sleep(100 * time.Millisecond); e.started.Store(true) }()
	if err := s.Run("true"); err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(errb.String(), `still starting "dev"`); n != 1 {
		t.Fatalf("slow-start notices = %d:\n%s", n, errb.String())
	}
}

func TestSSHExecSlowStartIsSilent(t *testing.T) {
	e := newEnv(t)
	e.srv.StartNoticeDelay = 10 * time.Millisecond
	e.started.Store(false)
	e.guest.Run = func(s *fakeguest.Session) wire.Exit { return wire.Exit{} }
	c, err := e.dial("dev", e.userKey)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := c.NewSession()
	var errb bytes.Buffer
	s.Stderr = &errb
	go func() { time.Sleep(100 * time.Millisecond); e.started.Store(true) }()
	if err := s.Run("true"); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(errb.String(), "still starting") {
		t.Fatalf("non-TTY exec was told about allocation:\n%s", errb.String())
	}
}

func TestSSHExecPTYHasNoBanner(t *testing.T) {
	e := newEnv(t)
	e.guest.Run = func(s *fakeguest.Session) wire.Exit { return wire.Exit{} }
	c, err := e.dial("dev", e.userKey)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := c.NewSession()
	var errb bytes.Buffer
	s.Stderr = &errb
	if err := s.RequestPty("xterm-256color", 40, 80, ssh.TerminalModes{}); err != nil {
		t.Fatal(err)
	}
	if err := s.Run("true"); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(errb.String(), "sandboxed") {
		t.Fatalf("pty exec printed the welcome banner:\n%s", errb.String())
	}
}

func TestSSHExitSignal(t *testing.T) {
	e := newEnv(t)
	e.guest.Run = func(s *fakeguest.Session) wire.Exit { return wire.Exit{Signal: "TERM"} }
	c, err := e.dial("dev", e.userKey)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := c.NewSession()
	err = s.Run("sleep 100")
	var exit *ssh.ExitError
	if !errors.As(err, &exit) || exit.Signal() != "TERM" {
		t.Fatalf("err = %v", err)
	}
}

func TestSSHRejectsUnknownKeyAndBadUser(t *testing.T) {
	e := newEnv(t)
	other, _ := newKey(t)
	if _, err := e.dial("dev", other); err == nil {
		t.Fatal("unknown key accepted")
	}
	if _, err := e.dial("Not_Valid", e.userKey); err == nil {
		t.Fatal("invalid sandbox name accepted")
	}
}

func TestSSHExecPtyResizeAndHangup(t *testing.T) {
	e := newEnv(t)
	got := make(chan []fakeguest.Event, 1)
	resized := make(chan struct{})
	e.guest.Run = func(s *fakeguest.Session) wire.Exit {
		s.Stdout("$ ")
		var evs []fakeguest.Event
		for {
			ev := s.NextEvent()
			evs = append(evs, ev)
			if ev.Resize != nil {
				select {
				case <-resized:
				default:
					close(resized)
				}
			}
			if ev.Signal == "HUP" || ev.Disconnected {
				got <- evs
				return wire.Exit{Code: 129}
			}
		}
	}
	c, err := e.dial("dev", e.userKey)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := c.NewSession()
	if err := s.RequestPty("xterm-256color", 40, 80, ssh.TerminalModes{}); err != nil {
		t.Fatal(err)
	}
	out := newSSHOutput()
	s.Stdout, s.Stderr = out, out
	if err := s.Start("exec /bin/sh"); err != nil {
		t.Fatal(err)
	}
	out.waitFor(t, 0, "$ ")
	if err := s.WindowChange(50, 120); err != nil {
		t.Fatal(err)
	}
	select {
	case <-resized:
	case <-time.After(5 * time.Second):
		t.Fatal("guest did not receive resize")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	var evs []fakeguest.Event
	select {
	case evs = <-got:
	case <-time.After(5 * time.Second):
		t.Fatal("guest did not receive disconnect")
	}
	if len(evs) < 2 || evs[0].Resize == nil || evs[0].Resize.Rows != 50 || evs[0].Resize.Cols != 120 || evs[1].Signal != "HUP" {
		t.Fatalf("events = %+v", evs)
	}
	o := e.guest.Opens()[0].Open
	if !o.TTY || o.Rows != 40 || o.Cols != 80 || strings.Join(o.Argv, "|") != "/bin/sh|-c|exec /bin/sh" || o.Env[0] != "TERM=xterm-256color" {
		t.Fatalf("open = %+v", o)
	}
}

func TestSSHSftpSubsystem(t *testing.T) {
	e := newEnv(t)
	e.guest.Run = func(s *fakeguest.Session) wire.Exit { return wire.Exit{} }
	c, err := e.dial("dev", e.userKey)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := c.NewSession()
	var errb bytes.Buffer
	s.Stderr = &errb
	if err := s.RequestSubsystem("sftp"); err != nil {
		t.Fatal(err)
	}
	s.Wait()
	if strings.Contains(errb.String(), "sandboxed") {
		t.Fatalf("sftp printed the welcome banner:\n%s", errb.String())
	}
	o := e.guest.Opens()[0].Open
	if o.TTY || o.Argv[0] != "/bin/sh" || !strings.Contains(o.Argv[2], "sftp-server") {
		t.Fatalf("open = %+v", o)
	}
	s2, _ := c.NewSession()
	if err := s2.RequestSubsystem("other"); err == nil {
		t.Fatal("unknown subsystem accepted")
	}
}

func TestSSHDirectTCPIP(t *testing.T) {
	e := newEnv(t)
	c, err := e.dial("dev", e.userKey)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := c.Dial("tcp", "localhost:8080")
	if err != nil {
		t.Fatal(err)
	}
	conn.Write([]byte("ping"))
	conn.(interface{ CloseWrite() error }).CloseWrite()
	b, _ := io.ReadAll(conn)
	if string(b) != "ping" {
		t.Fatalf("got %q", b)
	}
	o := e.guest.Opens()[0]
	if o.Pod != "pod-alice.dev" || o.Open.Mode != wire.OpenDial || o.Open.Host != "localhost" || o.Open.Port != 8080 {
		t.Fatalf("open = %+v", o)
	}
}

func TestSSHRejectsCrossOwnerSandbox(t *testing.T) {
	e := newEnv(t)
	bobKey, bobLine := newKey(t)
	e.srv.Users.Set(map[string]string{
		"alice": string(ssh.MarshalAuthorizedKey(e.userKey.PublicKey())),
		"bob":   bobLine,
	})
	// A resource named like bob's sandbox but owned by alice must not be
	// served to bob.
	st := &v1alpha1.BlipState{ObjectMeta: metav1.ObjectMeta{
		Name: "bob.default", Namespace: ns, Labels: map[string]string{v1alpha1.LabelOwner: "alice"},
	}}
	if err := e.kube.Create(context.Background(), st); err != nil {
		t.Fatal(err)
	}
	c, err := e.dial("default", bobKey)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := c.NewSession()
	if err := s.Run("true"); err == nil {
		t.Fatal("cross-owner sandbox served")
	}
	var blips v1alpha1.BlipList
	e.kube.List(context.Background(), &blips)
	if len(blips.Items) != 0 || len(e.guest.Opens()) != 0 {
		t.Fatalf("blips %d, opened %d guest sessions", len(blips.Items), len(e.guest.Opens()))
	}
}

// A state can disappear between ensureState and the Blip starting. The gateway
// must recreate it rather than leave the pending Blip and the SSH client stuck.
func TestEnsureSandboxRecoversMissingState(t *testing.T) {
	e := newEnv(t)
	e.started.Store(false)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	b := &v1alpha1.Blip{
		ObjectMeta: metav1.ObjectMeta{Name: "alice.default", Namespace: ns, Labels: map[string]string{v1alpha1.LabelOwner: "alice"}},
		Spec:       v1alpha1.BlipSpec{State: "alice.default"},
		Status:     v1alpha1.BlipStatus{Phase: v1alpha1.BlipPending, Reason: "StateNotFound"},
	}
	if err := e.kube.Create(ctx, b); err != nil {
		t.Fatal(err)
	}

	type result struct {
		pod string
		err error
	}
	done := make(chan result, 1)
	go func() {
		pod, err := e.srv.ensureSandbox(ctx, "alice", "alice.default")
		done <- result{pod, err}
	}()

	key := client.ObjectKey{Namespace: ns, Name: "alice.default"}
	deadline := time.Now().Add(3 * time.Second)
	for {
		var st v1alpha1.BlipState
		if err := e.kube.Get(ctx, key, &st); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("state was not recreated")
		}
		time.Sleep(10 * time.Millisecond)
	}

	if err := e.kube.Get(ctx, client.ObjectKeyFromObject(b), b); err != nil {
		t.Fatal(err)
	}
	b.Status.Phase, b.Status.Pod, b.Status.Reason = v1alpha1.BlipRunning, "pod-x", ""
	if err := e.kube.Update(ctx, b); err != nil {
		t.Fatal(err)
	}

	select {
	case got := <-done:
		if got.err != nil || got.pod != "pod-x" {
			t.Fatalf("ensureSandbox = %q, %v", got.pod, got.err)
		}
	case <-ctx.Done():
		t.Fatal("ensureSandbox did not recover")
	}
}

// ensureState must not hand back a state that is being deleted: the Blip
// created against it would see StateNotFound moments later.
func TestEnsureStateWaitsForDeletion(t *testing.T) {
	e := newEnv(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	st := &v1alpha1.BlipState{
		ObjectMeta: metav1.ObjectMeta{Name: "alice.default", Namespace: ns, Labels: map[string]string{v1alpha1.LabelOwner: "alice"}, Finalizers: []string{"test"}},
		Spec:       v1alpha1.BlipStateSpec{Image: "reg/dev:1"},
	}
	if err := e.kube.Create(ctx, st); err != nil {
		t.Fatal(err)
	}
	if err := e.kube.Delete(ctx, st); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() { done <- e.srv.ensureState(ctx, "alice", "alice.default") }()
	select {
	case err := <-done:
		t.Fatalf("ensureState returned while the state was deleting: %v", err)
	case <-time.After(100 * time.Millisecond):
	}

	if err := e.kube.Get(ctx, client.ObjectKeyFromObject(st), st); err != nil {
		t.Fatal(err)
	}
	st.Finalizers = nil
	if err := e.kube.Update(ctx, st); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("ensureState did not recreate the state")
	}
}
