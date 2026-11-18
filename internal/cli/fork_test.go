package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/Azure/blip/api/v1alpha1"
)

// ownedBlip is a running sandbox of owner alice with a state root.
func ownedBlip(name, root string, mounts ...v1alpha1.Mount) *v1alpha1.Blip {
	b := runningBlip(name, mounts...)
	b.Labels = map[string]string{ownerLabel: "alice"}
	b.Spec.Image, b.Spec.State = "", root
	return b
}

func TestSelfScopesNamesAndLabelsObjects(t *testing.T) {
	h := newHarness(t, ownedBlip("alice.box", "alice.home"), readyState("alice.repo"))
	h.self = "alice.box"
	code, out, errOut := h.run("", "run", "w1", "--image", "img", "-d", "--mount", "repo:/r", "--", "true")
	if code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	mustContain(t, out, "blip/w1 created")
	b := h.blip("alice.w1")
	if b.Labels[ownerLabel] != "alice" || b.Spec.Mounts[0].State != "alice.repo" {
		t.Fatalf("labels %v mounts %+v", b.Labels, b.Spec.Mounts)
	}
	h.ctrl.set(func(c *fakeController) { c.exited["alice.w1"] = 0 })
	code, out, _ = h.run("", "wait", "alice.w1")
	if code != 0 || !strings.HasPrefix(out, "blip/w1 Succeeded") {
		t.Fatalf("code %d out %q", code, out)
	}

	// The separator is always ".", whatever the caller's own name.
	h2 := newHarness(t, ownedBlip("alice-box", "alice.home"))
	h2.self = "alice-box"
	if code, _, errOut := h2.run("", "run", "w1", "--image", "img", "-d"); code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	h2.blip("alice.w1")

	// Without an owner, names are not scoped.
	h3 := newHarness(t, runningBlip("agent"))
	h3.self = "agent"
	if code, _, errOut := h3.run("", "run", "w1", "--image", "img", "-d"); code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	if b := h3.blip("w1"); b.Labels[ownerLabel] != "" {
		t.Fatalf("labels %v", b.Labels)
	}
}

func TestForkRoot(t *testing.T) {
	self := ownedBlip("alice.box", "alice.home")
	self.Spec.Pool, self.Spec.User = "big", "dev"
	h := newHarness(t, self, readyState("alice.home"))
	h.self = "alice.box"
	code, out, errOut := h.run("", "run", "w1", "--fork", "/", "-d", "--", "sh", "-c", "make")
	if code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	mustContain(t, out, "blip/w1 created")
	b := h.blip("alice.w1")
	wd, _ := os.Getwd()
	if b.Spec.State != "alice.w1" || b.Spec.Image != "" || b.Spec.Pool != "big" || b.Spec.User != "dev" || b.Spec.WorkingDir != wd {
		t.Fatalf("spec = %+v", b.Spec)
	}
	s := h.state("alice.w1")
	if s.Spec.CopyFrom != "alice.home" || s.Spec.Replicas != 1 || s.Labels[ownerLabel] != "alice" {
		t.Fatalf("state = %+v %v", s.Spec, s.Labels)
	}
	if refs := s.OwnerReferences; len(refs) != 1 || refs[0].Kind != "Blip" || refs[0].Name != "alice.w1" || refs[0].UID != b.UID || *refs[0].Controller {
		t.Fatalf("owner refs = %+v", refs)
	}
}

func TestForkCreatesNothingOnStateFailure(t *testing.T) {
	// An existing state of the worker's name is not reused.
	h := newHarness(t, ownedBlip("alice.box", "alice.home"), readyState("alice.home"), readyState("alice.w1"))
	h.self = "alice.box"
	code, _, errOut := h.run("", "run", "w1", "--fork", "/", "-d")
	if code != 1 || !strings.Contains(errOut, `state "w1" already exists`) {
		t.Fatalf("code %d: %s", code, errOut)
	}
	var b v1alpha1.Blip
	if err := h.kube.Get(context.Background(), client.ObjectKey{Namespace: ns, Name: "alice.w1"}, &b); !apierrors.IsNotFound(err) {
		t.Fatalf("blip created: %v", err)
	}

	// The worker is deleted if its copy cannot be created.
	h = newHarness(t, ownedBlip("alice.box", "alice.home"), readyState("alice.home"))
	h.self = "alice.box"
	h.kube = interceptor.NewClient(h.kube, interceptor.Funcs{Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
		if _, ok := obj.(*v1alpha1.BlipState); ok {
			return apierrors.NewForbidden(v1alpha1.GroupVersion.WithResource("blipstates").GroupResource(), obj.GetName(), errors.New("denied"))
		}
		return c.Create(ctx, obj, opts...)
	}})
	code, _, errOut = h.run("", "run", "w1", "--fork", "/", "-d")
	if code != 1 || !strings.Contains(errOut, "denied") {
		t.Fatalf("code %d: %s", code, errOut)
	}
	if err := h.kube.Get(context.Background(), client.ObjectKey{Namespace: ns, Name: "alice.w1"}, &b); !apierrors.IsNotFound(err) {
		t.Fatalf("blip left behind: %v", err)
	}
}

func TestForkMountDefaultsImageThroughCopies(t *testing.T) {
	base := readyState("alice.base")
	base.Spec.Image = "reg/dev:1"
	home := readyState("alice.home")
	home.Spec.CopyFrom = "alice.base"
	h := newHarness(t, ownedBlip("alice.box", "alice.home", v1alpha1.Mount{State: "alice.repo", Path: "/work", Writable: true}),
		base, home, readyState("alice.repo"))
	h.self = "alice.box"
	code, _, errOut := h.run("", "run", "w2", "--fork", "/work/", "-w", "/work/src", "-d", "--", "true")
	if code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	b := h.blip("alice.w2")
	want := v1alpha1.Mount{State: "alice.w2", Path: "/work", Writable: true}
	if b.Spec.Image != "reg/dev:1" || b.Spec.State != "" || b.Spec.WorkingDir != "/work/src" || len(b.Spec.Mounts) != 1 || b.Spec.Mounts[0] != want {
		t.Fatalf("spec = %+v", b.Spec)
	}
	if s := h.state("alice.w2"); s.Spec.CopyFrom != "alice.repo" {
		t.Fatalf("state = %+v", s.Spec)
	}
}

func TestForkMountCwdOutsideFallsBackToMount(t *testing.T) {
	home := readyState("alice.home")
	home.Spec.Image = "reg/dev:1"
	h := newHarness(t, ownedBlip("alice.box", "alice.home", v1alpha1.Mount{State: "alice.repo", Path: "/work", Writable: true}),
		home, readyState("alice.repo"))
	h.self = "alice.box"
	code, _, errOut := h.run("", "run", "w1", "--fork", "/work", "-d", "--", "true")
	if code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	if got := h.blip("alice.w1").Spec.WorkingDir; got != "/work" {
		t.Fatalf("working dir = %q, want fork mount", got)
	}
}

func TestForkRejections(t *testing.T) {
	imageRooted := runningBlip("imgbox", v1alpha1.Mount{State: "repo", Path: "/work"})
	bare := readyState("alice.bare")
	h := newHarness(t, ownedBlip("alice.box", "alice.home"), readyState("alice.home"), imageRooted, ownedBlip("alice.nobase", "alice.bare", v1alpha1.Mount{State: "alice.repo", Path: "/w"}), bare)
	for _, tc := range []struct {
		self string
		args []string
		want string
	}{
		{"", []string{"run", "x", "--fork", "/", "-d"}, "--fork only works inside a blip"},
		{"alice.box", []string{"run", "x", "--fork", "/", "--state", "s", "-d"}, "--fork and --state cannot be combined"},
		{"alice.box", []string{"run", "x", "--fork", "/", "--image", "i", "-d"}, "--image cannot be combined with --fork /"},
		{"imgbox", []string{"run", "x", "--fork", "/", "-d"}, "--fork / needs a blip with a state root"},
		{"alice.box", []string{"run", "x", "--fork", "/nope", "-d"}, "no state is mounted at /nope"},
		{"alice.nobase", []string{"run", "x", "--fork", "/w", "-d"}, "set --image"},
	} {
		h.self = tc.self
		code, _, errOut := h.run("", tc.args...)
		if code != 1 || !strings.Contains(errOut, tc.want) {
			t.Errorf("%v: code %d stderr %q", tc.args, code, errOut)
		}
	}
	var states v1alpha1.BlipStateList
	h.kube.List(context.Background(), &states)
	if len(states.Items) != 2 {
		t.Fatalf("rejected forks created states: %d", len(states.Items))
	}
}

func TestMountDefaultsToSelf(t *testing.T) {
	h := newHarness(t, runningBlip("agent"), readyState("repo"))
	code, _, errOut := h.run("", "mount", "repo", "--path", "/work")
	if code != 1 || !strings.Contains(errOut, "--blip is required outside a blip") {
		t.Fatalf("code %d err %q", code, errOut)
	}
	h.self = "agent"
	if code, _, errOut := h.run("", "mount", "repo", "--path", "/work"); code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	if code, _, errOut := h.run("", "unmount", "repo"); code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
}

func TestParseGitURLAndState(t *testing.T) {
	for in, want := range map[string][2]string{
		"w1/home/dev/src":        {"w1", "/home/dev/src"},
		"blip::w1/home/dev/src/": {"w1", "/home/dev/src"},
		"w1/":                    {"w1", "/"},
	} {
		name, dir, err := parseGitURL(in)
		if err != nil || name != want[0] || dir != want[1] {
			t.Errorf("%q: %q %q %v", in, name, dir, err)
		}
	}
	if _, _, err := parseGitURL("w1"); err == nil {
		t.Error("URL without a path accepted")
	}
	b := runningBlip("w", v1alpha1.Mount{State: "a", Path: "/work"}, v1alpha1.Mount{State: "b", Path: "/work/src"})
	b.Spec.State = "root"
	for dir, want := range map[string][2]string{
		"/work/src/x": {"b", "/x"},
		"/work/src":   {"b", ""},
		"/work/srcx":  {"a", "/srcx"},
		"/home/dev":   {"root", "/home/dev"},
	} {
		if s, rel := gitStateFor(b, dir); s != want[0] || rel != want[1] {
			t.Errorf("%s: %q %q", dir, s, rel)
		}
	}
}

// gitRepo makes a repository at dir with branch w1 and returns its commit.
func gitRepo(t *testing.T, dir string) string {
	t.Helper()
	for _, args := range [][]string{
		{"init", "-q", "-b", "w1", dir},
		{"-C", dir, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "--allow-empty", "-m", "w1"},
	} {
		if out, err := exec.Command("git", args...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
	}
	out, err := exec.Command("git", "-C", dir, "rev-parse", "HEAD").Output()
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(out))
}

func gitObjects() []client.Object {
	worker := ownedBlip("alice.w1", "alice.w1")
	worker.Status.Phase = v1alpha1.BlipSucceeded
	return []client.Object{ownedBlip("alice.box", "alice.home"), worker, readyState("alice.w1")}
}

func TestGitRemoteHelperServesWorkerStateReadOnly(t *testing.T) {
	root := t.TempDir()
	defer func(r string) { gitMountRoot = r }(gitMountRoot)
	gitMountRoot = root
	commit := gitRepo(t, filepath.Join(root, "alice.w1", "home/dev/src"))
	h := newHarness(t, gitObjects()...)
	h.self = "alice.box"
	var out, errOut bytes.Buffer
	in := strings.NewReader("capabilities\nconnect git-upload-pack\n0000")
	code := GitRemoteMain(context.Background(), h.env(in, &out, &errOut), []string{"origin", "blip::w1/home/dev/src"})
	if code != 0 {
		t.Fatalf("code %d: %s", code, errOut.String())
	}
	if !strings.HasPrefix(out.String(), "connect\n\n\n") || !strings.Contains(out.String(), commit+" refs/heads/w1") {
		t.Fatalf("out %q", out.String())
	}
	waitForCond(t, func() bool { return len(h.blip("alice.box").Spec.Mounts) == 0 })

	in = strings.NewReader("capabilities\nconnect git-receive-pack\n")
	if code := GitRemoteMain(context.Background(), h.env(in, &out, &errOut), []string{"origin", "w1/home/dev/src"}); code != 1 ||
		!strings.Contains(errOut.String(), "blip: push is not supported (read-only)") {
		t.Fatalf("code %d err %q", code, errOut.String())
	}

	s := h.state("alice.w1")
	s.Status.Writer = &v1alpha1.Writer{BlipName: "alice.w1"}
	if err := h.kube.Update(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	errOut.Reset()
	in = strings.NewReader("capabilities\nconnect git-upload-pack\n")
	if code := GitRemoteMain(context.Background(), h.env(in, &out, &errOut), []string{"origin", "w1/home/dev/src"}); code != 1 ||
		!strings.Contains(errOut.String(), "blip: w1 is still running; wait for it to finish (blip wait w1)") {
		t.Fatalf("code %d err %q", code, errOut.String())
	}
}

func TestGitCheckoutSharesAndReusesMounts(t *testing.T) {
	defer func(r string) { gitMountRoot = r }(gitMountRoot)
	gitMountRoot = "/run/blip-git"
	ctx := context.Background()
	h := newHarness(t, gitObjects()...)
	h.self = "alice.box"
	checkout := func() (string, func()) {
		a := &app{env: h.env(strings.NewReader(""), io.Discard, io.Discard)}
		dir, cleanup, err := a.gitCheckout(ctx, "w1", "/src")
		if err != nil {
			t.Fatal(err)
		}
		return dir, cleanup
	}
	// Concurrent fetches share the mount; the last one removes it.
	dir1, done1 := checkout()
	dir2, done2 := checkout()
	if dir1 != "/run/blip-git/alice.w1/src" || dir2 != dir1 {
		t.Fatalf("dirs %q %q", dir1, dir2)
	}
	done1()
	if m := h.blip("alice.box").Spec.Mounts; len(m) != 1 {
		t.Fatalf("mount removed under another fetch: %+v", m)
	}
	done2()
	if b := h.blip("alice.box"); len(b.Spec.Mounts) != 0 || b.Annotations[gitMountsAnnotation] != "" {
		t.Fatalf("mounts %+v annotations %v", b.Spec.Mounts, b.Annotations)
	}
	waitForCond(t, func() bool { return len(h.blip("alice.box").Status.Mounts) == 0 })

	// A mount of the caller's own is used and kept.
	if code, _, errOut := h.run("", "mount", "w1", "--path", "/w1", "--write"); code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	dir, done := checkout()
	done()
	if m := h.blip("alice.box").Spec.Mounts; dir != "/w1/src" || len(m) != 1 || !m[0].Writable {
		t.Fatalf("dir %q mounts %+v", dir, m)
	}
}

func waitForCond(t *testing.T, f func() bool) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); !f(); time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("timed out")
		}
	}
}

// TestGitFetch runs a real `git fetch blip::...` with this test binary
// installed as git-remote-blip (see TestMain).
func TestGitFetch(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	tmp := t.TempDir()
	root := filepath.Join(tmp, "mounts")
	commit := gitRepo(t, filepath.Join(root, "alice.w1", "home/dev/src"))
	objs, err := json.Marshal(gitObjects())
	if err != nil {
		t.Fatal(err)
	}
	objFile := filepath.Join(tmp, "objects.json")
	bin := filepath.Join(tmp, "bin")
	exe, _ := os.Executable()
	if err := os.WriteFile(objFile, objs, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(exe, filepath.Join(bin, "git-remote-blip")); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(tmp, "dst")
	if out, err := exec.Command("git", "init", "-q", dst).CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	cmd := exec.Command("git", "-C", dst, "fetch", "-q", "blip::w1/home/dev/src", "w1")
	cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "BLIP_TEST_OBJECTS="+objFile, "BLIP_TEST_MOUNTS="+root)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git fetch: %v %s", err, out)
	}
	out, err := exec.Command("git", "-C", dst, "rev-parse", "FETCH_HEAD").Output()
	if err != nil || strings.TrimSpace(string(out)) != commit {
		t.Fatalf("FETCH_HEAD %q %v, want %s", out, err, commit)
	}
}

func TestMain(m *testing.M) {
	if IsGitRemoteHelper(os.Args[0]) {
		os.Exit(fakeGitRemote())
	}
	os.Exit(m.Run())
}

// fakeGitRemote runs the helper against fake objects from TestGitFetch.
func fakeGitRemote() int {
	data, err := os.ReadFile(os.Getenv("BLIP_TEST_OBJECTS"))
	if err != nil {
		panic(err)
	}
	var raw []json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		panic(err)
	}
	b := fake.NewClientBuilder().WithScheme(Scheme)
	for i, r := range raw {
		var obj client.Object = &v1alpha1.Blip{}
		if i == len(raw)-1 {
			obj = &v1alpha1.BlipState{}
		}
		if err := json.Unmarshal(r, obj); err != nil {
			panic(err)
		}
		b.WithObjects(obj)
	}
	b.WithObjects(&v1alpha1.BlipPool{ObjectMeta: metav1.ObjectMeta{Name: "default", Namespace: ns}})
	kube := b.Build()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go (&fakeController{kube: kube, exited: map[string]int32{}}).loop(ctx)
	gitMountRoot = os.Getenv("BLIP_TEST_MOUNTS")
	nsFile := filepath.Join(filepath.Dir(os.Getenv("BLIP_TEST_OBJECTS")), "namespace")
	_ = os.WriteFile(nsFile, []byte(ns), 0o644)
	env := &Env{In: os.Stdin, Out: os.Stdout, Err: os.Stderr, NamespaceFile: nsFile,
		Hostname: func() (string, error) { return "alice.box", nil },
		Connect:  func(KubeFlags) (*Clients, error) { return &Clients{Kube: kube, Namespace: ns}, nil }}
	return GitRemoteMain(ctx, env, os.Args[1:])
}
