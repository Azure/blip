package cli

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
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

func TestParseCollectOpsAndState(t *testing.T) {
	const cwd = "/home/dev/src"
	for _, tc := range []struct {
		in, src, dest, branch string
		git                   bool
	}{
		{"/out/a.log:./a.log", "/out/a.log", "a.log", "", false},
		{"/out:./artifacts", "/out", "artifacts", "", false},
		{"notes.txt:./notes.txt", "/home/dev/src/notes.txt", "notes.txt", "", false},
		{"/a/../b:/tmp/x", "/b", "/tmp/x", "", false},
		{"git:/work/repo:w1", "/work/repo", "", "w1", true},
		{"git:.:w1", "/home/dev/src", "", "w1", true},
		{"git:/work/repo:feature/x", "/work/repo", "", "feature/x", true},
	} {
		op, err := parseCollectOp(tc.in, cwd)
		if err != nil || op.source != tc.src || op.dest != tc.dest || op.branch != tc.branch || op.git != tc.git {
			t.Errorf("%q: got %+v %v, want src %q dest %q branch %q git %v", tc.in, op, err, tc.src, tc.dest, tc.branch, tc.git)
		}
	}
	for _, in := range []string{"", "w1", ":path", "path:", "git:", "git::w1", "git:/w:", "git:/w:-x"} {
		if _, err := parseCollectOp(in, cwd); err == nil {
			t.Errorf("%q: accepted", in)
		}
	}

	b := runningBlip("w",
		v1alpha1.Mount{State: "repo", Path: "/work"},
		v1alpha1.Mount{State: "nested", Path: "/work/repo/deep"},
	)
	b.Spec.State = "root"
	for dir, want := range map[string][2]string{
		"/work/repo/sub":    {"repo", "/repo/sub"},
		"/work/repo/deep/x": {"nested", "/x"},
		"/work":             {"repo", ""},
		"/home/dev":         {"root", "/home/dev"},
	} {
		if s, rel := stateForPath(b, dir); s != want[0] || rel != want[1] {
			t.Errorf("%s: got %q %q, want %q %q", dir, s, rel, want[0], want[1])
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

func TestCollectMountSharesAndReusesMounts(t *testing.T) {
	defer func(r string) { collectMountRoot = r }(collectMountRoot)
	collectMountRoot = "/run/blip-collect"
	ctx := context.Background()
	h := newHarness(t, gitObjects()...)
	h.self = "alice.box"
	checkout := func() (string, func()) {
		a := &app{env: h.env(strings.NewReader(""), io.Discard, io.Discard)}
		dir, cleanup, err := a.collectMount(ctx, "alice.w1")
		if err != nil {
			t.Fatal(err)
		}
		return dir, cleanup
	}
	// Concurrent collects share the mount; the last one removes it.
	dir1, done1 := checkout()
	if m := findSpecMount(h.blip("alice.box").Spec.Mounts, "alice.w1"); m == nil || m.Writable {
		t.Fatalf("new mount is not read-only: %+v", m)
	}
	dir2, done2 := checkout()
	if dir1 != "/run/blip-collect/alice.w1" || dir2 != dir1 {
		t.Fatalf("dirs %q %q", dir1, dir2)
	}
	done1()
	if m := h.blip("alice.box").Spec.Mounts; len(m) != 1 {
		t.Fatalf("mount removed under another collect: %+v", m)
	}
	done2()
	if b := h.blip("alice.box"); len(b.Spec.Mounts) != 0 || b.Annotations[collectMountsAnnotation] != "" {
		t.Fatalf("mounts %+v annotations %v", b.Spec.Mounts, b.Annotations)
	}
	waitForCond(t, func() bool { return len(h.blip("alice.box").Status.Mounts) == 0 })

	// A mount of the caller's own is used and kept.
	if code, _, errOut := h.run("", "mount", "w1", "--path", "/w1", "--write"); code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	dir, done := checkout()
	done()
	if m := h.blip("alice.box").Spec.Mounts; dir != "/w1" || len(m) != 1 || !m[0].Writable {
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

// withCollectMountRoot points collect's mounts at a temporary directory for
// the duration of a test.
func withCollectMountRoot(t *testing.T) string {
	t.Helper()
	old := collectMountRoot
	root := t.TempDir()
	collectMountRoot = root
	t.Cleanup(func() { collectMountRoot = old })
	return root
}

func requireGit(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
}

// gitInit makes an empty repository at dir.
func gitInit(t *testing.T, dir string) {
	t.Helper()
	if out, err := exec.Command("git", "init", "-q", "-b", "main", dir).CombinedOutput(); err != nil {
		t.Fatalf("git init %s: %v %s", dir, err, out)
	}
}

// gitRun runs git in dir and returns its trimmed output.
func gitRun(t *testing.T, dir string, args ...string) string {
	t.Helper()
	args = append([]string{"-C", dir}, args...)
	out, err := exec.Command("git", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v %s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// assertCollectReleased checks that collect removed its mount and its use
// count from the caller blip.
func assertCollectReleased(t *testing.T, h *harness, blip, state string) {
	t.Helper()
	b := h.blip(blip)
	if m := findSpecMount(b.Spec.Mounts, state); m != nil {
		t.Fatalf("%s still mounts %s: %+v", blip, state, b.Spec.Mounts)
	}
	if v := b.Annotations[collectMountsAnnotation]; v != "" {
		t.Fatalf("%s annotation = %q, want cleared", blip, v)
	}
	waitForCond(t, func() bool { return findMount(h.blip(blip).Status.Mounts, state) == nil })
}

// TestCollectGit runs blip collect against real repositories.
func TestCollectGit(t *testing.T) {
	requireGit(t)

	t.Run("current directory", func(t *testing.T) {
		withCollectMountRoot(t)
		dst := filepath.Join(t.TempDir(), "dst")
		gitInit(t, dst)
		// The relative source resolves to the caller's cwd, which
		// stateForPath places under the worker's state root.
		commit := gitRepo(t, filepath.Join(collectMountRoot, "alice.w1", dst))
		h := newHarness(t, gitObjects()...)
		h.self = "alice.box"
		t.Chdir(dst)
		code, _, errOut := h.run("", "collect", "w1", "git:.:w1")
		if code != 0 {
			t.Fatalf("code %d: %s", code, errOut)
		}
		if got := gitRun(t, dst, "rev-parse", "w1"); got != commit {
			t.Fatalf("w1 = %s, want %s", got, commit)
		}
		assertCollectReleased(t, h, "alice.box", "alice.w1")
	})

	t.Run("subdirectory", func(t *testing.T) {
		withCollectMountRoot(t)
		dst := filepath.Join(t.TempDir(), "dst")
		gitInit(t, dst)
		sub := filepath.Join(dst, "repo", "sub")
		if err := os.MkdirAll(sub, 0o755); err != nil {
			t.Fatal(err)
		}
		// The corresponding source path is a subdirectory of the source
		// repository, so fetching has to resolve the repository top level.
		src := filepath.Join(collectMountRoot, "alice.w1", dst)
		commit := gitRepo(t, src)
		if err := os.MkdirAll(filepath.Join(src, "repo", "sub"), 0o755); err != nil {
			t.Fatal(err)
		}
		h := newHarness(t, gitObjects()...)
		h.self = "alice.box"
		t.Chdir(sub)
		code, _, errOut := h.run("", "collect", "w1", "git:.:w1")
		if code != 0 {
			t.Fatalf("code %d: %s", code, errOut)
		}
		if got := gitRun(t, dst, "rev-parse", "w1"); got != commit {
			t.Fatalf("w1 = %s, want %s", got, commit)
		}
		assertCollectReleased(t, h, "alice.box", "alice.w1")
	})

	t.Run("explicit path", func(t *testing.T) {
		withCollectMountRoot(t)
		dst := filepath.Join(t.TempDir(), "dst")
		gitInit(t, dst)
		commit := gitRepo(t, filepath.Join(collectMountRoot, "alice.w1", "home/dev/src"))
		h := newHarness(t, gitObjects()...)
		h.self = "alice.box"
		t.Chdir(dst)
		code, _, errOut := h.run("", "collect", "w1", "git:/home/dev/src:w1")
		if code != 0 {
			t.Fatalf("code %d: %s", code, errOut)
		}
		if got := gitRun(t, dst, "rev-parse", "w1"); got != commit {
			t.Fatalf("w1 = %s, want %s", got, commit)
		}
		assertCollectReleased(t, h, "alice.box", "alice.w1")
	})

	t.Run("git directory outside state", func(t *testing.T) {
		withCollectMountRoot(t)
		dst := filepath.Join(t.TempDir(), "dst")
		gitInit(t, dst)
		outside := filepath.Join(t.TempDir(), "outside")
		gitRepo(t, outside)
		src := filepath.Join(collectMountRoot, "alice.w1", "repo")
		gitRepo(t, src)
		if err := os.RemoveAll(filepath.Join(src, ".git")); err != nil {
			t.Fatal(err)
		}
		gitdir := "gitdir: " + filepath.Join(outside, ".git") + "\n"
		if err := os.WriteFile(filepath.Join(src, ".git"), []byte(gitdir), 0o644); err != nil {
			t.Fatal(err)
		}
		h := newHarness(t, gitObjects()...)
		h.self = "alice.box"
		t.Chdir(dst)
		code, _, errOut := h.run("", "collect", "w1", "git:/repo:w1")
		if code != 1 || !strings.Contains(errOut, "git directory outside state") {
			t.Fatalf("code %d stderr %q", code, errOut)
		}
		assertCollectReleased(t, h, "alice.box", "alice.w1")
	})

	t.Run("git failure releases mount", func(t *testing.T) {
		withCollectMountRoot(t)
		dst := filepath.Join(t.TempDir(), "dst")
		gitInit(t, dst)
		gitRepo(t, filepath.Join(collectMountRoot, "alice.w1", dst))
		h := newHarness(t, gitObjects()...)
		h.self = "alice.box"
		t.Chdir(dst)
		code, _, errOut := h.run("", "collect", "w1", "git:"+dst+":nope")
		if code == 0 {
			t.Fatalf("fetch of a nonexistent ref succeeded: %s", errOut)
		}
		assertCollectReleased(t, h, "alice.box", "alice.w1")
	})
}

func TestCollectRejections(t *testing.T) {
	worker := ownedBlip("alice.w1", "alice.w1")
	worker.Status.Phase = v1alpha1.BlipSucceeded
	failed := readyState("alice.w1")
	failed.Status.Phase = v1alpha1.StateFailed
	failed.Status.Message = "disk broke"
	for _, tc := range []struct {
		name string
		objs []client.Object
		self string
		args []string
		want string
	}{
		{"outside a blip", gitObjects(), "", []string{"collect", "w1", "/:./out"},
			"collect only works inside a blip"},
		{"self", gitObjects(), "alice.box", []string{"collect", "box", "/:./out"},
			"cannot collect from box, the blip running this collect"},
		{"missing worker", gitObjects(), "alice.box", []string{"collect", "nope", "/:./out"},
			`blip "alice.nope" not found`},
		{"blip with path", gitObjects(), "alice.box", []string{"collect", "w1:/src", "/:./out"},
			`invalid blip "w1:/src"`},
		{"image root", []client.Object{ownedBlip("alice.box", "alice.home"), func() *v1alpha1.Blip {
			b := runningBlip("alice.imgbox")
			b.Labels = map[string]string{ownerLabel: "alice"}
			return b
		}()},
			"alice.box", []string{"collect", "imgbox", "/:./out"},
			"is not on a state of blip imgbox"},
		{"invalid operation", gitObjects(), "alice.box", []string{"collect", "w1", "nonsense"},
			`invalid operation "nonsense"`},
		{"failed state", []client.Object{ownedBlip("alice.box", "alice.home"), worker, failed},
			"alice.box", []string{"collect", "w1", "/:./out"},
			`state "alice.w1" failed: disk broke`},
		{"missing state", []client.Object{ownedBlip("alice.box", "alice.home"), worker},
			"alice.box", []string{"collect", "w1", "/:./out"},
			`state "alice.w1" not found`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, tc.objs...)
			h.self = tc.self
			code, _, errOut := h.run("", tc.args...)
			if code != 1 || !strings.Contains(errOut, tc.want) {
				t.Fatalf("code %d stderr %q, want %q", code, errOut, tc.want)
			}
		})
	}
}
