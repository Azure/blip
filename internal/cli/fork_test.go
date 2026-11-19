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
	b.Labels = map[string]string{v1alpha1.LabelOwner: "alice"}
	b.Spec.State = root
	return b
}

func TestSelfScopesNamesAndLabelsObjects(t *testing.T) {
	h := newHarness(t, ownedBlip("alice.box", "alice.home"), readyState("alice.repo"))
	h.self = "alice.box"
	h.ctrl.set(func(c *fakeController) { c.autoFinish = true })
	code, out, errOut := h.run("", "run", "--name", "w1", "--state", "repo", "--", "true")
	if code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	if strings.TrimSpace(out) != "w1" {
		t.Fatalf("output %q", out)
	}
	b := h.blip("alice.w1")
	if b.Labels[v1alpha1.LabelOwner] != "alice" || b.Spec.State != "alice.repo" {
		t.Fatalf("labels %v spec %+v", b.Labels, b.Spec)
	}
	if fin := h.waitBlip("alice.w1"); fin.Status.Phase != v1alpha1.BlipSucceeded {
		t.Fatalf("phase %q", fin.Status.Phase)
	}

	// The separator is always ".", whatever the caller's own name.
	h2 := newHarness(t, ownedBlip("alice-box", "alice.home"))
	h2.self = "alice-box"
	h2.ctrl.set(func(c *fakeController) { c.autoFinish = true })
	if code, _, errOut := h2.run("", "run", "--name", "w1", "--from", "home", "--", "true"); code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	h2.blip("alice.w1")

	// Without an owner, names are not scoped.
	h3 := newHarness(t, runningBlip("agent"))
	h3.self = "agent"
	h3.ctrl.set(func(c *fakeController) { c.autoFinish = true })
	if code, _, errOut := h3.run("", "run", "--name", "w1", "--from", "agent-root", "--", "true"); code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	if b := h3.blip("w1"); b.Labels[v1alpha1.LabelOwner] != "" {
		t.Fatalf("labels %v", b.Labels)
	}
}

func TestForkRoot(t *testing.T) {
	self := ownedBlip("alice.box", "alice.home")
	self.Spec.Pool, self.Spec.User = "big", "dev"
	home := readyState("alice.home")
	home.Spec.Runtime = &v1alpha1.RuntimeDefaults{User: "workspace-user", WorkingDir: "/work"}
	h := newHarness(t, self, home)
	h.self = "alice.box"
	h.ctrl.set(func(c *fakeController) { c.autoFinish = true })
	code, _, errOut := h.run("", "run", "--name", "w1", "--from", "/", "--", "sh", "-c", "make")
	if code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	b := h.blip("alice.w1")
	// Inside a blip the working directory defaults to the caller's cwd.
	if b.Spec.State != "alice.w1" || b.Spec.Pool != "big" || b.Spec.User != "" || b.Spec.WorkingDir != cwd {
		t.Fatalf("spec = %+v", b.Spec)
	}
	s := h.state("alice.w1")
	if s.Spec.CopyFrom != "alice.home" || s.Spec.Replicas != 0 || s.Labels[v1alpha1.LabelOwner] != "alice" || s.Spec.Runtime.User != "workspace-user" {
		t.Fatalf("state = %+v %v", s.Spec, s.Labels)
	}
	// The fork is owned by the blip so deleting it frees the workspace.
	if refs := s.OwnerReferences; len(refs) != 1 || refs[0].Kind != "Blip" || refs[0].Name != "alice.w1" {
		t.Fatalf("owner refs = %+v", refs)
	}
	// run returns only after the fork's first snapshot is committed.
	if s.Status.Committed == nil {
		t.Fatalf("workspace has no snapshot: %+v", s.Status)
	}
}

func TestForkCreatesNothingOnStateFailure(t *testing.T) {
	// An existing state of the worker's name is not reused.
	h := newHarness(t, ownedBlip("alice.box", "alice.home"), readyState("alice.home"), readyState("alice.w1"))
	h.self = "alice.box"
	code, _, errOut := h.run("", "run", "--name", "w1", "--from", "/", "--", "true")
	if code != 1 || !strings.Contains(errOut, `state for blip "w1" already exists`) {
		t.Fatalf("code %d: %s", code, errOut)
	}
	var b v1alpha1.Blip
	if err := h.kube.Get(context.Background(), client.ObjectKey{Namespace: ns, Name: "alice.w1"}, &b); !apierrors.IsNotFound(err) {
		t.Fatalf("blip created: %v", err)
	}

	// The execution is never created if its workspace cannot be created.
	h = newHarness(t, ownedBlip("alice.box", "alice.home"), readyState("alice.home"))
	h.self = "alice.box"
	h.kube = interceptor.NewClient(h.kube, interceptor.Funcs{Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
		if _, ok := obj.(*v1alpha1.BlipState); ok {
			return apierrors.NewForbidden(v1alpha1.GroupVersion.WithResource("blipstates").GroupResource(), obj.GetName(), errors.New("denied"))
		}
		return c.Create(ctx, obj, opts...)
	}})
	code, _, errOut = h.run("", "run", "--name", "w1", "--from", "/", "--", "true")
	if code != 1 || !strings.Contains(errOut, "denied") {
		t.Fatalf("code %d: %s", code, errOut)
	}
	if err := h.kube.Get(context.Background(), client.ObjectKey{Namespace: ns, Name: "alice.w1"}, &b); !apierrors.IsNotFound(err) {
		t.Fatalf("blip left behind: %v", err)
	}
}

func TestForkRejections(t *testing.T) {
	h := newHarness(t, ownedBlip("alice.box", "alice.home"), readyState("alice.home"))
	for _, tc := range []struct {
		self string
		args []string
		want string
	}{
		{"", []string{"run", "--name", "x", "--from", "/", "--", "true"}, "--from / only works inside a blip; use --from SOURCE"},
		{"alice.box", []string{"run", "--name", "x", "--from", "/", "--state", "s", "--", "true"}, "set only one of --from and --state"},
		{"alice.box", []string{"run", "--name", "x", "--from", "/", "--image", "i", "--", "true"}, "unknown flag: --image"},
		{"alice.box", []string{"run", "--name", "x", "--from", "missing", "--", "true"}, `state "missing" not found`},
	} {
		h.self = tc.self
		code, _, errOut := h.run("", tc.args...)
		if code != 1 || !strings.Contains(errOut, tc.want) {
			t.Errorf("%v: code %d stderr %q", tc.args, code, errOut)
		}
	}
	var states v1alpha1.BlipStateList
	h.kube.List(context.Background(), &states)
	if len(states.Items) != 1 {
		t.Fatalf("rejected forks created states: %d", len(states.Items))
	}
}

func TestMountDefaultsToSelf(t *testing.T) {
	h := newHarness(t, runningBlip("agent"), readyState("repo"))
	code, _, errOut := h.run("", "mount", "repo:/work")
	if code != 1 || !strings.Contains(errOut, "--root is required outside a blip") {
		t.Fatalf("code %d err %q", code, errOut)
	}
	h.self = "agent"
	if code, _, errOut := h.run("", "mount", "repo:/work"); code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	if code, _, errOut := h.run("", "mount", "--rm", "repo"); code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
}

func TestFindSelfReportsForbidden(t *testing.T) {
	h := newHarness(t, readyState("repo"))
	h.self = "agent"
	gr := v1alpha1.GroupVersion.WithResource("blips").GroupResource()
	h.kube = interceptor.NewClient(h.kube, interceptor.Funcs{
		Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			if _, ok := obj.(*v1alpha1.Blip); ok {
				return apierrors.NewForbidden(gr, key.Name, errors.New("access denied"))
			}
			return c.Get(ctx, key, obj, opts...)
		},
	})
	code, _, errOut := h.run("", "mount", "repo:/work")
	if code != 1 || !strings.Contains(errOut, `cannot read blip "agent"`) || !strings.Contains(errOut, "forbidden") {
		t.Fatalf("code %d stderr %q", code, errOut)
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
	root := readyState("root")
	for dir, want := range map[string][2]string{
		"/work/repo/sub":    {"repo", "/repo/sub"},
		"/work/repo/deep/x": {"nested", "/x"},
		"/work":             {"repo", ""},
		"/home/dev":         {"root", "/home/dev"},
	} {
		if s, rel := stateForPath(b, root, dir); s != want[0] || rel != want[1] {
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
	if m := findSpecMount(h.rootState("alice.box").Spec.Mounts, "alice.w1"); m == nil || m.Writable || m.BlipUID == "" {
		t.Fatalf("new mount is not read-only: %+v", m)
	}
	dir2, done2 := checkout()
	if dir1 != "/run/blip-collect/alice.w1" || dir2 != dir1 {
		t.Fatalf("dirs %q %q", dir1, dir2)
	}
	done1()
	if m := h.rootState("alice.box").Spec.Mounts; len(m) != 1 {
		t.Fatalf("mount removed under another collect: %+v", m)
	}
	done2()
	if b := h.rootState("alice.box"); len(b.Spec.Mounts) != 0 || b.Annotations[v1alpha1.AnnotationCollectMounts] != "" {
		t.Fatalf("mounts %+v annotations %v", b.Spec.Mounts, b.Annotations)
	}
	waitForCond(t, func() bool { return len(h.blip("alice.box").Status.Mounts) == 0 })

	// A mount of the caller's own is used and kept.
	if code, _, errOut := h.run("", "mount", "w1:/w1:rw"); code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	dir, done := checkout()
	done()
	if m := h.rootState("alice.box").Spec.Mounts; dir != "/w1" || len(m) != 1 || !m[0].Writable {
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
	b := h.rootState(blip)
	if m := findSpecMount(b.Spec.Mounts, state); m != nil {
		t.Fatalf("%s still mounts %s: %+v", blip, state, b.Spec.Mounts)
	}
	if v := b.Annotations[v1alpha1.AnnotationCollectMounts]; v != "" {
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
		code, _, errOut := h.collect("w1", "git:.:w1")
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
		code, _, errOut := h.collect("w1", "git:.:w1")
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
		code, _, errOut := h.collect("w1", "git:/home/dev/src:w1")
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
		code, _, errOut := h.collect("w1", "git:/repo:w1")
		if code != 1 || !strings.Contains(errOut, "git directory outside state") {
			t.Fatalf("code %d stderr %q", code, errOut)
		}
		assertCollectReleased(t, h, "alice.box", "alice.w1")
	})

	t.Run("git common directory outside state", func(t *testing.T) {
		withCollectMountRoot(t)
		dst := filepath.Join(t.TempDir(), "dst")
		gitInit(t, dst)
		outside := filepath.Join(t.TempDir(), "outside")
		gitRepo(t, outside)
		src := filepath.Join(collectMountRoot, "alice.w1", "repo")
		gitRepo(t, src)
		rel, err := filepath.Rel(filepath.Join(src, ".git"), outside)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(src, ".git", "commondir"), []byte(rel+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		h := newHarness(t, gitObjects()...)
		h.self = "alice.box"
		t.Chdir(dst)
		code, _, errOut := h.collect("w1", "git:/repo:w1")
		if code != 1 || !strings.Contains(errOut, "git common directory outside state") {
			t.Fatalf("code %d stderr %q", code, errOut)
		}
		if out, err := exec.Command("git", "-C", dst, "rev-parse", "--verify", "w1").CombinedOutput(); err == nil {
			t.Fatalf("fetched from a redirected common directory: %s", out)
		}
		assertCollectReleased(t, h, "alice.box", "alice.w1")
	})

	t.Run("git alternates outside state", func(t *testing.T) {
		withCollectMountRoot(t)
		dst := filepath.Join(t.TempDir(), "dst")
		gitInit(t, dst)
		outside := filepath.Join(t.TempDir(), "outside")
		gitRepo(t, outside)
		src := filepath.Join(collectMountRoot, "alice.w1", "repo")
		gitRepo(t, src)
		objects := filepath.Join(src, ".git", "objects")
		if err := os.MkdirAll(filepath.Join(objects, "info"), 0o755); err != nil {
			t.Fatal(err)
		}
		rel, err := filepath.Rel(objects, filepath.Join(outside, ".git", "objects"))
		if err != nil {
			t.Fatal(err)
		}
		// A harmless first entry must not hide an escaping one.
		alternates := "objects\n" + rel + "\n"
		if err := os.WriteFile(filepath.Join(objects, "info", "alternates"), []byte(alternates), 0o644); err != nil {
			t.Fatal(err)
		}
		h := newHarness(t, gitObjects()...)
		h.self = "alice.box"
		t.Chdir(dst)
		code, _, errOut := h.collect("w1", "git:/repo:w1")
		if code != 1 || !strings.Contains(errOut, "git alternates outside state") {
			t.Fatalf("code %d stderr %q", code, errOut)
		}
		if out, err := exec.Command("git", "-C", dst, "rev-parse", "--verify", "w1").CombinedOutput(); err == nil {
			t.Fatalf("fetched from alternates outside the state: %s", out)
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
		code, _, errOut := h.collect("w1", "git:"+dst+":nope")
		if code != 1 || !strings.Contains(errOut, "git fetch") {
			t.Fatalf("code %d stderr %q, want 1 with a git fetch error", code, errOut)
		}
		assertCollectReleased(t, h, "alice.box", "alice.w1")
	})
}

// git: collection fetches commits only. A dirty worktree must warn instead of
// silently discarding the uncommitted and untracked work when the blip goes.
func TestCollectGitWarnsAboutUncommittedWork(t *testing.T) {
	requireGit(t)
	withCollectMountRoot(t)
	dst := filepath.Join(t.TempDir(), "dst")
	gitInit(t, dst)
	src := filepath.Join(collectMountRoot, "alice.w1", "home/dev/repo")
	gitRepo(t, src) // branch w1
	if err := os.WriteFile(filepath.Join(src, "tracked.txt"), []byte("base\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitRun(t, src, "add", "tracked.txt")
	gitRun(t, src, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "tracked")
	if err := os.WriteFile(filepath.Join(src, "tracked.txt"), []byte("dirty\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "untracked.txt"), []byte("new\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	h := newHarness(t, gitObjects()...)
	h.self = "alice.box"
	t.Chdir(dst)
	code, _, errOut := h.collect("w1", "git:/home/dev/repo:w1")
	if code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	mustContain(t, errOut, "uncommitted", "untracked", "only commits")
	assertCollectReleased(t, h, "alice.box", "alice.w1")
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
		{"outside a blip", gitObjects(), "", []string{"w1", "/:./out"},
			"collect only works inside a blip"},
		{"self", gitObjects(), "alice.box", []string{"box", "/:./out"},
			"cannot collect from box, the blip running this collect"},
		{"missing worker", gitObjects(), "alice.box", []string{"nope", "/:./out"},
			`blip "alice.nope" not found`},
		{"blip with path", gitObjects(), "alice.box", []string{"w1:/src", "/:./out"},
			`invalid blip "w1:/src"`},
		{"invalid operation", gitObjects(), "alice.box", []string{"w1", "nonsense"},
			`invalid operation "nonsense"`},
		{"failed state", []client.Object{ownedBlip("alice.box", "alice.home"), worker, failed},
			"alice.box", []string{"w1", "/:./out"},
			`state "alice.w1" failed: disk broke`},
		{"missing state", []client.Object{ownedBlip("alice.box", "alice.home"), worker},
			"alice.box", []string{"w1", "/:./out"},
			`state "alice.w1" not found`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, tc.objs...)
			h.self = tc.self
			code, _, errOut := h.collect(tc.args...)
			if code != 1 || !strings.Contains(errOut, tc.want) {
				t.Fatalf("code %d stderr %q, want %q", code, errOut, tc.want)
			}
		})
	}
}
