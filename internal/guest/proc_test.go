package guest

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/Azure/blip/internal/podapi"
)

// A non-interactive primary command must see end of input immediately. It used
// to get a pipe whose write end stayed open until exit, so `cat` (and any
// other read) waited forever because no primary client ever sends EOF.
func TestProcStdinEOF(t *testing.T) {
	child, parent, err := procStdin(true)
	if err != nil {
		t.Fatal(err)
	}
	defer child.Close()
	defer parent.Close()
	if n, err := parent.Write([]byte("discarded")); err != nil || n == 0 {
		t.Fatalf("writing to the discarded stdin: %d, %v", n, err)
	}
	buf := make([]byte, 1)
	if n, err := child.Read(buf); n != 0 || err != io.EOF {
		t.Fatalf("reading primary stdin = %d, %v; want 0, EOF", n, err)
	}
}

// Exec sessions keep a pipe so their client can upload stdin and forward its
// own end of input.
func TestProcStdinPipe(t *testing.T) {
	child, parent, err := procStdin(false)
	if err != nil {
		t.Fatal(err)
	}
	defer child.Close()
	if _, err := parent.Write([]byte("hi")); err != nil {
		t.Fatal(err)
	}
	parent.Close()
	buf := make([]byte, 2)
	if n, err := io.ReadFull(child, buf); err != nil || string(buf) != "hi" {
		t.Fatalf("read = %q, %v", buf[:n], err)
	}
	if n, err := child.Read(buf); n != 0 || err != io.EOF {
		t.Fatalf("after EOF: %d, %v", n, err)
	}
}

func TestWorkdirInRoot(t *testing.T) {
	for _, tc := range []struct {
		dir  string
		want string
	}{
		{"", "/"},
		{"/", "/"},
		{"/tmp", "/tmp"},
		{"/tmp/", "/tmp"},
		{"/tmp/../etc", "/etc"},
		{"tmp", "/tmp"},
		{"tmp/", "/tmp"},
		{"./tmp", "/tmp"},
		{"a/../tmp", "/tmp"},
		{"../etc", "/etc"},
		{"../../../etc", "/etc"},
		{"..", "/"},
	} {
		if got := workdirInRoot(tc.dir); got != tc.want {
			t.Errorf("workdirInRoot(%q) = %q, want %q", tc.dir, got, tc.want)
		}
	}
}

// A relative workdir must be resolved inside the workload root before it is
// validated or passed to os.StartProcess; the guest init's cwd after chroot is
// outside the root, so "tmp" used to mean the initramfs /tmp.
func TestStartProcNormalizesRelativeWorkdir(t *testing.T) {
	g := testGuest(t)
	_, _, err := g.startProc(procSpec{argv: []string{"/bin/sh"}, dir: "relative/dir"}, nil)
	if err == nil {
		t.Fatal("startProc accepted a missing relative workdir")
	}
	if want := "chdir /relative/dir: no such file or directory"; !strings.Contains(err.Error(), want) {
		t.Fatalf("error = %q, want it to contain %q", err, want)
	}

	// ".." is clamped at the root instead of escaping to the guest initramfs.
	// The temp root has /etc, so validation of "../../etc" must pass and the
	// failure must come from starting the (missing) executable.
	_, _, err = g.startProc(procSpec{argv: []string{"/does/not/exist"}, dir: "../../etc"}, nil)
	if err == nil {
		t.Fatal("starting a missing executable unexpectedly succeeded")
	}
	if strings.Contains(err.Error(), "chdir") {
		t.Fatalf("dot-dot workdir was not normalized inside the root: %v", err)
	}
}

// TestCheckDirAccessNamesInaccessibleWorkdir verifies that a workdir the
// target account cannot search is reported as such, instead of surfacing from
// the child as "fork/exec <program>: permission denied" and blaming the
// command. The owner and group cases must stay allowed.
func TestCheckDirAccessNamesInaccessibleWorkdir(t *testing.T) {
	root := testRoot(t)
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "home/dev")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		t.Skip("no stat ownership information")
	}

	outsider := &account{uid: st.Uid + 1, gid: st.Gid + 1, groups: []uint32{st.Gid + 1}}
	err = checkDirAccess(root, "/home/dev", outsider)
	if err == nil {
		t.Fatal("inaccessible workdir was accepted")
	}
	if want := "chdir /home/dev: permission denied"; !strings.Contains(err.Error(), want) {
		t.Fatalf("error = %q, want it to contain %q", err, want)
	}

	owner := &account{uid: st.Uid, gid: st.Gid + 1, groups: []uint32{st.Gid + 1}}
	if err := checkDirAccess(root, "/home/dev", owner); err != nil {
		t.Fatalf("owner was denied the workdir: %v", err)
	}
	group := &account{uid: st.Uid + 1, gid: st.Gid, groups: []uint32{st.Gid}}
	if err := checkDirAccess(root, "/home/dev", group); err != nil {
		t.Fatalf("group member was denied the workdir: %v", err)
	}
	rootUser := &account{uid: 0}
	if err := checkDirAccess(root, "/home/dev", rootUser); err != nil {
		t.Fatalf("root was denied the workdir: %v", err)
	}
}

// TestProcEnvReservedValuesCannotBeOverridden keeps a caller's exec -e from
// redirecting the guest-owned report endpoint. The reserved value must appear
// exactly once and win over both the claim environment and the session's
// environment, while ordinary variables still follow the usual last-wins rule.
func TestProcEnvReservedValuesCannotBeOverridden(t *testing.T) {
	acct := &account{name: "root", home: "/root", shell: "/bin/sh"}
	for _, tc := range []struct {
		name    string
		base    []string
		session []string
	}{
		{"session override", nil, []string{podapi.ReportEnv + "=http://127.0.0.1:1"}},
		{"claim and session override", []string{podapi.ReportEnv + "=http://claim.invalid"}, []string{podapi.ReportEnv + "=http://127.0.0.1:1"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := (&Guest{}).procEnv(acct, procSpec{env: append(tc.session, "A=session")}, append(tc.base, "A=claim"))
			var report, values []string
			for _, entry := range env {
				if v, ok := strings.CutPrefix(entry, podapi.ReportEnv+"="); ok {
					report = append(report, v)
				}
				if v, ok := strings.CutPrefix(entry, "A="); ok {
					values = append(values, v)
				}
			}
			if len(report) != 1 || report[0] != podapi.ReportURL {
				t.Fatalf("%s entries = %v, want one %q", podapi.ReportEnv, report, podapi.ReportURL)
			}
			if len(values) != 1 || values[0] != "session" {
				t.Fatalf("ordinary variable A = %v, want one %q", values, "session")
			}
		})
	}
}

func TestProcEnvNoProxy(t *testing.T) {
	acct := &account{name: "root", home: "/root", shell: "/bin/sh"}
	for _, tc := range []struct {
		name    string
		g       *Guest
		base    []string
		session []string
		want    [2]string // NO_PROXY, no_proxy
	}{
		{"no names", &Guest{}, nil, nil, [2]string{"blip", "blip"}},
		{"kubernetes", &Guest{kubeNamespace: "sandbox"}, nil, nil, [2]string{"blip,kube-apiserver", "blip,kube-apiserver"}},
		{"endpoints", &Guest{endpoints: []string{"api.default", "db.default"}}, nil, nil, [2]string{"blip,api.default,db.default", "blip,api.default,db.default"}},
		{"all", &Guest{kubeNamespace: "sandbox", endpoints: []string{"api.default"}}, nil, nil, [2]string{"blip,kube-apiserver,api.default", "blip,kube-apiserver,api.default"}},
		{"claim override", &Guest{kubeNamespace: "sandbox"}, []string{"NO_PROXY=corp.example"}, nil, [2]string{"blip,kube-apiserver,corp.example", "blip,kube-apiserver,corp.example"}},
		{"session override", &Guest{kubeNamespace: "sandbox"}, nil, []string{"no_proxy=corp.example"}, [2]string{"blip,kube-apiserver,corp.example", "blip,kube-apiserver,corp.example"}},
		{"both spellings merge", &Guest{kubeNamespace: "sandbox"}, []string{"NO_PROXY=claim.example"}, []string{"no_proxy=session.example"}, [2]string{"blip,kube-apiserver,claim.example,session.example", "blip,kube-apiserver,claim.example,session.example"}},
		{"duplicates and spaces", &Guest{kubeNamespace: "sandbox", endpoints: []string{"api.default"}}, []string{"NO_PROXY= blip, ,corp.example ,api.default"}, nil, [2]string{"blip,kube-apiserver,api.default,corp.example", "blip,kube-apiserver,api.default,corp.example"}},
		{"explicit empty keeps guest names", &Guest{kubeNamespace: "sandbox"}, []string{"NO_PROXY="}, []string{"no_proxy="}, [2]string{"blip,kube-apiserver", "blip,kube-apiserver"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := tc.g.procEnv(acct, procSpec{env: tc.session}, tc.base)
			for i, key := range []string{"NO_PROXY", "no_proxy"} {
				var vals []string
				for _, entry := range env {
					if v, ok := strings.CutPrefix(entry, key+"="); ok {
						vals = append(vals, v)
					}
				}
				if len(vals) != 1 || vals[0] != tc.want[i] {
					t.Fatalf("%s entries = %v, want %q", key, vals, tc.want[i])
				}
			}
		})
	}
}
