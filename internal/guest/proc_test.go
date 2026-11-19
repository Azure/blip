package guest

import (
	"strings"
	"testing"

	"github.com/Azure/blip/internal/podapi"
)

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
		{"claim override", &Guest{kubeNamespace: "sandbox"}, []string{"NO_PROXY=corp.example"}, nil, [2]string{"corp.example", "blip,kube-apiserver"}},
		{"session override", &Guest{kubeNamespace: "sandbox"}, nil, []string{"no_proxy=corp.example"}, [2]string{"blip,kube-apiserver", "corp.example"}},
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
