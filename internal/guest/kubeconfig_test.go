package guest

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
	"k8s.io/client-go/tools/clientcmd"
)

func TestKubeConfigContainsNoCredentials(t *testing.T) {
	run := t.TempDir()
	fd, err := unix.Open(run, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err := writeKubeConfig(fd, "sandbox", "alice.default"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(run, "blip/kubeconfig"))
	if err != nil {
		t.Fatal(err)
	}
	config, err := clientcmd.Load(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(config.AuthInfos) != 0 {
		t.Fatalf("kubeconfig contains users: %+v", config.AuthInfos)
	}
	cc := clientcmd.NewNonInteractiveClientConfig(*config, config.CurrentContext, &clientcmd.ConfigOverrides{}, nil)
	rest, err := cc.ClientConfig()
	if err != nil {
		t.Fatal(err)
	}
	if rest.Host != "http://kube-apiserver" || rest.BearerToken != "" || rest.BearerTokenFile != "" ||
		rest.Username != "" || rest.Password != "" || rest.CAFile != "" || len(rest.CAData) != 0 ||
		rest.CertFile != "" || len(rest.CertData) != 0 || rest.KeyFile != "" || len(rest.KeyData) != 0 ||
		rest.ExecProvider != nil || rest.AuthProvider != nil {
		t.Fatalf("unexpected client config: %+v", rest)
	}
	if ns, _, err := cc.Namespace(); err != nil || ns != "sandbox" {
		t.Fatalf("client namespace = %q, %v", ns, err)
	}
	if ns, err := os.ReadFile(filepath.Join(run, "blip/namespace")); err != nil || string(ns) != "sandbox" {
		t.Fatalf("metadata namespace = %q, %v", ns, err)
	}
	if name, err := os.ReadFile(filepath.Join(run, "blip/name")); err != nil || string(name) != "alice.default" {
		t.Fatalf("metadata blip name = %q, %v", name, err)
	}
	var files []string
	err = filepath.WalkDir(run, func(path string, d os.DirEntry, err error) error {
		if err != nil || path == run {
			return err
		}
		name, _ := filepath.Rel(run, path)
		files = append(files, name)
		fi, err := d.Info()
		if err != nil {
			return err
		}
		wantMode := os.FileMode(0o644)
		if d.IsDir() {
			wantMode = 0o755
		}
		if fi.Mode().Perm() != wantMode {
			t.Errorf("%s permissions = %v, want %v", name, fi.Mode().Perm(), wantMode)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"blip", "blip/kubeconfig", "blip/name", "blip/namespace"}; !reflect.DeepEqual(files, want) {
		t.Fatalf("installed files = %v, want %v (no token or CA files)", files, want)
	}
}

func TestKubeConfigInstallOutsidePID1(t *testing.T) {
	if isInit() {
		t.Skip("running as PID 1")
	}
	g := &Guest{root: t.TempDir(), kubeNamespace: "sandbox"}
	if err := g.installKubeConfigLocked("alice.default"); err != errNotInit {
		t.Fatalf("install = %v, want %v", err, errNotInit)
	}
	g.kubeNamespace = ""
	if err := g.installKubeConfigLocked("alice.default"); err != nil {
		t.Fatalf("disabled install = %v", err)
	}
	if entries, err := os.ReadDir(g.root); err != nil || len(entries) != 0 {
		t.Fatalf("guest root changed outside PID 1: %v, %v", entries, err)
	}
}

func TestKubeMetadataRejectsSymlinks(t *testing.T) {
	for _, target := range []string{"blip", "blip/kubeconfig", "blip/name", "blip/namespace"} {
		t.Run(target, func(t *testing.T) {
			run, outside := t.TempDir(), t.TempDir()
			if err := os.MkdirAll(filepath.Dir(filepath.Join(run, target)), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outside, filepath.Join(run, target)); err != nil {
				t.Fatal(err)
			}
			fd, err := unix.Open(run, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer unix.Close(fd)
			if err := writeKubeConfig(fd, "sandbox", "alice.default"); err == nil {
				t.Fatal("metadata installation followed a symlink")
			}
			if entries, err := os.ReadDir(outside); err != nil || len(entries) != 0 {
				t.Fatalf("wrote outside /run: %v, %v", entries, err)
			}
		})
	}
}

func TestPrimaryAndSessionKubeconfigEnvironment(t *testing.T) {
	for _, user := range []*account{
		{name: "root", home: "/root", shell: "/bin/sh"},
		{name: "alice", uid: 1000, gid: 1000, home: "/home/alice", shell: "/bin/bash"},
	} {
		for _, tc := range []struct {
			name          string
			base, session []string
			want          string
		}{
			{name: "primary", want: kubeconfigPath},
			{name: "exec", session: []string{"TERM=xterm"}, want: kubeconfigPath},
			{name: "claim override", base: []string{"KUBECONFIG=/custom"}, want: "/custom"},
			{name: "session override", base: []string{"KUBECONFIG=/custom"}, session: []string{"KUBECONFIG=/session"}, want: "/session"},
			{name: "explicit empty", session: []string{"KUBECONFIG="}, want: ""},
		} {
			t.Run(user.name+"/"+tc.name, func(t *testing.T) {
				g := &Guest{kubeNamespace: "sandbox"}
				env := g.procEnv(user, procSpec{env: tc.session}, tc.base)
				var kubeconfigs []string
				for _, entry := range env {
					if strings.HasPrefix(entry, "KUBECONFIG=") {
						kubeconfigs = append(kubeconfigs, entry)
					}
				}
				if !reflect.DeepEqual(kubeconfigs, []string{"KUBECONFIG=" + tc.want}) {
					t.Fatalf("environment = %v", env)
				}
			})
		}
	}
	g := &Guest{}
	for _, entry := range g.procEnv(&account{}, procSpec{}, nil) {
		if strings.HasPrefix(entry, "KUBECONFIG=") {
			t.Fatalf("disabled API exported %q", entry)
		}
	}
}
