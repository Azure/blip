// Package guest is the part of kubectl-blip that runs inside a Blip: it
// finds the Blip the plugin runs in, points the Kubernetes client at the
// API server with the Blip's service account, and mounts, unmounts and
// syncs attached volumes.
package guest

import (
	"bufio"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Paths, variables for tests.
var (
	// RunDir holds name and namespace files written by images such as
	// images/blip-ubuntu (blip-identity.service).
	RunDir = "/run/blip"
	// TokenFile is the service account token that images write from the
	// metadata disk (blip-meta creds).
	TokenFile = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	// readMeta reads the identity from the metadata disk.
	readMeta = metaIdentity
)

// Identity is the Blip the process runs in.
type Identity struct {
	Name, Namespace string
}

// Self returns the Blip this process runs in. It checks, in order, the
// BLIP_NAME and BLIP_NAMESPACE environment variables, the files in RunDir
// and the metadata disk (Linux, needs root). ok is false outside a Blip.
func Self() (id Identity, ok bool, err error) {
	if n := os.Getenv("BLIP_NAME"); n != "" {
		return Identity{Name: n, Namespace: os.Getenv("BLIP_NAMESPACE")}, true, nil
	}
	if n := readFile(filepath.Join(RunDir, "name")); n != "" {
		return Identity{Name: n, Namespace: readFile(filepath.Join(RunDir, "namespace"))}, true, nil
	}
	return readMeta()
}

func readFile(p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// InClusterEnv sets KUBERNETES_SERVICE_HOST and KUBERNETES_SERVICE_PORT to
// the in-cluster API server name when they are unset and the service
// account token exists, so that client-go uses the Blip's service account
// when there is no kubeconfig (like in a pod). It reports whether it set
// them.
func InClusterEnv() bool {
	if os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
		return false
	}
	if _, err := os.Stat(TokenFile); err != nil {
		return false
	}
	_ = os.Setenv("KUBERNETES_SERVICE_HOST", "kubernetes.default.svc")
	if os.Getenv("KUBERNETES_SERVICE_PORT") == "" {
		_ = os.Setenv("KUBERNETES_SERVICE_PORT", "443")
	}
	return true
}

// ErrUnsupported is returned by the mount functions outside Linux.
var ErrUnsupported = errors.New("only supported inside a Linux Blip")

// MountPoints returns the mount points of the device majMin ("8:16") listed
// in a /proc/<pid>/mountinfo, in mount order.
func MountPoints(mountinfo io.Reader, majMin string) []string {
	var out []string
	s := bufio.NewScanner(mountinfo)
	s.Buffer(make([]byte, 64*1024), 1024*1024)
	for s.Scan() {
		// id parent maj:min root mountpoint options ...
		f := strings.Fields(s.Text())
		if len(f) >= 5 && f[2] == majMin {
			out = append(out, unescapeMount(f[4]))
		}
	}
	return out
}

// unescapeMount decodes the octal escapes (\040 for space) of mountinfo.
func unescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+4 <= len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
