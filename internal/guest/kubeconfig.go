package guest

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// kubeconfigPath contains only connection settings and self metadata. It lives
// in the root's /run tmpfs, never on a durable disk.
const (
	kubeconfigPath = "/run/blip/kubeconfig"
	apiServer      = "http://kube-apiserver"
)

// installKubeConfigLocked runs during root setup, before accepting the claim
// or starting any workload. Never mount or write guest files on the host.
func (g *Guest) installKubeConfigLocked() error {
	if g.kubeNamespace == "" {
		return nil
	}
	if !isInit() {
		return errNotInit
	}
	runfd, err := mkdirInRoot(g.root, "/run", false)
	if err != nil {
		return err
	}
	defer unix.Close(runfd)
	var st unix.Statfs_t
	if err := unix.Fstatfs(runfd, &st); err != nil {
		return err
	}
	if st.Type != unix.TMPFS_MAGIC {
		return errors.New("/run is not a tmpfs")
	}
	return writeKubeConfig(runfd, g.kubeNamespace)
}

// writeKubeConfig creates public, credential-free metadata relative to the
// already-mounted /run. Using directory descriptors prevents symlink escapes.
func writeKubeConfig(runfd int, namespace string) error {
	config, err := json.Marshal(map[string]any{
		"apiVersion": "v1",
		"kind":       "Config",
		"clusters": []any{map[string]any{
			"name": "blip", "cluster": map[string]string{"server": apiServer},
		}},
		"contexts": []any{map[string]any{
			"name": "blip", "context": map[string]string{"cluster": "blip", "namespace": namespace},
		}},
		"current-context": "blip",
	})
	if err != nil {
		return err
	}
	if err := unix.Mkdirat(runfd, "blip", 0o755); err != nil && err != unix.EEXIST {
		return err
	}
	dirfd, err := openat2(runfd, "blip", unix.O_RDONLY|unix.O_DIRECTORY, 0,
		unix.RESOLVE_BENEATH|unix.RESOLVE_NO_SYMLINKS)
	if err != nil {
		return err
	}
	defer unix.Close(dirfd)
	if err := unix.Fchmod(dirfd, 0o755); err != nil {
		return err
	}
	for _, file := range []struct {
		name string
		data []byte
	}{
		{"kubeconfig", append(config, '\n')},
		{"namespace", []byte(namespace)},
	} {
		fd, err := unix.Openat(dirfd, file.name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o644)
		if err != nil {
			return fmt.Errorf("create %s: %w", file.name, err)
		}
		f := os.NewFile(uintptr(fd), file.name)
		_, err = f.Write(file.data)
		if err == nil {
			err = f.Chmod(0o644) // also readable by non-root workloads
		}
		if err := errors.Join(err, f.Close()); err != nil {
			return fmt.Errorf("write %s: %w", file.name, err)
		}
	}
	return nil
}
