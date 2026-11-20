// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Package nvme exports block devices over NVMe/TCP through the kernel nvmet
// target (configfs) and connects to them with the kernel initiator, without
// nvme-cli. Every configfs name is derived from the node name because kind
// nodes share one kernel.
package nvme

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

const (
	configFS = "/sys/kernel/config"
	nvmetDir = configFS + "/nvmet"
)

// NQNPrefix is the prefix of every NQN the cluster uses.
const NQNPrefix = "nqn.2014-08.dev.blip:"

// NodeHash is the per-node hash used in kernel-global names.
func NodeHash(node string) string {
	sum := sha256.Sum256([]byte(node))
	return hex.EncodeToString(sum[:4])
}

// SubsystemNQN is the NQN of node's export for lease.
func SubsystemNQN(node, lease string) string { return NQNPrefix + NodeHash(node) + ":" + lease }

// Target manages one node's nvmet port and subsystems.
type Target struct {
	node string
	addr string
	port int
	key  []byte
	mu   sync.Mutex
}

// NewTarget prepares the nvmet target of node listening on addr:port. Hosts
// authenticate with secrets derived from key, the cluster disk key.
func NewTarget(node, addr string, port int, key []byte) (*Target, error) {
	if err := checkKey(key); err != nil {
		return nil, err
	}
	if err := ensureConfigFS(); err != nil {
		return nil, err
	}
	if err := checkAuth(node); err != nil {
		return nil, err
	}
	return &Target{node: node, addr: addr, port: port, key: key}, nil
}

func ensureConfigFS() error {
	if _, err := os.Stat(nvmetDir); err == nil {
		return nil
	}
	if err := unix.Mount("none", configFS, "configfs", 0, ""); err != nil && !errors.Is(err, unix.EBUSY) {
		return fmt.Errorf("mount configfs: %w", err)
	}
	if _, err := os.Stat(nvmetDir); err != nil {
		return errors.New("nvmet is not available (load the nvmet and nvmet_tcp modules)")
	}
	return nil
}

// portID is the node's nvmet port, derived from the node hash (see
// hack/storage-cleanup.sh).
func (t *Target) portID() string {
	h, _ := strconv.ParseUint(NodeHash(t.node)[:4], 16, 32)
	return strconv.FormatUint(h%60000+1000, 10)
}

func (t *Target) portDir() string { return filepath.Join(nvmetDir, "ports", t.portID()) }

func subsysDir(nqn string) string { return filepath.Join(nvmetDir, "subsystems", nqn) }

// Export publishes device as namespace 1 of the lease's subsystem, readable
// only by hostNQN. It is idempotent.
func (t *Target) Export(lease, device, hostNQN string) (string, error) {
	if lease == "" || strings.ContainsAny(lease+hostNQN, "/ \n") || hostNQN == "" {
		return "", errors.New("nvme: invalid lease or host NQN")
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	nqn := SubsystemNQN(t.node, lease)
	if err := t.export(nqn, device, hostNQN); err != nil {
		t.unexport(nqn)
		return "", err
	}
	return nqn, nil
}

func (t *Target) export(nqn, device, hostNQN string) error {
	sub := subsysDir(nqn)
	if err := mkdir(sub); err != nil {
		return err
	}
	if err := writeAttr(sub, "attr_allow_any_host", "0"); err != nil {
		return err
	}
	ns := filepath.Join(sub, "namespaces", "1")
	if err := mkdir(ns); err != nil {
		return err
	}
	if readAttr(ns, "enable") != "1" || readAttr(ns, "device_path") != device {
		writeAttr(ns, "enable", "0")
		if err := writeAttr(ns, "device_path", device); err != nil {
			return err
		}
		if err := writeAttr(ns, "device_uuid", uuidFrom(nqn)); err != nil {
			return err
		}
		if err := writeAttr(ns, "enable", "1"); err != nil {
			return err
		}
	}
	host := filepath.Join(nvmetDir, "hosts", hostNQN)
	if err := mkdir(host); err != nil {
		return err
	}
	hostKey, ctrlKey := secrets(t.key, hostNQN)
	for k, v := range map[string]string{"dhchap_key": hostKey, "dhchap_ctrl_key": ctrlKey} {
		if readAttr(host, k) == v {
			continue
		}
		if err := writeAttr(host, k, v); err != nil {
			return err
		}
	}
	if err := symlink(host, filepath.Join(sub, "allowed_hosts", hostNQN)); err != nil {
		return err
	}
	port := t.portDir()
	if err := mkdir(port); err != nil {
		return err
	}
	links, _ := os.ReadDir(filepath.Join(port, "subsystems"))
	want := map[string]string{"addr_trtype": "tcp", "addr_adrfam": "ipv4", "addr_traddr": t.addr, "addr_trsvcid": strconv.Itoa(t.port)}
	for k, v := range want {
		if readAttr(port, k) == v {
			continue
		}
		if len(links) > 0 {
			return fmt.Errorf("nvme: port %s is in use with %s=%s", t.portID(), k, readAttr(port, k))
		}
		if err := writeAttr(port, k, v); err != nil {
			return err
		}
	}
	return symlink(sub, filepath.Join(port, "subsystems", nqn))
}

// Unexport removes the lease's subsystem (and the port and host entries
// once unused). It is idempotent.
func (t *Target) Unexport(lease string) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.unexport(SubsystemNQN(t.node, lease))
}

func (t *Target) unexport(nqn string) error {
	port := t.portDir()
	if err := rmLink(filepath.Join(port, "subsystems", nqn)); err != nil {
		return err
	}
	sub := subsysDir(nqn)
	ns := filepath.Join(sub, "namespaces", "1")
	if _, err := os.Stat(ns); err == nil {
		writeAttr(ns, "enable", "0")
		if err := rmdir(ns); err != nil {
			return err
		}
	}
	hosts, _ := os.ReadDir(filepath.Join(sub, "allowed_hosts"))
	for _, h := range hosts {
		if err := rmLink(filepath.Join(sub, "allowed_hosts", h.Name())); err != nil {
			return err
		}
	}
	if err := rmdir(sub); err != nil {
		return err
	}
	for _, h := range hosts {
		if !hostReferenced(h.Name()) {
			// Another node on this kernel may link it concurrently; that
			// export retries.
			os.Remove(filepath.Join(nvmetDir, "hosts", h.Name()))
		}
	}
	if links, err := os.ReadDir(filepath.Join(port, "subsystems")); err == nil && len(links) == 0 {
		os.Remove(port)
	}
	return nil
}

// Leases lists the leases this node currently exports.
func (t *Target) Leases() []string {
	prefix := SubsystemNQN(t.node, "")
	entries, _ := os.ReadDir(filepath.Join(nvmetDir, "subsystems"))
	var out []string
	for _, e := range entries {
		if lease, ok := strings.CutPrefix(e.Name(), prefix); ok {
			out = append(out, lease)
		}
	}
	return out
}

func hostReferenced(host string) bool {
	links, _ := filepath.Glob(filepath.Join(nvmetDir, "subsystems", "*", "allowed_hosts", host))
	return len(links) > 0
}

func mkdir(p string) error {
	if err := os.Mkdir(p, 0o755); err != nil && !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("nvme: %w", err)
	}
	return nil
}

func rmdir(p string) error {
	if err := unix.Rmdir(p); err != nil && !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("nvme: rmdir %s: %w", p, err)
	}
	return nil
}

func symlink(target, link string) error {
	if err := os.Symlink(target, link); err != nil && !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("nvme: %w", err)
	}
	return nil
}

func rmLink(p string) error {
	if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("nvme: %w", err)
	}
	return nil
}

func writeAttr(dir, name, value string) error {
	f, err := os.OpenFile(filepath.Join(dir, name), os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("nvme: %w", err)
	}
	defer f.Close()
	if _, err := f.WriteString(value); err != nil {
		if strings.HasPrefix(name, "dhchap_") {
			value = "<redacted>"
		}
		return fmt.Errorf("nvme: write %s=%s: %w", filepath.Join(dir, name), value, err)
	}
	return nil
}

func readAttr(dir, name string) string {
	b, _ := os.ReadFile(filepath.Join(dir, name))
	return strings.TrimSpace(string(b))
}

// uuidFrom derives a stable RFC 4122 (v4 layout) UUID from s.
func uuidFrom(s string) string {
	b := sha256.Sum256([]byte(s))
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b[:16])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}
