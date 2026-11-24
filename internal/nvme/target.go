// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Package nvme exports block devices over NVMe/TCP and, when the host supports
// it, NVMe/RDMA through the kernel nvmet target (configfs) and connects to
// them with the kernel initiator, without nvme-cli. Every configfs name is
// derived from the node name because kind nodes share one kernel.
package nvme

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

// Transport is an NVMe fabric transport.
type Transport string

const (
	TCP  Transport = "tcp"
	RDMA Transport = "rdma"
)

// Endpoint is one transport address of an exported subsystem.
type Endpoint struct {
	Transport Transport
	Addr      string
	Port      int
}

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

// Target manages one node's nvmet ports and subsystems.
type Target struct {
	node string
	addr string
	port int
	rdma int // optional RDMA port; zero when disabled
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

// rdmaPortID is the node's RDMA port, in a range portID cannot produce (see
// hack/storage-cleanup.sh).
func (t *Target) rdmaPortID() string {
	h, _ := strconv.ParseUint(NodeHash(t.node)[:4], 16, 32)
	return strconv.FormatUint(61000+h%3000, 10)
}

func (t *Target) rdmaDir() string { return filepath.Join(nvmetDir, "ports", t.rdmaPortID()) }

func subsysDir(nqn string) string { return filepath.Join(nvmetDir, "subsystems", nqn) }

// EnableRDMA adds an RDMA port for every lease and marks the TCP port
// non-optimized so a multipath host prefers RDMA and falls back to TCP. A zero
// port removes the extra path. It is idempotent.
func (t *Target) EnableRDMA(port int) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if port <= 0 {
		t.rdma = 0
		if err := t.removeRDMAPort(); err != nil {
			return err
		}
		t.ana(t.portDir(), "optimized")
		return nil
	}
	dir := t.rdmaDir()
	if err := ensurePort(dir, Endpoint{RDMA, t.addr, port}); err != nil {
		return err
	}
	t.rdma = port
	for _, lease := range t.leases() {
		if err := linkPort(dir, SubsystemNQN(t.node, lease)); err != nil {
			slog.Warn("nvme: link RDMA path", "lease", lease, "err", err)
		}
	}
	t.ana(t.portDir(), "non-optimized")
	return nil
}

// ana prefers port over the host's other paths. nvmet group names vary by
// kernel, so use the port's only group; a missing group leaves the default.
func (t *Target) ana(port, state string) {
	groups, err := os.ReadDir(filepath.Join(port, "ana_groups"))
	if err != nil || len(groups) != 1 {
		return
	}
	dir := filepath.Join(port, "ana_groups", groups[0].Name())
	if readAttr(dir, "ana_state") == state {
		return
	}
	if err := writeAttr(dir, "ana_state", state); err != nil {
		slog.Warn("nvme: set ANA state", "port", filepath.Base(port), "state", state, "err", err)
	}
}

// removeRDMAPort unlinks this node's subsystems from the RDMA port and removes
// the port once no other subsystem uses it.
func (t *Target) removeRDMAPort() error {
	dir := t.rdmaDir()
	prefix := SubsystemNQN(t.node, "")
	subs, _ := os.ReadDir(filepath.Join(dir, "subsystems"))
	for _, s := range subs {
		if strings.HasPrefix(s.Name(), prefix) {
			if err := rmLink(filepath.Join(dir, "subsystems", s.Name())); err != nil {
				return err
			}
		}
	}
	if links, err := os.ReadDir(filepath.Join(dir, "subsystems")); err == nil && len(links) == 0 {
		return rmdir(dir)
	}
	return nil
}

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
	if err := ensurePort(port, Endpoint{TCP, t.addr, t.port}); err != nil {
		return err
	}
	if t.rdma != 0 {
		// The RDMA path is best effort: hosts that cannot use it still have
		// TCP, and the extra path must not fail the lease.
		if err := linkPort(t.rdmaDir(), nqn); err != nil {
			slog.Warn("nvme: link RDMA path", "nqn", nqn, "err", err)
		}
		t.ana(port, "non-optimized")
	}
	return linkPort(port, nqn)
}

// ensurePort creates or updates a port's address. Changing the address of a
// port that already exports subsystems is refused by the kernel.
func ensurePort(dir string, ep Endpoint) error {
	if err := mkdir(dir); err != nil {
		return err
	}
	links, _ := os.ReadDir(filepath.Join(dir, "subsystems"))
	want := map[string]string{
		"addr_trtype":  string(ep.Transport),
		"addr_adrfam":  "ipv4",
		"addr_traddr":  ep.Addr,
		"addr_trsvcid": strconv.Itoa(ep.Port),
	}
	for k, v := range want {
		if readAttr(dir, k) == v {
			continue
		}
		if len(links) > 0 {
			return fmt.Errorf("nvme: port %s is in use with %s=%s", filepath.Base(dir), k, readAttr(dir, k))
		}
		if err := writeAttr(dir, k, v); err != nil {
			return err
		}
	}
	return nil
}

// linkPort makes subsystem nqn reachable through port.
func linkPort(port, nqn string) error {
	return symlink(subsysDir(nqn), filepath.Join(port, "subsystems", nqn))
}

// Unexport removes the lease's subsystem (and the port and host entries
// once unused). It is idempotent.
func (t *Target) Unexport(lease string) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.unexport(SubsystemNQN(t.node, lease))
}

func (t *Target) unexport(nqn string) error {
	ports, _ := filepath.Glob(filepath.Join(nvmetDir, "ports", "*"))
	for _, port := range ports {
		if err := rmLink(filepath.Join(port, "subsystems", nqn)); err != nil {
			return err
		}
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
	t.removePortIfEmpty(t.portDir())
	if t.rdma != 0 {
		t.removePortIfEmpty(t.rdmaDir())
	}
	return nil
}

// removePortIfEmpty removes port once no subsystem uses it.
func (t *Target) removePortIfEmpty(port string) {
	if links, err := os.ReadDir(filepath.Join(port, "subsystems")); err == nil && len(links) == 0 {
		os.Remove(port)
	}
}

// Paths lists the transports the lease's subsystem is exported on.
func (t *Target) Paths(lease string) []Endpoint {
	t.mu.Lock()
	defer t.mu.Unlock()
	nqn := SubsystemNQN(t.node, lease)
	ports, _ := filepath.Glob(filepath.Join(nvmetDir, "ports", "*"))
	var out []Endpoint
	for _, port := range ports {
		if _, err := os.Stat(filepath.Join(port, "subsystems", nqn)); err != nil {
			continue
		}
		ep := Endpoint{
			Transport: Transport(readAttr(port, "addr_trtype")),
			Addr:      readAttr(port, "addr_traddr"),
		}
		ep.Port, _ = strconv.Atoi(readAttr(port, "addr_trsvcid"))
		if ep.Transport != "" && ep.Addr != "" && ep.Port != 0 {
			out = append(out, ep)
		}
	}
	return out
}

// Leases lists the leases this node currently exports.
func (t *Target) Leases() []string {
	return t.leases()
}

func (t *Target) leases() []string {
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
