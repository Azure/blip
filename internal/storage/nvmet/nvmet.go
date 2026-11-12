// Package nvmet manages NVMe/TCP target exports through configfs.
//
// Every port requires TLS 1.3 (addr_tsas=tls1.3, addr_treq=required). A
// port starts listening when the first subsystem is linked to it, in the
// network namespace of the process that creates the link. All calls are
// idempotent.
//
// nvmet has no read-only namespace option and cannot open a read-only
// block device. Read-only access is enforced by the host (see package
// storage).
package nvmet

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/example/blip/internal/storage/run"
)

// DefaultRoot is where the nvmet configfs tree is mounted.
const DefaultRoot = "/sys/kernel/config/nvmet"

// Target edits one nvmet configfs tree.
type Target struct {
	Root string
}

// New returns a Target for root, or DefaultRoot if root is empty. It mounts
// configfs if needed (containers do not mount it).
func New(root string) (*Target, error) {
	if root == "" {
		root = DefaultRoot
	}
	if _, err := os.Stat(root); err != nil {
		cfg := filepath.Dir(root)
		if err := syscall.Mount("configfs", cfg, "configfs", 0, ""); err != nil && !errors.Is(err, syscall.EBUSY) {
			return nil, fmt.Errorf("mount configfs on %s: %w", cfg, err)
		}
		if _, err := os.Stat(root); err != nil {
			return nil, fmt.Errorf("nvmet configfs not available (is nvmet loaded?): %w", err)
		}
	}
	return &Target{Root: root}, nil
}

// Port is a TCP listen address.
type Port struct {
	ID   uint16
	Addr string // IPv4 or IPv6 address
	Svc  int    // TCP port, usually 4420
}

func (p Port) family() string {
	if strings.Contains(p.Addr, ":") {
		return "ipv6"
	}
	return "ipv4"
}

func (t *Target) portDir(id uint16) string {
	return filepath.Join(t.Root, "ports", strconv.Itoa(int(id)))
}

// EnsurePort creates the port with TLS required. If it exists, its
// attributes must match, unless no subsystem is linked to it yet: then
// they are set again (an earlier EnsurePort was interrupted).
func (t *Target) EnsurePort(p Port) error {
	dir := t.portDir(p.ID)
	want := [][2]string{
		{"addr_trtype", "tcp"},
		{"addr_adrfam", p.family()},
		{"addr_traddr", p.Addr},
		{"addr_trsvcid", strconv.Itoa(p.Svc)},
		{"addr_tsas", "tls1.3"},
		{"addr_treq", "required"},
	}
	if _, err := os.Stat(dir); err == nil {
		var bad error
		for _, kv := range want {
			if got := readAttr(dir, kv[0]); got != kv[1] && bad == nil {
				bad = fmt.Errorf("nvmet port %d exists with %s=%q, want %q", p.ID, kv[0], got, kv[1])
			}
		}
		if bad == nil {
			return nil
		}
		if ents, err := os.ReadDir(filepath.Join(dir, "subsystems")); err != nil || len(ents) > 0 {
			return bad
		}
	} else if err := mkdir(dir); err != nil {
		return fmt.Errorf("create nvmet port %d: %w", p.ID, err)
	}
	for _, kv := range want {
		if err := writeAttr(dir, kv[0], kv[1]); err != nil {
			os.Remove(dir)
			return err
		}
	}
	return nil
}

// RemovePort removes the port if no subsystem is linked to it.
func (t *Target) RemovePort(id uint16) error {
	dir := t.portDir(id)
	ents, err := os.ReadDir(filepath.Join(dir, "subsystems"))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if len(ents) > 0 {
		return fmt.Errorf("nvmet port %d still has %d subsystems", id, len(ents))
	}
	return rmdir(dir)
}

// Export allows HostNQN to reach Device through subsystem SubNQN on port
// PortID.
type Export struct {
	SubNQN  string
	HostNQN string
	Device  string // block device path, opened by the kernel
	PortID  uint16
}

// Export creates or completes an export. Call EnsurePort first.
func (t *Target) Export(e Export) error {
	if e.SubNQN == "" || e.HostNQN == "" || e.Device == "" {
		return errors.New("nvmet export: missing field")
	}
	sub := filepath.Join(t.Root, "subsystems", e.SubNQN)
	if err := mkdir(sub); err != nil {
		return err
	}
	if readAttr(sub, "attr_allow_any_host") != "0" {
		if err := writeAttr(sub, "attr_allow_any_host", "0"); err != nil {
			return err
		}
	}
	ns := filepath.Join(sub, "namespaces", "1")
	if err := mkdir(ns); err != nil {
		return err
	}
	if readAttr(ns, "device_path") != e.Device || readAttr(ns, "enable") != "1" {
		if readAttr(ns, "enable") == "1" {
			if err := writeAttr(ns, "enable", "0"); err != nil {
				return err
			}
		}
		if err := writeAttr(ns, "device_path", e.Device); err != nil {
			return err
		}
		// Stable identifiers: after a target restart or re-export the
		// host sees the same namespace and can reconnect to it. Random
		// ones make the host reject the namespace ("identifiers
		// changed").
		uuid, nguid := NamespaceIDs(e.SubNQN)
		if err := writeAttr(ns, "device_uuid", uuid); err != nil {
			return err
		}
		if err := writeAttr(ns, "device_nguid", nguid); err != nil {
			return err
		}
		if err := writeAttr(ns, "enable", "1"); err != nil {
			return err
		}
	}
	host := filepath.Join(t.Root, "hosts", e.HostNQN)
	if err := mkdir(host); err != nil {
		return err
	}
	if err := symlink(host, filepath.Join(sub, "allowed_hosts", e.HostNQN)); err != nil {
		return err
	}
	if _, err := os.Stat(t.portDir(e.PortID)); err != nil {
		return fmt.Errorf("nvmet port %d: %w", e.PortID, err)
	}
	return symlink(sub, filepath.Join(t.portDir(e.PortID), "subsystems", e.SubNQN))
}

// Unexport removes hostNQN from the subsystem. When no host is left, the
// subsystem is removed. Missing entries are not an error.
func (t *Target) Unexport(subNQN, hostNQN string) error {
	sub := filepath.Join(t.Root, "subsystems", subNQN)
	if err := unlink(filepath.Join(sub, "allowed_hosts", hostNQN)); err != nil {
		return err
	}
	t.removeHostIfUnused(hostNQN)
	ents, _ := os.ReadDir(filepath.Join(sub, "allowed_hosts"))
	if len(ents) > 0 {
		return nil
	}
	return t.RemoveSubsystem(subNQN)
}

// RemoveSubsystem removes a subsystem with all its links. Connected hosts
// lose their controllers.
func (t *Target) RemoveSubsystem(subNQN string) error {
	sub := filepath.Join(t.Root, "subsystems", subNQN)
	if _, err := os.Stat(sub); os.IsNotExist(err) {
		return nil
	}
	ports, _ := os.ReadDir(filepath.Join(t.Root, "ports"))
	for _, p := range ports {
		if err := unlink(filepath.Join(t.Root, "ports", p.Name(), "subsystems", subNQN)); err != nil {
			return err
		}
	}
	hosts, _ := os.ReadDir(filepath.Join(sub, "allowed_hosts"))
	for _, h := range hosts {
		if err := unlink(filepath.Join(sub, "allowed_hosts", h.Name())); err != nil {
			return err
		}
		t.removeHostIfUnused(h.Name())
	}
	nss, _ := os.ReadDir(filepath.Join(sub, "namespaces"))
	for _, n := range nss {
		d := filepath.Join(sub, "namespaces", n.Name())
		if readAttr(d, "enable") == "1" {
			if err := writeAttr(d, "enable", "0"); err != nil {
				return err
			}
		}
		if err := rmdir(d); err != nil {
			return err
		}
	}
	return rmdir(sub)
}

// removeHostIfUnused removes hosts/<nqn> when no subsystem allows it.
// Errors are ignored: another node sharing the kernel may still use it.
func (t *Target) removeHostIfUnused(hostNQN string) {
	subs, _ := os.ReadDir(filepath.Join(t.Root, "subsystems"))
	for _, s := range subs {
		if _, err := os.Lstat(filepath.Join(t.Root, "subsystems", s.Name(), "allowed_hosts", hostNQN)); err == nil {
			return
		}
	}
	_ = rmdir(filepath.Join(t.Root, "hosts", hostNQN))
}

// Subsystem is the state of one subsystem.
type Subsystem struct {
	NQN     string
	Device  string
	Enabled bool
	Hosts   []string
	Ports   []uint16
}

// List returns subsystems whose NQN satisfies match (nil means all).
func (t *Target) List(match func(nqn string) bool) ([]Subsystem, error) {
	subs, err := os.ReadDir(filepath.Join(t.Root, "subsystems"))
	if err != nil {
		return nil, err
	}
	linked := map[string][]uint16{}
	ports, _ := os.ReadDir(filepath.Join(t.Root, "ports"))
	for _, p := range ports {
		id, err := strconv.ParseUint(p.Name(), 10, 16)
		if err != nil {
			continue
		}
		ls, _ := os.ReadDir(filepath.Join(t.Root, "ports", p.Name(), "subsystems"))
		for _, l := range ls {
			linked[l.Name()] = append(linked[l.Name()], uint16(id))
		}
	}
	var out []Subsystem
	for _, s := range subs {
		if match != nil && !match(s.Name()) {
			continue
		}
		dir := filepath.Join(t.Root, "subsystems", s.Name())
		ns := filepath.Join(dir, "namespaces", "1")
		st := Subsystem{
			NQN:     s.Name(),
			Device:  readAttr(ns, "device_path"),
			Enabled: readAttr(ns, "enable") == "1",
			Ports:   linked[s.Name()],
		}
		hs, _ := os.ReadDir(filepath.Join(dir, "allowed_hosts"))
		for _, h := range hs {
			st.Hosts = append(st.Hosts, h.Name())
		}
		out = append(out, st)
	}
	return out, nil
}

// NamespaceIDs derives a namespace UUID and NGUID from a subsystem NQN.
func NamespaceIDs(subNQN string) (uuid, nguid string) {
	h := sha256.Sum256([]byte(subNQN))
	h[6] = h[6]&0x0f | 0x80
	h[8] = h[8]&0x3f | 0x80
	uuid = fmt.Sprintf("%x-%x-%x-%x-%x", h[0:4], h[4:6], h[6:8], h[8:10], h[10:16])
	nguid = fmt.Sprintf("%x-%x-%x-%x-%x", h[16:20], h[20:22], h[22:24], h[24:26], h[26:32])
	return uuid, nguid
}

func readAttr(dir, name string) string {
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func writeAttr(dir, name, val string) error {
	return run.Step("write", []string{filepath.Join(dir, name), val}, func() error {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(val), 0o644); err != nil {
			return fmt.Errorf("write %s=%q: %w", filepath.Join(dir, name), val, err)
		}
		return nil
	})
}

func mkdir(p string) error {
	return run.Step("mkdir", []string{p}, func() error {
		if err := os.Mkdir(p, 0o755); err != nil && !os.IsExist(err) {
			return fmt.Errorf("mkdir %s: %w", p, err)
		}
		return nil
	})
}

func rmdir(p string) error {
	return run.Step("rmdir", []string{p}, func() error {
		if err := syscall.Rmdir(p); err != nil && !errors.Is(err, syscall.ENOENT) {
			return fmt.Errorf("rmdir %s: %w", p, err)
		}
		return nil
	})
}

func symlink(target, link string) error {
	return run.Step("symlink", []string{target, link}, func() error {
		if err := os.Symlink(target, link); err != nil && !os.IsExist(err) {
			return fmt.Errorf("link %s: %w", link, err)
		}
		return nil
	})
}

func unlink(p string) error {
	return run.Step("unlink", []string{p}, func() error {
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("unlink %s: %w", p, err)
		}
		return nil
	})
}
