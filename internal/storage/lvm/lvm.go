// Package lvm manages thin LVs in one volume group.
//
// All commands of one LVM value run one at a time. LVM is confined to the
// configured physical volumes with a global_filter and does not use udev,
// so it works in containers and never touches other disks of the host.
package lvm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/example/blip/internal/storage/devnode"
	"github.com/example/blip/internal/storage/run"
)

// Config selects the volume group.
type Config struct {
	VG      string
	Pool    string   // thin pool LV name, default "pool"
	Devices []string // physical volume paths; LVM ignores every other device
	// LockDir is the directory of LVM file locks. Empty means
	// $BLIP_LVM_LOCKING_DIR, or the LVM default. Tests on private loop
	// devices set it so a hung host LVM command holding the global lock
	// cannot block them.
	LockDir string
}

// LVM runs LVM commands for one volume group, one at a time.
type LVM struct {
	cfg Config
	mu  sync.Mutex
}

// New returns an LVM for cfg.
func New(cfg Config) (*LVM, error) {
	if cfg.VG == "" || len(cfg.Devices) == 0 {
		return nil, errors.New("lvm: VG and devices are required")
	}
	if cfg.Pool == "" {
		cfg.Pool = "pool"
	}
	if cfg.LockDir == "" {
		cfg.LockDir = os.Getenv("BLIP_LVM_LOCKING_DIR")
	}
	return &LVM{cfg: cfg}, nil
}

// VG returns the volume group name.
func (l *LVM) VG() string { return l.cfg.VG }

// Config returns the --config string used for every command.
func (l *LVM) configString() string {
	var acc []string
	for _, d := range l.cfg.Devices {
		acc = append(acc, fmt.Sprintf(`"a|^%s$|"`, regexp.QuoteMeta(d)))
	}
	acc = append(acc, `"r|.*|"`)
	global := "global { event_activation=0 use_lvmpolld=0 }"
	if l.cfg.LockDir != "" {
		global = fmt.Sprintf("global { event_activation=0 use_lvmpolld=0 locking_dir=%q }", l.cfg.LockDir)
	}
	return "devices { use_devicesfile=0 obtain_device_list_from_udev=0 scan_lvs=0 global_filter=[" +
		strings.Join(acc, ",") + "] } " +
		"activation { udev_sync=0 udev_rules=0 verify_udev_operations=0 monitoring=0 } " +
		global
}

func (l *LVM) cmd(ctx context.Context, args ...string) ([]byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	args = append(args[:1:1], append([]string{"--config", l.configString()}, args[1:]...)...)
	return run.Cmd(ctx, nil, "lvm", args...)
}

// Setup creates the PV, VG and thin pool if the VG does not exist. It is
// meant for operators and tests. The pool uses 64KiB chunks,
// error_if_no_space and metaSize bytes of metadata.
func (l *LVM) Setup(ctx context.Context, metaSize int64) error {
	if _, err := l.cmd(ctx, "vgs", l.cfg.VG); err == nil {
		return nil
	}
	for _, d := range l.cfg.Devices {
		if _, err := l.cmd(ctx, "pvcreate", "-q", "-y", "--metadatasize", "64m", d); err != nil {
			return err
		}
	}
	if _, err := l.cmd(ctx, append([]string{"vgcreate", "-q", "--setautoactivation", "n", l.cfg.VG}, l.cfg.Devices...)...); err != nil {
		return err
	}
	_, err := l.cmd(ctx, "lvcreate", "-q", "--type", "thin-pool", "-l", "90%FREE", "--chunksize", "64k",
		"--poolmetadatasize", strconv.FormatInt(metaSize, 10)+"b", "--zero", "n",
		"-n", l.cfg.Pool, l.cfg.VG)
	if err != nil {
		return err
	}
	_, err = l.cmd(ctx, "lvchange", "-q", "--errorwhenfull", "y", l.cfg.VG+"/"+l.cfg.Pool)
	return err
}

// RemoveVG removes the volume group and its PVs. For tests.
func (l *LVM) RemoveVG(ctx context.Context) error {
	if _, err := l.cmd(ctx, "vgs", l.cfg.VG); err != nil {
		return nil
	}
	if _, err := l.cmd(ctx, "vgremove", "-q", "-f", l.cfg.VG); err != nil {
		return err
	}
	for _, d := range l.cfg.Devices {
		if _, err := l.cmd(ctx, "pvremove", "-q", "-y", d); err != nil {
			return err
		}
	}
	return nil
}

// LV is one thin LV.
type LV struct {
	Name    string
	Tags    []string
	ThinID  uint32
	Origin  string
	Size    int64 // bytes
	Created time.Time
	Active  bool
	Dev     devnode.Dev // valid when Active
}

// HasTag reports whether the LV has tag t.
func (lv LV) HasTag(t string) bool {
	for _, x := range lv.Tags {
		if x == t {
			return true
		}
	}
	return false
}

// TagValue returns the value of a tag "key=value".
func (lv LV) TagValue(key string) string {
	for _, x := range lv.Tags {
		if v, ok := strings.CutPrefix(x, key+"="); ok {
			return v
		}
	}
	return ""
}

// Report is the state of the VG from one lvs call.
type Report struct {
	LVs         map[string]LV // thin LVs of the pool by name
	DataPercent float64
	MetaPercent float64
	PoolSize    int64
	// Devices of the active pool layers, for thin_dump and thin_delta.
	PoolDM   string      // dm name of the "-tpool" layer, which takes messages
	MetaDev  devnode.Dev // the "_tmeta" device
	PoolOpen bool
}

type lvsJSON struct {
	Report []struct {
		LV []map[string]string `json:"lv"`
	} `json:"report"`
}

// Report lists the VG with one lvs call.
func (l *LVM) Report(ctx context.Context) (Report, error) {
	out, err := l.cmd(ctx, "lvs", "-a", "--reportformat", "json", "--units", "b", "--nosuffix",
		"-o", "lv_name,lv_tags,thin_id,pool_lv,origin,lv_size,lv_time,lv_active,lv_kernel_major,lv_kernel_minor,data_percent,metadata_percent",
		l.cfg.VG)
	if err != nil {
		return Report{}, err
	}
	return parseReport(out, l.cfg.VG, l.cfg.Pool)
}

func parseReport(out []byte, vg, pool string) (Report, error) {
	var j lvsJSON
	if err := json.Unmarshal(out, &j); err != nil {
		return Report{}, fmt.Errorf("lvs output: %w", err)
	}
	r := Report{LVs: map[string]LV{}, PoolDM: DMName(vg, pool) + "-tpool"}
	for _, rep := range j.Report {
		for _, m := range rep.LV {
			name := m["lv_name"]
			switch {
			case name == pool:
				r.DataPercent, _ = strconv.ParseFloat(m["data_percent"], 64)
				r.MetaPercent, _ = strconv.ParseFloat(m["metadata_percent"], 64)
				r.PoolSize, _ = strconv.ParseInt(m["lv_size"], 10, 64)
			case name == "["+pool+"_tmeta]":
				r.MetaDev, _ = kernelDev(m)
			case m["pool_lv"] == pool:
				lv := LV{Name: name, Origin: m["origin"], Active: m["lv_active"] == "active"}
				id, err := strconv.ParseUint(m["thin_id"], 10, 32)
				if err != nil {
					return Report{}, fmt.Errorf("lvs: bad thin_id for %s", name)
				}
				lv.ThinID = uint32(id)
				lv.Size, _ = strconv.ParseInt(m["lv_size"], 10, 64)
				if t := m["lv_tags"]; t != "" {
					lv.Tags = strings.Split(t, ",")
				}
				lv.Created, _ = time.Parse("2006-01-02 15:04:05 -0700", m["lv_time"])
				if lv.Active {
					lv.Dev, _ = kernelDev(m)
				}
				r.LVs[name] = lv
			}
		}
	}
	return r, nil
}

func kernelDev(m map[string]string) (devnode.Dev, bool) {
	ma, err1 := strconv.ParseUint(m["lv_kernel_major"], 10, 32)
	mi, err2 := strconv.ParseUint(m["lv_kernel_minor"], 10, 32)
	if err1 != nil || err2 != nil || m["lv_kernel_major"] == "-1" {
		return devnode.Dev{}, false
	}
	return devnode.Dev{Major: uint32(ma), Minor: uint32(mi)}, true
}

// DMName is the device-mapper name LVM uses for vg/lv.
func DMName(vg, lv string) string {
	return strings.ReplaceAll(vg, "-", "--") + "-" + strings.ReplaceAll(lv, "-", "--")
}

// Get returns one LV, or ErrNotFound.
func (l *LVM) Get(ctx context.Context, name string) (LV, error) {
	r, err := l.Report(ctx)
	if err != nil {
		return LV{}, err
	}
	lv, ok := r.LVs[name]
	if !ok {
		return LV{}, ErrNotFound
	}
	return lv, nil
}

// ErrNotFound is returned for a missing LV.
var ErrNotFound = errors.New("logical volume not found")

func exists(err error) bool {
	return err != nil && strings.Contains(err.Error(), "already exists")
}

func missing(err error) bool {
	return err != nil && (strings.Contains(err.Error(), "Failed to find logical volume") ||
		strings.Contains(err.Error(), "not found"))
}

func tagArgs(flag string, tags []string) []string {
	var a []string
	for _, t := range tags {
		a = append(a, flag, t)
	}
	return a
}

// CreateThin creates a thin LV of size bytes with tags. If it exists, it
// is left as is.
func (l *LVM) CreateThin(ctx context.Context, name string, size int64, tags []string) error {
	args := append([]string{"lvcreate", "-q", "-V", strconv.FormatInt(size, 10) + "b", "-T", l.cfg.VG + "/" + l.cfg.Pool, "-n", name}, tagArgs("--addtag", tags)...)
	_, err := l.cmd(ctx, args...)
	if exists(err) {
		return nil
	}
	return err
}

// Snapshot creates a thin snapshot name of origin with tags. Snapshots
// skip activation by default; use Activate. If name exists, it is left as
// is.
func (l *LVM) Snapshot(ctx context.Context, origin, name string, tags []string) error {
	args := append([]string{"lvcreate", "-q", "-s", l.cfg.VG + "/" + origin, "-n", name}, tagArgs("--addtag", tags)...)
	_, err := l.cmd(ctx, args...)
	if exists(err) {
		return nil
	}
	if missing(err) {
		return fmt.Errorf("snapshot origin %s: %w", origin, ErrNotFound)
	}
	return err
}

// Tag adds and removes tags.
func (l *LVM) Tag(ctx context.Context, name string, add, del []string) error {
	if len(add) == 0 && len(del) == 0 {
		return nil
	}
	args := append([]string{"lvchange", "-q"}, tagArgs("--addtag", add)...)
	args = append(args, tagArgs("--deltag", del)...)
	_, err := l.cmd(ctx, append(args, l.cfg.VG+"/"+name)...)
	if missing(err) {
		return ErrNotFound
	}
	return err
}

// Activate activates an LV (also one that skips activation) and returns
// its device number.
func (l *LVM) Activate(ctx context.Context, name string) (devnode.Dev, error) {
	if _, err := l.cmd(ctx, "lvchange", "-q", "-ay", "-K", l.cfg.VG+"/"+name); err != nil {
		if missing(err) {
			return devnode.Dev{}, ErrNotFound
		}
		return devnode.Dev{}, err
	}
	lv, err := l.Get(ctx, name)
	if err != nil {
		return devnode.Dev{}, err
	}
	if !lv.Active {
		return devnode.Dev{}, fmt.Errorf("lv %s did not activate", name)
	}
	return lv.Dev, nil
}

// Deactivate deactivates an LV. A missing LV is not an error.
func (l *LVM) Deactivate(ctx context.Context, name string) error {
	_, err := l.cmd(ctx, "lvchange", "-q", "-an", l.cfg.VG+"/"+name)
	if missing(err) {
		return nil
	}
	return err
}

// Remove removes an LV. A missing LV is not an error.
func (l *LVM) Remove(ctx context.Context, name string) error {
	_, err := l.cmd(ctx, "lvremove", "-q", "-y", l.cfg.VG+"/"+name)
	if missing(err) {
		return nil
	}
	return err
}

// ActivatePool makes sure the thin pool is active (needed for messages,
// thin_dump and thin_delta) and returns a fresh report.
func (l *LVM) ActivatePool(ctx context.Context) (Report, error) {
	if _, err := l.cmd(ctx, "lvchange", "-q", "-ay", l.cfg.VG+"/"+l.cfg.Pool); err != nil {
		return Report{}, err
	}
	return l.Report(ctx)
}

// DeactivateVG deactivates every LV of the VG.
func (l *LVM) DeactivateVG(ctx context.Context) error {
	_, err := l.cmd(ctx, "vgchange", "-q", "-an", l.cfg.VG)
	return err
}
