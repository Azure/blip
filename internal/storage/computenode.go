package storage

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/example/blip/internal/storage/devnode"
	"github.com/example/blip/internal/storage/dm"
	"github.com/example/blip/internal/storage/names"
)

// Defaults of ComputeConfig.
const (
	DefaultDisksPerSlot  = 8
	DefaultVolumeLinkDir = "/dev/blip/volumes"
	DefaultSuspendBudget = 2 * time.Second
)

// ComputeConfig configures a ComputeNode.
type ComputeConfig struct {
	Node   string
	Device string // local disk for the pool; wiped when the pool is created
	DevDir string // private directory for device nodes
	// MetaSize is the thin metadata size in bytes. Default: 1/256 of the
	// device, at least 64MiB and at most 16GiB.
	MetaSize int64
	Timeouts Timeouts
	// DisksPerSlot is the number of disk devices of each slot. Default
	// DefaultDisksPerSlot.
	DisksPerSlot int
	// JournalPath is the intent journal. It must be on a file system that
	// is cleared on reboot, like the pool itself. Default
	// DefaultJournalPath.
	JournalPath string
	// VolumeLinkDir holds the host links <uid> -> overlay device. Default
	// DefaultVolumeLinkDir.
	VolumeLinkDir string
	// SuspendBudget bounds the time overlays stay suspended during
	// CaptureLocal. Default DefaultSuspendBudget.
	SuspendBudget time.Duration
}

// ComputeNode runs storage operations on one compute node.
//
// Every attachment of a BlipVol to an allocation has a read-only
// multipath device over the replica exports of the BlipVol's content (the
// origin), and a local thin device that uses it as external origin (the
// overlay). Local snapshots of overlays are read-only thin devices with
// the same external origin. Slot disks are linear maps onto overlays.
type ComputeNode struct {
	cfg  ComputeConfig
	host *host

	// mu serializes changes to the pool, the journal and device-mapper
	// devices. NVMe connects run without it.
	mu sync.Mutex
	j  *journal // loaded on first use
}

// NewComputeNode checks the config.
func NewComputeNode(cfg ComputeConfig) (*ComputeNode, error) {
	h, err := newHost(cfg.Node, cfg.DevDir, cfg.Timeouts)
	if err != nil {
		return nil, err
	}
	if cfg.Device == "" {
		return nil, errors.New("compute: Device is required")
	}
	if cfg.DisksPerSlot == 0 {
		cfg.DisksPerSlot = DefaultDisksPerSlot
	}
	if cfg.DisksPerSlot < 1 || cfg.DisksPerSlot > 64 {
		return nil, fmt.Errorf("compute: DisksPerSlot %d out of range 1..64", cfg.DisksPerSlot)
	}
	if cfg.JournalPath == "" {
		cfg.JournalPath = DefaultJournalPath
	}
	if cfg.VolumeLinkDir == "" {
		cfg.VolumeLinkDir = DefaultVolumeLinkDir
	}
	if cfg.SuspendBudget == 0 {
		cfg.SuspendBudget = DefaultSuspendBudget
	}
	return &ComputeNode{cfg: cfg, host: h}, nil
}

// DisksPerSlot returns the configured number of disks per slot.
func (c *ComputeNode) DisksPerSlot() int { return c.cfg.DisksPerSlot }

// Errors of compute node operations.
var (
	// ErrStaleGeneration is returned by PrepareReceive for a receive
	// prepared with a higher generation.
	ErrStaleGeneration = errors.New("stale generation")
	// ErrLeftOnly is returned by LocalDelta when the base has blocks the
	// newer snapshot does not have. Overlays never discard, so this means
	// something is wrong; the caller sends the whole device instead.
	ErrLeftOnly = errors.New("thin delta has blocks mapped only in the base")
	// ErrSuspendBudget is returned by CaptureLocal when the overlays
	// stayed suspended longer than the budget. Nothing was captured.
	ErrSuspendBudget = errors.New("suspend budget exceeded")
	// ErrSlotDiskBusy is returned when a slot disk already maps another
	// attachment.
	ErrSlotDiskBusy = errors.New("slot disk is in use")
)

// headerSectors is reserved at the start of the device for a header that
// records the boot ID the pool was created in.
const headerSectors = 2048 // 1MiB

const headerMagic = "BLIPPOOL1\n"

func bootID() string {
	b, _ := os.ReadFile("/proc/sys/kernel/random/boot_id")
	return strings.TrimSpace(string(b))
}

// journal returns the loaded journal, loading it again after a failed
// save (memory may then be ahead of the file). c.mu must be held.
func (c *ComputeNode) journal() (*journal, error) {
	if c.j == nil || c.j.stale {
		j, err := loadJournal(c.cfg.JournalPath, c.cfg.Node)
		if err != nil {
			return nil, err
		}
		c.j = j
	}
	return c.j, nil
}

// PreparePool makes sure the local thin pool exists. If the pool device
// exists, it was created in this boot (device-mapper state does not
// survive a reboot) and is reused. Otherwise the disk is wiped, a new
// pool is created, the boot ID is written to the header and the journal
// is reset. It returns true if a new pool was created.
func (c *ComputeNode) PreparePool(ctx context.Context) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := c.cfg.Node
	if _, err := dm.Get(ctx, names.Pool(n)); err == nil {
		return false, nil
	} else if !errors.Is(err, dm.ErrNotFound) {
		return false, err
	}
	// Leftover pieces of a pool whose creation failed.
	for _, name := range []string{names.PoolMeta(n), names.PoolData(n)} {
		if err := dm.Remove(ctx, name); err != nil {
			return false, err
		}
	}
	disk, err := diskDev(c.cfg.Device)
	if err != nil {
		return false, err
	}
	total, err := devnode.Sectors(disk)
	if err != nil {
		return false, err
	}
	meta := c.cfg.MetaSize / 512
	if meta == 0 {
		meta = min(max(total/256, 64<<20/512), 16<<30/512)
	}
	meta = meta / 8 * 8
	const blk = BlockSize / 512
	data := (total - headerSectors - meta) / blk * blk
	if data < 16*blk {
		return false, fmt.Errorf("compute device %s is too small", c.cfg.Device)
	}
	// A new pool has no thin IDs: start a new journal.
	c.j = newJournal(c.cfg.JournalPath, n)
	if err := c.j.save(); err != nil {
		return false, err
	}
	// Header and an empty metadata superblock, so the pool starts fresh.
	if err := writeAt(c.cfg.Device, 0, header()); err != nil {
		return false, err
	}
	mi, err := dm.Create(ctx, names.PoolMeta(n), names.DMUUID(names.PoolMeta(n)), dm.LinearTable(meta, disk, headerSectors), false)
	if err != nil {
		return false, err
	}
	metaPath, err := devnode.Ensure(c.cfg.DevDir, names.PoolMeta(n), mi.Dev)
	if err != nil {
		return false, err
	}
	if err := writeAt(metaPath, 0, make([]byte, 4096)); err != nil {
		return false, err
	}
	di, err := dm.Create(ctx, names.PoolData(n), names.DMUUID(names.PoolData(n)), dm.LinearTable(data, disk, headerSectors+meta), false)
	if err != nil {
		return false, err
	}
	if _, err := dm.Create(ctx, names.Pool(n), names.DMUUID(names.Pool(n)), dm.ThinPoolTable(data, mi.Dev, di.Dev, blk), false); err != nil {
		return false, err
	}
	return true, nil
}

func header() []byte {
	b := make([]byte, 4096)
	copy(b, headerMagic+"boot_id="+bootID()+"\n")
	return b
}

// PoolBootID returns the boot ID recorded in the device header, or "".
func (c *ComputeNode) PoolBootID() string {
	f, err := os.Open(c.cfg.Device)
	if err != nil {
		return ""
	}
	defer f.Close()
	b := make([]byte, 4096)
	if _, err := f.ReadAt(b, 0); err != nil {
		return ""
	}
	rest, ok := bytes.CutPrefix(b, []byte(headerMagic+"boot_id="))
	if !ok {
		return ""
	}
	id, _, _ := bytes.Cut(rest, []byte("\n"))
	return string(id)
}

func diskDev(path string) (devnode.Dev, error) { return statDev(path) }

func writeAt(path string, off int64, b []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.WriteAt(b, off); err != nil {
		return err
	}
	return f.Sync()
}

// RemovePool removes the pool and every device of this node, and the
// journal. For tests and node teardown.
func (c *ComputeNode) RemovePool(ctx context.Context) error {
	st, err := c.Rescan(ctx)
	if err != nil {
		return err
	}
	var errs []error
	for id := range st.Allocations {
		errs = append(errs, c.Cleanup(ctx, id))
	}
	for id := range st.Slots {
		errs = append(errs, c.RemoveSlot(ctx, id))
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	n := c.cfg.Node
	for _, name := range []string{names.Pool(n), names.PoolMeta(n), names.PoolData(n)} {
		errs = append(errs, dm.Remove(ctx, name))
	}
	if err := errors.Join(errs...); err != nil {
		return err
	}
	c.j = nil
	if err := os.Remove(c.cfg.JournalPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func (c *ComputeNode) poolInfo(ctx context.Context) (dm.Info, error) {
	i, err := dm.Get(ctx, names.Pool(c.cfg.Node))
	if errors.Is(err, dm.ErrNotFound) {
		return dm.Info{}, errors.New("compute pool is not prepared")
	}
	return i, err
}

func (c *ComputeNode) metaPath(ctx context.Context) (string, error) {
	mi, err := dm.Get(ctx, names.PoolMeta(c.cfg.Node))
	if err != nil {
		return "", err
	}
	return devnode.Ensure(c.cfg.DevDir, names.PoolMeta(c.cfg.Node), mi.Dev)
}

// devices is a parsed listing of this node's device-mapper devices.
type devices struct {
	pool      *dm.Info
	origins   map[string]dm.Info           // attKey -> origin
	overlays  map[string]thinDev           // attKey -> overlay
	snaps     map[string]map[int64]thinDev // attKey -> seq -> snapshot
	slotDisks map[string]map[int]dm.Info   // slot -> disk -> device
	thinIDs   map[uint32]string            // thin ID -> device name
	all       []dm.Info
}

type thinDev struct {
	dm.Info
	ThinID uint32
}

func (c *ComputeNode) list(ctx context.Context) (*devices, error) {
	infos, err := dm.List(ctx, names.DMPrefix(c.cfg.Node))
	if err != nil {
		return nil, err
	}
	d := &devices{
		origins: map[string]dm.Info{}, overlays: map[string]thinDev{}, snaps: map[string]map[int64]thinDev{},
		slotDisks: map[string]map[int]dm.Info{}, thinIDs: map[uint32]string{}, all: infos,
	}
	for _, i := range infos {
		n, ok := names.ParseDM(c.cfg.Node, i.Name)
		if !ok {
			continue
		}
		k := attKey(n.AllocID, n.AttID)
		switch n.Kind {
		case names.KindPool:
			d.pool = &i
		case names.KindOrigin:
			d.origins[k] = i
		case names.KindOverlay:
			d.overlays[k] = thinDev{i, n.ThinID}
			d.thinIDs[n.ThinID] = i.Name
		case names.KindLocalSnap:
			if d.snaps[k] == nil {
				d.snaps[k] = map[int64]thinDev{}
			}
			d.snaps[k][n.Seq] = thinDev{i, n.ThinID}
			d.thinIDs[n.ThinID] = i.Name
		case names.KindSlotDisk:
			if d.slotDisks[n.SlotID] == nil {
				d.slotDisks[n.SlotID] = map[int]dm.Info{}
			}
			d.slotDisks[n.SlotID][n.Disk] = i
		}
	}
	return d, nil
}

// EnsureSlot creates the disks of a slot as 1-sector error targets if they
// do not exist, and returns their device numbers, disk 0 first. The device
// plugin hands them to the slot container as /dev/blip/disks/<n>.
func (c *ComputeNode) EnsureSlot(ctx context.Context, slotID string) ([]devnode.Dev, error) {
	if err := names.Check("slot ID", slotID); err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []devnode.Dev
	for n := range c.cfg.DisksPerSlot {
		name := names.SlotDisk(c.cfg.Node, slotID, n)
		if err := names.CheckDM(name); err != nil {
			return nil, err
		}
		i, err := dm.Create(ctx, name, names.DMUUID(name), dm.ErrorTable(1), false)
		if err != nil {
			return nil, err
		}
		out = append(out, i.Dev)
	}
	return out, nil
}

// RemoveSlot removes every disk of the slot.
func (c *ComputeNode) RemoveSlot(ctx context.Context, slotID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	d, err := c.list(ctx)
	if err != nil {
		return err
	}
	var errs []error
	for _, i := range d.slotDisks[slotID] {
		errs = append(errs, dm.Remove(ctx, i.Name))
	}
	return errors.Join(errs...)
}

// slotDiskTarget returns the device a slot disk maps, or a zero Dev for
// the error target.
func slotDiskTarget(ctx context.Context, name string) (devnode.Dev, error) {
	t, err := dm.Table(ctx, name)
	if err != nil {
		return devnode.Dev{}, err
	}
	return linearTarget(t)
}

// linearTarget returns the device a linear table maps, or a zero Dev.
func linearTarget(t string) (devnode.Dev, error) {
	f := strings.Fields(t)
	if len(f) >= 4 && f[2] == "linear" {
		return devnode.Parse(f[3])
	}
	return devnode.Dev{}, nil
}

// pointSlotDisk maps slot disk n onto dev. It fails with ErrSlotDiskBusy
// if the disk maps a live overlay other than dev.
func (c *ComputeNode) pointSlotDisk(ctx context.Context, d *devices, slotID string, n int, dev devnode.Dev, sectors int64) error {
	i, ok := d.slotDisks[slotID][n]
	if !ok {
		return fmt.Errorf("slot %s disk %d: %w", slotID, n, ErrNotFound)
	}
	cur, err := slotDiskTarget(ctx, i.Name)
	if err != nil {
		return err
	}
	if cur != (devnode.Dev{}) && cur != dev {
		for _, o := range d.overlays {
			if o.Dev == cur {
				return fmt.Errorf("slot %s disk %d maps %s: %w", slotID, n, o.Name, ErrSlotDiskBusy)
			}
		}
	}
	return dm.Reload(ctx, i.Name, dm.LinearTable(sectors, dev, 0))
}

// resetSlotDisks points every slot disk that maps one of devs back at a
// 1-sector error target. An inactive table that maps one of devs (left
// by an interrupted reload) is dropped: it keeps the device open.
func (c *ComputeNode) resetSlotDisks(ctx context.Context, d *devices, devs map[devnode.Dev]bool) error {
	var errs []error
	for _, disks := range d.slotDisks {
		for _, i := range disks {
			cur, err := slotDiskTarget(ctx, i.Name)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			if devs[cur] {
				errs = append(errs, dm.Reload(ctx, i.Name, dm.ErrorTable(1)))
			}
			t, err := dm.InactiveTable(ctx, i.Name)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			if dev, _ := linearTarget(t); devs[dev] {
				errs = append(errs, dm.Clear(ctx, i.Name))
			}
		}
	}
	return errors.Join(errs...)
}

// ResetSlotDisk points disk n of a slot back at the error target. A
// missing disk is not an error.
func (c *ComputeNode) ResetSlotDisk(ctx context.Context, slotID string, n int) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	err := dm.Reload(ctx, names.SlotDisk(c.cfg.Node, slotID, n), dm.ErrorTable(1))
	if errors.Is(err, dm.ErrNotFound) || (err != nil && strings.Contains(err.Error(), "No such device")) {
		return nil
	}
	return err
}

// volumeLink is the host link of a BlipVol UID.
func (c *ComputeNode) volumeLink(uid string) string { return filepath.Join(c.cfg.VolumeLinkDir, uid) }

// ensureLink makes link a symlink to target, replacing anything there.
func ensureLink(link, target string) error {
	if cur, err := os.Readlink(link); err == nil && cur == target {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		return err
	}
	tmp := link + ".tmp"
	_ = os.Remove(tmp)
	if err := os.Symlink(target, tmp); err != nil {
		return err
	}
	return os.Rename(tmp, link)
}

// removeLinkTo removes link if it points to target.
func removeLinkTo(link, target string) error {
	if cur, err := os.Readlink(link); err == nil && cur == target {
		if err := os.Remove(link); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

// sortedKeys returns the keys of m in order.
func sortedKeys[V any](m map[string]V) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}
