package storage

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	blockSize    = 64 << 10 // thin pool block size and dm-clone region size
	blockSectors = blockSize / 512
)

// run executes a tool and returns its trimmed combined output.
func run(name string, args ...string) (string, error) { return runIn("", nil, name, args...) }

// runIn is run with stdin and extra environment variables.
func runIn(stdin string, env []string, name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	// No udev in containers: libdevmapper must manage /dev/mapper itself.
	cmd.Env = append(append(os.Environ(), "DM_DISABLE_UDEV=1"), env...)
	out, err := cmd.CombinedOutput()
	text := strings.TrimSpace(string(out))
	if err != nil {
		return text, fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, text)
	}
	return text, nil
}

func dmsetup(args ...string) (string, error) { return run("dmsetup", args...) }

func mapperPath(name string) string { return "/dev/mapper/" + name }

// dmNames returns the names of all active device-mapper devices.
func dmNames() map[string]bool {
	names := map[string]bool{}
	paths, _ := filepath.Glob("/sys/block/dm-*/dm/name")
	for _, p := range paths {
		if b, err := os.ReadFile(p); err == nil {
			names[strings.TrimSpace(string(b))] = true
		}
	}
	return names
}

func dmExists(name string) bool { return dmNames()[name] }

func dmCreate(name, table string, readOnly bool) error {
	args := []string{"--noudevsync", "create", name}
	if readOnly {
		args = append(args, "--readonly")
	}
	if _, err := runIn(table+"\n", nil, "dmsetup", args...); err != nil {
		return err
	}
	_, err := dmsetup("mknodes", name)
	return err
}

// dmRemove removes a device; a missing device is not an error. An open
// device returns ErrInUse.
func dmRemove(name string) error {
	if !dmExists(name) {
		os.Remove(mapperPath(name))
		return nil
	}
	if _, err := dmsetup("--noudevsync", "remove", "--retry", name); err != nil {
		if !dmExists(name) {
			return nil
		}
		if strings.Contains(err.Error(), "busy") {
			return fmt.Errorf("%w: %s", ErrInUse, name)
		}
		return err
	}
	os.Remove(mapperPath(name))
	return nil
}

// dmReload replaces the table of an active device, keeping its name and
// device number.
func dmReload(name, table string, readOnly bool) error {
	return (&Store{}).deviceReload(name, table, readOnly)
}

// dmResume is idempotent for recovery: resuming an already-active device can
// fail with EINVAL on some kernels. The attr field includes 's' when suspended.
func dmResume(name string) error {
	if !dmExists(name) {
		return nil
	}
	attr, err := dmsetup("info", "-c", "--noheadings", "-o", "attr", name)
	if err != nil {
		return err
	}
	if !strings.Contains(attr, "s") {
		return nil
	}
	_, err = dmsetup("--noudevsync", "resume", name)
	return err
}

func dmTable(name string) (string, error) { return dmsetup("table", name) }

func dmStatus(name string) (string, error) { return dmsetup("status", name) }

// dmOpenCount reports how many times a device is open, by processes or by
// stacked devices.
func dmOpenCount(name string) (int, error) {
	out, err := dmsetup("info", "-c", "--noheadings", "-o", "open", name)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(out))
}

func dmMessage(name string, msg ...string) error {
	_, err := dmsetup(append([]string{"message", name, "0"}, msg...)...)
	return err
}

func thinTable(pool string, thin uint32, size int64) string {
	return fmt.Sprintf("0 %d thin %s %d", size/512, mapperPath(pool), thin)
}

func linearTable(dev string, size int64) string {
	return fmt.Sprintf("0 %d linear %s 0", size/512, dev)
}

// cryptTable maps the plaintext of dev. The IV is the sector number, so
// equal plaintext at equal offsets is equal ciphertext under one key: thin
// snapshots, deltas, and digests work on the ciphertext. Tables go to dmsetup
// on stdin, so the key never appears in a process's arguments.
func cryptTable(dev string, size int64, key []byte) string {
	return fmt.Sprintf("0 %d crypt aes-xts-plain64 %x 0 %s 0 3 allow_discards no_read_workqueue no_write_workqueue", size/512, key, dev)
}

// pool messages

func (s *Store) createThin(id uint32) error {
	return s.runOperation([]deviceEffect{{Kind: eCreateThin, Name: s.poolName(), Thin: id}}, nil)
}

func (s *Store) createSnap(id, origin uint32) error {
	return s.runOperation([]deviceEffect{{Kind: eSnapshot, Name: s.poolName(), Thin: id, Origin: origin}}, nil)
}

// deleteThin deletes a thin device; a missing one is not an error.
func (s *Store) deleteThin(id uint32) error {
	return s.runOperation([]deviceEffect{{Kind: eDeleteThin, Name: s.poolName(), Thin: id}}, nil)
}

func deleteThin(pool string, id uint32) error {
	if id == 0 {
		return nil
	}
	err := dmMessage(pool, "delete", strconv.FormatUint(uint64(id), 10))
	if err != nil && strings.Contains(err.Error(), "No data available") {
		return nil
	}
	return err
}

// ensureBlockNode makes sure path is a block device node for the sysfs
// "major:minor" in devFile.
func ensureBlockNode(path, devFile string) error {
	b, err := os.ReadFile(devFile)
	if err != nil {
		return err
	}
	major, minor, err := parseDevNum(string(b))
	if err != nil {
		return err
	}
	return ensureNode(path, major, minor, true)
}

func parseDevNum(s string) (uint32, uint32, error) {
	ma, mi, ok := strings.Cut(strings.TrimSpace(s), ":")
	if !ok {
		return 0, 0, errors.New("bad device number " + s)
	}
	a, err1 := strconv.ParseUint(ma, 10, 32)
	b, err2 := strconv.ParseUint(mi, 10, 32)
	if err1 != nil || err2 != nil {
		return 0, 0, errors.New("bad device number " + s)
	}
	return uint32(a), uint32(b), nil
}
