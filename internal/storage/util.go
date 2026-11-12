package storage

import (
	"fmt"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/example/blip/internal/storage/devnode"
	"github.com/example/blip/internal/storage/tlskeys"
)

func statDev(path string) (devnode.Dev, error) {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return devnode.Dev{}, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFBLK {
		return devnode.Dev{}, fmt.Errorf("%s is not a block device", path)
	}
	return devnode.Dev{Major: unix.Major(st.Rdev), Minor: unix.Minor(st.Rdev)}, nil
}

// removeHostKeys removes host keys of hostNQN whose subsystem NQN matches.
func removeHostKeys(kr int, hostNQN string, match func(sub string) bool) error {
	prefix := "NVMe0R01 " + hostNQN + " "
	return tlskeys.RemoveMatching(kr, tlskeys.Host, func(ident string) bool {
		sub, ok := strings.CutPrefix(ident, prefix)
		return ok && match(sub)
	})
}
