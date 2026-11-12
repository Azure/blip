package nvmehost

import (
	"github.com/example/blip/internal/storage/devnode"
	"golang.org/x/sys/unix"
)

func mknodChar(path string, d devnode.Dev) error {
	return unix.Mknod(path, unix.S_IFCHR|0o600, int(unix.Mkdev(d.Major, d.Minor)))
}
