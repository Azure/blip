// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package guest

import (
	"errors"
	"os"
	"runtime"
	"strings"

	"golang.org/x/sys/unix"
)

// errAccessUnavailable means the process cannot evaluate the access check with
// the target account's credentials (it is neither root nor already running as
// that account), or the kernel lacks faccessat2/AT_EMPTY_PATH. Callers then
// fall back to the mode-bit approximation.
var errAccessUnavailable = errors.New("access check unavailable")

// checkAccess reports whether acct may access p inside root with mode (R_OK,
// W_OK, or X_OK). It asks the kernel rather than interpreting mode bits, so
// POSIX ACLs, supplementary groups, and root's capability semantics all match
// what the child will see after chroot.
//
// The path is resolved with RESOLVE_IN_ROOT, so absolute symlinks and ".."
// are clamped to the workload root exactly as they are for the child.
func checkAccess(root, p string, mode uint32, acct *account) error {
	rootfd, err := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(rootfd)

	if os.Geteuid() != 0 {
		// Without root we can only ask the kernel about the account we are
		// already running as. Switching supplementary groups needs
		// CAP_SETGID, so require an exact group match rather than guessing.
		if uint32(os.Geteuid()) == acct.uid && currentGroupsMatch(acct) {
			return accessAt(rootfd, p, mode)
		}
		return errAccessUnavailable
	}
	return withAccountCreds(acct, func() error {
		return accessAt(rootfd, p, mode)
	})
}

// accessAt checks p relative to rootfd as the current credentials. It first
// requires search permission on the root itself (faccessat2 on an O_PATH fd
// does not re-check its own starting directory), then lets openat2/namei
// enforce search permission on every component before checking the final
// object.
func accessAt(rootfd int, p string, mode uint32) error {
	if err := unix.Faccessat2(rootfd, "", unix.X_OK, unix.AT_EMPTY_PATH|unix.AT_EACCESS); err != nil {
		return accessError(err)
	}
	rel := strings.TrimPrefix(p, "/")
	if rel == "" {
		rel = "."
	}
	fd, err := openat2(rootfd, rel, unix.O_PATH, 0, unix.RESOLVE_IN_ROOT)
	if err != nil {
		return accessError(err)
	}
	defer unix.Close(fd)
	return accessError(unix.Faccessat2(fd, "", mode, unix.AT_EMPTY_PATH|unix.AT_EACCESS))
}

// accessError maps a syscall that is unavailable on this kernel to
// errAccessUnavailable so the caller can use its fallback. Real access
// denials stay EACCES and a missing component stays ENOENT.
func accessError(err error) error {
	if errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EINVAL) {
		// EINVAL here is the old-kernel/old-glibc response to
		// faccessat2 flags rather than a property of the file.
		return errAccessUnavailable
	}
	return err
}

// currentGroupsMatch reports whether the current process already has exactly
// the effective group set acct would get: fsgid plus supplementary groups.
func currentGroupsMatch(acct *account) bool {
	groups, err := unix.Getgroups()
	if err != nil {
		return false
	}
	want := map[uint32]bool{acct.gid: true}
	for _, g := range acct.groups {
		want[g] = true
	}
	got := map[uint32]bool{uint32(os.Getegid()): true}
	for _, g := range groups {
		got[uint32(g)] = true
	}
	if len(want) != len(got) {
		return false
	}
	for g := range want {
		if !got[g] {
			return false
		}
	}
	return true
}

// withAccountCreds runs fn with the filesystem credentials of acct.
//
// Linux keeps credentials per thread. runtime.LockOSThread pins this goroutine
// so the setfsuid/setfsgid/setgroups/capset switch is visible to fn's syscalls
// and invisible to every other goroutine, and the deferred restore runs on the
// same thread. The window is still tiny but not free: a thread created by this
// M during the switch would inherit these credentials. The guest does not
// create threads from the request path, but the restore is deliberately
// unconditional (including on panic) for that reason.
//
// Effective capabilities are cleared for a non-root account because the guest
// runs as root; leaving CAP_DAC_OVERRIDE set would make every faccessat2
// succeed and hide exactly the ACL denials this helper exists to catch. The
// permitted set is untouched, so the saved effective set can be restored
// before fsuid/fsgid/groups are restored.
func withAccountCreds(acct *account, fn func() error) (err error) {
	if acct.uid == 0 {
		// The guest already runs as root; the kernel applies root's
		// capability semantics to this check exactly as it will to the
		// child.
		return fn()
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	oldGroups, err := unix.Getgroups()
	if err != nil {
		return errAccessUnavailable
	}
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var saved [2]unix.CapUserData
	if err := unix.Capget(&hdr, &saved[0]); err != nil {
		return errAccessUnavailable
	}

	oldUID, _ := unix.SetfsuidRetUid(int(acct.uid))
	if now, _ := unix.SetfsuidRetUid(int(acct.uid)); now != int(acct.uid) {
		unix.SetfsuidRetUid(oldUID)
		return errAccessUnavailable
	}
	// Registered in reverse restore order below: fsuid, fsgid, groups, then
	// the capability set (which must come back first so the others are
	// permitted).
	defer unix.SetfsuidRetUid(oldUID)

	oldGID, _ := unix.SetfsgidRetGid(int(acct.gid))
	if now, _ := unix.SetfsgidRetGid(int(acct.gid)); now != int(acct.gid) {
		return errAccessUnavailable
	}
	defer unix.SetfsgidRetGid(oldGID)

	gids := make([]int, 0, len(acct.groups))
	for _, g := range acct.groups {
		gids = append(gids, int(g))
	}
	if err := unix.Setgroups(gids); err != nil {
		return errAccessUnavailable
	}
	defer unix.Setgroups(oldGroups)

	dropped := saved
	dropped[0].Effective = 0
	dropped[1].Effective = 0
	if err := unix.Capset(&hdr, &dropped[0]); err != nil {
		return errAccessUnavailable
	}
	defer unix.Capset(&hdr, &saved[0])

	return fn()
}
