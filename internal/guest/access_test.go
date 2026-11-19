// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package guest

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// POSIX ACL tags and the "undefined" id used by the on-disk encoding.
const (
	aclUserObj  = 0x01
	aclUser     = 0x02
	aclGroupObj = 0x04
	aclGroup    = 0x08
	aclMask     = 0x10
	aclOther    = 0x20
	aclUndef    = 0xffffffff
)

type aclEntry struct {
	tag  uint16
	perm uint16
	id   uint32
}

// setAccessACL installs a POSIX access ACL. Callers must set the mode before
// the ACL: the kernel derives the group permission bits from the mask.
func setAccessACL(t *testing.T, p string, entries ...aclEntry) {
	t.Helper()
	blob := make([]byte, 4)
	binary.LittleEndian.PutUint32(blob, 2) // POSIX_ACL_XATTR_VERSION
	for _, e := range entries {
		raw := make([]byte, 8)
		binary.LittleEndian.PutUint16(raw[0:], e.tag)
		binary.LittleEndian.PutUint16(raw[2:], e.perm)
		binary.LittleEndian.PutUint32(raw[4:], e.id)
		blob = append(blob, raw...)
	}
	if err := unix.Setxattr(p, "system.posix_acl_access", blob, 0); err != nil {
		if errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EOPNOTSUPP) {
			t.Skipf("filesystem does not support POSIX ACLs: %v", err)
		}
		t.Fatalf("setting ACL on %s: %v", p, err)
	}
}

// requireCredentialSwitch skips tests that need chown to an arbitrary uid and
// the setfsuid/setgroups capability to evaluate that account's access.
func requireCredentialSwitch(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires root for chown and credential switching")
	}
}

// A workdir granted to a named user only by an ACL must pass the preflight;
// the mode-bit check alone rejects it (0750 root:root, no group access).
func TestCheckDirAccessAllowsNamedUserACL(t *testing.T) {
	requireCredentialSwitch(t)
	root := testRoot(t)
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "acldir")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(dir, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	// USER_OBJ rwx, named USER 1000 r-x, GROUP_OBJ ---, MASK r-x, OTHER ---.
	setAccessACL(t, dir,
		aclEntry{aclUserObj, 7, aclUndef},
		aclEntry{aclUser, 5, 1000},
		aclEntry{aclGroupObj, 0, aclUndef},
		aclEntry{aclMask, 5, aclUndef},
		aclEntry{aclOther, 0, aclUndef},
	)

	dev := &account{uid: 1000, gid: 1000, groups: []uint32{1000}}
	fi, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if canSearchDir(fi, dev) {
		t.Fatal("test setup: mode bits already grant search, ACL is not the reason")
	}
	if err := checkDirAccess(root, "/acldir", dev); err != nil {
		t.Fatalf("ACL-granted workdir was rejected: %v", err)
	}
}

// A workdir denied by an ACL must be reported as a workdir failure even though
// its mode bits grant group search (0770 root:dev with GROUP_OBJ --- and
// MASK rwx). Otherwise the child chdir fails and the error blames the command.
func TestCheckDirAccessDeniesACLMaskedGroup(t *testing.T) {
	requireCredentialSwitch(t)
	root := testRoot(t)
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "acldeny")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(dir, 0, 1000); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o770); err != nil {
		t.Fatal(err)
	}
	// USER_OBJ rwx, named USER 1234 rwx, GROUP_OBJ ---, MASK rwx, OTHER ---.
	// The group bits therefore read 0770, but the group class grants nothing.
	setAccessACL(t, dir,
		aclEntry{aclUserObj, 7, aclUndef},
		aclEntry{aclUser, 7, 1234},
		aclEntry{aclGroupObj, 0, aclUndef},
		aclEntry{aclMask, 7, aclUndef},
		aclEntry{aclOther, 0, aclUndef},
	)

	dev := &account{uid: 1000, gid: 1000, groups: []uint32{1000}}
	fi, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !canSearchDir(fi, dev) {
		t.Fatal("test setup: mode bits do not grant search, ACL is not the reason")
	}
	err = checkDirAccess(root, "/acldeny", dev)
	if err == nil {
		t.Fatal("ACL-denied workdir was accepted")
	}
	want := "chdir /acldeny: permission denied for uid 1000"
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("error = %q, want it to contain %q", err, want)
	}
}

// A PATH executable granted only by a named-user ACL must be found. The file
// is 0750 root:root, so the old mode-bit check reported 126.
func TestLookPathAllowsNamedUserACL(t *testing.T) {
	requireCredentialSwitch(t)
	root := testRoot(t)
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(root, "bin", "aclhello")
	if err := os.WriteFile(file, []byte("#!/bin/sh\necho ACLHELLO\n"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(file, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(file, 0o750); err != nil {
		t.Fatal(err)
	}
	setAccessACL(t, file,
		aclEntry{aclUserObj, 7, aclUndef},
		aclEntry{aclUser, 5, 1000},
		aclEntry{aclGroupObj, 0, aclUndef},
		aclEntry{aclMask, 5, aclUndef},
		aclEntry{aclOther, 0, aclUndef},
	)

	dev := &account{uid: 1000, gid: 1000, groups: []uint32{1000}}
	fi, err := os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	if canExecFile(fi, dev) {
		t.Fatal("test setup: mode bits already grant execution, ACL is not the reason")
	}
	p, err := lookPath(root, "/", "aclhello", []string{"PATH=/bin"}, dev)
	if err != nil || p != "/bin/aclhello" {
		t.Fatalf("ACL-granted command: %q, %v; want /bin/aclhello", p, err)
	}
}

// A PATH executable denied by an ACL must be reported as permission denied
// (126), not accepted. The 0770 root:dev file grants group execute in mode
// bits, but GROUP_OBJ --- and MASK rwx deny the account in the kernel. A later
// candidate must still win, as execvp continues the search.
func TestLookPathDeniesACLMaskedGroup(t *testing.T) {
	requireCredentialSwitch(t)
	root := testRoot(t)
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{"bin", "later"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	denied := filepath.Join(root, "bin", "acldeny")
	if err := os.WriteFile(denied, []byte("#!/bin/sh\necho DENIED\n"), 0o770); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(denied, 0, 1000); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(denied, 0o770); err != nil {
		t.Fatal(err)
	}
	setAccessACL(t, denied,
		aclEntry{aclUserObj, 7, aclUndef},
		aclEntry{aclGroupObj, 0, aclUndef},
		aclEntry{aclMask, 7, aclUndef},
		aclEntry{aclOther, 0, aclUndef},
	)
	later := filepath.Join(root, "later", "acldeny")
	if err := os.WriteFile(later, []byte("#!/bin/sh\necho LATER\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	dev := &account{uid: 1000, gid: 1000, groups: []uint32{1000}}
	fi, err := os.Stat(denied)
	if err != nil {
		t.Fatal(err)
	}
	if !canExecFile(fi, dev) {
		t.Fatal("test setup: mode bits do not grant execution, ACL is not the reason")
	}

	_, err = lookPath(root, "/", "acldeny", []string{"PATH=/bin"}, dev)
	if startExitCode(err) != 126 || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("ACL-denied command: %v, code %d; want 126 permission denied", err, startExitCode(err))
	}
	p, err := lookPath(root, "/", "acldeny", []string{"PATH=/bin:/later"}, dev)
	if err != nil || p != "/later/acldeny" {
		t.Fatalf("later candidate after ACL denial: %q, %v; want /later/acldeny", p, err)
	}
}

// A named group ACL entry must be honoured for a supplementary group, not just
// the primary gid. This exercises the temporary supplementary group switch.
func TestCheckAccessSupplementaryGroupACL(t *testing.T) {
	requireCredentialSwitch(t)
	root := testRoot(t)
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "aclgrp")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(dir, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	// USER_OBJ rwx, named GROUP 4242 r-x, GROUP_OBJ ---, MASK r-x, OTHER ---.
	setAccessACL(t, dir,
		aclEntry{aclUserObj, 7, aclUndef},
		aclEntry{aclGroupObj, 0, aclUndef},
		aclEntry{aclGroup, 5, 4242},
		aclEntry{aclMask, 5, aclUndef},
		aclEntry{aclOther, 0, aclUndef},
	)

	without := &account{uid: 1000, gid: 1000, groups: []uint32{1000}}
	if err := checkDirAccess(root, "/aclgrp", without); err == nil {
		t.Fatal("supplementary-group ACL applied without that group")
	}
	with := &account{uid: 1000, gid: 1000, groups: []uint32{1000, 4242}}
	if err := checkDirAccess(root, "/aclgrp", with); err != nil {
		t.Fatalf("supplementary-group ACL was not honoured: %v", err)
	}
}
