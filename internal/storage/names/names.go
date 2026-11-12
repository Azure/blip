// Package names builds every name Blip storage creates in the kernel.
//
// Several nodes can share one kernel (kind), so each name includes the node
// name (design section 7.1).
package names

import (
	"crypto/sha256"
	"fmt"
	"hash/fnv"
	"regexp"
	"strconv"
	"strings"
)

// NQNPrefix is the prefix of every NQN Blip uses.
const NQNPrefix = "nqn.2026-01.com.example.blip"

// DMUUIDPrefix starts the uuid of every device-mapper device Blip creates,
// so a host multipathd ignores them.
const DMUUIDPrefix = "BLIP-"

var validName = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$`)

// Check returns an error if s is not a safe name part: lower case letters,
// digits, '.' and '-', at most 63 characters. Node names, content IDs and
// allocation IDs must pass it.
func Check(kind, s string) error {
	if len(s) == 0 || len(s) > 63 || !validName.MatchString(s) {
		return fmt.Errorf("invalid %s %q", kind, s)
	}
	return nil
}

// HostNQN is the host NQN of a node.
func HostNQN(node string) string { return NQNPrefix + ":host:" + node }

// HostID is a stable UUID for a host NQN. The kernel rejects two host NQNs
// with the same host ID, so each node needs its own.
func HostID(hostNQN string) string {
	h := sha256.Sum256([]byte(hostNQN))
	h[6] = h[6]&0x0f | 0x80 // version 8 (custom)
	h[8] = h[8]&0x3f | 0x80 // RFC 4122 variant
	return fmt.Sprintf("%x-%x-%x-%x-%x", h[0:4], h[4:6], h[6:8], h[8:10], h[10:16])
}

// LV is the LV name of a content.
func LV(contentID string) string { return "c-" + contentID }

// ContentOfLV returns the content ID of an LV name, or false.
func ContentOfLV(lv string) (string, bool) {
	return strings.CutPrefix(lv, "c-")
}

// SubsystemNQN is the subsystem NQN for an export of a content on a node.
// Read-only and read-write exports use different NQNs.
func SubsystemNQN(node, contentID string, rw bool) string {
	n := NQNPrefix + ":" + node + ":" + LV(contentID)
	if rw {
		n += ":rw"
	}
	return n
}

// ParseSubsystemNQN splits a subsystem NQN made by SubsystemNQN.
func ParseSubsystemNQN(nqn string) (node, contentID string, rw bool, ok bool) {
	rest, ok := strings.CutPrefix(nqn, NQNPrefix+":")
	if !ok {
		return "", "", false, false
	}
	parts := strings.Split(rest, ":")
	if len(parts) == 3 && parts[2] == "rw" {
		rw = true
		parts = parts[:2]
	}
	if len(parts) != 2 || parts[0] == "host" {
		return "", "", false, false
	}
	id, ok := ContentOfLV(parts[1])
	if !ok {
		return "", "", false, false
	}
	return parts[0], id, rw, true
}

// PortID is the nvmet port number for a node's listen address. configfs
// port names must be numbers, so the node name is hashed into one.
func PortID(node, addr string, svc int) uint16 {
	h := fnv.New32a()
	fmt.Fprintf(h, "%s/%s/%d", node, addr, svc)
	return uint16(h.Sum32()%60000) + 1000
}

// Device-mapper names. They all start with DMPrefix(node). Parts are
// separated by "_", which node names and IDs never contain, so parsing is
// unambiguous even when node names contain "-".

// DMPrefix starts every device-mapper name of a node.
func DMPrefix(node string) string { return "blip_" + node + "_" }

// DMUUID is the uuid for a device-mapper name.
func DMUUID(name string) string { return DMUUIDPrefix + name }

// PoolMeta, PoolData and Pool are the compute pool devices.
func PoolMeta(node string) string { return DMPrefix(node) + "pool_meta" }
func PoolData(node string) string { return DMPrefix(node) + "pool_data" }
func Pool(node string) string     { return DMPrefix(node) + "pool" }

// MaxDMName is the longest device-mapper name Blip creates: the kernel
// accepts 127 bytes for names and 128 for uuids, and DMUUID adds a prefix.
const MaxDMName = 128 - len(DMUUIDPrefix)

// CheckDM returns an error if name (or its DMUUID) is too long for
// device-mapper. Long node names leave less room for IDs.
func CheckDM(name string) error {
	if len(name) > MaxDMName {
		return fmt.Errorf("device-mapper name %q is longer than %d bytes", name, MaxDMName)
	}
	return nil
}

// Origin is the read-only multipath device over the replica exports of an
// attachment's input content: the external origin of its overlay and
// local snapshots.
func Origin(node, allocID, attID string) string {
	return DMPrefix(node) + "mp_" + allocID + "_" + attID
}

// Overlay is the writable local thin device of an attachment.
func Overlay(node string, thinID uint32, allocID, attID string) string {
	return DMPrefix(node) + "ov_" + strconv.FormatUint(uint64(thinID), 10) + "_" + allocID + "_" + attID
}

// LocalSnap is the read-only device of local snapshot seq of an
// attachment.
func LocalSnap(node string, thinID uint32, allocID, attID string, seq int64) string {
	return DMPrefix(node) + "ls_" + strconv.FormatUint(uint64(thinID), 10) + "_" + allocID + "_" + attID + "_" + strconv.FormatInt(seq, 10)
}

// SlotDisk is disk n of a slot, exposed in the slot container as
// /dev/blip/disks/<n>.
func SlotDisk(node, slotID string, n int) string {
	return DMPrefix(node) + "slot_" + slotID + "_d" + strconv.Itoa(n)
}

// Kind of a parsed device-mapper name.
type Kind int

const (
	KindUnknown Kind = iota
	KindPoolMeta
	KindPoolData
	KindPool
	KindOrigin
	KindOverlay
	KindLocalSnap
	KindSlotDisk
)

// DMName is a parsed device-mapper name.
type DMName struct {
	Kind    Kind
	ThinID  uint32
	AllocID string
	AttID   string
	Seq     int64
	SlotID  string
	Disk    int
}

// ParseDM parses a device-mapper name of node. ok is false for names of
// other nodes or unknown names.
func ParseDM(node, name string) (DMName, bool) {
	rest, ok := strings.CutPrefix(name, DMPrefix(node))
	if !ok {
		return DMName{}, false
	}
	kind, rest, _ := strings.Cut(rest, "_")
	parts := strings.Split(rest, "_")
	for _, p := range parts {
		if p == "" {
			parts = nil
		}
	}
	thin := func(s string) (uint32, bool) {
		n, err := strconv.ParseUint(s, 10, 32)
		return uint32(n), err == nil
	}
	switch {
	case kind == "pool" && rest == "meta":
		return DMName{Kind: KindPoolMeta}, true
	case kind == "pool" && rest == "data":
		return DMName{Kind: KindPoolData}, true
	case kind == "pool" && rest == "":
		return DMName{Kind: KindPool}, true
	case kind == "mp" && len(parts) == 2:
		return DMName{Kind: KindOrigin, AllocID: parts[0], AttID: parts[1]}, true
	case kind == "ov" && len(parts) == 3:
		id, ok := thin(parts[0])
		return DMName{Kind: KindOverlay, ThinID: id, AllocID: parts[1], AttID: parts[2]}, ok
	case kind == "ls" && len(parts) == 4:
		id, ok := thin(parts[0])
		seq, err := strconv.ParseInt(parts[3], 10, 64)
		return DMName{Kind: KindLocalSnap, ThinID: id, AllocID: parts[1], AttID: parts[2], Seq: seq}, ok && err == nil
	case kind == "slot" && len(parts) == 2:
		d, ok := strings.CutPrefix(parts[1], "d")
		n, err := strconv.Atoi(d)
		return DMName{Kind: KindSlotDisk, SlotID: parts[0], Disk: n}, ok && err == nil && n >= 0
	}
	return DMName{}, false
}
