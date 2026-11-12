package meta

import "time"

// HostData is written by the host into the host slots. Fields are only ever
// added so old guest helpers keep working.
type HostData struct {
	Version      int          `json:"version"`
	AllocationID string       `json:"allocationID,omitempty"`
	Identity     Identity     `json:"identity"`
	Boot         Boot         `json:"boot"`
	Credentials  *Credentials `json:"credentials,omitempty"`
	Volumes      []Volume     `json:"volumes,omitempty"`
	Hostname     string       `json:"hostname,omitempty"`
	Network      *Network     `json:"network,omitempty"`
}

type Identity struct {
	Name      string `json:"name,omitempty"`
	Namespace string `json:"namespace,omitempty"`
	UID       string `json:"uid,omitempty"`
}

type Boot struct {
	// RootSerial is the virtio serial of the root disk (the root volume name).
	RootSerial       string   `json:"rootSerial,omitempty"`
	Init             []string `json:"init,omitempty"`
	RootMountOptions string   `json:"rootMountOptions,omitempty"`
	RootFSType       string   `json:"rootFSType,omitempty"`
}

type Credentials struct {
	Token      string    `json:"token,omitempty"`
	CACrt      string    `json:"caCrt,omitempty"`
	Namespace  string    `json:"namespace,omitempty"`
	Expiration time.Time `json:"expiration,omitzero"`
}

type Volume struct {
	Name   string `json:"name"`
	Serial string `json:"serial"`
}

// Network is informational; the guest gets its config via DHCP.
type Network struct {
	MAC       string   `json:"mac,omitempty"`
	MTU       int      `json:"mtu,omitempty"`
	Addresses []string `json:"addresses,omitempty"` // CIDR
	Routes    []Route  `json:"routes,omitempty"`
	DNS       []string `json:"dns,omitempty"`
	Search    []string `json:"search,omitempty"`
}

type Route struct {
	Dst     string `json:"dst"` // CIDR, "0.0.0.0/0" for default
	Gateway string `json:"gateway,omitempty"`
}

// GuestState is the boot state reported by the guest.
type GuestState string

const (
	StateWaiting GuestState = "WAITING"
	StateExec    GuestState = "EXEC"
	StateFail    GuestState = "FAIL"
)

// Failure reasons for StateFail.
const (
	ReasonMetaNotFound    = "MetaNotFound"
	ReasonRootNotFound    = "RootNotFound"
	ReasonRootMountFailed = "RootMountFailed"
	ReasonInitNotFound    = "InitNotFound"
)

// GuestData is written by the guest into the guest area. The host must treat
// it as untrusted.
type GuestData struct {
	Seq       uint64     `json:"seq"`
	State     GuestState `json:"state,omitempty"`
	Reason    string     `json:"reason,omitempty"`
	Message   string     `json:"message,omitempty"`
	BootCount int        `json:"bootCount"`
	ExitCode  *int       `json:"exitCode,omitempty"`
	Time      time.Time  `json:"time,omitzero"`
}
