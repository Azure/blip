// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Package peer provides key-pinned mutual TLS control for authenticated
// ciphertext NVMe/TCP exports.
// See the README's implementation outline.
package peer

import (
	"context"
	"time"

	"github.com/Azure/blip/internal/nvme"
	"github.com/Azure/blip/internal/storage"
)

const (
	ExportPort   = 7890
	NVMePort     = 4420
	NVMeRDMAPort = 4421
)

// Peer is another node.
type Peer struct {
	Node      string
	PublicKey string
	Endpoint  string // host IPv4 address, for HTTPS and NVMe/TCP
}

// ExportRequest asks a peer to export a commit.
type ExportRequest struct {
	StateUID string `json:"stateUID"`
	CommitID string `json:"commitID"`
	Purpose  string `json:"purpose"` // replica, attach, mount, copy
	// Bases are commits the requesting node holds with identical bytes; the
	// exporter may use one as a delta base. Empty means send every block.
	Bases []string `json:"bases,omitempty"`
	// BaseDigests are further commits the requesting node holds, by content
	// digest (storage.Store.Digest): commits each node built from an image
	// itself. The exporter may use one as a delta base only if its own copy
	// has the same digest.
	BaseDigests map[string]string `json:"baseDigests,omitempty"`
	HostNQN     string            `json:"hostNQN"`
}

// NVMePath is one transport a lease is exported on.
type NVMePath struct {
	Transport string `json:"transport"`
	Address   string `json:"address"`
	Port      int    `json:"port"`
}

// ExportResponse describes an exported commit.
type ExportResponse struct {
	LeaseID   string           `json:"leaseID"`
	NQN       string           `json:"nqn"`
	Address   string           `json:"address"`
	Port      int              `json:"port"`
	SizeBytes int64            `json:"sizeBytes"`
	Base      string           `json:"base"`
	Regions   []storage.Region `json:"regions"`
	Paths     []NVMePath       `json:"paths,omitempty"`
}

// Authorizer decides whether node may read req.CommitID. It must answer from
// cached cluster state.
type Authorizer func(node string, req ExportRequest) error

// ExportStore is the storage boundary used by the production lease service.
// Operations must be idempotent, including when their previous result was lost.
type ExportStore interface {
	Pin(commitID, holder string) error
	Unpin(commitID, holder string) error
	OpenExport(commitID, leaseID string) (string, error)
	CloseExport(leaseID string) error
	Get(string) (storage.Volume, bool)
	Diff(context.Context, string, []string, map[string]string) (string, []storage.Region, error)
	Exports() map[string]string
	List() []storage.Volume
}

type ExportTarget interface {
	Export(leaseID, device, hostNQN string) (string, error)
	Unexport(leaseID string) error
	Leases() []string
}

// ServerConfig configures the export service.
type ServerConfig struct {
	Store     ExportStore
	NodeName  string
	HostIP    string
	DiskKey   []byte // cluster disk key; NVMe authentication secrets derive from it
	Identity  *Identity
	Peers     *Registry
	Authorize Authorizer
	DataDir   string // lease persistence
	// Stream serves the trajectory/stdin routes. It is optional; without it
	// the stream routes report that the service is unavailable.
	Stream StreamTarget
	// Optional instance dependencies; production defaults use the kernel,
	// fsync-backed lease file, cryptographic lease IDs, and real time.
	Target          ExportTarget
	Persistence     LeasePersistence
	Clock           Clock
	NewLeaseID      func() string
	RecheckInterval time.Duration
	// RDMA also exports every lease over NVMe/RDMA when the target is created
	// by NewServer. A caller-supplied Target owns its own RDMA setup.
	RDMA bool
	// RDMARequired makes a failure to publish the RDMA path fatal instead of
	// leaving the node on NVMe/TCP.
	RDMARequired bool
}

// HostNQN returns this node's NVMe host NQN.
func HostNQN(node string) string { return nvme.NQNPrefix + "host:" + node }
