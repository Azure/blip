// Package peer provides key-pinned mutual TLS control for authenticated
// ciphertext NVMe/TCP exports.
// See docs/ARCHITECTURE.md.
package peer

import (
	"context"
	"time"

	"github.com/Azure/blip/internal/storage"
)

const (
	ExportPort = 7890
	NVMePort   = 4420
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

// ExportResponse describes an exported commit.
type ExportResponse struct {
	LeaseID   string           `json:"leaseID"`
	NQN       string           `json:"nqn"`
	Address   string           `json:"address"`
	Port      int              `json:"port"`
	SizeBytes int64            `json:"sizeBytes"`
	Base      string           `json:"base"`
	Regions   []storage.Region `json:"regions"`
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
	// Optional instance dependencies; production defaults use the kernel,
	// fsync-backed lease file, cryptographic lease IDs, and real time.
	Target          ExportTarget
	Persistence     LeasePersistence
	Clock           Clock
	NewLeaseID      func() string
	RecheckInterval time.Duration
}

// HostNQN returns this node's NVMe host NQN.
func HostNQN(node string) string { return "nqn.2014-08.dev.blip:host:" + node }
