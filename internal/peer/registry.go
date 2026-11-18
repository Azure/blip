package peer

import (
	"crypto/ed25519"
	"encoding/base64"
	"net"
	"sync"
)

// Valid reports whether this peer has a node name, a canonical Ed25519 public
// key, and an IPv4 endpoint. Certificate names and source addresses are not
// identities.
func (p Peer) Valid() bool {
	key, err := base64.StdEncoding.Strict().DecodeString(p.PublicKey)
	return p.Node != "" && net.ParseIP(p.Endpoint).To4() != nil && err == nil &&
		len(key) == ed25519.PublicKeySize && base64.StdEncoding.EncodeToString(key) == p.PublicKey
}

// Registry is the current Kubernetes-published node/key/endpoint snapshot.
// Readers never observe a partially applied snapshot.
type Registry struct {
	mu    sync.RWMutex
	nodes map[string]Peer
	keys  map[string]string
	ready chan struct{}
	once  sync.Once
}

func NewRegistry() *Registry { return &Registry{ready: make(chan struct{})} }

// SetPeers replaces the registry. Invalid entries are ignored; conflicting
// node names or public keys make every involved entry untrusted.
func (r *Registry) SetPeers(peers []Peer) {
	unique := make(map[Peer]struct{}, len(peers))
	nodeCount, keyCount := map[string]int{}, map[string]int{}
	for _, p := range peers {
		if !p.Valid() {
			continue
		}
		if _, ok := unique[p]; ok {
			continue
		}
		unique[p] = struct{}{}
		nodeCount[p.Node]++
		keyCount[p.PublicKey]++
	}
	nodes, keys := map[string]Peer{}, map[string]string{}
	for p := range unique {
		if nodeCount[p.Node] == 1 && keyCount[p.PublicKey] == 1 {
			nodes[p.Node] = p
			keys[p.PublicKey] = p.Node
		}
	}
	r.mu.Lock()
	r.nodes, r.keys = nodes, keys
	r.mu.Unlock()
	r.once.Do(func() { close(r.ready) })
}

func (r *Registry) Lookup(node string) (Peer, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.nodes[node]
	return p, ok
}

func (r *Registry) NodeForKey(key string) (string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	node, ok := r.keys[key]
	return node, ok
}

// Ready closes after the first snapshot, including an empty snapshot.
func (r *Registry) Ready() <-chan struct{} { return r.ready }
