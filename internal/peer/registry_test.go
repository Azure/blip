// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package peer

import "testing"

func TestRegistryValidationAndReadiness(t *testing.T) {
	r := NewRegistry()
	select {
	case <-r.Ready():
		t.Fatal("registry ready before initial snapshot")
	default:
	}
	p := Peer{Node: "node", PublicKey: testIdentity(t).PublicKey(), Endpoint: "192.0.2.1"}
	if !p.Valid() {
		t.Fatal("valid peer rejected")
	}
	for _, invalid := range []Peer{
		{Node: "", PublicKey: p.PublicKey, Endpoint: p.Endpoint},
		{Node: "bad-key", PublicKey: "invalid", Endpoint: p.Endpoint},
		{Node: "bad-ip", PublicKey: p.PublicKey, Endpoint: "host.example"},
		{Node: "ipv6", PublicKey: p.PublicKey, Endpoint: "2001:db8::1"},
	} {
		if invalid.Valid() {
			t.Fatalf("invalid peer accepted: %+v", invalid)
		}
		r.SetPeers([]Peer{invalid})
		if _, ok := r.Lookup(invalid.Node); ok {
			t.Fatal("invalid peer entered registry")
		}
	}
	select {
	case <-r.Ready():
	default:
		t.Fatal("initial filtered snapshot did not mark registry ready")
	}
	r.SetPeers([]Peer{p})
	if got, ok := r.Lookup(p.Node); !ok || got != p {
		t.Fatalf("Lookup = %+v, %v", got, ok)
	}
	if node, ok := r.NodeForKey(p.PublicKey); !ok || node != p.Node {
		t.Fatalf("NodeForKey = %q, %v", node, ok)
	}
	r.SetPeers(nil)
	if _, ok := r.Lookup(p.Node); ok {
		t.Fatal("deleted node remains trusted")
	}
	if _, ok := r.NodeForKey(p.PublicKey); ok {
		t.Fatal("deleted key remains trusted")
	}
}

func TestRegistryAmbiguousIdentitiesFailClosed(t *testing.T) {
	a := Peer{Node: "a", PublicKey: testIdentity(t).PublicKey(), Endpoint: "192.0.2.1"}
	b := Peer{Node: "b", PublicKey: testIdentity(t).PublicKey(), Endpoint: "192.0.2.2"}
	for _, duplicate := range []Peer{
		{Node: "other", PublicKey: a.PublicKey, Endpoint: "192.0.2.3"},
		{Node: a.Node, PublicKey: testIdentity(t).PublicKey(), Endpoint: "192.0.2.3"},
		{Node: a.Node, PublicKey: a.PublicKey, Endpoint: "192.0.2.3"},
	} {
		r := NewRegistry()
		r.SetPeers([]Peer{a, b, duplicate})
		for _, rejected := range []Peer{a, duplicate} {
			if _, ok := r.Lookup(rejected.Node); ok {
				t.Fatalf("ambiguous node remains trusted: %+v", rejected)
			}
			if _, ok := r.NodeForKey(rejected.PublicKey); ok {
				t.Fatalf("ambiguous key remains trusted: %+v", rejected)
			}
		}
		if _, ok := r.Lookup(b.Node); !ok {
			t.Fatal("unrelated peer was removed")
		}
	}
	// An identical duplicate carries no ambiguity.
	r := NewRegistry()
	r.SetPeers([]Peer{a, a})
	if _, ok := r.Lookup(a.Node); !ok {
		t.Fatal("identical records were treated as conflicting identities")
	}
}
