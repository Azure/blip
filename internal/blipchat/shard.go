// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package blipchat

import (
	"context"
	"hash/fnv"
	"log/slog"
	"sort"
	"sync"
	"time"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

const (
	shardRefresh      = 5 * time.Second
	reconcileInterval = 2 * time.Second
)

// sharder assigns each chat to exactly one blipchat replica. Ownership is a
// pure function of the ready endpoint list and the chat name, so replicas agree
// without any shared state. The node still serializes every append, so a stale
// endpoint list is a performance problem, not a correctness one.
type sharder struct {
	cluster   Cluster
	namespace string
	service   string
	self      string
	log       *slog.Logger

	mu      sync.Mutex
	members []string
	changed bool
}

func newSharder(cluster Cluster, namespace, service, self string, log *slog.Logger) *sharder {
	return &sharder{cluster: cluster, namespace: namespace, service: service, self: self, log: log}
}

func (sh *sharder) run(ctx context.Context) {
	sh.refresh(ctx)
	ticker := time.NewTicker(shardRefresh)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sh.refresh(ctx)
		}
	}
}

func (sh *sharder) refresh(ctx context.Context) {
	if sh.service == "" {
		return
	}
	members, err := sh.cluster.ListEndpointMembers(ctx, sh.namespace, sh.service)
	if err != nil {
		// Keep the previous view: ownership is advisory and the node still
		// serializes writes.
		sh.log.Debug("list blipchat endpoints", "service", sh.service, "err", err)
		return
	}
	sort.Strings(members)
	sh.mu.Lock()
	if !sameMembers(sh.members, members) {
		sh.changed = true
	}
	sh.members = members
	sh.mu.Unlock()
}

// owns reports whether this replica should drive the chat. An unknown or empty
// membership means every replica owns everything, which is correct for a single
// replica and during startup before the endpoint list is visible.
// takeChanged reports whether the endpoint set changed since the last call.
// A change can move chats between replicas, so the supervisor does a full pass
// (including chats whose last generation already ended).
func (sh *sharder) takeChanged() bool {
	if sh == nil {
		return false
	}
	sh.mu.Lock()
	defer sh.mu.Unlock()
	changed := sh.changed
	sh.changed = false
	return changed
}

func sameMembers(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func (sh *sharder) owns(chat string) bool {
	if sh == nil || sh.service == "" || sh.self == "" {
		return true
	}
	sh.mu.Lock()
	members := sh.members
	sh.mu.Unlock()
	if len(members) == 0 {
		return true
	}
	best := ""
	var bestScore uint64
	for _, member := range members {
		score := rendezvousScore(member, chat)
		if best == "" || score > bestScore || (score == bestScore && member < best) {
			best, bestScore = member, score
		}
	}
	return best == sh.self
}

func rendezvousScore(member, chat string) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(member))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(chat))
	return h.Sum64()
}

// supervise keeps an engine running for every chat this replica owns that has
// an active generation. The first pass also adopts chats whose last generation
// is over, so a prompt left undelivered by a previous pod is retried.
func (s *Server) supervise(ctx context.Context) {
	s.reconcile(ctx, true)
	ticker := time.NewTicker(reconcileInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.reconcile(ctx, s.shards != nil && s.shards.takeChanged())
		}
	}
}

func (s *Server) reconcile(ctx context.Context, full bool) {
	states, err := s.cluster.ListSessions(ctx, s.namespace)
	if err != nil {
		s.log.Debug("reconcile chats", "err", err)
		return
	}
	blips, err := s.cluster.ListSessionBlips(ctx, s.namespace)
	if err != nil {
		s.log.Debug("reconcile chat blips", "err", err)
		return
	}
	byState := make(map[string][]v1.Blip, len(states))
	for i := range blips {
		if name := blips[i].Labels[LabelSession]; name != "" {
			byState[name] = append(byState[name], blips[i])
		}
	}
	for i := range states {
		st := &states[i]
		if s.shards != nil && !s.shards.owns(st.Name) {
			continue
		}
		active := activeBlip(byState[st.Name]) != nil
		if !active && !(full && st.Status.Phase == v1.StateReady) {
			continue
		}
		s.ensureEngine(st.Name)
	}
	s.reapSessions(ctx, states, byState, time.Now())
}
