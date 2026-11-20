// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package storage

import (
	"context"
	"errors"
	"maps"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

var (
	deltaRe  = regexp.MustCompile(`<(different|left_only|right_only) begin="(\d+)" length="(\d+)"`)
	rangeRe  = regexp.MustCompile(`<range_mapping origin_begin="(\d+)" data_begin="\d+" length="(\d+)"`)
	singleRe = regexp.MustCompile(`<single_mapping origin_block="(\d+)"`)
)

// Diff returns the byte ranges a reader holding one of bases must copy to
// reconstruct id. base is the chosen base ("" = none, regions cover every
// mapped block of id). digests lists further commits the reader holds by
// content digest (see Digest); one is a base only if this store's copy has
// the same digest.
func (s *Store) Diff(ctx context.Context, id string, bases []string, digests map[string]string) (string, []Region, error) {
	r, err := s.source(id, "")
	if err != nil {
		return "", nil, err
	}
	defer s.unhold(id)
	if slices.Contains(bases, id) {
		return id, nil, nil
	}
	base := s.pickBase(ctx, r, bases, digests)
	if base != nil {
		defer s.unhold(base.ID)
	}

	var regions []Region
	err = s.withMetaSnap(func() error {
		if base == nil {
			regions, err = s.mapped(r)
			return err
		}
		out, err := run("thin_delta", "-m", "--snap1", strconv.FormatUint(uint64(base.Thin), 10),
			"--snap2", strconv.FormatUint(uint64(r.Thin), 10), s.meta)
		if err != nil {
			return err
		}
		for _, m := range deltaRe.FindAllStringSubmatch(out, -1) {
			regions = append(regions, blocks(m[2], m[3]))
		}
		regions = MergeRegions(regions)
		return nil
	})
	if err != nil {
		return "", nil, err
	}
	// Clip to the volume size (a base may be larger).
	out := regions[:0]
	for _, g := range regions {
		if g.Offset >= r.Size {
			break
		}
		g.Length = min(g.Length, r.Size-g.Offset)
		out = append(out, g)
	}
	baseID := ""
	if base != nil {
		baseID = base.ID
	}
	return baseID, out, nil
}

// withMetaSnap runs fn while the pool holds a metadata snapshot, which
// thin_dump and thin_delta read from s.meta.
func (s *Store) withMetaSnap(fn func() error) (err error) {
	s.snapMu.Lock()
	defer s.snapMu.Unlock()
	pool := s.poolName()
	message := func(msg string) error {
		return s.runOperation([]deviceEffect{{Kind: eMessage, Name: pool, Table: msg}}, nil)
	}
	if err := message("reserve_metadata_snap"); err != nil {
		// A snapshot left by a crash blocks a new one.
		if rerr := message("release_metadata_snap"); rerr != nil {
			return errors.Join(err, rerr)
		}
		if err := message("reserve_metadata_snap"); err != nil {
			return err
		}
	}
	defer func() { err = errors.Join(err, message("release_metadata_snap")) }()
	return fn()
}

// mapped returns the merged regions of r's mapped blocks. It must run in
// withMetaSnap.
func (s *Store) mapped(r *record) ([]Region, error) {
	out, err := run("thin_dump", "-m", "--dev-id", strconv.FormatUint(uint64(r.Thin), 10), s.meta)
	if err != nil {
		return nil, err
	}
	var regions []Region
	for _, m := range rangeRe.FindAllStringSubmatch(out, -1) {
		regions = append(regions, blocks(m[1], m[2]))
	}
	for _, m := range singleRe.FindAllStringSubmatch(out, -1) {
		regions = append(regions, blocks(m[1], "1"))
	}
	return MergeRegions(regions), nil
}

func blocks(begin, length string) Region {
	b, _ := strconv.ParseInt(begin, 10, 64)
	l, _ := strconv.ParseInt(length, 10, 64)
	return Region{Offset: b * blockSize, Length: l * blockSize}
}

// pickBase chooses a held base for r: the nearest ancestor the reader holds,
// else one belonging to the same state. The returned record is held.
//
// A commit named in bases qualifies by ID, unless this store built it from
// an image: each node converts images itself, so the reader's copy may
// differ. A commit named in digests qualifies, whatever its origin, only if
// this store's copy has the reader's content digest.
func (s *Store) pickBase(ctx context.Context, r *record, bases []string, digests map[string]string) *record {
	s.mu.Lock()
	held := map[string]bool{}
	for _, b := range bases {
		if v, ok := s.vols[b]; ok && v.Phase == phaseReady && v.Kind == KindCommit && !s.fromImage(v) {
			held[b] = true
		}
	}
	others := slices.Sorted(maps.Keys(digests))
	for _, b := range others {
		if v, ok := s.vols[b]; ok && v.Phase == phaseReady && v.Kind == KindCommit {
			held[b] = true
		}
	}
	var cands []string
	seen := map[string]bool{}
	for cur := r.Base; cur != "" && !seen[cur]; {
		seen[cur] = true
		if held[cur] {
			cands = append(cands, cur)
		}
		v, ok := s.vols[cur]
		if !ok {
			break
		}
		cur = v.Base
	}
	if r.StateUID != "" {
		for _, b := range append(slices.Clone(bases), others...) {
			if v := s.vols[b]; held[b] && !seen[b] && v.StateUID == r.StateUID {
				seen[b] = true
				cands = append(cands, b)
			}
		}
	}
	s.mu.Unlock()
	for _, b := range cands {
		if !slices.Contains(bases, b) || s.fromImageID(b) {
			if !s.sameContent(ctx, b, digests[b]) {
				continue
			}
		}
		if v, err := s.source(b, ""); err == nil {
			return v
		}
	}
	return nil
}

// fromImage reports whether commit r was built directly from an image. Once
// the image is deleted only its ID is left, and image IDs are digests
// ("sha256:..."), which commit IDs never resemble. s.mu must be held.
func (s *Store) fromImage(r *record) bool {
	if b, ok := s.vols[r.Base]; ok {
		return b.Kind == KindImage
	}
	return strings.Contains(r.Base, ":")
}

func (s *Store) fromImageID(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.vols[id]
	return ok && s.fromImage(v)
}
