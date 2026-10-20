package blipfs

import (
	"bytes"
	"fmt"
	"math/rand"
	"sort"
	"testing"
)

// memLoader serves persisted nodes from a byte slice.
type memLoader struct{ buf []byte }

func (m *memLoader) readNode(l Loc) ([]byte, error) { return m.buf[l.Off : l.Off+int64(l.Len)], nil }

func treeOf(t *testing.T, tr Tree) map[string]string {
	t.Helper()
	got := map[string]string{}
	var prev []byte
	err := tr.Ascend(nil, func(k, v []byte) bool {
		if prev != nil && bytes.Compare(prev, k) >= 0 {
			t.Fatalf("keys out of order: %q then %q", prev, k)
		}
		prev = append([]byte(nil), k...)
		got[string(k)] = string(v)
		return true
	})
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func applyModel(t *testing.T, tr Tree, model map[string]string, edits map[string]Edit) Tree {
	t.Helper()
	nt, err := tr.Mutate(sortEdits(edits))
	if err != nil {
		t.Fatal(err)
	}
	for k, e := range edits {
		if e.Del {
			delete(model, k)
		} else {
			model[k] = string(e.Val)
		}
	}
	return nt
}

func TestProllyRandom(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	model := map[string]string{}
	var tr Tree
	for round := range 60 {
		edits := map[string]Edit{}
		n := 1 + r.Intn(400)
		if round%10 == 0 {
			n = 3000
		}
		for range n {
			k := fmt.Sprintf("k%06d", r.Intn(20000))
			if r.Intn(3) == 0 {
				edits[k] = Edit{Key: []byte(k), Del: true}
			} else {
				edits[k] = Edit{Key: []byte(k), Val: []byte(fmt.Sprint(r.Int()))}
			}
		}
		old := tr
		oldModel := map[string]string{}
		for k, v := range model {
			oldModel[k] = v
		}
		tr = applyModel(t, tr, model, edits)
		got := treeOf(t, tr)
		if len(got) != len(model) {
			t.Fatalf("round %d: %d keys, want %d", round, len(got), len(model))
		}
		for k, v := range model {
			if got[k] != v {
				t.Fatalf("round %d: %s=%q want %q", round, k, got[k], v)
			}
			if gv, ok, err := tr.Get([]byte(k)); err != nil || !ok || string(gv) != v {
				t.Fatalf("Get %s = %q %v %v", k, gv, ok, err)
			}
		}

		// Canonical: building the same contents from scratch gives the same root.
		all := map[string]Edit{}
		for k, v := range model {
			all[k] = Edit{Key: []byte(k), Val: []byte(v)}
		}
		fresh, err := Tree{}.Mutate(sortEdits(all))
		if err != nil {
			t.Fatal(err)
		}
		if !fresh.Equal(tr) {
			t.Fatalf("round %d: tree not canonical", round)
		}

		// Diff reports exactly the changed keys.
		want := map[string]bool{}
		for k := range edits {
			if oldModel[k] != model[k] {
				want[k] = true
			}
		}
		seen := map[string]bool{}
		err = Diff(old, tr, func(k, av, bv []byte) error {
			ks := string(k)
			seen[ks] = true
			_, inA := oldModel[ks]
			_, inB := model[ks]
			if (av != nil) != inA || (bv != nil) != inB {
				t.Fatalf("diff %s: presence mismatch", ks)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(seen) != len(want) {
			t.Fatalf("round %d: diff saw %d keys, want %d", round, len(seen), len(want))
		}
		for k := range want {
			if !seen[k] {
				t.Fatalf("round %d: diff missed %s", round, k)
			}
		}
	}
	// Delete everything.
	edits := map[string]Edit{}
	for k := range model {
		edits[k] = Edit{Key: []byte(k), Del: true}
	}
	tr = applyModel(t, tr, model, edits)
	if tr.Root != nil {
		t.Fatal("empty tree should have nil root")
	}
}

func TestProllyFloorAndPersist(t *testing.T) {
	edits := map[string]Edit{}
	var keys []string
	for i := range 5000 {
		k := fmt.Sprintf("x%05d", i*2)
		keys = append(keys, k)
		edits[k] = Edit{Key: []byte(k), Val: []byte(k)}
	}
	tr, err := Tree{}.Mutate(sortEdits(edits))
	if err != nil {
		t.Fatal(err)
	}
	ld := &memLoader{}
	p := &persistBatch{base: 0, locs: map[*Ref]Loc{}}
	p.add(tr.Root)
	ld.buf = p.buf
	l := p.locs[tr.Root]
	loaded := Tree{Root: RefAt(tr.Root.Hash[:], l, ld)}
	sort.Strings(keys)
	for _, tc := range []struct{ q, want string }{
		{"x00000", "x00000"}, {"x00001", "x00000"}, {"x09999", "x09998"}, {"y", "x09998"}, {"a", ""},
	} {
		for _, tt := range []Tree{tr, loaded} {
			k, _, ok, err := tt.Floor([]byte(tc.q))
			if err != nil {
				t.Fatal(err)
			}
			if string(k) != tc.want || ok != (tc.want != "") {
				t.Fatalf("Floor(%s) = %s %v, want %s", tc.q, k, ok, tc.want)
			}
		}
	}
	if got := treeOf(t, loaded); len(got) != 5000 {
		t.Fatalf("loaded tree has %d keys", len(got))
	}
	// Mutating a loaded tree works and keeps hashes canonical.
	nt, err := loaded.Mutate([]Edit{{Key: []byte("x00002"), Del: true}})
	if err != nil {
		t.Fatal(err)
	}
	nt2, _ := tr.Mutate([]Edit{{Key: []byte("x00002"), Del: true}})
	if !nt.Equal(nt2) {
		t.Fatal("hash differs between loaded and in-memory trees")
	}
}
