// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package stream

import "testing"

func TestReadFutureCursorIsNotRingLoss(t *testing.T) {
	w, r, _ := newTest(t, MinSize)
	if _, err := w.Append(TypeOut, []byte("newest")); err != nil {
		t.Fatal(err)
	}
	head, tail := w.Head()
	for _, from := range []uint64{tail, tail + 1, ^uint64(0)} {
		recs, gotHead, err := r.Read(from, 0)
		if err != nil || len(recs) != 0 || gotHead != head {
			t.Fatalf("Read(%d) = %v, head %d, %v; want empty read at head %d without gap", from, recs, gotHead, err, head)
		}
	}
}
