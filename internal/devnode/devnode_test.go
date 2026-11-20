// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package devnode

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestParse(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want uint64
	}{
		{"8:0", unix.Mkdev(8, 0)},
		{" 259:3\n", unix.Mkdev(259, 3)},
	} {
		got, err := Parse(tc.in)
		if err != nil {
			t.Fatalf("Parse(%q): %v", tc.in, err)
		}
		if got != tc.want {
			t.Errorf("Parse(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
	for _, in := range []string{"", "8", "x:0", "8:y", "8:0:1"} {
		if _, err := Parse(in); err == nil {
			t.Errorf("Parse(%q) succeeded", in)
		}
	}
}
