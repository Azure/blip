package main

import (
	"fmt"
	"strconv"
	"strings"
)

// sizeFlag parses sizes like 4096, 64KiB, 64K or 1MiB.
type sizeFlag int64

func (s *sizeFlag) String() string { return strconv.FormatInt(int64(*s), 10) }

func (s *sizeFlag) Set(v string) error {
	units := []struct {
		suffix string
		mul    int64
	}{{"KiB", 1 << 10}, {"MiB", 1 << 20}, {"K", 1 << 10}, {"M", 1 << 20}, {"B", 1}, {"", 1}}
	for _, u := range units {
		if n, ok := strings.CutSuffix(v, u.suffix); ok {
			x, err := strconv.ParseInt(n, 10, 64)
			if err != nil {
				return fmt.Errorf("bad size %q", v)
			}
			*s = sizeFlag(x * u.mul)
			return nil
		}
	}
	return fmt.Errorf("bad size %q", v)
}
