//go:build linux

package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/example/blip/internal/meta"
)

// credFiles maps file name to (content, mode).
func credFiles(c *meta.Credentials) map[string]struct {
	data []byte
	mode os.FileMode
} {
	type f = struct {
		data []byte
		mode os.FileMode
	}
	return map[string]f{
		"token":     {[]byte(c.Token), 0o600},
		"ca.crt":    {[]byte(c.CACrt), 0o644},
		"namespace": {[]byte(c.Namespace), 0o644},
	}
}

// WriteCreds writes c into dir using the kubelet atomic-writer layout:
// dir/..<timestamp>/{token,ca.crt,namespace}, dir/..data -> ..<timestamp>,
// dir/<file> -> ..data/<file>. Nothing is written if the content is
// unchanged. It reports whether it wrote.
func WriteCreds(dir string, c *meta.Credentials) (bool, error) {
	files := credFiles(c)
	if unchanged(dir, files) {
		return false, nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return false, err
	}
	old, _ := os.Readlink(filepath.Join(dir, "..data"))
	ts, err := os.MkdirTemp(dir, time.Now().UTC().Format("..2006_01_02_15_04_05."))
	if err != nil {
		return false, err
	}
	if err := os.Chmod(ts, 0o755); err != nil {
		return false, err
	}
	for name, f := range files {
		if err := os.WriteFile(filepath.Join(ts, name), f.data, f.mode); err != nil {
			os.RemoveAll(ts)
			return false, err
		}
	}
	tmp := filepath.Join(dir, "..data_tmp")
	os.Remove(tmp)
	if err := os.Symlink(filepath.Base(ts), tmp); err != nil {
		os.RemoveAll(ts)
		return false, err
	}
	if err := os.Rename(tmp, filepath.Join(dir, "..data")); err != nil {
		os.RemoveAll(ts)
		return false, err
	}
	for name := range files {
		link := filepath.Join(dir, name)
		if t, err := os.Readlink(link); err == nil && t == filepath.Join("..data", name) {
			continue
		}
		os.Remove(link)
		if err := os.Symlink(filepath.Join("..data", name), link); err != nil {
			return true, fmt.Errorf("link %s: %w", name, err)
		}
	}
	if old != "" && old != filepath.Base(ts) && strings.HasPrefix(old, "..") {
		os.RemoveAll(filepath.Join(dir, old))
	}
	return true, nil
}

func unchanged(dir string, files map[string]struct {
	data []byte
	mode os.FileMode
}) bool {
	for name, f := range files {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil || !bytes.Equal(b, f.data) {
			return false
		}
	}
	return true
}
