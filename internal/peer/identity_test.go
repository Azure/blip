// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package peer

import (
	"bytes"
	"crypto/x509"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func testIdentity(t *testing.T) *Identity {
	t.Helper()
	i, err := LoadIdentity(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return i
}

func TestIdentityPersistence(t *testing.T) {
	dir := t.TempDir()
	first, err := LoadIdentity(dir)
	if err != nil {
		t.Fatal(err)
	}
	second, err := LoadIdentity(dir)
	if err != nil {
		t.Fatal(err)
	}
	if first.PublicKey() != second.PublicKey() {
		t.Fatal("identity changed across reload")
	}
	info, err := os.Stat(filepath.Join(dir, "identity.key"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("identity key permissions: %v, %v", info, err)
	}
	if third := testIdentity(t); third.PublicKey() == first.PublicKey() {
		t.Fatal("different nodes received the same identity")
	}
}

func TestIdentityConcurrentCreation(t *testing.T) {
	dir := t.TempDir()
	var wg sync.WaitGroup
	keys := make(chan string, 12)
	for range cap(keys) {
		wg.Go(func() {
			i, err := LoadIdentity(dir)
			if err != nil {
				t.Error(err)
				return
			}
			keys <- i.PublicKey()
		})
	}
	wg.Wait()
	close(keys)
	var want string
	for key := range keys {
		if want != "" && key != want {
			t.Fatal("concurrent creators published different keys")
		}
		want = key
	}
}

func TestIdentityCorruptionFailsClosed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "identity.key")
	bad := []byte("damaged identity")
	if err := os.WriteFile(path, bad, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadIdentity(dir); err == nil {
		t.Fatal("corrupt identity accepted")
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, bad) {
		t.Fatal("corrupt identity was replaced")
	}
}

func TestCertificateRenewalKeepsIdentity(t *testing.T) {
	i := testIdentity(t)
	first, err := i.certificate()
	if err != nil {
		t.Fatal(err)
	}
	key, err := certificateKey([]*x509.Certificate{first.Leaf})
	if err != nil || key != i.PublicKey() {
		t.Fatalf("initial certificate key = %q, %v", key, err)
	}
	first.Leaf.NotAfter = time.Now().Add(time.Hour)
	second, err := i.certificate()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first.Certificate[0], second.Certificate[0]) {
		t.Fatal("expiring certificate was not renewed")
	}
	key, err = certificateKey([]*x509.Certificate{second.Leaf})
	if err != nil || key != i.PublicKey() {
		t.Fatalf("renewal changed identity: %q, %v", key, err)
	}
	if !second.Leaf.NotAfter.After(time.Now().Add(23 * time.Hour)) {
		t.Fatal("renewed certificate lifetime too short")
	}
}
