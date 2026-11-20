// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package apiproxy

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The api-proxy container can start before the node agent widens the shared
// socket directory. listenUnix must wait for that chmod instead of exiting
// and taking the VM down with it.
func TestListenUnixRetriesPermissionDenied(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permission test does not apply to root")
	}
	dir := filepath.Join(t.TempDir(), "sock")
	if err := os.Mkdir(dir, 0500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0700) })
	path := filepath.Join(dir, "vsock.sock_1")

	go func() {
		time.Sleep(300 * time.Millisecond)
		_ = os.Chmod(dir, 0777)
	}()

	start := time.Now()
	listener, cleanup, err := listenUnix(path)
	if err != nil {
		t.Fatalf("listenUnix: %v", err)
	}
	defer cleanup()
	if elapsed := time.Since(start); elapsed < 200*time.Millisecond {
		t.Fatalf("listenUnix returned after %s, before the directory was made writable", elapsed)
	}
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("socket was not created: %v", err)
	}
	_ = listener.Close()
}
