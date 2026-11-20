// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package peer

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Azure/blip/internal/nvme"
	"github.com/Azure/blip/internal/storage"
	"golang.org/x/sys/unix"
)

var e2eDiskKey = bytes.Repeat([]byte{7}, 64)

// TestE2ETwoNodes runs as two cooperating containers on one docker network
// (hack/storage-test.sh e2e): node b holds commits and serves exports, node
// a remote-attaches and fetches ciphertext over authenticated NVMe/TCP,
// leasing over mutually authenticated HTTPS. Both use the node's host IP.
// They exchange endpoint and TLS public key through files in BLIP_E2E_SHARED.
func TestE2ETwoNodes(t *testing.T) {
	role, shared := os.Getenv("BLIP_E2E_ROLE"), os.Getenv("BLIP_E2E_SHARED")
	if role == "" || shared == "" {
		t.Skip("two-node test: run via hack/storage-test.sh e2e")
	}
	privileged(t)
	run := os.Getenv("BLIP_TEST_RUN")
	nodes := map[string]string{"a": "blipt-" + run + "-a", "b": "blipt-" + run + "-b"}
	other := map[string]string{"a": "b", "b": "a"}[role]
	if other == "" || run == "" {
		t.Fatal("two-node test requires role a or b and BLIP_TEST_RUN")
	}
	node := nodes[role]
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()

	dir := t.TempDir()
	identity, err := LoadIdentity(dir)
	must(t, err)
	registry := NewRegistry()
	client := NewClient(identity, registry, e2eDiskKey)
	t.Cleanup(client.Close)
	t.Cleanup(func() { removeNodeKernelState(node) })
	st, err := storage.Open(ctx, storage.Config{
		DataDir: dir, NodeName: node, PoolBytes: 4 << 30, Key: e2eDiskKey,
		ReleaseRemote: client.ReleaseRemote, ResumeRemote: client.ResumeRemote,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	hostIP := e2eHostIP(t)
	fw, err := NewFirewall(hostIP)
	if err != nil {
		t.Fatal(err)
	}
	writeJSON(t, filepath.Join(shared, role+".json"), Peer{Node: node, PublicKey: identity.PublicKey(), Endpoint: hostIP})
	var peer Peer
	waitJSON(t, ctx, filepath.Join(shared, other+".json"), &peer)
	if !peer.Valid() || peer.Node != nodes[other] {
		t.Fatalf("invalid peer record: %+v", peer)
	}
	registry.SetPeers([]Peer{peer})
	if err := fw.SetPeers([]Peer{peer}); err != nil {
		t.Fatal(err)
	}

	srv, err := NewServer(ServerConfig{
		Store: st, NodeName: node, HostIP: hostIP, DataDir: dir,
		DiskKey: e2eDiskKey, Identity: identity, Peers: registry,
		Authorize: func(n string, req ExportRequest) error {
			if n != nodes[other] || req.CommitID == deniedCommit {
				return errors.New("not authorized")
			}
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	serverDone := make(chan error, 1)
	go func() { serverDone <- srv.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-serverDone; err != nil {
			t.Errorf("peer server: %v", err)
		}
	})
	waitPeerReady(t, ctx, client, nodes[other], HostNQN(node))

	if role == "b" {
		e2eSource(t, ctx, st, srv, shared)
	} else {
		e2eReader(t, ctx, st, client, shared, nodes)
	}
}

const (
	deniedCommit = "dddddddddddddddd"
	commit0      = "c100000000000000"
	commit1      = "c100000000000001"
	commit2      = "c100000000000002"
)

type sourceInfo struct{ C1Hash, C2Hash, BigHash, ChangedHash string }

// A denied request exercises the real pinned-key TLS client and the peer
// registry without creating an NVMe export. A TCP/HTTP probe can report ready
// before the other node has installed this node's identity and firewall rule.
func waitPeerReady(t *testing.T, ctx context.Context, client *Client, node, hostNQN string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	for {
		attempt, stop := context.WithTimeout(ctx, time.Second)
		remote, err := client.Open(attempt, node, ExportRequest{CommitID: deniedCommit, HostNQN: hostNQN})
		stop()
		if err == nil {
			remote.Release()
			t.Fatal("readiness request unexpectedly authorized")
		}
		if strings.Contains(err.Error(), ": 403 Forbidden:") {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("authenticated peer %s did not become ready: %v", node, err)
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func e2eSource(t *testing.T, ctx context.Context, st *storage.Store, srv *Server, shared string) {
	big, changed := randBytes(160<<20), randBytes(4<<20)
	img := mkImage(t, 512<<20, map[string][]byte{"big": big, "small": []byte("small file")})
	must(t, st.CreateImage(ctx, "sha256:"+strings.Repeat("e2", 32), 512<<20, func(dev string) error {
		// Not sparse: an unwritten block reads back as the decryption of zeros.
		out, err := exec.Command("dd", "if="+img, "of="+dev, "bs=64k", "conv=notrunc,fsync", "status=none").CombinedOutput()
		if err != nil {
			return fmt.Errorf("dd: %w: %s", err, out)
		}
		return nil
	}))
	// Commits built from an image are delta bases only by content digest
	// (each node converts images itself), so commit1 is a copy of one.
	must(t, st.CreateCommit(ctx, storage.CreateCommit{StateUID: "u", CommitID: commit0, FromImage: "sha256:" + strings.Repeat("e2", 32)}))
	must(t, st.CreateCommit(ctx, storage.CreateCommit{StateUID: "u", CommitID: commit1, FromCommit: commit0}))
	w, err := st.CreateWorking(ctx, storage.CreateWorking{AttachmentID: "b0000000000000a1", StateUID: "u", FromCommit: commit1})
	must(t, err)
	writeFile(t, w, "changed", changed)
	_, err = st.Seal(ctx, "b0000000000000a1", commit2)
	must(t, err)
	must(t, st.Delete(ctx, "b0000000000000a1"))
	d1, _ := st.Activate(commit1)
	d2, _ := st.Activate(commit2)
	writeJSON(t, filepath.Join(shared, "b-ready.json"), sourceInfo{
		C1Hash: hashFile(t, d1, 512<<20), C2Hash: hashFile(t, d2, 512<<20),
		BigHash: sum(big), ChangedHash: sum(changed),
	})

	var result string
	waitJSON(t, ctx, filepath.Join(shared, "a-done.json"), &result)
	if result != "ok" {
		t.Fatalf("node a failed")
	}
	// Every lease was released by the reader: nothing pinned or exported.
	deadline := time.Now().Add(15 * time.Second)
	for srv.Pinned(commit1) || srv.Pinned(commit2) || len(srv.target.Leases()) > 0 || len(st.Exports()) > 0 {
		if time.Now().After(deadline) {
			t.Fatalf("leases not released: pinned %v %v, nvmet %v, exports %v",
				srv.Pinned(commit1), srv.Pinned(commit2), srv.target.Leases(), st.Exports())
		}
		time.Sleep(200 * time.Millisecond)
	}
	if v, _ := st.Get(commit1); len(v.Pins) != 0 {
		t.Fatalf("pins left: %v", v.Pins)
	}
	writeJSON(t, filepath.Join(shared, "b-done.json"), "ok")
}

func e2eReader(t *testing.T, ctx context.Context, st *storage.Store, client *Client, shared string, nodes map[string]string) {
	result := "fail"
	t.Cleanup(func() {
		if result != "ok" {
			writeJSON(t, filepath.Join(shared, "a-done.json"), result)
		}
	})
	var src sourceInfo
	waitJSON(t, ctx, filepath.Join(shared, "b-ready.json"), &src)
	host := HostNQN(nodes["a"])

	if _, err := client.Open(ctx, nodes["b"], ExportRequest{CommitID: deniedCommit, HostNQN: host}); err == nil || !strings.Contains(err.Error(), ": 403 Forbidden:") {
		t.Fatalf("unauthorized export: %v", err)
	}
	if _, err := client.Open(ctx, nodes["b"], ExportRequest{CommitID: commit1, HostNQN: HostNQN(nodes["b"])}); err == nil || !strings.Contains(err.Error(), ": 403 Forbidden:") {
		t.Fatalf("export for another host NQN: %v", err)
	}

	// Remote attach: usable before hydration completes, then swapped in place.
	r, err := client.Open(ctx, nodes["b"], ExportRequest{StateUID: "u", CommitID: commit1, Purpose: "attach", HostNQN: host})
	must(t, err)
	if r.Base != "" || len(r.Regions) == 0 {
		t.Fatalf("attach export: base %q, %d regions", r.Base, len(r.Regions))
	}
	dev, err := st.CreateWorking(ctx, storage.CreateWorking{AttachmentID: "a0000000000000a1", StateUID: "u", Remote: &r})
	must(t, err)
	if v, _ := st.Get("a0000000000000a1"); !v.Hydrating {
		t.Fatal("remote attach finished hydrating before first use; make the test data larger")
	}
	var before unix.Stat_t
	must(t, unix.Stat(dev, &before))
	if got := string(catFile(t, dev, "small")); got != "small file" {
		t.Fatalf("read during hydration: %q", got)
	}
	newData := randBytes(1 << 20)
	writeFile(t, dev, "new", newData)
	v, _ := st.Get("a0000000000000a1")
	t.Logf("still hydrating after first write: %v", v.Hydrating)
	waitHydrated(t, ctx, st, "a0000000000000a1")
	var after unix.Stat_t
	must(t, unix.Stat(dev, &after))
	// dev is the crypt device over the volume's top device.
	table, _ := exec.Command("dmsetup", "table", strings.TrimSuffix(filepath.Base(dev), "-p")).Output()
	if before.Rdev != after.Rdev || !strings.Contains(string(table), " linear ") {
		t.Fatalf("not swapped to linear in place: %s", table)
	}
	if !bytes.Equal(catFile(t, dev, "new"), newData) || sum(catFile(t, dev, "big")) != src.BigHash {
		t.Fatal("data after hydration differs")
	}
	_, err = st.Seal(ctx, "a0000000000000a1", "a1000000000000a1")
	must(t, err)
	must(t, st.Delete(ctx, "a0000000000000a1"))

	// Replica fetch, full.
	r1, err := client.Open(ctx, nodes["b"], ExportRequest{StateUID: "u", CommitID: commit1, Purpose: "replica", HostNQN: host})
	must(t, err)
	var last [2]int64
	must(t, st.FetchCommit(ctx, "u", commit1, r1, func(done, total int64) { last = [2]int64{done, total} }))
	if last[0] != last[1] || last[1] != 512<<20 {
		t.Fatalf("progress %v", last)
	}
	d1, _ := st.Activate(commit1)
	if hashFile(t, d1, 512<<20) != src.C1Hash {
		t.Fatal("fetched commit 1 differs")
	}

	// Generation 1, built from an image on b, is a delta base only when
	// offered with a matching content digest. Fetch it so a holds the same
	// bytes under the same ID, as if a had converted the image itself.
	r0, err := client.Open(ctx, nodes["b"], ExportRequest{StateUID: "u", CommitID: commit0, Purpose: "replica", HostNQN: host})
	must(t, err)
	must(t, st.FetchCommit(ctx, "u", commit0, r0, nil))
	digest0, err := st.Digest(ctx, commit0)
	must(t, err)
	for _, c := range []struct {
		bases   []string
		digests map[string]string
		base    string
	}{
		{bases: []string{commit0}},
		{digests: map[string]string{commit0: "v1:sha256:" + strings.Repeat("0", 64)}},
		{digests: map[string]string{commit0: digest0}, base: commit0},
	} {
		r, err := client.Open(ctx, nodes["b"], ExportRequest{StateUID: "u", CommitID: commit2, Purpose: "replica", Bases: c.bases, BaseDigests: c.digests, HostNQN: host})
		must(t, err)
		r.Release()
		if r.Base != c.base {
			t.Fatalf("export with bases %v digests %v: base %q", c.bases, c.digests, r.Base)
		}
	}

	// Replica fetch, delta against the held commit 1.
	r2, err := client.Open(ctx, nodes["b"], ExportRequest{StateUID: "u", CommitID: commit2, Purpose: "replica", Bases: []string{"ffffffffffffffff", commit1}, HostNQN: host})
	must(t, err)
	var delta int64
	for _, g := range r2.Regions {
		delta += g.Length
	}
	if r2.Base != commit1 || delta == 0 || delta > 32<<20 {
		t.Fatalf("delta export: base %q, %d bytes", r2.Base, delta)
	}
	must(t, st.FetchCommit(ctx, "u", commit2, r2, nil))
	d2, _ := st.Activate(commit2)
	ro, err := st.CreateWorking(ctx, storage.CreateWorking{AttachmentID: "a0000000000000a2", StateUID: "u", FromCommit: commit2, ReadOnly: true})
	must(t, err)
	if hashFile(t, d2, 512<<20) != src.C2Hash || sum(catFile(t, ro, "changed")) != src.ChangedHash {
		t.Fatal("fetched commit 2 differs")
	}
	must(t, st.Delete(ctx, "a0000000000000a2"))

	// Every NVMe session to b is gone.
	prefix := "nqn.2014-08.dev.blip:" + nvme.NodeHash(nodes["b"]) + ":"
	paths, _ := filepath.Glob("/sys/class/nvme/nvme*/subsysnqn")
	for _, p := range paths {
		if b, _ := os.ReadFile(p); strings.HasPrefix(string(b), prefix) {
			t.Fatalf("controller still connected: %s", p)
		}
	}
	result = "ok"
	writeJSON(t, filepath.Join(shared, "a-done.json"), result)
	// Keep the client's release retries alive until the source confirms that
	// every lease and export has gone away.
	var released string
	waitJSON(t, ctx, filepath.Join(shared, "b-done.json"), &released)
	if released != "ok" {
		t.Fatalf("source cleanup failed: %q", released)
	}
}

func waitHydrated(t *testing.T, ctx context.Context, st *storage.Store, id string) {
	t.Helper()
	for {
		v, ok := st.Get(id)
		if !ok || v.Failed != "" {
			t.Fatalf("volume %s: %+v", id, v)
		}
		if !v.Hydrating {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("hydration timed out")
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// removeNodeKernelState removes the dm devices, nvmet exports, and NVMe
// sessions of a test node (hack/storage-cleanup.sh does the same from
// outside).
func removeNodeKernelState(node string) {
	h := nvme.NodeHash(node)
	paths, _ := filepath.Glob("/sys/class/nvme/nvme*/subsysnqn")
	for _, p := range paths {
		if b, _ := os.ReadFile(p); strings.HasPrefix(string(b), "nqn.2014-08.dev.blip:"+h+":") {
			os.WriteFile(filepath.Join(filepath.Dir(p), "delete_controller"), []byte("1"), 0)
		}
	}
	if tgt, err := nvme.NewTarget(node, "", 0, e2eDiskKey); err == nil {
		for _, l := range tgt.Leases() {
			tgt.Unexport(l)
		}
	}
	prefix := storage.DMPrefix(node) + "-"
	for range 5 {
		out, _ := exec.Command("dmsetup", "ls").Output()
		left := 0
		for _, line := range strings.Split(string(out), "\n") {
			name := strings.Fields(line + " x")[0]
			if strings.HasPrefix(name, prefix) && name != prefix+"pool" {
				exec.Command("dmsetup", "--noudevsync", "remove", "--retry", name).Run()
				left++
			}
		}
		if left == 0 {
			break
		}
	}
	exec.Command("dmsetup", "--noudevsync", "remove", "--retry", prefix+"pool").Run()
}

func e2eHostIP(t *testing.T) string {
	t.Helper()
	iface, err := net.InterfaceByName("eth0")
	if err != nil {
		t.Fatal(err)
	}
	addrs, _ := iface.Addrs()
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil {
			return ipn.IP.String()
		}
	}
	t.Fatal("no IPv4 on eth0")
	return ""
}

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, err := json.Marshal(v)
	must(t, err)
	must(t, os.WriteFile(path+".tmp", b, 0o644))
	must(t, os.Rename(path+".tmp", path))
}

func waitJSON(t *testing.T, ctx context.Context, path string, v any) {
	t.Helper()
	for {
		if b, err := os.ReadFile(path); err == nil {
			if err := json.Unmarshal(b, v); err != nil {
				t.Fatal(err)
			}
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("timed out waiting for %s", path)
		case <-time.After(200 * time.Millisecond):
		}
	}
}

func mkImage(t *testing.T, size int64, files map[string][]byte) string {
	t.Helper()
	dir := t.TempDir()
	root := filepath.Join(dir, "root")
	os.MkdirAll(root, 0o755)
	for name, data := range files {
		must(t, os.WriteFile(filepath.Join(root, name), data, 0o644))
	}
	img := filepath.Join(dir, "img")
	if out, err := exec.Command("mkfs.ext4", "-q", "-F", "-b", "4096", "-d", root, img, fmt.Sprint(size/1024)+"k").CombinedOutput(); err != nil {
		t.Fatalf("mkfs: %v %s", err, out)
	}
	return img
}

func catFile(t *testing.T, dev, name string) []byte {
	t.Helper()
	out, err := exec.Command("debugfs", "-R", "cat /"+name, dev).Output()
	if err != nil {
		t.Fatalf("debugfs cat %s: %v", name, err)
	}
	return out
}

func writeFile(t *testing.T, dev, name string, data []byte) {
	t.Helper()
	src := filepath.Join(t.TempDir(), "f")
	os.WriteFile(src, data, 0o644)
	if out, err := exec.Command("debugfs", "-w", "-R", "write "+src+" "+name, dev).CombinedOutput(); err != nil {
		t.Fatalf("debugfs write: %v %s", err, out)
	}
}

func hashFile(t *testing.T, path string, n int64) string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.CopyN(h, f, n); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func sum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
