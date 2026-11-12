package node

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"testing"

	pb "github.com/example/blip/internal/proto/nodepb"
	"github.com/example/blip/internal/storage"
	"github.com/example/blip/internal/storage/image"
)

func TestPullAuth(t *testing.T) {
	cfg := fmt.Sprintf(`{"auths": {
		"https://index.docker.io/v1/": {"auth": %q},
		"ghcr.io": {"username": "u2", "password": "p2"}}}`,
		base64.StdEncoding.EncodeToString([]byte("u1:p:1")))
	for ref, want := range map[string]string{
		"busybox":               "u1/p:1",
		"docker.io/library/x:1": "u1/p:1",
		"ghcr.io/a/b@sha256:" + fmt.Sprintf("%064x", 1): "u2/p2",
		"quay.io/a/b": "",
	} {
		a, err := pullAuth([]byte(cfg), ref)
		if err != nil {
			t.Fatal(ref, err)
		}
		got := ""
		if a != nil {
			got = a.Username + "/" + a.Password
		}
		if got != want {
			t.Errorf("%s: got %q, want %q", ref, got, want)
		}
	}
	if a, err := pullAuth(nil, "busybox"); a != nil || err != nil {
		t.Fatal(a, err)
	}
	if _, err := pullAuth([]byte("{"), "busybox"); err == nil {
		t.Fatal("bad json accepted")
	}
}

func TestGroupHashes(t *testing.T) {
	var sums [][32]byte
	for i := range 5 {
		sums = append(sums, sha256.Sum256([]byte{byte(i)}))
	}
	r := groupHashes(sums, 0, 0, 1)
	if len(r.Hashes) != 5 || string(r.Hashes[3]) != string(sums[3][:]) {
		t.Fatalf("per chunk: %d hashes", len(r.Hashes))
	}
	r = groupHashes(sums, 1, 3, 2) // chunks 1-2 and 3
	if len(r.Hashes) != 2 || r.StartChunk != 1 || r.BlocksPerHash != 2 {
		t.Fatalf("grouped: %+v", r)
	}
	h := sha256.New()
	h.Write(sums[3][:])
	if string(r.Hashes[1]) != string(h.Sum(nil)) {
		t.Fatal("last group hash")
	}
	if r := groupHashes(sums, 9, 0, 4); len(r.Hashes) != 0 {
		t.Fatal("start past end")
	}
}

func TestKinds(t *testing.T) {
	for k := range kindTags {
		if kindOf(kindTag(k)) != k {
			t.Errorf("round trip %v", k)
		}
	}
	if kindOf("content") != pb.ContentKind_CONTENT_KIND_ROOT || kindTag(pb.ContentKind_CONTENT_KIND_UNSPECIFIED) != "content" {
		t.Fatal("content kind")
	}
}

func TestCodeOf(t *testing.T) {
	for err, want := range map[error]pb.ErrorCode{
		fmt.Errorf("x: %w", storage.ErrNotFound):                      pb.ErrorCode_ERROR_CODE_NOT_FOUND,
		fmt.Errorf("pull: %w: boom", image.ErrPull):                   pb.ErrorCode_ERROR_CODE_IMAGE_PULL,
		errors.New("lvcreate: Insufficient free space for thin pool"): pb.ErrorCode_ERROR_CODE_NO_SPACE,
		errors.New("write: no space left on device"):                  pb.ErrorCode_ERROR_CODE_NO_SPACE,
		errors.New("other"):                                           pb.ErrorCode_ERROR_CODE_UNSPECIFIED,
		Codef(pb.ErrorCode_ERROR_CODE_TLS, "tls"):                     pb.ErrorCode_ERROR_CODE_TLS,
		fmt.Errorf("x: %w", storage.ErrSuspendBudget):                 pb.ErrorCode_ERROR_CODE_SUSPEND_TIMEOUT,
		fmt.Errorf("x: %w", storage.ErrStaleGeneration):               pb.ErrorCode_ERROR_CODE_STALE_GENERATION,
	} {
		if got := ErrorCodeOf(codeOf(err)); got != want {
			t.Errorf("%v: %v, want %v", err, got, want)
		}
	}
}

func TestRealStorageRoles(t *testing.T) {
	r, err := NewRealStorage(RealConfig{Node: "n1"})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := r.SetHostKey(ctx, "nqn.2026-01.com.example.blip:host:n2", make([]byte, 32)); ErrorCodeOf(err) != pb.ErrorCode_ERROR_CODE_TLS {
		t.Fatalf("wrong NQN: %v", err)
	}
	if err := r.SetHostKey(ctx, "nqn.2026-01.com.example.blip:host:n1", make([]byte, 31)); ErrorCodeOf(err) != pb.ErrorCode_ERROR_CODE_TLS {
		t.Fatalf("short PSK: %v", err)
	}
	if err := r.SetHostKey(ctx, "nqn.2026-01.com.example.blip:host:n1", make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Export(ctx, &pb.Export{ContentId: "a"}); err == nil {
		t.Fatal("export on a node without storage")
	}
	if _, err := r.SlotDisks(ctx, "s0"); err == nil {
		t.Fatal("slot disks on a node without compute")
	}
	if err := r.PrepareReceive(ctx, ReceiveSpec{ContentID: "c", SizeBytes: 1}); err == nil {
		t.Fatal("receive on a node without storage")
	}
	sc, cc, err := r.Capacity(ctx)
	if sc != nil || cc != nil || err != nil {
		t.Fatal(sc, cc, err)
	}
	st, err := r.State(ctx)
	if err != nil || len(st.Contents) != 0 {
		t.Fatal(st, err)
	}
	if _, err := NewRealStorage(RealConfig{Node: "n1", VG: "blip", DevDir: t.TempDir()}); err == nil {
		t.Fatal("storage node without devices accepted")
	}
}
