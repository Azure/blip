package node

import (
	"bytes"
	"context"
	"os"
	"testing"

	"github.com/example/blip/internal/api"
	pb "github.com/example/blip/internal/proto/nodepb"
)

// storageHarness is a storage node named name.
func storageHarness(t *testing.T, name string) *harness {
	t.Helper()
	h := newHarnessCfg(t, t.TempDir(), 0, func(c *Config) { c.NodeName = name })
	h.st.Node = name
	return h
}

func TestWriteSnapshot(t *testing.T) {
	ctx := context.Background()
	w := newHarness(t, t.TempDir(), 1)
	w.keyed()
	w.ready("a", "slot-0", "p0")
	if _, err := w.n.AttachVolume(ctx, attachCmd("a", attData, "u-x", "x", 1, 3)); err != nil {
		t.Fatal(err)
	}
	if _, err := w.n.CaptureLocal(ctx, &pb.CaptureLocal{AllocationId: "a", Seq: 1, Attachments: []*pb.AttachmentRef{{AttachmentId: attData, Generation: 3}}}); err != nil {
		t.Fatal(err)
	}
	s1, s2 := storageHarness(t, "s1"), storageHarness(t, "s2")

	prepare := func(h *harness, id, base string) {
		t.Helper()
		for range 2 { // idempotent
			r := h.run(&pb.Command{Op: &pb.Command_PrepareReceive{PrepareReceive: &pb.PrepareReceive{
				ContentId: id, BaseContentId: base, SizeBytes: 1 << 20, Owner: &pb.ObjectRef{Uid: "snap-uid"}, Generation: 3,
				AllocationId: "a", AttachmentId: attData,
			}}})
			if r.Status != pb.ResultStatus_RESULT_STATUS_OK || !r.GetPrepareReceive().GetOk() {
				t.Fatal(r)
			}
		}
	}
	export := func(h *harness, id string) *pb.Path {
		t.Helper()
		r := h.run(&pb.Command{Op: &pb.Command_Export{Export: &pb.Export{ContentId: id, Mode: pb.ExportMode_EXPORT_MODE_READ_WRITE,
			HostNode: "w1", HostNqn: api.HostNQN("w1"), HostPsk: make([]byte, 32)}}})
		if r.Status != pb.ResultStatus_RESULT_STATUS_OK {
			t.Fatal(r)
		}
		return r.GetExport().Path
	}
	prepare(s1, "snap1", "")
	prepare(s2, "snap1", "")
	st, _ := s1.n.State(ctx)
	if len(st.Contents) != 2 || st.Contents[1].ContentId != "snap1" || st.Contents[1].Sealed || st.Contents[1].Kind != pb.ContentKind_CONTENT_KIND_SNAPSHOT {
		t.Fatal(st.Contents)
	}
	p1, p2 := export(s1, "snap1"), export(s2, "snap1")

	ws := &pb.WriteSnapshot{AllocationId: "a", AttachmentId: attData, Generation: 3, Seq: 1, ContentId: "snap1", Targets: []*pb.Path{p1, p2}}
	r := w.run(&pb.Command{Op: &pb.Command_WriteSnapshot{WriteSnapshot: ws}})
	res := r.GetWriteSnapshot()
	if r.Status != pb.ResultStatus_RESULT_STATUS_OK || len(res.Targets) != 2 || !res.Targets[0].Ok || !res.Targets[1].Ok ||
		res.ChangedBytes != 64<<10 || res.FullResend {
		t.Fatal(r)
	}
	for _, h := range []*harness{s1, s2} {
		b, _ := os.ReadFile(h.st.ContentPath("snap1"))
		if len(b) != 1<<20 || !bytes.Equal(b[:4096], bytes.Repeat([]byte{1}, 4096)) || b[4096] != 0 {
			t.Fatal("written content", len(b))
		}
		// Seal needs the export gone.
		if r := h.run(&pb.Command{Op: &pb.Command_Seal{Seal: &pb.Seal{ContentId: "snap1"}}}); r.Status == pb.ResultStatus_RESULT_STATUS_OK {
			t.Fatal("sealed while exported")
		}
		h.run(&pb.Command{Op: &pb.Command_Unexport{Unexport: &pb.Unexport{ContentId: "snap1"}}})
		if r := h.run(&pb.Command{Op: &pb.Command_Seal{Seal: &pb.Seal{ContentId: "snap1"}}}); r.Status != pb.ResultStatus_RESULT_STATUS_OK {
			t.Fatal(r)
		}
	}
	// Sealed content cannot be prepared again.
	r = s1.run(&pb.Command{Op: &pb.Command_PrepareReceive{PrepareReceive: &pb.PrepareReceive{ContentId: "snap1", SizeBytes: 1 << 20, Generation: 3}}})
	if r.Status != pb.ResultStatus_RESULT_STATUS_REJECTED {
		t.Fatal(r)
	}

	// Incremental, one target gone (unexported): partial success.
	if _, err := w.n.CaptureLocal(ctx, &pb.CaptureLocal{AllocationId: "a", Seq: 2, Attachments: []*pb.AttachmentRef{{AttachmentId: attData, Generation: 3}}}); err != nil {
		t.Fatal(err)
	}
	prepare(s1, "snap2", "snap1")
	prepare(s2, "snap2", "snap1")
	p1, p2 = export(s1, "snap2"), export(s2, "snap2")
	s2.run(&pb.Command{Op: &pb.Command_Unexport{Unexport: &pb.Unexport{ContentId: "snap2"}}})
	r = w.run(&pb.Command{Op: &pb.Command_WriteSnapshot{WriteSnapshot: &pb.WriteSnapshot{AllocationId: "a", AttachmentId: attData, Generation: 3,
		Seq: 2, BaseSeq: 1, ContentId: "snap2", Targets: []*pb.Path{p1, p2}}}})
	res = r.GetWriteSnapshot()
	if r.Status != pb.ResultStatus_RESULT_STATUS_OK || !res.Targets[0].Ok || res.Targets[1].Ok {
		t.Fatal(r)
	}
	b, _ := os.ReadFile(s1.st.ContentPath("snap2"))
	if !bytes.Equal(b[:4096], bytes.Repeat([]byte{2}, 4096)) {
		t.Fatal("incremental content")
	}

	// No target written: TRANSFER.
	r = w.run(&pb.Command{Op: &pb.Command_WriteSnapshot{WriteSnapshot: &pb.WriteSnapshot{AllocationId: "a", AttachmentId: attData, Generation: 3,
		Seq: 2, BaseSeq: 1, ContentId: "snap2", Targets: []*pb.Path{p2}}}})
	if r.Status != pb.ResultStatus_RESULT_STATUS_FAILED || r.Code != pb.ErrorCode_ERROR_CODE_TRANSFER {
		t.Fatal(r)
	}
	// Unknown snapshot: NOT_FOUND.
	r = w.run(&pb.Command{Op: &pb.Command_WriteSnapshot{WriteSnapshot: &pb.WriteSnapshot{AllocationId: "a", AttachmentId: attData, Generation: 3,
		Seq: 9, ContentId: "snap9", Targets: []*pb.Path{p1}}}})
	if r.Status != pb.ResultStatus_RESULT_STATUS_FAILED || r.Code != pb.ErrorCode_ERROR_CODE_NOT_FOUND {
		t.Fatal(r)
	}
}
