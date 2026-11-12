package node

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/example/blip/internal/api"
	pb "github.com/example/blip/internal/proto/nodepb"
)

// fakeController is a controller that records what nodes send.
type fakeController struct {
	pb.UnimplementedControllerServer
	hellos   chan *pb.Hello
	cmds     chan *pb.Command
	results  chan *pb.CommandResult
	states   chan *pb.NodeState
	finished []string
	tokens   chan string
}

func newFakeController() *fakeController {
	return &fakeController{
		hellos: make(chan *pb.Hello, 10), cmds: make(chan *pb.Command, 10), results: make(chan *pb.CommandResult, 100),
		states: make(chan *pb.NodeState, 1000), tokens: make(chan string, 100),
	}
}

func (f *fakeController) token(ctx context.Context) {
	md, _ := metadata.FromIncomingContext(ctx)
	if v := md.Get("authorization"); len(v) > 0 {
		select {
		case f.tokens <- v[0]:
		default:
		}
	}
}

func (f *fakeController) Session(s pb.Controller_SessionServer) error {
	f.token(s.Context())
	m, err := s.Recv()
	if err != nil {
		return err
	}
	if m.GetHello() == nil {
		return status.Error(codes.InvalidArgument, "want hello")
	}
	f.hellos <- m.GetHello()
	psk := make([]byte, 32)
	w := &pb.Welcome{
		HostNqn: api.HostNQN(m.GetHello().NodeName), HostPsk: psk, FinishedAllocationIds: f.finished,
		HeartbeatInterval: durationpb.New(50 * time.Millisecond),
	}
	if err := s.Send(&pb.ControllerMessage{Msg: &pb.ControllerMessage_Welcome{Welcome: w}}); err != nil {
		return err
	}
	errc := make(chan error, 1)
	go func() {
		for {
			m, err := s.Recv()
			if err != nil {
				errc <- err
				return
			}
			switch x := m.Msg.(type) {
			case *pb.NodeMessage_Result:
				f.results <- x.Result
			case *pb.NodeMessage_State:
				select {
				case f.states <- x.State:
				default:
				}
			}
		}
	}()
	t := time.NewTicker(50 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case err := <-errc:
			return err
		case c := <-f.cmds:
			if err := s.Send(&pb.ControllerMessage{Msg: &pb.ControllerMessage_Command{Command: c}}); err != nil {
				return err
			}
		case <-t.C:
			if err := s.Send(&pb.ControllerMessage{Msg: &pb.ControllerMessage_Heartbeat{Heartbeat: &pb.Heartbeat{}}}); err != nil {
				return err
			}
		}
	}
}

// testTLS writes a CA and returns a server TLS config for name.
func testTLS(t *testing.T, dir, name string) *tls.Config {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "blip-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		DNSNames: []string{name}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "ca.crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
}

func TestSession(t *testing.T) {
	dir := t.TempDir()
	h := newHarness(t, dir, 1)
	fc := newFakeController()
	fc.finished = []string{"gone-1"}

	// TLS controller on localhost, dialed by name.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serverTLS := testTLS(t, dir, "localhost")
	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(serverTLS)))
	pb.RegisterControllerServer(srv, fc)
	go srv.Serve(l)
	defer srv.Stop()
	os.WriteFile(filepath.Join(dir, "token"), []byte("tok-1\n"), 0o600)
	_, port, _ := net.SplitHostPort(l.Addr().String())
	conn, err := DialController("localhost:"+port, filepath.Join(dir, "ca.crt"), filepath.Join(dir, "token"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go h.n.RunSession(ctx, pb.NewControllerClient(conn))

	var hello *pb.Hello
	select {
	case hello = <-fc.hellos:
	case <-time.After(5 * time.Second):
		t.Fatal("no hello")
	}
	if hello.NodeName != "w1" || hello.BootId != "boot-1" || !hello.Capabilities.Compute || !hello.Capabilities.Storage || hello.State == nil ||
		hello.Capacity.Compute.DisksPerSlot != 8 {
		t.Fatalf("hello %v", hello)
	}
	if tok := <-fc.tokens; tok != "Bearer tok-1" {
		t.Fatal(tok)
	}
	h.eventually("host key", func() bool { return h.st.CallCount("SetHostKey") == 1 })
	if h.st.HostNQN != api.HostNQN("w1") || !h.n.isFinished("gone-1") {
		t.Fatal("welcome not applied")
	}

	result := func(c *pb.Command) *pb.CommandResult {
		t.Helper()
		fc.cmds <- c
		for {
			select {
			case r := <-fc.results:
				if r.OperationId == c.OperationId {
					return r
				}
			case <-time.After(5 * time.Second):
				t.Fatalf("no result for %s", c.OperationId)
			}
		}
	}
	r := result(&pb.Command{OperationId: "op1", Op: &pb.Command_CreateContent{CreateContent: &pb.CreateContent{ContentId: "seed", SizeBytes: 1}}})
	if r.Status != pb.ResultStatus_RESULT_STATUS_OK {
		t.Fatal(r)
	}
	// Same operation ID: cached result, storage not called again.
	r = result(&pb.Command{OperationId: "op1", Op: &pb.Command_CreateContent{CreateContent: &pb.CreateContent{ContentId: "seed", SizeBytes: 1}}})
	if r.Status != pb.ResultStatus_RESULT_STATUS_OK || h.st.CallCount("CreateContent") != 1 {
		t.Fatal(r)
	}
	r = result(&pb.Command{OperationId: "op2", Op: &pb.Command_Scrub{Scrub: &pb.Scrub{ContentId: "missing"}}})
	if r.Status != pb.ResultStatus_RESULT_STATUS_FAILED || r.Code != pb.ErrorCode_ERROR_CODE_NOT_FOUND {
		t.Fatal(r)
	}
	r = result(&pb.Command{OperationId: "op3", Op: &pb.Command_Export{Export: &pb.Export{ContentId: "seed", Mode: pb.ExportMode_EXPORT_MODE_READ_ONLY, AllocationId: "gone-1"}}})
	if r.Status != pb.ResultStatus_RESULT_STATUS_REJECTED {
		t.Fatal(r)
	}
	r = result(&pb.Command{OperationId: "op4", Op: &pb.Command_Export{Export: &pb.Export{ContentId: "seed", Mode: pb.ExportMode_EXPORT_MODE_READ_ONLY, HostNqn: "h"}}})
	if r.Status != pb.ResultStatus_RESULT_STATUS_OK || r.GetExport().Path.Node != "w1" {
		t.Fatal(r)
	}
	r = result(&pb.Command{OperationId: "op5", Deadline: timestampAgo(), Op: &pb.Command_Unexport{Unexport: &pb.Unexport{ContentId: "seed"}}})
	if r.Status != pb.ResultStatus_RESULT_STATUS_DEADLINE_EXCEEDED {
		t.Fatal(r)
	}
	r = result(&pb.Command{OperationId: "op6", Op: &pb.Command_ListState{ListState: &pb.ListState{}}})
	if r.Status != pb.ResultStatus_RESULT_STATUS_OK || len(r.GetState().Contents) != 2 {
		t.Fatal(r)
	}
	for _, c := range []*pb.Command{
		{OperationId: "u1", Op: &pb.Command_Unexport{Unexport: &pb.Unexport{ContentId: "seed"}}},
		{OperationId: "s1", Op: &pb.Command_Seal{Seal: &pb.Seal{ContentId: "seed"}}},
		{OperationId: "c1", Op: &pb.Command_CreateContent{CreateContent: &pb.CreateContent{ContentId: "new", SizeBytes: 1}}},
		{OperationId: "i1", Op: &pb.Command_Import{Import: &pb.Import{ContentId: "img", ImageReference: "x", Targets: []*pb.Path{{Node: "s2"}}}}},
		{OperationId: "cl1", Op: &pb.Command_Clone{Clone: &pb.Clone{ContentId: "cl", ParentContentId: "in", Mode: pb.CloneMode_CLONE_MODE_SNAPSHOT}}},
		{OperationId: "rp1", Op: &pb.Command_Repair{Repair: &pb.Repair{ContentId: "in", Target: &pb.Path{Node: "s3"}}}},
		{OperationId: "sc1", Op: &pb.Command_Scrub{Scrub: &pb.Scrub{ContentId: "in", BlocksPerHash: 16}}},
		{OperationId: "dc1", Op: &pb.Command_DeleteContent{DeleteContent: &pb.DeleteContent{ContentIds: []string{"cl"}}}},
	} {
		if r := result(c); r.Status != pb.ResultStatus_RESULT_STATUS_OK {
			t.Fatal(c.OperationId, r)
		}
	}
	// Every change was sent as a full state, before the result of the
	// command that made it.
	var last *pb.NodeState
	for len(fc.states) > 0 {
		last = <-fc.states
	}
	have := map[string]bool{}
	for _, c := range last.GetContents() {
		have[c.ContentId] = true
	}
	if !have["new"] || have["cl"] {
		t.Fatalf("last state %v", last)
	}

	// Reconnect: the server goes away and comes back; the node says Hello again.
	srv.Stop()
	l2, err := net.Listen("tcp", l.Addr().String())
	if err != nil {
		t.Skip("port reuse failed:", err)
	}
	srv2 := grpc.NewServer(grpc.Creds(credentials.NewTLS(serverTLS)))
	pb.RegisterControllerServer(srv2, fc)
	go srv2.Serve(l2)
	defer srv2.Stop()
	select {
	case hello = <-fc.hellos:
	case <-time.After(10 * time.Second):
		t.Fatal("no hello after reconnect")
	}
	if len(hello.State.Contents) == 0 {
		t.Fatal("no inventory on reconnect")
	}
}

func timestampAgo() *timestamppb.Timestamp { return timestamppb.New(time.Now().Add(-time.Second)) }
