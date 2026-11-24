// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package blipchat

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
)

// ErrNotRunning means the state has no running agent (HTTP 409). The engine
// starts a new generation and retries.
var ErrNotRunning = errors.New("blipchat: blip is not running")

// ErrUnavailable is a transient 503 from the aggregated stream API.
var ErrUnavailable = errors.New("blipchat: stream API unavailable")

// ErrPrecondition means another writer appended to the stream since the
// caller's view was built (HTTP 412). The caller rereads the log and retries.
var ErrPrecondition = errors.New("blipchat: stream changed")

// Wire carries raw stdin and the trajectory log for one state.
type Wire interface {
	// Send appends data to stdin. note records are stored in the trajectory
	// but not forwarded to the agent. after is the offset of the writer's
	// newest input record; a non-zero after that no longer matches the stream
	// returns ErrPrecondition. Send returns the offset of the newest record
	// written (or the newest input record for an EOF-only send).
	Send(ctx context.Context, namespace, state string, data []byte, eof, note bool, after uint64) (uint64, error)
	OpenLog(ctx context.Context, namespace, state string, offset uint64) (io.ReadCloser, error)
	ReadLog(ctx context.Context, namespace, state string, offset uint64) (io.ReadCloser, error)
	LogEnd(ctx context.Context, namespace, state string) (uint64, error)
}

type restWire struct {
	rc rest.Interface
}

// NewWire builds the aggregated stream client. The API lives at
// /apis/stream.blip.dev/v1alpha1 and is not a normal Kubernetes resource.
func NewWire(cfg *rest.Config) (Wire, error) {
	c := rest.CopyConfig(cfg)
	c.APIPath = "/apis"
	c.GroupVersion = &schema.GroupVersion{Group: "stream.blip.dev", Version: "v1alpha1"}
	c.NegotiatedSerializer = scheme.Codecs.WithoutConversion()
	rc, err := rest.RESTClientFor(c)
	if err != nil {
		return nil, err
	}
	return &restWire{rc: rc}, nil
}

func (w *restWire) path(namespace, state, action string) string {
	return fmt.Sprintf("/apis/stream.blip.dev/v1alpha1/namespaces/%s/blipstreams/%s/%s",
		url.PathEscape(namespace), url.PathEscape(state), action)
}

func (w *restWire) Send(ctx context.Context, namespace, state string, data []byte, eof, note bool, after uint64) (uint64, error) {
	req := w.rc.Post().AbsPath(w.path(namespace, state, "stdin")).
		SetHeader("Content-Type", "application/octet-stream").
		Body(data)
	if eof {
		req = req.Param("eof", "true")
	}
	if note {
		req = req.Param("note", "true")
	}
	if after != 0 {
		req = req.Param("after", strconv.FormatUint(after, 10))
	}
	raw, err := req.DoRaw(ctx)
	if err != nil {
		return 0, wireError(err)
	}
	var out struct {
		Offset uint64 `json:"offset"`
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return 0, nil
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return 0, fmt.Errorf("blipchat: decode stdin response: %w", err)
	}
	return out.Offset, nil
}

func (w *restWire) OpenLog(ctx context.Context, namespace, state string, offset uint64) (io.ReadCloser, error) {
	return w.openLog(ctx, namespace, state, offset, true)
}

// ReadLog reads the retained log once instead of following new records.
func (w *restWire) ReadLog(ctx context.Context, namespace, state string, offset uint64) (io.ReadCloser, error) {
	return w.openLog(ctx, namespace, state, offset, false)
}

func (w *restWire) openLog(ctx context.Context, namespace, state string, offset uint64, follow bool) (io.ReadCloser, error) {
	req := w.rc.Get().AbsPath(w.path(namespace, state, "log")).
		Param("offset", strconv.FormatUint(offset, 10)).
		Param("follow", strconv.FormatBool(follow))
	body, err := req.Stream(ctx)
	if err != nil {
		return nil, wireError(err)
	}
	return body, nil
}

// LogEnd returns the offset of the newest record the state's ring holds. It is
// a cursor for stop and message boundaries, not a way to find inherited
// history: a copied state starts with an empty trajectory ring. A state with no
// records, or no running or saved writer, has no end.
func (w *restWire) LogEnd(ctx context.Context, namespace, state string) (uint64, error) {
	body, err := w.rc.Get().AbsPath(w.path(namespace, state, "log")).
		Param("follow", "false").
		Stream(ctx)
	if err != nil {
		return 0, wireError(err)
	}
	defer body.Close()
	return scanLogEnd(body)
}

// streamRecordHeader is the on-disk header size of one trajectory record.
const streamRecordHeader = 32

func scanLogEnd(body io.Reader) (uint64, error) {
	var end uint64
	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 64<<10), acpMaxLine)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var rec streamLogRecord
		if err := json.Unmarshal(line, &rec); err != nil {
			continue
		}
		if rec.Type != recordGap {
			// LogEnd is a ring cursor, so it must be an exact record
			// boundary. Return the position just past the newest record.
			if tail := rec.Offset + streamRecordHeader + uint64(len(rec.Data)); tail > end {
				end = tail
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, err
	}
	return end, nil
}

func wireError(err error) error {
	if err == nil {
		return nil
	}
	// DoRaw builds a generic error from the HTTP status code, labeling a
	// POST 409 AlreadyExists rather than preserving the server's reason.
	var status apierrors.APIStatus
	if errors.As(err, &status) {
		switch status.Status().Code {
		case http.StatusConflict:
			return fmt.Errorf("%w: %v", ErrNotRunning, err)
		case http.StatusServiceUnavailable, http.StatusTooManyRequests:
			return fmt.Errorf("%w: %v", ErrUnavailable, err)
		case http.StatusPreconditionFailed:
			return fmt.Errorf("%w: %v", ErrPrecondition, err)
		}
	}
	return err
}

// streamLogRecord is one NDJSON record from the log endpoint. The fields are
// short on the wire: o=offset, g=generation, t=type, d=data. Data is base64.
type streamLogRecord struct {
	Offset uint64
	Gen    uint64
	Type   streamRecordType
	Data   []byte
}

type streamRecordType byte

const (
	recordOut   streamRecordType = 1
	recordErr   streamRecordType = 2
	recordIn    streamRecordType = 3
	recordStart streamRecordType = 4
	recordEnd   streamRecordType = 5
	recordGap   streamRecordType = 6
	recordNote  streamRecordType = 7
)

// UnmarshalJSON accepts an object shaped {o,g,t,d} and also a four-element
// array, so a small change in the encoder cannot silently break chat.
func (r *streamLogRecord) UnmarshalJSON(data []byte) error {
	var raw struct {
		O uint64          `json:"o"`
		G uint64          `json:"g"`
		T json.RawMessage `json:"t"`
		D json.RawMessage `json:"d"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		var arr []json.RawMessage
		if err2 := json.Unmarshal(data, &arr); err2 != nil || len(arr) < 4 {
			return err
		}
		if err := json.Unmarshal(arr[0], &raw.O); err != nil {
			return err
		}
		if err := json.Unmarshal(arr[1], &raw.G); err != nil {
			return err
		}
		raw.T, raw.D = arr[2], arr[3]
	}
	r.Offset, r.Gen = raw.O, raw.G
	t, err := parseRecordType(raw.T)
	if err != nil {
		return err
	}
	r.Type = t
	d, err := parseRecordData(raw.D)
	if err != nil {
		return err
	}
	r.Data = d
	return nil
}

func parseRecordType(raw json.RawMessage) (streamRecordType, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return recordOut, nil
	}
	var n int
	if err := json.Unmarshal(raw, &n); err == nil {
		return streamRecordType(n), nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		switch s {
		case "out", "stdout":
			return recordOut, nil
		case "err", "stderr":
			return recordErr, nil
		case "in", "stdin":
			return recordIn, nil
		case "start":
			return recordStart, nil
		case "end":
			return recordEnd, nil
		case "gap":
			return recordGap, nil
		case "note":
			return recordNote, nil
		}
	}
	return 0, fmt.Errorf("unknown stream record type %s", raw)
}

func parseRecordData(raw json.RawMessage) ([]byte, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, err
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	// Be forgiving if an endpoint writes plain text instead of base64.
	return []byte(s), nil
}
