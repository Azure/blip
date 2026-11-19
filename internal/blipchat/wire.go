// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package blipchat

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strconv"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
)

// ErrNotRunning means the state has no running agent (HTTP 409). The driver
// starts a new generation and retries.
var ErrNotRunning = errors.New("blipchat: blip is not running")

// ErrUnavailable is a transient 503 from the aggregated stream API.
var ErrUnavailable = errors.New("blipchat: stream API unavailable")

// Wire carries raw stdin and the trajectory log for one state.
type Wire interface {
	Send(ctx context.Context, namespace, state string, data []byte, eof bool) error
	OpenLog(ctx context.Context, namespace, state string, offset uint64) (io.ReadCloser, error)
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

func (w *restWire) Send(ctx context.Context, namespace, state string, data []byte, eof bool) error {
	req := w.rc.Post().AbsPath(w.path(namespace, state, "stdin")).
		SetHeader("Content-Type", "application/octet-stream").
		Body(data)
	if eof {
		req = req.Param("eof", "true")
	}
	_, err := req.DoRaw(ctx)
	return wireError(err)
}

func (w *restWire) OpenLog(ctx context.Context, namespace, state string, offset uint64) (io.ReadCloser, error) {
	req := w.rc.Get().AbsPath(w.path(namespace, state, "log")).
		Param("offset", strconv.FormatUint(offset, 10)).
		Param("follow", "true")
	body, err := req.Stream(ctx)
	if err != nil {
		return nil, wireError(err)
	}
	return body, nil
}

func wireError(err error) error {
	switch {
	case err == nil:
		return nil
	case apierrors.IsConflict(err):
		return fmt.Errorf("%w: %v", ErrNotRunning, err)
	case apierrors.IsServiceUnavailable(err), apierrors.IsTooManyRequests(err):
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	default:
		return err
	}
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
