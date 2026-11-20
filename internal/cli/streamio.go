// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package cli

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/rest"

	"github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/stream"
)

// streamAPI is the aggregated stream API. Blips have no attach or exec
// sessions: the durable trajectory ring of the blip's state is the only
// channel for stdin, stdout, stderr and lifecycle records.
type streamAPI interface {
	Log(ctx context.Context, namespace, state string, offset int64, follow bool) (io.ReadCloser, error)
	Stdin(ctx context.Context, namespace, state string, data []byte, eof bool) error
}

// streamClient talks to the aggregated stream API through a REST client with
// an empty base path, so AbsPath reaches /apis/stream.blip.dev/... unchanged.
type streamClient struct {
	rest rest.Interface
}

// stream returns the configured stream client, falling back to REST for a
// caller that supplied only a REST client.
func (c *Clients) stream() streamAPI {
	if c.Stream != nil {
		return c.Stream
	}
	if c.REST != nil {
		return &streamClient{rest: c.REST}
	}
	return nil
}

func streamLogPath(namespace, state string) string {
	return "/apis/stream.blip.dev/v1alpha1/namespaces/" + url.PathEscape(namespace) +
		"/blipstreams/" + url.PathEscape(state) + "/log"
}

func streamStdinPath(namespace, state string) string {
	return "/apis/stream.blip.dev/v1alpha1/namespaces/" + url.PathEscape(namespace) +
		"/blipstreams/" + url.PathEscape(state) + "/stdin"
}

func (c *streamClient) Log(ctx context.Context, namespace, state string, offset int64, follow bool) (io.ReadCloser, error) {
	req := c.rest.Get().AbsPath(streamLogPath(namespace, state)).
		SetHeader("Accept", "application/x-ndjson")
	if offset > 0 {
		req = req.Param("offset", strconv.FormatInt(offset, 10))
	}
	if follow {
		req = req.Param("follow", "true")
	}
	return req.Stream(ctx)
}

func (c *streamClient) Stdin(ctx context.Context, namespace, state string, data []byte, eof bool) error {
	req := c.rest.Post().AbsPath(streamStdinPath(namespace, state)).
		SetHeader("Content-Type", "application/octet-stream")
	if eof {
		req = req.Param("eof", "true")
	}
	_, err := req.Body(data).DoRaw(ctx)
	return err
}

// streamBytes accepts either the base64 form of a JSON []byte or a plain JSON
// string, so a hand-written fixture and a Go server both decode.
type streamBytes []byte

func (b *streamBytes) UnmarshalJSON(p []byte) error {
	if string(p) == "null" {
		*b = nil
		return nil
	}
	var s string
	if err := json.Unmarshal(p, &s); err != nil {
		return err
	}
	if dec, err := base64.StdEncoding.DecodeString(s); err == nil {
		*b = dec
		return nil
	}
	*b = []byte(s)
	return nil
}

// streamKind is a record type. The server writes the numeric stream type;
// fixtures may also spell it out.
type streamKind uint8

func (t *streamKind) UnmarshalJSON(p []byte) error {
	var n uint8
	if err := json.Unmarshal(p, &n); err == nil {
		*t = streamKind(n)
		return nil
	}
	var s string
	if err := json.Unmarshal(p, &s); err != nil {
		return err
	}
	switch strings.ToLower(s) {
	case "out", "stdout":
		*t = streamKind(stream.TypeOut)
	case "err", "stderr":
		*t = streamKind(stream.TypeErr)
	case "in", "stdin":
		*t = streamKind(stream.TypeIn)
	case "start":
		*t = streamKind(stream.TypeStart)
	case "end":
		*t = streamKind(stream.TypeEnd)
	case "gap":
		*t = streamKind(stream.TypeGap)
	case "note":
		*t = streamKind(stream.TypeNote)
	default:
		return fmt.Errorf("unknown stream record type %q", s)
	}
	return nil
}

// streamRecord is one NDJSON record from the stream API.
type streamRecord struct {
	Offset uint64      `json:"o"`
	Gen    uint64      `json:"g"`
	Type   streamKind  `json:"t"`
	Data   streamBytes `json:"d"`
}

func decodeStream(r io.Reader, fn func(streamRecord) error) error {
	dec := json.NewDecoder(r)
	for {
		var rec streamRecord
		if err := dec.Decode(&rec); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("decode stream: %w", err)
		}
		if err := fn(rec); err != nil {
			return err
		}
	}
}

// recordWriter prints trajectory records. out and err are raw byte streams;
// control records are status lines on stderr. With raw set, only stdout is
// written.
type recordWriter struct {
	out   io.Writer
	err   io.Writer
	raw   bool
	label string
}

func (w *recordWriter) write(rec streamRecord) error {
	switch stream.RecordType(rec.Type) {
	case stream.TypeOut:
		_, err := w.out.Write(rec.Data)
		return err
	case stream.TypeErr:
		if w.raw {
			return nil
		}
		_, err := w.err.Write(rec.Data)
		return err
	case stream.TypeIn:
		if w.raw {
			return nil
		}
		writeInput(w.err, rec.Data)
	case stream.TypeStart:
		w.status("start")
	case stream.TypeEnd:
		w.status("end")
	case stream.TypeGap:
		w.status("gap")
	case stream.TypeNote:
		w.status("note")
	}
	return nil
}

func (w *recordWriter) status(kind string) {
	if w.raw {
		return
	}
	if w.label != "" {
		fmt.Fprintf(w.err, "%s: %s\n", w.label, kind)
		return
	}
	fmt.Fprintln(w.err, kind)
}

func writeInput(w io.Writer, data []byte) {
	for len(data) > 0 {
		line := data
		if i := bytes.IndexByte(data, '\n'); i >= 0 {
			line, data = data[:i], data[i+1:]
		} else {
			data = nil
		}
		fmt.Fprintf(w, "> %s\n", strings.TrimSuffix(string(line), "\r"))
	}
}

// streamTarget is the state a log or stdin request goes to. blip is set when
// the caller named a Blip and lets followers stop when that Blip finishes.
type streamTarget struct {
	namespace string
	state     string
	blip      string
}

// resolveStreamTarget maps a Blip or BlipState name to its state. A Blip uses
// its spec.state; a state uses its own name.
func (a *app) resolveStreamTarget(ctx context.Context, name, state string) (streamTarget, error) {
	c, err := a.clients()
	if err != nil {
		return streamTarget{}, err
	}
	if state != "" {
		ns, stateName := c.Namespace, state
		if before, after, ok := strings.Cut(state, "/"); ok {
			ns, stateName = before, after
		}
		if err := a.validateStateName(stateName); err != nil {
			return streamTarget{}, err
		}
		return streamTarget{namespace: ns, state: stateName}, nil
	}
	if name == "" {
		return streamTarget{}, errors.New("a blip or state name is required")
	}
	if err := a.scope(&name); err != nil {
		return streamTarget{}, err
	}
	if err := a.validateName("blip", name); err != nil {
		return streamTarget{}, err
	}
	b, err := get(ctx, c, name, &v1alpha1.Blip{})
	if err == nil {
		if b.Spec.State == "" {
			return streamTarget{}, fmt.Errorf("blip %q has no state", a.short(b.Name))
		}
		return streamTarget{namespace: b.Namespace, state: b.Spec.State, blip: b.Name}, nil
	}
	if !apierrors.IsNotFound(err) {
		return streamTarget{}, err
	}
	st, err := get(ctx, c, name, &v1alpha1.BlipState{})
	if err == nil {
		return streamTarget{namespace: st.Namespace, state: st.Name}, nil
	}
	return streamTarget{}, notFound("blip or state", name, c.Namespace, err)
}

// readStream reads a state's trajectory. With follow it keeps reading from
// the last record until ctx ends or done reports that the blip is finished,
// then makes one retained read from offset 0 so a late follower still sees
// output the API retained after the pod is gone.
func (a *app) readStream(ctx context.Context, target streamTarget, offset int64, follow bool, w *recordWriter, done func(context.Context) bool) error {
	c, err := a.clients()
	if err != nil {
		return err
	}
	api := c.stream()
	if api == nil {
		return errors.New("stream API is unavailable")
	}
	type recordKey struct {
		offset uint64
		gen    uint64
		typ    streamKind
	}
	start := offset
	seen := map[recordKey]bool{}
	delay := 50 * time.Millisecond
	for {
		rc, err := api.Log(ctx, target.namespace, target.state, offset, follow)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if !follow || !retryableStreamError(err) {
				return err
			}
			if done != nil && done(ctx) {
				return nil
			}
			if !sleepContext(ctx, delay) {
				return nil
			}
			delay = min(2*delay, 500*time.Millisecond)
			continue
		}
		delay = 50 * time.Millisecond
		last := offset
		ended := false
		decodeErr := decodeStream(rc, func(rec streamRecord) error {
			key := recordKey{rec.Offset, rec.Gen, rec.Type}
			if seen[key] {
				return nil
			}
			seen[key] = true
			// The API takes a record offset, not a byte position. Asking
			// for the last record again on reconnect is harmless: seen
			// skips it and the records after it follow.
			last = int64(rec.Offset)
			if stream.RecordType(rec.Type) == stream.TypeEnd {
				ended = true
			}
			return w.write(rec)
		})
		rc.Close()
		if ended {
			return nil
		}
		if decodeErr != nil {
			if !follow || !retryableStreamError(decodeErr) {
				return decodeErr
			}
		}
		if ctx.Err() != nil {
			return nil
		}
		if !follow {
			return nil
		}
		if done != nil && done(ctx) {
			// The Guest may be gone, but the ring is durable. Read the
			// retained trajectory once so a follower that attached late
			// still prints everything that was retained.
			if start == 0 && !ended {
				if rc, err := api.Log(ctx, target.namespace, target.state, 0, false); err == nil {
					_ = decodeStream(rc, func(rec streamRecord) error {
						key := recordKey{rec.Offset, rec.Gen, rec.Type}
						if seen[key] {
							return nil
						}
						seen[key] = true
						return w.write(rec)
					})
					rc.Close()
				}
			}
			return nil
		}
		offset = last
		if !sleepContext(ctx, 50*time.Millisecond) {
			return nil
		}
	}
}

func sleepContext(ctx context.Context, d time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}

// retryableStreamError reports a stream API error that can clear on its own:
// the guest has not connected yet, the state is not attached, or the transport
// failed. Authorization and bad-request errors are terminal.
func retryableStreamError(err error) bool {
	if err == nil {
		return false
	}
	if apierrors.IsConflict(err) || apierrors.IsServiceUnavailable(err) ||
		apierrors.IsNotFound(err) || apierrors.IsTooManyRequests(err) ||
		apierrors.IsTimeout(err) || apierrors.IsServerTimeout(err) {
		return true
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	msg := err.Error()
	for _, s := range []string{
		"connection refused",
		"connection reset",
		"broken pipe",
		"no such host",
		"unexpected EOF",
		"i/o timeout",
		// A blip that was just started has a writer but no attached guest
		// yet, and a peer hop may not know the node until placement settles.
		// These clear once the command connects to its stdio.
		"stream: state has no trajectory",
		"stream: guest stdio is not connected",
		"peer: unknown node",
	} {
		if strings.Contains(msg, s) {
			return true
		}
	}
	return false
}

// closeStdin asks the stream API to send EOF to the blip's command. The API
// may answer 409 or 503 until the guest connects, so be brief and best-effort.
func (a *app) closeStdin(ctx context.Context, target streamTarget) {
	c, err := a.clients()
	if err != nil {
		return
	}
	api := c.stream()
	if api == nil || target.state == "" {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	delay := 50 * time.Millisecond
	for {
		err := api.Stdin(ctx, target.namespace, target.state, nil, true)
		if err == nil || ctx.Err() != nil || !retryableStreamError(err) {
			return
		}
		// A command that already exited needs no EOF. Stop retrying instead
		// of delaying run for the whole window.
		if target.blip != "" && c.Kube != nil {
			if b, gerr := get(ctx, c, target.blip, &v1alpha1.Blip{}); gerr == nil && v1alpha1.Finished(b) {
				return
			}
		}
		if !sleepContext(ctx, delay) {
			return
		}
		delay = min(2*delay, 500*time.Millisecond)
	}
}
