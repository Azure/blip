package gateway

import (
	"io"
	"sync"
)

// channelInput owns the only SSH reader across menu/guest transitions. Its
// one-chunk buffer bounds typeahead; each phase gets a revocable input lease.
// In particular, Bubble Tea's fallback cancelreader cannot interrupt a blocked
// SSH Read, and would otherwise eat the next guest's input after quitting.
type channelInput struct {
	mu     sync.Mutex
	ready  *sync.Cond
	buf    []byte
	err    error
	closed bool
	ended  chan struct{}
}

func newChannelInput(r io.Reader) *channelInput {
	in := &channelInput{ended: make(chan struct{})}
	in.ready = sync.NewCond(&in.mu)
	go func() {
		defer close(in.ended)
		buf := make([]byte, 32<<10)
		for {
			n, err := r.Read(buf)
			in.mu.Lock()
			for len(in.buf) > 0 && !in.closed {
				in.ready.Wait()
			}
			if in.closed {
				in.mu.Unlock()
				return
			}
			in.buf = append(in.buf[:0], buf[:n]...)
			in.err = err
			in.ready.Broadcast()
			in.mu.Unlock()
			if err != nil {
				return
			}
		}
	}()
	return in
}

func (in *channelInput) close() {
	in.mu.Lock()
	in.closed = true
	in.ready.Broadcast()
	in.mu.Unlock()
}

func (in *channelInput) reader() *inputLease { return &inputLease{input: in} }

type inputLease struct {
	input  *channelInput
	closed bool // protected by input.mu, including the read's buffer consumption
}

func (r *inputLease) Read(p []byte) (int, error) {
	in := r.input
	in.mu.Lock()
	defer in.mu.Unlock()
	for {
		if r.closed || in.closed {
			return 0, io.EOF
		}
		if len(p) == 0 {
			return 0, nil
		}
		if len(in.buf) > 0 {
			n := copy(p, in.buf)
			in.buf = in.buf[n:]
			in.ready.Broadcast()
			return n, nil
		}
		if in.err != nil {
			return 0, in.err
		}
		in.ready.Wait()
	}
}

func (r *inputLease) Close() error {
	r.input.mu.Lock()
	r.closed = true
	r.input.ready.Broadcast()
	r.input.mu.Unlock()
	return nil
}
