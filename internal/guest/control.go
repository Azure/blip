// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package guest

import (
	"errors"
	"io"
	"sync"
	"time"

	"github.com/Azure/blip/internal/wire"
)

// Control writes must finish well within a freeze lease. A runtime that stops
// reading must reconnect and resynchronize rather than receive an arbitrarily
// old success, or prevent the guest from shutting down.
const controlWriteTimeout = 5 * time.Second

type controlConn struct {
	*wire.Conn
	stream io.ReadWriteCloser
	mu     sync.Mutex
}

func (c *controlConn) WriteJSON(t wire.Type, v any) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.writeLocked(t, v)
}

func (c *controlConn) writeLocked(t wire.Type, v any) error {
	return c.writeTimeoutLocked(t, v, controlWriteTimeout)
}

func (c *controlConn) writeTimeoutLocked(t wire.Type, v any, timeout time.Duration) error {
	if timeout <= 0 {
		c.stream.Close()
		return io.ErrClosedPipe
	}
	timer := time.AfterFunc(timeout, func() { c.stream.Close() })
	defer timer.Stop()
	err := c.Conn.WriteJSON(t, v)
	if err != nil {
		c.stream.Close()
	}
	return err
}

// Sample state only after acquiring the output slot: a queued expiry must not
// report a new freeze as thawed, nor a queued success resurrect an old freeze.
func (c *controlConn) freezeResult(g *Guest, id string, err error, freezing bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	timeout := controlWriteTimeout
	g.fmu.Lock()
	f := g.frozen[id]
	frozen := f != nil
	if frozen && err == nil {
		// A response queued near expiry has less than a full write timeout
		// left. Never let its pending success outlive the lease it describes.
		timeout = min(timeout, time.Until(f.lease.until))
	}
	g.fmu.Unlock()
	if freezing && !frozen && err == nil {
		err = errors.New("freeze expired before acknowledgement")
	}
	_ = c.writeTimeoutLocked(wire.TFreezeResult, wire.FreezeResult{ID: id, Frozen: frozen, Error: errString(err)}, timeout)
}
