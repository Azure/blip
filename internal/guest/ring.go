package guest

import (
	"bytes"
	"strings"

	"github.com/Azure/blip/internal/wire"
)

// ringSize bounds the output kept per session for replay.
const ringSize = 1 << 20

// exitOutputMax bounds the output reported with a failed primary command.
const exitOutputMax = 1024

type frame struct {
	t    wire.Type
	data []byte
}

// ring keeps the most recent output frames of a session. Frames are numbered;
// readers keep a cursor (the next frame number they want).
type ring struct {
	max    int
	size   int
	first  uint64 // number of frames[0]
	frames []frame
}

func (r *ring) next() uint64 { return r.first + uint64(len(r.frames)) }

func (r *ring) add(t wire.Type, data []byte) {
	r.addPinned(t, data, r.next())
}

// addPinned appends a frame, keeping frames at or after pin. pin is the
// slowest attached client's next frame; output it has not received yet must
// not be evicted, or a fast writer would silently truncate a download.
func (r *ring) addPinned(t wire.Type, data []byte, pin uint64) {
	r.frames = append(r.frames, frame{t, data})
	r.size += len(data)
	r.trim(pin)
}

func (r *ring) trim(pin uint64) {
	for r.size > r.max && len(r.frames) > 1 && r.first < pin {
		r.size -= len(r.frames[0].data)
		r.frames[0] = frame{}
		r.frames = r.frames[1:]
		r.first++
	}
}

// since returns the frames from cursor on, the new cursor, and whether
// frames before the returned ones were dropped.
func (r *ring) since(cursor uint64) ([]frame, uint64, bool) {
	gap := cursor < r.first
	if gap {
		cursor = r.first
	}
	out := append([]frame(nil), r.frames[cursor-r.first:]...)
	return out, r.next(), gap
}

// tail returns the last max bytes of output, starting at a line boundary
// when possible.
func (r *ring) tail(max int) string {
	var b []byte
	for i := len(r.frames) - 1; i >= 0 && len(b) < max; i-- {
		b = append(append([]byte(nil), r.frames[i].data...), b...)
	}
	if len(b) > max {
		b = b[len(b)-max:]
		if i := bytes.IndexByte(b, '\n'); i >= 0 && i < len(b)-1 {
			b = b[i+1:]
		}
	}
	return strings.ToValidUTF8(string(b), "")
}

// clear drops all frames, keeping numbering.
func (r *ring) clear() {
	r.first = r.next()
	r.frames = nil
	r.size = 0
}
