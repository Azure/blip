package blipfs

import (
	"context"
	"fmt"
	"time"
)

const (
	batchOps   = 512 // max ops per group-committed record
	writeTries = 30
)

// refresh forces the next remote call to re-read the control blob.
func (c *SeqClient) refresh(ctx context.Context) {
	if c.v.leader.Load() == nil {
		c.remote(ctx, true)
	}
}

// writeRecord gets a token for streams and writes one record. A fenced
// write (the epoch was sealed) is retried with a fresh token.
func (v *Vol) writeRecord(ctx context.Context, typ uint8, streams []string, ops []Op) (uint64, error) {
	payload := mustCBOR(&Body{Ops: ops})
	delay := 10 * time.Millisecond
	var lastErr error
	for range writeTries {
		epoch, lsn, back, err := v.seq.Token(ctx, streams, 1)
		if err != nil {
			return 0, err
		}
		rec := &Record{Epoch: epoch, LSN: lsn, Type: typ, Streams: streams, Backptrs: back, Node: v.node, Payload: payload}
		for range 3 {
			if err = v.wal.Write(ctx, rec); err == nil || isFenced(err) {
				break
			}
			time.Sleep(delay)
		}
		if err == nil {
			v.seq.Acked(lsn)
			v.keepOwn(rec)
			return lsn, nil
		}
		lastErr = err
		if !isFenced(err) {
			return 0, fmt.Errorf("wal write %d: %w", lsn, err)
		}
		v.seq.refresh(ctx)
		time.Sleep(delay)
		delay = min(delay*2, time.Second)
	}
	return 0, fmt.Errorf("wal write kept being fenced: %w", lastErr)
}

const ownKeep = 4096 // how many recent LSNs of own records to keep

func (v *Vol) keepOwn(r *Record) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.own == nil {
		v.own = map[uint64]*Record{}
	}
	v.own[r.LSN] = r
	if len(v.own) > 2*ownKeep {
		for l := range v.own {
			if l+ownKeep < r.LSN {
				delete(v.own, l)
			}
		}
	}
}

func (v *Vol) ownRecord(l uint64) *Record {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.own[l]
}

func streamsFor(ops []Op) []string {
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, op := range ops {
		switch {
		case isChunkOp(op.Kind):
			add(chunksStream)
		default:
			add(branchStream(op.Branch))
			if op.Kind == OpBranchCreate || op.Kind == OpMergeStart || op.Kind == OpBranchClose {
				add(branchesStream)
			}
		}
	}
	return out
}

func chunkEnts(ops []Op) []ChunkEnt {
	var out []ChunkEnt
	for _, op := range ops {
		if op.Kind == OpChunkPut {
			out = append(out, op.Chunks...)
		}
	}
	return out
}

// write writes a record of ops and replays it locally; it returns the LSN
// and the outcome of each op that targets branch b (others are zero).
func (v *Vol) write(ctx context.Context, typ uint8, b *Branch, ops []Op) (uint64, []opResult, error) {
	lsn, err := v.writeRecord(ctx, typ, streamsFor(ops), ops)
	if err != nil {
		return 0, nil, err
	}
	if ents := chunkEnts(ops); len(ents) > 0 {
		v.chunks.noteOwn(lsn, ents)
	}
	if b == nil {
		return lsn, nil, nil
	}
	if err := b.s.catchUp(ctx, lsn); err != nil {
		return lsn, nil, err
	}
	res := b.takeResults(lsn)
	if res == nil {
		res = make([]opResult, len(ops))
	}
	return lsn, res, nil
}

type commitReq struct {
	ops  []Op
	done chan struct{}
	lsn  uint64
	res  []opResult
	err  error
}

// commit group-commits ops on branch b: concurrent callers share records.
func (b *Branch) commit(ctx context.Context, ops ...Op) (uint64, []opResult, error) {
	r := &commitReq{ops: ops, done: make(chan struct{})}
	b.cmu.Lock()
	b.queue = append(b.queue, r)
	if !b.flushing {
		b.flushing = true
		go b.flushQueue()
	}
	b.cmu.Unlock()
	select {
	case <-r.done:
		return r.lsn, r.res, r.err
	case <-ctx.Done():
		return 0, nil, ctx.Err()
	}
}

func (b *Branch) flushQueue() {
	for {
		b.cmu.Lock()
		var batch []*commitReq
		n, creates := 0, 0
		for len(b.queue) > 0 {
			r := b.queue[0]
			c := 0
			for _, op := range r.ops {
				if op.Kind == OpCreate {
					c++
				}
			}
			if len(batch) > 0 && (n+len(r.ops) > batchOps || creates+c > createsPerL) {
				break
			}
			batch, n, creates = append(batch, r), n+len(r.ops), creates+c
			b.queue = b.queue[1:]
		}
		if len(batch) == 0 {
			b.flushing = false
			b.cmu.Unlock()
			return
		}
		b.cmu.Unlock()

		var ops []Op
		for _, r := range batch {
			ops = append(ops, r.ops...)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		lsn, res, err := b.v.write(ctx, RecCommit, b, ops)
		cancel()
		i := 0
		for _, r := range batch {
			r.lsn, r.err = lsn, err
			if err == nil {
				r.res = res[i : i+len(r.ops)]
			}
			i += len(r.ops)
			close(r.done)
		}
	}
}
