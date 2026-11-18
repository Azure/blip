package guest

// openDisposition is the single-flight decision shared by lookup and start.
// Waiting, process creation, and waking waiters are effects of the caller.
type openDisposition uint8

const (
	openStart openDisposition = iota
	openWait
	openReuse
	openCompleted
)

func (r *openRecord) disposition() openDisposition {
	switch {
	case r == nil:
		return openStart
	case r.completed:
		return openCompleted
	case r.session != nil:
		return openReuse
	default:
		return openWait
	}
}

// complete is idempotent, including when removal races the open acknowledgement.
// The caller adds a tombstone to its bounded history only on the first change.
func (r *openRecord) complete() bool {
	if r.completed {
		return false
	}
	r.session = nil
	r.completed = true
	return true
}

// sessionRetention decides which resources an exit/detach can release. An
// unattached caller may still hold the session pointer returned by openExec,
// so even an unlisted session keeps its replay until that caller has attached.
func sessionRetention(primary, exited, attached bool, clients int) (clearReplay, remove bool) {
	remove = !primary && exited && clients == 0
	return remove && attached, remove
}
