// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package blipchat

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	apierrors "k8s.io/apimachinery/pkg/api/errors"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

// noteAdmission has no effect on the chat beyond advancing LastSeq. The node's
// after=0 means unconditional, so a generation with no input needs this marker
// before any prompt can be appended conditionally. Concurrent markers are safe:
// they only invalidate earlier admission snapshots, never enqueue work.
const noteAdmission = "admission"

// appendMessage admits HTTP composer prompts at the node's serialized
// compare-and-append boundary, including submissions through other replicas.
// Every conflict needs a fresh replay; the display cache is not authoritative.
// Queued includes the in-flight turn. Answers do not consume prompt slots.
// Other producers using appendNote directly retain their existing behavior.
func (s *Server) appendMessage(ctx context.Context, st *v1.BlipState, profile Profile, sender, text string) error {
	var data []byte
	restarts := 0
	for attempt := 0; ctx.Err() == nil; attempt++ {
		if attempt > 0 {
			// An offline stop changes metadata, not the ring's CAS token.
			// Replays after a conflict or restart need its latest boundary.
			current, err := s.cluster.GetSession(ctx, s.namespace, st.Name)
			if err != nil {
				return err
			}
			st = current
		}
		view, err := s.messageView(ctx, st)
		if err != nil {
			return err
		}
		if view.Question != nil {
			return s.appendNote(ctx, st, profile, noteRecord{
				Type: noteAnswer, QID: view.Question.ID, Text: text, Sender: sender, Gen: view.questionGen(view.Question.ID),
			})
		}
		if len(view.Queued) >= maxQueue {
			return errSessionBusy
		}
		if data == nil {
			note, err := s.promptNote(st, profile, sender, text)
			if err != nil {
				return err
			}
			data, err = json.Marshal(note)
			if err != nil {
				return err
			}
		}
		after, ok := view.canWrite()
		if !ok {
			if restarts >= 3 {
				return errSessionBusy
			}
			restarts++
			if err := s.appendNote(ctx, st, profile, noteRecord{Type: noteAdmission}); err != nil {
				return err
			}
			continue
		}
		_, err = s.wire.Send(ctx, s.namespace, st.Name, data, false, true, after)
		switch {
		case err == nil:
			s.invalidateView(st.Name)
			return nil
		case errors.Is(err, ErrPrecondition):
			// Another input or note changed the queue or its generation.
			continue
		case errors.Is(err, ErrNotRunning):
			if restarts >= 3 {
				return errSessionBusy
			}
			restarts++
			waitNoActive(ctx, s, st.Name)
			if _, err := s.ensureRunning(ctx, st, profile); err != nil {
				return err
			}
		default:
			return err
		}
	}
	return ctx.Err()
}

// messageView deliberately neither reads nor populates the display cache. A
// failed or partial replay must not admit prompts against an incomplete count.
func (s *Server) messageView(ctx context.Context, st *v1.BlipState) (*chatView, error) {
	v := newChatView(st.Annotations[AnnotationACPSession])
	v.applyStopBefore(stopBefore(st))
	rc, err := s.wire.ReadLog(ctx, s.namespace, st.Name, chatStart(st))
	if apierrors.IsNotFound(err) || errors.Is(err, ErrNotRunning) {
		// A new state has no trajectory yet. Admission will first append a
		// marker (starting its agent if needed), then replay before sending.
		return v, nil
	}
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	dec := json.NewDecoder(rc)
	for {
		var rec streamLogRecord
		if err := dec.Decode(&rec); err != nil {
			if errors.Is(err, io.EOF) {
				return v, nil
			}
			return nil, fmt.Errorf("read message queue: %w", err)
		}
		v.observe(rec)
	}
}
