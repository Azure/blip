// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package blipchat

import (
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

// Labels and annotations blipchat keeps on a chat's BlipState. They are
// low-churn metadata: the title the agent reports, the ACP session to resume,
// the ring offsets the chat starts and stops at, and the tree position.
// Everything else, including every message, prompt, note, and question, lives
// in the trajectory ring.
const (
	LabelSession = v1.LabelChatSession
	LabelParent  = v1.AnnotationChatParent

	AnnotationTitle         = "chat.blip.dev/title"
	AnnotationScope         = "chat.blip.dev/scope"
	AnnotationUser          = "chat.blip.dev/user"
	AnnotationProfile       = v1.AnnotationChatProfile
	AnnotationBase          = "chat.blip.dev/base"
	AnnotationACPSession    = "chat.blip.dev/acp-session"
	AnnotationStart         = "chat.blip.dev/start"
	AnnotationStopBefore    = "chat.blip.dev/stop-before"
	AnnotationGeneration    = "chat.blip.dev/generation"
	AnnotationParent        = v1.AnnotationChatParent
	AnnotationRoot          = v1.AnnotationChatRoot
	AnnotationDepth         = v1.AnnotationChatDepth
	AnnotationParentProfile = v1.AnnotationChatParentProfile
	AnnotationParentDepth   = v1.AnnotationChatParentDepth
)

func stopBefore(st *v1.BlipState) uint64 {
	n, _ := strconv.ParseUint(st.Annotations[AnnotationStopBefore], 10, 64)
	return n
}

// Errors the handlers map to HTTP statuses and tool results.
var (
	errSessionBusy        = errors.New("session is busy")
	errMessageTooLong     = errors.New("message is too long")
	errProfileUnavailable = errors.New("profile is unavailable")
	errQuestionOpen       = errors.New("a question is already open")
	errQuestionPending    = errors.New("the user has not answered yet")
	errQuestionCancelled  = errors.New("the user cancelled the question")
	errNoQuestion         = errors.New("no question is open")
)

// maxQueue bounds the accepted-but-unsent prompts for one chat.
const maxQueue = 32

// defaultQuestionTimeout is how long ask_user waits before telling the agent
// to end its turn and receive the answer as the next prompt.
const defaultQuestionTimeout = 30 * time.Second

// Event is one server-sent event. The shape is part of the UI contract.
type Event struct {
	Offset  uint64          `json:"offset"`
	Type    string          `json:"type"`
	Message json.RawMessage `json:"message,omitempty"`
	Status  *Status         `json:"status,omitempty"`
}

// Status is a chat lifecycle event. Question is set while the agent waits for
// the user's answer.
type Status struct {
	Phase    string    `json:"phase"`
	Running  bool      `json:"running"`
	Detail   string    `json:"detail,omitempty"`
	Question *Question `json:"question,omitempty"`
}

// latestBlip returns the newest generation, running or not.
func latestBlip(blips []v1.Blip) *v1.Blip {
	var best *v1.Blip
	var max int64 = -1
	for i := range blips {
		if g := generationOf(&blips[i]); g > max {
			max = g
			best = &blips[i]
		}
	}
	return best
}

// runningBlip returns the newest blip that is still attached to the state.
func runningBlip(blips []v1.Blip) *v1.Blip {
	var best *v1.Blip
	var max int64 = -1
	for i := range blips {
		if blips[i].Status.Phase != v1.BlipRunning {
			continue
		}
		if g := generationOf(&blips[i]); g > max {
			max = g
			best = &blips[i]
		}
	}
	return best
}

// generationOf reads the generation from the annotation, falling back to the
// conventional -g<N> name suffix for blips created before the annotation.
func generationOf(blip *v1.Blip) int64 {
	if raw := blip.Annotations[AnnotationGeneration]; raw != "" {
		if n, err := strconv.ParseInt(raw, 10, 64); err == nil {
			return n
		}
	}
	if i := strings.LastIndex(blip.Name, "-g"); i >= 0 {
		if n, err := strconv.ParseInt(blip.Name[i+2:], 10, 64); err == nil {
			return n
		}
	}
	return 0
}
