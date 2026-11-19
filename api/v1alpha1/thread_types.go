package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ---------------------------------------------------------------------------
// BlipThread

// BlipThread is one project's long-running coordinator. Its spec is owned by
// administrators; blipchat is the only writer of its status. The thread does
// not itself run anything: blipchat turns its turns, timers, and the blips it
// starts into coordinator steps.
type BlipThreadSpec struct {
	// Charter is the project's standing instructions for the coordinator:
	// what the project is, how work is reviewed, and which task attribute
	// conventions (state, after, pr, ...) the project uses. The engine never
	// interprets attributes, so conventions live here.
	// +kubebuilder:validation:MaxLength=16384
	Charter string `json:"charter,omitempty"`
	// SystemPrompt is the full system prompt for coordinator steps. When
	// empty, blipchat uses its built-in coordinator prompt. The charter is
	// appended after this text.
	// +kubebuilder:validation:MaxLength=16384
	SystemPrompt string `json:"systemPrompt,omitempty"`
	// Pool is the BlipPool tasks run in.
	// +kubebuilder:validation:MinLength=1
	Pool string `json:"pool"`
	// Base is the BlipState new task blips fork from, when the coordinator
	// does not choose another one.
	Base string `json:"base,omitempty"`
	// MaxRunning caps concurrently running blips labelled with this thread.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=2147483647
	// +kubebuilder:default=1
	MaxRunning int32 `json:"maxRunning,omitempty"`
	// Model is the model name passed to the OpenAI-compatible endpoint.
	Model string `json:"model,omitempty"`
	// DailyTokens caps the tokens one day of coordinator steps may spend.
	// 0 means no cap.
	// +kubebuilder:validation:Minimum=0
	DailyTokens int64 `json:"dailyTokens,omitempty"`
	// Heartbeat wakes the coordinator while it has open tasks. The default
	// is 30 minutes.
	// +kubebuilder:validation:XValidation:rule="duration(self) >= duration('0s')",message="heartbeat must be a non-negative duration"
	Heartbeat *metav1.Duration `json:"heartbeat,omitempty"`
	// Retention bounds the history blipchat keeps for this thread.
	Retention ThreadRetention `json:"retention,omitempty"`
}

// ThreadRetention bounds the history blipchat keeps. Zero values select the
// defaults: turns 168h, keepTurns 200, closedTasks 72h, maxTasks 200.
type ThreadRetention struct {
	// Turns is how long processed turns are kept.
	// +kubebuilder:validation:XValidation:rule="duration(self) >= duration('0s')",message="retention.turns must be a non-negative duration"
	Turns *metav1.Duration `json:"turns,omitempty"`
	// KeepTurns is the minimum number of turns kept per thread.
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=2147483647
	KeepTurns int32 `json:"keepTurns,omitempty"`
	// ClosedTasks is how long closed tasks are kept after their last update.
	// +kubebuilder:validation:XValidation:rule="duration(self) >= duration('0s')",message="retention.closedTasks must be a non-negative duration"
	ClosedTasks *metav1.Duration `json:"closedTasks,omitempty"`
	// MaxTasks caps the task board. The oldest closed tasks are pruned first.
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=2147483647
	MaxTasks int32 `json:"maxTasks,omitempty"`
}

// BlipThreadStatus is written only by blipchat.
type BlipThreadStatus struct {
	// LastSeq is the highest turn sequence reserved for this thread.
	LastSeq int64 `json:"lastSeq,omitempty"`
	// ConsumedSeq is the highest turn sequence included in a coordinator
	// step. Turns at or below it are history.
	ConsumedSeq int64 `json:"consumedSeq,omitempty"`
	// Summary is the coordinator's rolling summary of consumed history.
	// +kubebuilder:validation:MaxLength=16384
	Summary string `json:"summary,omitempty"`
	// Timers wake the coordinator at a fixed time.
	// +kubebuilder:validation:MaxItems=32
	// +listType=map
	// +listMapKey=id
	Timers []ThreadTimer `json:"timers,omitempty"`
	// NextWake is when blipchat next runs a step, if any.
	NextWake *metav1.Time `json:"nextWake,omitempty"`
	// TokensToday is the token spend in the current day.
	TokensToday int64 `json:"tokensToday,omitempty"`
	// TokenDay is the day TokensToday refers to, in YYYY-MM-DD. It resets
	// the daily budget at midnight UTC.
	TokenDay string `json:"tokenDay,omitempty"`
	// Paused stops coordinator steps. Turns still accumulate.
	Paused *ThreadPause `json:"paused,omitempty"`
	// Tasks is the coordinator's task board.
	// +kubebuilder:validation:MaxItems=200
	// +listType=map
	// +listMapKey=id
	Tasks []ThreadTask `json:"tasks,omitempty"`
}

// ThreadTimer is a pending wake-up.
type ThreadTimer struct {
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	ID   string      `json:"id"`
	At   metav1.Time `json:"at"`
	Note string      `json:"note,omitempty"`
}

// ThreadPause records why steps are paused.
type ThreadPause struct {
	Reason string `json:"reason,omitempty"`
}

// ThreadTask is one unit of project work. Ids and titles are chosen by the
// coordinator; attributes are free-form conventions declared in the charter.
type ThreadTask struct {
	// ID is short and DNS-safe because it labels blips.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=16
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	ID string `json:"id"`
	// +kubebuilder:validation:MaxLength=120
	Title string `json:"title,omitempty"`
	Open  bool   `json:"open,omitempty"`
	// Blips are the blips the coordinator started for this task. The engine
	// maintains the list.
	// +kubebuilder:validation:MaxItems=8
	// +listType=set
	Blips []string `json:"blips,omitempty"`
	// Attributes are coordinator-owned conventions such as state, after, or
	// pr. The engine never interprets them.
	// +kubebuilder:validation:MaxProperties=16
	// +kubebuilder:validation:XValidation:rule="self.all(k, k.size() <= 63 && self[k].size() <= 256)",message="attribute keys are at most 63 and values at most 256 characters"
	Attributes map[string]string `json:"attributes,omitempty"`
	// +kubebuilder:validation:MaxLength=256
	Note    string       `json:"note,omitempty"`
	Updated *metav1.Time `json:"updated,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Pool",type=string,JSONPath=`.spec.pool`
// +kubebuilder:printcolumn:name="Seq",type=integer,JSONPath=`.status.lastSeq`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type BlipThread struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              BlipThreadSpec   `json:"spec"`
	Status            BlipThreadStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
type BlipThreadList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []BlipThread `json:"items"`
}

// ---------------------------------------------------------------------------
// BlipTurn

// Turn author kinds. Only blipchat may write kinds other than
// ServiceAccount.
const (
	TurnAuthorUser           = "User"
	TurnAuthorBlip           = "Blip"
	TurnAuthorServiceAccount = "ServiceAccount"
	TurnAuthorCoordinator    = "Coordinator"
	TurnAuthorSystem         = "System"
)

// Turn wake modes.
const (
	WakeNow   = "Now"
	WakeBatch = "Batch"
	WakeNone  = "None"
)

// BlipTurnSpec is written by the turn's producer.
type BlipTurnSpec struct {
	// Thread is the name of a BlipThread in the same namespace. It must be a
	// valid thread (DNS subdomain) name so a typo cannot create a turn that
	// no thread can ever claim.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`
	Thread string     `json:"thread"`
	Author TurnAuthor `json:"author"`
	// Topic is a free-form dotted label such as blip.report, chat.propose,
	// or engine.capacity. Nothing in the engine interprets it.
	// +kubebuilder:validation:MaxLength=63
	Topic string `json:"topic,omitempty"`
	// InReplyTo is the sequence number of the turn this one answers.
	// +kubebuilder:validation:Minimum=0
	InReplyTo int64 `json:"inReplyTo,omitempty"`
	// Subjects name the objects this turn is about.
	// +kubebuilder:validation:MaxItems=8
	Subjects []TurnSubject `json:"subjects,omitempty"`
	// Attributes carry structured fields from the producer. The coordinator
	// reads them; the engine does not.
	// +kubebuilder:validation:MaxProperties=16
	// +kubebuilder:validation:XValidation:rule="self.all(k, k.size() <= 63 && self[k].size() <= 256)",message="attribute keys are at most 63 and values at most 256 characters"
	Attributes map[string]string `json:"attributes,omitempty"`
	// Text is the bounded human-readable payload.
	// +kubebuilder:validation:MaxLength=2048
	Text string `json:"text,omitempty"`
	// Wake asks blipchat to run a step: Now before the next turn, Batch
	// after a short debounce, None never.
	// +kubebuilder:validation:Enum=Now;Batch;None
	// +kubebuilder:default=Batch
	Wake string `json:"wake,omitempty"`
}

// TurnAuthor identifies who produced a turn.
type TurnAuthor struct {
	// +kubebuilder:validation:Enum=User;Blip;ServiceAccount;Coordinator;System
	Kind string `json:"kind"`
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name"`
}

// TurnSubject names something a turn refers to: a blip, a task, a state, or
// an external object addressed by URI.
//
// +kubebuilder:validation:XValidation:rule="has(self.name) != has(self.uri)",message="a subject sets exactly one of name and uri"
type TurnSubject struct {
	// Kind names the subject type, such as Blip, BlipState, BlipThread,
	// Task, or URL.
	// +kubebuilder:validation:MaxLength=32
	Kind string `json:"kind,omitempty"`
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name,omitempty"`
	// +kubebuilder:validation:MaxLength=512
	URI string `json:"uri,omitempty"`
}

// BlipTurnStatus is written only by blipchat.
//
// The struct-level rule makes seq immutable once it has been set. A rule on
// the seq property alone does not run when seq is removed: a status writer
// could clear it with `seq: null`, and the sequencer would then stamp a later
// sequence, reordering the thread's history.
//
// +kubebuilder:validation:XValidation:rule="!oldSelf.hasValue() || (has(self.seq) == has(oldSelf.value().seq) && (!has(self.seq) || self.seq == oldSelf.value().seq))",optionalOldSelf=true,message="seq is immutable once set"
type BlipTurnStatus struct {
	// Seq is the turn's position in the thread's single global order.
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:XValidation:rule="!oldSelf.hasValue() || self == oldSelf.value()",optionalOldSelf=true,message="seq is immutable once set"
	Seq int64 `json:"seq,omitempty"`
	// AcceptedTime is when blipchat sequenced the turn.
	AcceptedTime *metav1.Time `json:"acceptedTime,omitempty"`
	// ThreadUID is the UID of the BlipThread incarnation that sequenced the
	// turn. A deleted and recreated thread has a new UID, so turns sequenced
	// by the old incarnation are ignored rather than adopted as history.
	ThreadUID string `json:"threadUID,omitempty"`
	// OrphanedAt is when blipchat stopped retrying a turn whose thread does
	// not exist. Such a turn is never sequenced, and retention deletes it
	// after the default turn age. The sequencer clears it if the thread
	// appears later.
	OrphanedAt *metav1.Time `json:"orphanedAt,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Thread",type=string,JSONPath=`.spec.thread`
// +kubebuilder:printcolumn:name="Seq",type=integer,JSONPath=`.status.seq`
// +kubebuilder:printcolumn:name="Author",type=string,JSONPath=`.spec.author.kind`
// +kubebuilder:printcolumn:name="Topic",type=string,JSONPath=`.spec.topic`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
//
// BlipTurn is one event in a thread's coordinator history: a user message, a
// blip report, a finished blip, or a coordinator step. Blipchat stamps
// status.seq to give every turn one global order. Turns are immutable.
// +kubebuilder:validation:XValidation:rule="self.spec == oldSelf.spec",message="turns are immutable"
type BlipTurn struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              BlipTurnSpec   `json:"spec,omitempty"`
	Status            BlipTurnStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
type BlipTurnList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []BlipTurn `json:"items"`
}
