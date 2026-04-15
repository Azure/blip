package ghactions

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Listener connects to the Actions Service message queue and receives
// job events via long-poll. It replaces the REST API Poller for scale set mode.
type Listener struct {
	client            *ScaleSetClient
	sessionID         string
	messageQueueURL   string
	messageQueueToken string
	lastMessageID     int64
	maxRunners        int
	vmClaimer         VMClaimer
	runnerConfigStore RunnerConfigStore
	vmPoolName        string
	podName           string

	mu             sync.Mutex
	activeSessions map[string]string // runnerRequestID (string) -> session ID
	wg             sync.WaitGroup
}

// ListenerConfig configures the scale set Listener.
type ListenerConfig struct {
	Client            *ScaleSetClient
	VMClaimer         VMClaimer
	RunnerConfigStore RunnerConfigStore
	VMPoolName        string
	PodName           string
	MaxRunners        int
}

// NewListener creates a new scale set Listener.
func NewListener(cfg ListenerConfig) *Listener {
	if cfg.MaxRunners <= 0 {
		cfg.MaxRunners = 10
	}
	return &Listener{
		client:            cfg.Client,
		maxRunners:        cfg.MaxRunners,
		vmClaimer:         cfg.VMClaimer,
		runnerConfigStore: cfg.RunnerConfigStore,
		vmPoolName:        cfg.VMPoolName,
		podName:           cfg.PodName,
		activeSessions:    make(map[string]string),
	}
}

// MessageType represents the type of a scale set message.
type MessageType string

const (
	MessageTypeJobAvailable MessageType = "JobAvailable"
	MessageTypeJobAssigned  MessageType = "JobAssigned"
	MessageTypeJobStarted   MessageType = "JobStarted"
	MessageTypeJobCompleted MessageType = "JobCompleted"
)

// ScaleSetMessage is a message received from the Actions Service message queue.
type ScaleSetMessage struct {
	MessageID   int64           `json:"messageId"`
	MessageType MessageType     `json:"messageType"`
	Body        json.RawMessage `json:"body"`
}

// JobAvailableMessage is the body of a JobAvailable message.
type JobAvailableMessage struct {
	RunnerRequestID int64 `json:"runnerRequestId"`
}

// JobCompletedMessage is the body of a JobCompleted message.
type JobCompletedMessage struct {
	RunnerRequestID int64  `json:"runnerRequestId"`
	Result          string `json:"result"`
}

// Run starts the scale set listener event loop. Blocks until ctx is cancelled.
func (l *Listener) Run(ctx context.Context) error {
	slog.Info("scale set listener starting", "max_runners", l.maxRunners)

	// 1. Create or resume session.
	if err := l.ensureSession(ctx); err != nil {
		return fmt.Errorf("create session: %w", err)
	}

	defer func() {
		// Clean up session on shutdown.
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		if err := l.client.DeleteSession(cleanupCtx, l.sessionID); err != nil {
			slog.Warn("failed to delete session on shutdown", "session_id", l.sessionID, "error", err)
		} else {
			slog.Info("scale set session deleted", "session_id", l.sessionID)
		}
	}()

	// 2. Long-poll loop.
	for {
		if ctx.Err() != nil {
			slog.Info("scale set listener stopping")
			return ctx.Err()
		}

		messages, err := l.pollMessages(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			slog.Error("failed to poll messages", "error", err)
			// Back off before retrying.
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(5 * time.Second):
			}
			continue
		}

		for _, msg := range messages {
			l.handleMessage(ctx, msg)
			// Acknowledge the message so the server does not redeliver it.
			if err := l.client.DeleteMessage(ctx, l.sessionID, msg.MessageID); err != nil {
				slog.Warn("failed to delete message", "message_id", msg.MessageID, "error", err)
			}
		}
	}
}

// ensureSession creates a new session, retrying on SessionConflict (409).
// If another controller owns the session, we back off and retry.
func (l *Listener) ensureSession(ctx context.Context) error {
	const maxRetries = 5
	backoff := 5 * time.Second

	for attempt := 0; attempt < maxRetries; attempt++ {
		session, err := l.client.CreateSession(ctx)
		if err != nil {
			// Check for session conflict (another controller owns the scale set).
			if isSessionConflict(err) {
				slog.Warn("session conflict, another controller owns this scale set; retrying",
					"attempt", attempt+1,
					"backoff", backoff,
				)
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(backoff):
				}
				backoff *= 2
				continue
			}
			return err
		}

		l.sessionID = session.SessionID
		l.messageQueueURL = session.MessageQueueURL
		l.messageQueueToken = session.MessageQueueAccessToken
		l.lastMessageID = 0
		return nil
	}

	return fmt.Errorf("failed to create session after %d retries (session conflict)", maxRetries)
}

// isSessionConflict checks if the error indicates a 409 Conflict (session owned
// by another controller).
func isSessionConflict(err error) bool {
	if err == nil {
		return false
	}
	// The doActionsAPI method returns errors like "Actions Service HTTP 409: ..."
	return strings.Contains(err.Error(), "HTTP 409")
}

// pollMessages performs a single long-poll for messages from the queue.
func (l *Listener) pollMessages(ctx context.Context) ([]ScaleSetMessage, error) {
	if l.messageQueueURL == "" {
		return nil, fmt.Errorf("message queue URL not set")
	}

	url := fmt.Sprintf("%s?lastMessageId=%d", l.messageQueueURL, l.lastMessageID)

	// Use a longer timeout for long-polling -- the server may hold the
	// connection for up to 50 seconds before responding with 202 (no messages).
	pollCtx, pollCancel := context.WithTimeout(ctx, 70*time.Second)
	defer pollCancel()

	req, err := http.NewRequestWithContext(pollCtx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create poll request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+l.messageQueueToken)
	req.Header.Set("Accept", "application/json")

	// Tell the server our maximum capacity so it can batch job assignments.
	currentActive := l.ActiveSessionCount()
	capacity := l.maxRunners - currentActive
	if capacity < 0 {
		capacity = 0
	}
	req.Header.Set("X-ScaleSetMaxCapacity", strconv.Itoa(capacity))

	resp, err := l.client.LongPollHTTPClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("poll request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodySize))
	if err != nil {
		return nil, fmt.Errorf("read poll response: %w", err)
	}

	switch resp.StatusCode {
	case http.StatusOK:
		// Messages available.
		var result struct {
			Count    int               `json:"count"`
			Messages []ScaleSetMessage `json:"value"`
		}
		if err := json.Unmarshal(body, &result); err != nil {
			return nil, fmt.Errorf("decode poll response: %w", err)
		}
		return result.Messages, nil

	case http.StatusAccepted:
		// 202: no messages, long-poll timeout. This is normal.
		return nil, nil

	case http.StatusUnauthorized:
		// Session token expired. Refresh the session.
		slog.Warn("message queue token expired, refreshing session")
		session, err := l.client.RefreshSession(pollCtx, l.sessionID)
		if err != nil {
			return nil, fmt.Errorf("refresh session: %w", err)
		}
		l.messageQueueURL = session.MessageQueueURL
		l.messageQueueToken = session.MessageQueueAccessToken
		return nil, nil

	default:
		return nil, fmt.Errorf("poll returned HTTP %d: %s", resp.StatusCode, string(body))
	}
}

// handleMessage routes a message to the appropriate handler.
func (l *Listener) handleMessage(ctx context.Context, msg ScaleSetMessage) {
	// Update last message ID for the next poll.
	if msg.MessageID > l.lastMessageID {
		l.lastMessageID = msg.MessageID
	}

	switch msg.MessageType {
	case MessageTypeJobAvailable:
		l.handleJobAvailable(ctx, msg)
	case MessageTypeJobAssigned:
		slog.Info("job assigned (informational)", "message_id", msg.MessageID)
	case MessageTypeJobStarted:
		slog.Info("job started (informational)", "message_id", msg.MessageID)
	case MessageTypeJobCompleted:
		l.handleJobCompleted(ctx, msg)
	default:
		slog.Warn("unknown message type", "type", msg.MessageType, "message_id", msg.MessageID)
	}
}

// handleJobAvailable processes a JobAvailable message: acquires the job,
// generates a JIT config, claims a VM, and stores the config.
// The heavy work (HTTP calls to Actions Service + VM claim) runs in a
// background goroutine so the long-poll loop is not blocked.
func (l *Listener) handleJobAvailable(ctx context.Context, msg ScaleSetMessage) {
	var jobMsg JobAvailableMessage
	if err := json.Unmarshal(msg.Body, &jobMsg); err != nil {
		slog.Error("failed to decode JobAvailable body", "error", err, "message_id", msg.MessageID)
		return
	}

	reqIDStr := strconv.FormatInt(jobMsg.RunnerRequestID, 10)
	log := slog.With("runner_request_id", jobMsg.RunnerRequestID, "message_id", msg.MessageID)

	// Check idempotency.
	l.mu.Lock()
	if _, exists := l.activeSessions[reqIDStr]; exists {
		l.mu.Unlock()
		log.Info("job already being handled, skipping")
		return
	}
	l.activeSessions[reqIDStr] = "" // sentinel: in-flight
	l.mu.Unlock()

	// Run the heavy setup work in a goroutine so we don't block the poll loop.
	l.wg.Add(1)
	go func() {
		defer l.wg.Done()
		setupCtx, setupCancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer setupCancel()
		if err := l.processJobAvailable(setupCtx, log, jobMsg, reqIDStr); err != nil {
			log.Error("failed to process job", "error", err)
		}
	}()
}

// processJobAvailable does the actual work for a JobAvailable message.
func (l *Listener) processJobAvailable(ctx context.Context, log *slog.Logger, jobMsg JobAvailableMessage, reqIDStr string) error {
	success := false
	defer func() {
		if !success {
			l.mu.Lock()
			delete(l.activeSessions, reqIDStr)
			l.mu.Unlock()
		}
	}()

	// 1. Acquire the job.
	log.Info("acquiring job")
	_, err := l.client.AcquireJobs(ctx, []int64{jobMsg.RunnerRequestID})
	if err != nil {
		return fmt.Errorf("acquire job: %w", err)
	}

	// 2. Generate JIT config.
	sid := fmt.Sprintf("blip-ss-%016x", jobMsg.RunnerRequestID)
	runnerName := fmt.Sprintf("blip-%s", reqIDStr)
	log.Info("generating JIT config", "runner_name", runnerName)

	jitResp, err := l.client.GenerateJitRunnerConfig(ctx, runnerName)
	if err != nil {
		return fmt.Errorf("generate JIT config: %w", err)
	}

	// 3. Claim VM from pool.
	log.Info("claiming VM", "session_id", sid)
	ttl := int(DefaultActionsTTL.Seconds())

	claimCtx, claimCancel := context.WithTimeout(ctx, 10*time.Second)
	defer claimCancel()

	result, err := l.vmClaimer.Claim(
		claimCtx, l.vmPoolName, sid, l.podName,
		ttl, "github-actions:scaleset", 0,
	)
	if err != nil {
		return fmt.Errorf("claim VM: %w", err)
	}

	log.Info("VM claimed", "session_id", sid, "vm_name", result.Name, "vm_ip", result.PodIP)

	// 4. Store JIT config on VM.
	if err := l.runnerConfigStore.StoreRunnerConfig(ctx, result.Name, RunnerConfig{
		JITConfig: jitResp.EncodedJITConfig,
	}); err != nil {
		log.Error("failed to store JIT config, releasing VM", "error", err)
		if releaseErr := l.vmClaimer.ReleaseVM(ctx, sid); releaseErr != nil {
			log.Error("failed to release VM after config store failure", "error", releaseErr)
		}
		return fmt.Errorf("store JIT config: %w", err)
	}

	// Mark as fully set up.
	l.mu.Lock()
	l.activeSessions[reqIDStr] = sid
	l.mu.Unlock()
	success = true

	log.Info("JIT config stored, runner will start automatically",
		"session_id", sid,
		"vm_name", result.Name,
	)
	return nil
}

// handleJobCompleted processes a JobCompleted message: releases the VM.
func (l *Listener) handleJobCompleted(ctx context.Context, msg ScaleSetMessage) {
	var jobMsg JobCompletedMessage
	if err := json.Unmarshal(msg.Body, &jobMsg); err != nil {
		slog.Error("failed to decode JobCompleted body", "error", err, "message_id", msg.MessageID)
		return
	}

	reqIDStr := strconv.FormatInt(jobMsg.RunnerRequestID, 10)
	log := slog.With("runner_request_id", jobMsg.RunnerRequestID, "result", jobMsg.Result)

	l.mu.Lock()
	sid, exists := l.activeSessions[reqIDStr]
	if exists {
		delete(l.activeSessions, reqIDStr)
	}
	l.mu.Unlock()

	if !exists || sid == "" {
		log.Info("job completed but no active session found (may have been cleaned up already)")
		return
	}

	log.Info("job completed, releasing VM", "session_id", sid)
	if err := l.vmClaimer.ReleaseVM(ctx, sid); err != nil {
		log.Warn("failed to release VM (will be cleaned up by TTL)", "session_id", sid, "error", err)
	}
}

// ActiveSessionCount returns the number of currently tracked sessions.
func (l *Listener) ActiveSessionCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.activeSessions)
}

// WaitForPending blocks until all in-flight async goroutines have completed.
func (l *Listener) WaitForPending() {
	l.wg.Wait()
}
