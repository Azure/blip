package webhook

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/project-unbounded/blip/internal/gateway/vm"
)

// --- Mock implementations ---

type mockVMClaimer struct {
	mu          sync.Mutex
	claimResult *vm.ClaimResult
	claimErr    error
	claimDelay  func() // optional delay to simulate slow claims
	releaseErr  error

	// Track calls for assertions.
	claimedSessions  []string
	releasedSessions []string
}

func (m *mockVMClaimer) Claim(_ context.Context, _, sessionID, _ string, _ int, _ string, _ int) (*vm.ClaimResult, error) {
	if m.claimDelay != nil {
		m.claimDelay()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.claimedSessions = append(m.claimedSessions, sessionID)
	if m.claimErr != nil {
		return nil, m.claimErr
	}
	return m.claimResult, nil
}

func (m *mockVMClaimer) ReleaseVM(_ context.Context, sessionID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.releasedSessions = append(m.releasedSessions, sessionID)
	return m.releaseErr
}

type mockTokenProvider struct {
	token *RegistrationToken
	err   error
	calls atomic.Int64
}

func (m *mockTokenProvider) CreateRegistrationToken(_ context.Context, _ string) (*RegistrationToken, error) {
	m.calls.Add(1)
	if m.err != nil {
		return nil, m.err
	}
	return m.token, nil
}

type mockConfigStore struct {
	mu     sync.Mutex
	stored []storedConfig
	err    error
}

type storedConfig struct {
	VMName string
	Config RunnerConfig
}

func (m *mockConfigStore) StoreRunnerConfig(_ context.Context, vmName string, cfg RunnerConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stored = append(m.stored, storedConfig{VMName: vmName, Config: cfg})
	return m.err
}

// --- Helpers ---

func signPayload(body []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func makeWebhookPayload(action string, jobID int64, labels []string, repo string) []byte {
	event := workflowJobEvent{
		Action: action,
		WorkflowJob: workflowJob{
			ID:     jobID,
			Labels: labels,
			Name:   "test-job",
		},
		Repository: repository{
			FullName: repo,
		},
	}
	data, _ := json.Marshal(event)
	return data
}

func newTestHandler(claimer *mockVMClaimer, tokens *mockTokenProvider, store *mockConfigStore) *Handler {
	return NewHandler(HandlerConfig{
		VMClaimer:          claimer,
		RunnerConfigStore:  store,
		TokenProvider:      tokens,
		VMPoolName:         "blip",
		RunnerLabels:       []string{"self-hosted", "blip"},
		MaxSessionDuration: 3600,
		PodName:            "test-pod",
	})
}

func newTestHandlerWithSecret(claimer *mockVMClaimer, tokens *mockTokenProvider, store *mockConfigStore, secret string) *Handler {
	return NewHandler(HandlerConfig{
		WebhookSecret:      []byte(secret),
		VMClaimer:          claimer,
		RunnerConfigStore:  store,
		TokenProvider:      tokens,
		VMPoolName:         "blip",
		RunnerLabels:       []string{"self-hosted", "blip"},
		MaxSessionDuration: 3600,
		PodName:            "test-pod",
	})
}

// sendWebhook is a helper that sends a POST to the handler and waits for async processing.
func sendWebhook(h *Handler, body []byte, event string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(string(body)))
	r.Header.Set("X-GitHub-Event", event)
	h.ServeHTTP(w, r)
	return w
}

// waitForSessions waits for all async goroutines to complete, then asserts the
// expected number of active sessions.
func waitForSessions(t *testing.T, h *Handler, expected int) {
	t.Helper()
	h.WaitForPending()
	got := h.ActiveSessionCount()
	if got != expected {
		t.Fatalf("expected %d active sessions, got %d", expected, got)
	}
}

// --- Tests ---

func TestSessionID(t *testing.T) {
	assert.Equal(t, "blip-00000000000003e8", sessionID(1000))
	assert.Equal(t, "blip-0000000000000001", sessionID(1))
	assert.Equal(t, "blip-0000000000000000", sessionID(0))
	// Verify it can handle large IDs.
	assert.Equal(t, "blip-7fffffffffffffff", sessionID(9223372036854775807))
}

func TestHandler_MethodNotAllowed(t *testing.T) {
	h := newTestHandler(&mockVMClaimer{}, &mockTokenProvider{}, &mockConfigStore{})
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/webhook", nil)
	h.ServeHTTP(w, r)
	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

func TestHandler_PingEvent(t *testing.T) {
	h := newTestHandler(&mockVMClaimer{}, &mockTokenProvider{}, &mockConfigStore{})
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader("{}"))
	r.Header.Set("X-GitHub-Event", "ping")
	h.ServeHTTP(w, r)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestHandler_SignatureValidation(t *testing.T) {
	secret := "test-secret"
	h := newTestHandlerWithSecret(&mockVMClaimer{}, &mockTokenProvider{}, &mockConfigStore{}, secret)

	t.Run("missing signature", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader("{}"))
		r.Header.Set("X-GitHub-Event", "ping")
		h.ServeHTTP(w, r)
		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("invalid signature", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader("{}"))
		r.Header.Set("X-GitHub-Event", "ping")
		r.Header.Set("X-Hub-Signature-256", "sha256=deadbeef")
		h.ServeHTTP(w, r)
		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("valid signature", func(t *testing.T) {
		body := []byte(`{}`)
		sig := signPayload(body, secret)
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(string(body)))
		r.Header.Set("X-GitHub-Event", "ping")
		r.Header.Set("X-Hub-Signature-256", sig)
		h.ServeHTTP(w, r)
		assert.Equal(t, http.StatusOK, w.Code)
	})
}

func TestHandler_QueuedJob(t *testing.T) {
	claimer := &mockVMClaimer{
		claimResult: &vm.ClaimResult{Name: "vm-1", PodIP: "10.0.0.1", NodeName: "node-1"},
	}
	tokens := &mockTokenProvider{
		token: &RegistrationToken{Token: "AABBC123"},
	}
	store := &mockConfigStore{}
	h := newTestHandler(claimer, tokens, store)

	body := makeWebhookPayload("queued", 42, []string{"self-hosted", "blip"}, "org/repo")
	w := sendWebhook(h, body, "workflow_job")

	// Response is immediate (async processing).
	assert.Equal(t, http.StatusOK, w.Code)

	// Wait for async processing.
	waitForSessions(t, h, 1)

	// Verify VM was claimed.
	claimer.mu.Lock()
	require.Len(t, claimer.claimedSessions, 1)
	assert.Equal(t, "blip-000000000000002a", claimer.claimedSessions[0])
	claimer.mu.Unlock()

	// Verify registration token was requested.
	assert.Equal(t, int64(1), tokens.calls.Load())

	// Verify runner config was stored with VM name.
	store.mu.Lock()
	require.Len(t, store.stored, 1)
	assert.Equal(t, "vm-1", store.stored[0].VMName)
	assert.Equal(t, "AABBC123", store.stored[0].Config.Token)
	assert.Equal(t, "https://github.com/org/repo", store.stored[0].Config.RepoURL)
	assert.Equal(t, []string{"self-hosted", "blip"}, store.stored[0].Config.Labels)
	store.mu.Unlock()

	assert.Equal(t, 1, h.ActiveSessionCount())
}

func TestHandler_QueuedJob_NonMatchingLabels(t *testing.T) {
	claimer := &mockVMClaimer{}
	tokens := &mockTokenProvider{}
	store := &mockConfigStore{}
	h := newTestHandler(claimer, tokens, store)

	body := makeWebhookPayload("queued", 42, []string{"ubuntu-latest"}, "org/repo")
	w := sendWebhook(h, body, "workflow_job")

	assert.Equal(t, http.StatusOK, w.Code)

	// Give async goroutine a chance to run (it should be a no-op).
	waitForSessions(t, h, 0)

	claimer.mu.Lock()
	assert.Empty(t, claimer.claimedSessions, "should not claim VM for non-matching labels")
	claimer.mu.Unlock()
	assert.Equal(t, int64(0), tokens.calls.Load())
}

func TestHandler_QueuedJob_CaseInsensitiveLabels(t *testing.T) {
	claimer := &mockVMClaimer{
		claimResult: &vm.ClaimResult{Name: "vm-1", PodIP: "10.0.0.1"},
	}
	tokens := &mockTokenProvider{
		token: &RegistrationToken{Token: "tok"},
	}
	store := &mockConfigStore{}
	h := newTestHandler(claimer, tokens, store)

	body := makeWebhookPayload("queued", 42, []string{"BLIP"}, "org/repo")
	w := sendWebhook(h, body, "workflow_job")

	assert.Equal(t, http.StatusOK, w.Code)
	waitForSessions(t, h, 1)

	claimer.mu.Lock()
	assert.Len(t, claimer.claimedSessions, 1, "should match case-insensitively")
	claimer.mu.Unlock()
}

func TestHandler_QueuedJob_DuplicateIsIdempotent(t *testing.T) {
	claimer := &mockVMClaimer{
		claimResult: &vm.ClaimResult{Name: "vm-1", PodIP: "10.0.0.1"},
	}
	tokens := &mockTokenProvider{
		token: &RegistrationToken{Token: "tok"},
	}
	store := &mockConfigStore{}
	h := newTestHandler(claimer, tokens, store)

	body := makeWebhookPayload("queued", 42, []string{"blip"}, "org/repo")

	// First request.
	sendWebhook(h, body, "workflow_job")
	waitForSessions(t, h, 1)

	// Second request (duplicate webhook delivery).
	sendWebhook(h, body, "workflow_job")

	// Give the second goroutine time to process (it should skip).
	waitForSessions(t, h, 1)

	// VM should only be claimed once.
	claimer.mu.Lock()
	assert.Len(t, claimer.claimedSessions, 1)
	claimer.mu.Unlock()
	assert.Equal(t, int64(1), tokens.calls.Load())
}

func TestHandler_QueuedJob_ClaimFailure(t *testing.T) {
	claimer := &mockVMClaimer{
		claimErr: fmt.Errorf("no VMs available"),
	}
	tokens := &mockTokenProvider{}
	store := &mockConfigStore{}
	h := newTestHandler(claimer, tokens, store)

	body := makeWebhookPayload("queued", 42, []string{"blip"}, "org/repo")
	w := sendWebhook(h, body, "workflow_job")

	// Response is always 200 (async processing).
	assert.Equal(t, http.StatusOK, w.Code)

	// Wait for async processing to clean up.
	waitForSessions(t, h, 0)

	assert.Equal(t, int64(0), tokens.calls.Load(), "should not request token if claim fails")
	assert.Equal(t, 0, h.ActiveSessionCount(), "should not track failed sessions")
}

func TestHandler_QueuedJob_TokenFailure_ReleasesVM(t *testing.T) {
	claimer := &mockVMClaimer{
		claimResult: &vm.ClaimResult{Name: "vm-1", PodIP: "10.0.0.1"},
	}
	tokens := &mockTokenProvider{
		err: fmt.Errorf("GitHub API error"),
	}
	store := &mockConfigStore{}
	h := newTestHandler(claimer, tokens, store)

	body := makeWebhookPayload("queued", 42, []string{"blip"}, "org/repo")
	sendWebhook(h, body, "workflow_job")

	// Wait for async processing.
	waitForSessions(t, h, 0)

	// VM should have been released after token failure.
	claimer.mu.Lock()
	require.Len(t, claimer.releasedSessions, 1)
	assert.Equal(t, "blip-000000000000002a", claimer.releasedSessions[0])
	claimer.mu.Unlock()
	assert.Equal(t, 0, h.ActiveSessionCount())
}

func TestHandler_QueuedJob_ConfigStoreFailure_ReleasesVM(t *testing.T) {
	claimer := &mockVMClaimer{
		claimResult: &vm.ClaimResult{Name: "vm-1", PodIP: "10.0.0.1"},
	}
	tokens := &mockTokenProvider{
		token: &RegistrationToken{Token: "tok"},
	}
	store := &mockConfigStore{err: fmt.Errorf("patch failed")}
	h := newTestHandler(claimer, tokens, store)

	body := makeWebhookPayload("queued", 42, []string{"blip"}, "org/repo")
	sendWebhook(h, body, "workflow_job")

	// Wait for async processing.
	waitForSessions(t, h, 0)

	// VM should have been released after config store failure.
	claimer.mu.Lock()
	require.Len(t, claimer.releasedSessions, 1)
	assert.Equal(t, "blip-000000000000002a", claimer.releasedSessions[0])
	claimer.mu.Unlock()
	assert.Equal(t, 0, h.ActiveSessionCount())
}

func TestHandler_QueuedJob_InvalidRepoFormat(t *testing.T) {
	claimer := &mockVMClaimer{
		claimResult: &vm.ClaimResult{Name: "vm-1", PodIP: "10.0.0.1"},
	}
	tokens := &mockTokenProvider{}
	store := &mockConfigStore{}
	h := newTestHandler(claimer, tokens, store)

	// Send a payload with an invalid repository name.
	body := makeWebhookPayload("queued", 42, []string{"blip"}, "../evil/../../etc/passwd")
	sendWebhook(h, body, "workflow_job")

	// Wait for async processing.
	waitForSessions(t, h, 0)

	// Should not claim any VM.
	claimer.mu.Lock()
	assert.Empty(t, claimer.claimedSessions)
	claimer.mu.Unlock()
}

func TestHandler_CompletedJob(t *testing.T) {
	claimer := &mockVMClaimer{
		claimResult: &vm.ClaimResult{Name: "vm-1", PodIP: "10.0.0.1"},
	}
	tokens := &mockTokenProvider{
		token: &RegistrationToken{Token: "tok"},
	}
	store := &mockConfigStore{}
	h := newTestHandler(claimer, tokens, store)

	// First, queue the job.
	queueBody := makeWebhookPayload("queued", 42, []string{"blip"}, "org/repo")
	sendWebhook(h, queueBody, "workflow_job")
	waitForSessions(t, h, 1)

	// Now, complete the job.
	completeBody := makeWebhookPayload("completed", 42, []string{"blip"}, "org/repo")
	sendWebhook(h, completeBody, "workflow_job")

	// Wait for release.
	waitForSessions(t, h, 0)

	// VM should have been released.
	claimer.mu.Lock()
	require.Len(t, claimer.releasedSessions, 1)
	assert.Equal(t, "blip-000000000000002a", claimer.releasedSessions[0])
	claimer.mu.Unlock()
}

func TestHandler_CompletedJob_Untracked(t *testing.T) {
	claimer := &mockVMClaimer{}
	h := newTestHandler(claimer, &mockTokenProvider{}, &mockConfigStore{})

	// Complete a job we never queued.
	body := makeWebhookPayload("completed", 999, []string{"blip"}, "org/repo")
	sendWebhook(h, body, "workflow_job")

	// Wait for async processing.
	waitForSessions(t, h, 0)

	// Should still attempt release.
	claimer.mu.Lock()
	require.Len(t, claimer.releasedSessions, 1)
	claimer.mu.Unlock()
}

func TestHandler_IgnoresOtherActions(t *testing.T) {
	claimer := &mockVMClaimer{}
	h := newTestHandler(claimer, &mockTokenProvider{}, &mockConfigStore{})

	for _, action := range []string{"in_progress", "waiting"} {
		t.Run(action, func(t *testing.T) {
			body := makeWebhookPayload(action, 42, []string{"blip"}, "org/repo")
			w := sendWebhook(h, body, "workflow_job")
			assert.Equal(t, http.StatusOK, w.Code)

			claimer.mu.Lock()
			assert.Empty(t, claimer.claimedSessions)
			assert.Empty(t, claimer.releasedSessions)
			claimer.mu.Unlock()
		})
	}
}

func TestHandler_InvalidJSON(t *testing.T) {
	h := newTestHandler(&mockVMClaimer{}, &mockTokenProvider{}, &mockConfigStore{})
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader("not json"))
	r.Header.Set("X-GitHub-Event", "workflow_job")
	h.ServeHTTP(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandler_ActiveSessionCount(t *testing.T) {
	claimer := &mockVMClaimer{
		claimResult: &vm.ClaimResult{Name: "vm-1", PodIP: "10.0.0.1"},
	}
	tokens := &mockTokenProvider{
		token: &RegistrationToken{Token: "tok"},
	}
	store := &mockConfigStore{}
	h := newTestHandler(claimer, tokens, store)

	assert.Equal(t, 0, h.ActiveSessionCount())

	body := makeWebhookPayload("queued", 42, []string{"blip"}, "org/repo")
	sendWebhook(h, body, "workflow_job")
	waitForSessions(t, h, 1)

	assert.Equal(t, 1, h.ActiveSessionCount())
}

func TestVerifyWebhookSignature(t *testing.T) {
	secret := []byte("mysecret")
	body := []byte(`{"action":"queued"}`)

	t.Run("valid", func(t *testing.T) {
		sig := signPayload(body, "mysecret")
		assert.True(t, VerifyWebhookSignature(body, sig, secret))
	})

	t.Run("wrong secret", func(t *testing.T) {
		sig := signPayload(body, "wrong")
		assert.False(t, VerifyWebhookSignature(body, sig, secret))
	})

	t.Run("no prefix", func(t *testing.T) {
		assert.False(t, VerifyWebhookSignature(body, "deadbeef", secret))
	})

	t.Run("invalid hex", func(t *testing.T) {
		assert.False(t, VerifyWebhookSignature(body, "sha256=zzzz", secret))
	})

	t.Run("empty signature", func(t *testing.T) {
		assert.False(t, VerifyWebhookSignature(body, "", secret))
	})
}

func TestMatchesLabels(t *testing.T) {
	h := NewHandler(HandlerConfig{
		RunnerLabels: []string{"self-hosted", "blip"},
	})

	assert.True(t, h.matchesLabels([]string{"self-hosted", "blip"}))
	assert.True(t, h.matchesLabels([]string{"BLIP"}))
	assert.True(t, h.matchesLabels([]string{"ubuntu-latest", "Self-Hosted"}))
	assert.False(t, h.matchesLabels([]string{"ubuntu-latest"}))
	assert.False(t, h.matchesLabels([]string{}))
	assert.False(t, h.matchesLabels(nil))
}

func TestHandler_ConcurrentDuplicateWebhooks(t *testing.T) {
	// Verify that concurrent duplicate webhooks for the same job ID only claim one VM.
	claimer := &mockVMClaimer{
		claimResult: &vm.ClaimResult{Name: "vm-1", PodIP: "10.0.0.1"},
	}
	tokens := &mockTokenProvider{
		token: &RegistrationToken{Token: "tok"},
	}
	store := &mockConfigStore{}
	h := newTestHandler(claimer, tokens, store)

	body := makeWebhookPayload("queued", 42, []string{"blip"}, "org/repo")

	// Fire 10 concurrent webhooks for the same job.
	var wg sync.WaitGroup
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sendWebhook(h, body, "workflow_job")
		}()
	}
	wg.Wait()

	// Wait for all async processing.
	waitForSessions(t, h, 1)

	// Only one VM should be claimed.
	claimer.mu.Lock()
	assert.Len(t, claimer.claimedSessions, 1, "should only claim one VM for duplicate webhooks")
	claimer.mu.Unlock()
}

func TestHandler_CompletedDuringInflightQueued(t *testing.T) {
	// Simulate a "completed" event arriving while "queued" is still processing
	// (e.g., between Claim and StoreRunnerConfig). The completed handler should
	// delete the sentinel, and the queued handler should detect this and release
	// the VM rather than leaving a zombie session.

	claimReady := make(chan struct{})
	claimProceed := make(chan struct{})

	claimer := &mockVMClaimer{
		claimResult: &vm.ClaimResult{Name: "vm-1", PodIP: "10.0.0.1"},
		claimDelay: func() {
			// Signal that we're inside Claim, then wait for the test to send "completed".
			close(claimReady)
			<-claimProceed
		},
	}
	tokens := &mockTokenProvider{
		token: &RegistrationToken{Token: "tok"},
	}
	store := &mockConfigStore{}
	h := newTestHandler(claimer, tokens, store)

	// Send "queued" — the Claim call will block until we release it.
	queueBody := makeWebhookPayload("queued", 42, []string{"blip"}, "org/repo")
	sendWebhook(h, queueBody, "workflow_job")

	// Wait until the goroutine is inside the Claim call.
	<-claimReady

	// Now send "completed" while "queued" is still in-flight.
	completeBody := makeWebhookPayload("completed", 42, []string{"blip"}, "org/repo")
	sendWebhook(h, completeBody, "workflow_job")

	// Let the "completed" handler finish (it will delete the sentinel and release).
	// We need to wait for the completed goroutine to process. Use a brief sleep
	// since we can't use WaitForPending while queued is still blocked.
	// The completed goroutine should be fast (just map delete + ReleaseVM).
	for range 1000 {
		claimer.mu.Lock()
		released := len(claimer.releasedSessions)
		claimer.mu.Unlock()
		if released >= 1 {
			break
		}
		time.Sleep(time.Millisecond)
	}

	// Now let the Claim call proceed.
	close(claimProceed)

	// Wait for all goroutines to finish.
	h.WaitForPending()

	// The queued handler should detect the sentinel was deleted and release the VM.
	// The completed handler also releases. So we expect 2 releases total.
	claimer.mu.Lock()
	assert.Len(t, claimer.releasedSessions, 2, "both completed and queued should release")
	claimer.mu.Unlock()

	// No zombie sessions should remain.
	assert.Equal(t, 0, h.ActiveSessionCount(), "no zombie sessions should remain")
}
