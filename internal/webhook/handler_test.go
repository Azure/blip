package webhook

import (
	"context"
	"fmt"
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
	claimDelay  func()
	releaseErr  error

	claimedSessions  []string
	claimedDurations []int
	releasedSessions []string
}

func (m *mockVMClaimer) Claim(_ context.Context, _, sessionID, _ string, maxDuration int, _ string, _ int) (*vm.ClaimResult, error) {
	if m.claimDelay != nil {
		m.claimDelay()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.claimedSessions = append(m.claimedSessions, sessionID)
	m.claimedDurations = append(m.claimedDurations, maxDuration)
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

type mockJobsProvider struct {
	mu   sync.Mutex
	jobs map[string][]WorkflowJob // repo -> jobs
	err  error
}

func (m *mockJobsProvider) ListQueuedJobs(_ context.Context, ownerRepo string) ([]WorkflowJob, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return nil, m.err
	}
	return m.jobs[ownerRepo], nil
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

type staticRepoProvider struct {
	repos []string
}

func (s *staticRepoProvider) ActionsRepos() []string { return s.repos }

// --- Helpers ---

func newTestPoller(claimer *mockVMClaimer, tokens *mockTokenProvider, jobs *mockJobsProvider, store *mockConfigStore, repos []string) *Poller {
	return NewPoller(PollerConfig{
		VMClaimer:          claimer,
		RunnerConfigStore:  store,
		TokenProvider:      tokens,
		JobsProvider:       jobs,
		RepoProvider:       &staticRepoProvider{repos: repos},
		VMPoolName:         "blip",
		RunnerLabels:       []string{"self-hosted", "blip"},
		MaxSessionDuration: 3600,
		PodName:            "test-pod",
		PollInterval:       time.Second,
	})
}

// --- Tests ---

func TestSessionID(t *testing.T) {
	assert.Equal(t, "blip-00000000000003e8", sessionID(1000))
	assert.Equal(t, "blip-0000000000000001", sessionID(1))
	assert.Equal(t, "blip-0000000000000000", sessionID(0))
	assert.Equal(t, "blip-7fffffffffffffff", sessionID(9223372036854775807))
}

func TestPoller_QueuedJob(t *testing.T) {
	claimer := &mockVMClaimer{
		claimResult: &vm.ClaimResult{Name: "vm-1", PodIP: "10.0.0.1", NodeName: "node-1"},
	}
	tokens := &mockTokenProvider{
		token: &RegistrationToken{Token: "AABBC123"},
	}
	jobs := &mockJobsProvider{
		jobs: map[string][]WorkflowJob{
			"org/repo": {{ID: 42, Name: "test-job", Labels: []string{"self-hosted", "blip"}, Status: "queued"}},
		},
	}
	store := &mockConfigStore{}
	p := newTestPoller(claimer, tokens, jobs, store, []string{"org/repo"})

	p.poll(context.Background())
	p.WaitForPending()

	claimer.mu.Lock()
	require.Len(t, claimer.claimedSessions, 1)
	assert.Equal(t, "blip-000000000000002a", claimer.claimedSessions[0])
	claimer.mu.Unlock()

	assert.Equal(t, int64(1), tokens.calls.Load())

	store.mu.Lock()
	require.Len(t, store.stored, 1)
	assert.Equal(t, "vm-1", store.stored[0].VMName)
	assert.Equal(t, "AABBC123", store.stored[0].Config.Token)
	assert.Equal(t, "https://github.com/org/repo", store.stored[0].Config.RepoURL)
	assert.Equal(t, []string{"self-hosted", "blip"}, store.stored[0].Config.Labels)
	store.mu.Unlock()

	assert.Equal(t, 1, p.ActiveSessionCount())
}

func TestPoller_DefaultTTLFallback(t *testing.T) {
	claimer := &mockVMClaimer{
		claimResult: &vm.ClaimResult{Name: "vm-1", PodIP: "10.0.0.1"},
	}
	tokens := &mockTokenProvider{
		token: &RegistrationToken{Token: "tok"},
	}
	jobs := &mockJobsProvider{
		jobs: map[string][]WorkflowJob{
			"org/repo": {{ID: 42, Labels: []string{"blip"}, Status: "queued"}},
		},
	}
	store := &mockConfigStore{}

	p := NewPoller(PollerConfig{
		VMClaimer:          claimer,
		RunnerConfigStore:  store,
		TokenProvider:      tokens,
		JobsProvider:       jobs,
		RepoProvider:       &staticRepoProvider{repos: []string{"org/repo"}},
		VMPoolName:         "blip",
		RunnerLabels:       []string{"blip"},
		MaxSessionDuration: 0,
		PodName:            "test-pod",
	})

	p.poll(context.Background())
	p.WaitForPending()

	claimer.mu.Lock()
	require.Len(t, claimer.claimedDurations, 1)
	assert.Equal(t, int(DefaultActionsTTL.Seconds()), claimer.claimedDurations[0])
	claimer.mu.Unlock()
}

func TestPoller_ExplicitTTL(t *testing.T) {
	claimer := &mockVMClaimer{
		claimResult: &vm.ClaimResult{Name: "vm-1", PodIP: "10.0.0.1"},
	}
	tokens := &mockTokenProvider{
		token: &RegistrationToken{Token: "tok"},
	}
	jobs := &mockJobsProvider{
		jobs: map[string][]WorkflowJob{
			"org/repo": {{ID: 42, Labels: []string{"blip"}, Status: "queued"}},
		},
	}
	store := &mockConfigStore{}
	p := newTestPoller(claimer, tokens, jobs, store, []string{"org/repo"})

	p.poll(context.Background())
	p.WaitForPending()

	claimer.mu.Lock()
	require.Len(t, claimer.claimedDurations, 1)
	assert.Equal(t, 3600, claimer.claimedDurations[0])
	claimer.mu.Unlock()
}

func TestPoller_NonMatchingLabels(t *testing.T) {
	claimer := &mockVMClaimer{}
	tokens := &mockTokenProvider{}
	jobs := &mockJobsProvider{
		jobs: map[string][]WorkflowJob{
			"org/repo": {{ID: 42, Labels: []string{"ubuntu-latest"}, Status: "queued"}},
		},
	}
	store := &mockConfigStore{}
	p := newTestPoller(claimer, tokens, jobs, store, []string{"org/repo"})

	p.poll(context.Background())
	p.WaitForPending()

	claimer.mu.Lock()
	assert.Empty(t, claimer.claimedSessions)
	claimer.mu.Unlock()
	assert.Equal(t, int64(0), tokens.calls.Load())
}

func TestPoller_CaseInsensitiveLabels(t *testing.T) {
	claimer := &mockVMClaimer{
		claimResult: &vm.ClaimResult{Name: "vm-1", PodIP: "10.0.0.1"},
	}
	tokens := &mockTokenProvider{
		token: &RegistrationToken{Token: "tok"},
	}
	jobs := &mockJobsProvider{
		jobs: map[string][]WorkflowJob{
			"org/repo": {{ID: 42, Labels: []string{"BLIP"}, Status: "queued"}},
		},
	}
	store := &mockConfigStore{}
	p := newTestPoller(claimer, tokens, jobs, store, []string{"org/repo"})

	p.poll(context.Background())
	p.WaitForPending()

	claimer.mu.Lock()
	assert.Len(t, claimer.claimedSessions, 1)
	claimer.mu.Unlock()
}

func TestPoller_DuplicateIsIdempotent(t *testing.T) {
	claimer := &mockVMClaimer{
		claimResult: &vm.ClaimResult{Name: "vm-1", PodIP: "10.0.0.1"},
	}
	tokens := &mockTokenProvider{
		token: &RegistrationToken{Token: "tok"},
	}
	jobs := &mockJobsProvider{
		jobs: map[string][]WorkflowJob{
			"org/repo": {{ID: 42, Labels: []string{"blip"}, Status: "queued"}},
		},
	}
	store := &mockConfigStore{}
	p := newTestPoller(claimer, tokens, jobs, store, []string{"org/repo"})

	// First poll.
	p.poll(context.Background())
	p.WaitForPending()

	// Second poll (same job still queued).
	p.poll(context.Background())
	p.WaitForPending()

	claimer.mu.Lock()
	assert.Len(t, claimer.claimedSessions, 1)
	claimer.mu.Unlock()
	assert.Equal(t, int64(1), tokens.calls.Load())
}

func TestPoller_ClaimFailure(t *testing.T) {
	claimer := &mockVMClaimer{
		claimErr: fmt.Errorf("no VMs available"),
	}
	tokens := &mockTokenProvider{}
	jobs := &mockJobsProvider{
		jobs: map[string][]WorkflowJob{
			"org/repo": {{ID: 42, Labels: []string{"blip"}, Status: "queued"}},
		},
	}
	store := &mockConfigStore{}
	p := newTestPoller(claimer, tokens, jobs, store, []string{"org/repo"})

	p.poll(context.Background())
	p.WaitForPending()

	assert.Equal(t, int64(0), tokens.calls.Load())
	assert.Equal(t, 0, p.ActiveSessionCount())
}

func TestPoller_TokenFailure_ReleasesVM(t *testing.T) {
	claimer := &mockVMClaimer{
		claimResult: &vm.ClaimResult{Name: "vm-1", PodIP: "10.0.0.1"},
	}
	tokens := &mockTokenProvider{
		err: fmt.Errorf("GitHub API error"),
	}
	jobs := &mockJobsProvider{
		jobs: map[string][]WorkflowJob{
			"org/repo": {{ID: 42, Labels: []string{"blip"}, Status: "queued"}},
		},
	}
	store := &mockConfigStore{}
	p := newTestPoller(claimer, tokens, jobs, store, []string{"org/repo"})

	p.poll(context.Background())
	p.WaitForPending()

	claimer.mu.Lock()
	require.Len(t, claimer.releasedSessions, 1)
	assert.Equal(t, "blip-000000000000002a", claimer.releasedSessions[0])
	claimer.mu.Unlock()
	assert.Equal(t, 0, p.ActiveSessionCount())
}

func TestPoller_ConfigStoreFailure_ReleasesVM(t *testing.T) {
	claimer := &mockVMClaimer{
		claimResult: &vm.ClaimResult{Name: "vm-1", PodIP: "10.0.0.1"},
	}
	tokens := &mockTokenProvider{
		token: &RegistrationToken{Token: "tok"},
	}
	jobs := &mockJobsProvider{
		jobs: map[string][]WorkflowJob{
			"org/repo": {{ID: 42, Labels: []string{"blip"}, Status: "queued"}},
		},
	}
	store := &mockConfigStore{err: fmt.Errorf("patch failed")}
	p := newTestPoller(claimer, tokens, jobs, store, []string{"org/repo"})

	p.poll(context.Background())
	p.WaitForPending()

	claimer.mu.Lock()
	require.Len(t, claimer.releasedSessions, 1)
	assert.Equal(t, "blip-000000000000002a", claimer.releasedSessions[0])
	claimer.mu.Unlock()
	assert.Equal(t, 0, p.ActiveSessionCount())
}

func TestPoller_InvalidRepoFormat(t *testing.T) {
	claimer := &mockVMClaimer{}
	tokens := &mockTokenProvider{}
	jobs := &mockJobsProvider{}
	store := &mockConfigStore{}
	p := newTestPoller(claimer, tokens, jobs, store, []string{"../evil/../../etc/passwd"})

	p.poll(context.Background())
	p.WaitForPending()

	claimer.mu.Lock()
	assert.Empty(t, claimer.claimedSessions)
	claimer.mu.Unlock()
}

func TestPoller_Reconciliation(t *testing.T) {
	claimer := &mockVMClaimer{
		claimResult: &vm.ClaimResult{Name: "vm-1", PodIP: "10.0.0.1"},
	}
	tokens := &mockTokenProvider{
		token: &RegistrationToken{Token: "tok"},
	}
	jobs := &mockJobsProvider{
		jobs: map[string][]WorkflowJob{
			"org/repo": {{ID: 42, Labels: []string{"blip"}, Status: "queued"}},
		},
	}
	store := &mockConfigStore{}
	p := newTestPoller(claimer, tokens, jobs, store, []string{"org/repo"})

	// Poll to claim.
	p.poll(context.Background())
	p.WaitForPending()
	assert.Equal(t, 1, p.ActiveSessionCount())

	// Simulate job completing: remove it from the mock jobs list.
	jobs.mu.Lock()
	jobs.jobs["org/repo"] = nil
	jobs.mu.Unlock()

	// Next poll should reconcile and release.
	p.poll(context.Background())
	p.WaitForPending()

	claimer.mu.Lock()
	require.Len(t, claimer.releasedSessions, 1)
	assert.Equal(t, "blip-000000000000002a", claimer.releasedSessions[0])
	claimer.mu.Unlock()
	assert.Equal(t, 0, p.ActiveSessionCount())
}

func TestPoller_Reconciliation_SkipsInFlightSessions(t *testing.T) {
	// Sessions with empty sentinel (still setting up) should not be reconciled.
	claimer := &mockVMClaimer{
		claimResult: &vm.ClaimResult{Name: "vm-1", PodIP: "10.0.0.1"},
	}
	// Use a blocking token provider to keep the session in-flight.
	tokenReady := make(chan struct{})
	tokenProceed := make(chan struct{})
	tokens := &blockingTokenProvider{
		delegate:  &mockTokenProvider{token: &RegistrationToken{Token: "tok"}},
		readyCh:   tokenReady,
		proceedCh: tokenProceed,
	}
	jobs := &mockJobsProvider{
		jobs: map[string][]WorkflowJob{
			"org/repo": {{ID: 42, Labels: []string{"blip"}, Status: "queued"}},
		},
	}
	store := &mockConfigStore{}

	p := NewPoller(PollerConfig{
		VMClaimer:          claimer,
		RunnerConfigStore:  store,
		TokenProvider:      tokens,
		JobsProvider:       jobs,
		RepoProvider:       &staticRepoProvider{repos: []string{"org/repo"}},
		VMPoolName:         "blip",
		RunnerLabels:       []string{"blip"},
		MaxSessionDuration: 3600,
		PodName:            "test-pod",
	})

	// First poll: claims VM, setup goroutine blocks on token fetch.
	p.poll(context.Background())
	<-tokenReady

	// Remove the job from the queue and poll again.
	// The session has an empty sentinel, so reconciliation should skip it.
	jobs.mu.Lock()
	jobs.jobs["org/repo"] = nil
	jobs.mu.Unlock()

	p.poll(context.Background())

	// Session should still be tracked (not reconciled away).
	assert.Equal(t, 1, p.ActiveSessionCount())

	// Let setup complete.
	close(tokenProceed)
	p.WaitForPending()

	// Now a third poll should reconcile it (job still not in queue, session is fully set up).
	p.poll(context.Background())

	claimer.mu.Lock()
	// One release from reconciliation.
	assert.Len(t, claimer.releasedSessions, 1)
	claimer.mu.Unlock()
	assert.Equal(t, 0, p.ActiveSessionCount())
}

func TestPoller_NoRepos(t *testing.T) {
	claimer := &mockVMClaimer{}
	p := newTestPoller(claimer, &mockTokenProvider{}, &mockJobsProvider{}, &mockConfigStore{}, nil)

	p.poll(context.Background())
	p.WaitForPending()

	claimer.mu.Lock()
	assert.Empty(t, claimer.claimedSessions)
	claimer.mu.Unlock()
}

func TestPoller_MultipleRepos(t *testing.T) {
	claimer := &mockVMClaimer{
		claimResult: &vm.ClaimResult{Name: "vm-1", PodIP: "10.0.0.1"},
	}
	tokens := &mockTokenProvider{
		token: &RegistrationToken{Token: "tok"},
	}
	jobs := &mockJobsProvider{
		jobs: map[string][]WorkflowJob{
			"org/repo1": {{ID: 1, Labels: []string{"blip"}, Status: "queued"}},
			"org/repo2": {{ID: 2, Labels: []string{"blip"}, Status: "queued"}},
		},
	}
	store := &mockConfigStore{}
	p := newTestPoller(claimer, tokens, jobs, store, []string{"org/repo1", "org/repo2"})

	p.poll(context.Background())
	p.WaitForPending()

	claimer.mu.Lock()
	assert.Len(t, claimer.claimedSessions, 2)
	claimer.mu.Unlock()
	assert.Equal(t, 2, p.ActiveSessionCount())
}

func TestPoller_ConcurrentDuplicates(t *testing.T) {
	claimer := &mockVMClaimer{
		claimResult: &vm.ClaimResult{Name: "vm-1", PodIP: "10.0.0.1"},
	}
	tokens := &mockTokenProvider{
		token: &RegistrationToken{Token: "tok"},
	}
	jobs := &mockJobsProvider{
		jobs: map[string][]WorkflowJob{
			"org/repo": {{ID: 42, Labels: []string{"blip"}, Status: "queued"}},
		},
	}
	store := &mockConfigStore{}
	p := newTestPoller(claimer, tokens, jobs, store, []string{"org/repo"})

	// Fire 10 concurrent polls.
	var wg sync.WaitGroup
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p.poll(context.Background())
		}()
	}
	wg.Wait()
	p.WaitForPending()

	claimer.mu.Lock()
	assert.Len(t, claimer.claimedSessions, 1)
	claimer.mu.Unlock()
}

func TestPoller_RunStopsOnCancel(t *testing.T) {
	p := newTestPoller(&mockVMClaimer{}, &mockTokenProvider{}, &mockJobsProvider{}, &mockConfigStore{}, nil)
	p.cfg.PollInterval = 10 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		p.Run(ctx)
		close(done)
	}()

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run did not stop after context cancellation")
	}
}

func TestMatchesLabels(t *testing.T) {
	p := NewPoller(PollerConfig{
		RunnerLabels: []string{"self-hosted", "blip"},
		RepoProvider: &staticRepoProvider{},
	})

	assert.True(t, p.matchesLabels([]string{"self-hosted", "blip"}))
	assert.True(t, p.matchesLabels([]string{"BLIP"}))
	assert.True(t, p.matchesLabels([]string{"ubuntu-latest", "Self-Hosted"}))
	assert.False(t, p.matchesLabels([]string{"ubuntu-latest"}))
	assert.False(t, p.matchesLabels([]string{}))
	assert.False(t, p.matchesLabels(nil))
}

func TestPoller_ActiveSessionCount(t *testing.T) {
	claimer := &mockVMClaimer{
		claimResult: &vm.ClaimResult{Name: "vm-1", PodIP: "10.0.0.1"},
	}
	tokens := &mockTokenProvider{
		token: &RegistrationToken{Token: "tok"},
	}
	jobs := &mockJobsProvider{
		jobs: map[string][]WorkflowJob{
			"org/repo": {{ID: 42, Labels: []string{"blip"}, Status: "queued"}},
		},
	}
	store := &mockConfigStore{}
	p := newTestPoller(claimer, tokens, jobs, store, []string{"org/repo"})

	assert.Equal(t, 0, p.ActiveSessionCount())

	p.poll(context.Background())
	p.WaitForPending()

	assert.Equal(t, 1, p.ActiveSessionCount())
}

func TestPoller_ListJobsError(t *testing.T) {
	claimer := &mockVMClaimer{}
	tokens := &mockTokenProvider{}
	jobs := &mockJobsProvider{
		err: fmt.Errorf("API error"),
	}
	store := &mockConfigStore{}
	p := newTestPoller(claimer, tokens, jobs, store, []string{"org/repo"})

	p.poll(context.Background())
	p.WaitForPending()

	claimer.mu.Lock()
	assert.Empty(t, claimer.claimedSessions)
	claimer.mu.Unlock()
}

func TestPoller_ListJobsError_SkipsReconciliation(t *testing.T) {
	// Existing sessions must survive when ListQueuedJobs fails, because
	// the incomplete job list could cause false reconciliation.
	claimer := &mockVMClaimer{
		claimResult: &vm.ClaimResult{Name: "vm-1", PodIP: "10.0.0.1"},
	}
	tokens := &mockTokenProvider{
		token: &RegistrationToken{Token: "tok"},
	}
	jobs := &mockJobsProvider{
		jobs: map[string][]WorkflowJob{
			"org/repo": {{ID: 42, Labels: []string{"blip"}, Status: "queued"}},
		},
	}
	store := &mockConfigStore{}
	p := newTestPoller(claimer, tokens, jobs, store, []string{"org/repo"})

	// First poll: claim a VM.
	p.poll(context.Background())
	p.WaitForPending()
	assert.Equal(t, 1, p.ActiveSessionCount())

	// Make listing fail on next poll.
	jobs.mu.Lock()
	jobs.err = fmt.Errorf("transient API error")
	jobs.mu.Unlock()

	// Second poll: listing fails, reconciliation should be skipped.
	p.poll(context.Background())
	p.WaitForPending()

	// Session must still be active — not falsely reconciled.
	assert.Equal(t, 1, p.ActiveSessionCount())
	claimer.mu.Lock()
	assert.Empty(t, claimer.releasedSessions, "should not release sessions when listing fails")
	claimer.mu.Unlock()
}

// blockingTokenProvider wraps a TokenProvider, blocking on the first call
// until signalled. Used for testing races between setup and reconciliation.
type blockingTokenProvider struct {
	delegate  TokenProvider
	readyCh   chan struct{}
	proceedCh chan struct{}
	once      sync.Once
}

func (b *blockingTokenProvider) CreateRegistrationToken(ctx context.Context, ownerRepo string) (*RegistrationToken, error) {
	b.once.Do(func() {
		close(b.readyCh)
		<-b.proceedCh
	})
	return b.delegate.CreateRegistrationToken(ctx, ownerRepo)
}
