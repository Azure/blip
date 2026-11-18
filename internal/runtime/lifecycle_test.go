package runtime

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Azure/blip/internal/podapi"
	"github.com/Azure/blip/internal/wire"
)

func awaitWorker(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("runtime worker did not stop")
	}
}

func closeRuntime(t *testing.T, r *runtime) {
	t.Helper()
	done := make(chan struct{})
	go func() { r.close(); close(done) }()
	awaitWorker(t, done)
}

func inotifyFDs(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, entry := range entries {
		if target, _ := os.Readlink(filepath.Join("/proc/self/fd", entry.Name())); target == "anon_inode:inotify" {
			n++
		}
	}
	return n
}

func TestWatchDesiredCancellation(t *testing.T) {
	for _, mode := range []string{"idle", "blocked delivery", "watch unavailable"} {
		t.Run(mode, func(t *testing.T) {
			before := inotifyFDs(t)
			r := newRuntime(Options{Dir: t.TempDir(), SkipNetwork: true})
			ch := make(chan podapi.Desired)
			if mode == "watch unavailable" {
				r.o.Dir = filepath.Join(r.o.Dir, "absent")
			} else if err := podapi.WriteJSON(r.o.path(podapi.DesiredFile), podapi.Desired{Stop: true}); err != nil {
				t.Fatal(err)
			}
			r.start(func() { r.watchDesired(ch) })
			if mode == "idle" {
				select {
				case <-ch:
				case <-time.After(5 * time.Second):
					t.Fatal("watcher did not read initial desired")
				}
			}
			closeRuntime(t, r)
			if after := inotifyFDs(t); after != before {
				t.Fatalf("inotify descriptors leaked: %d -> %d", before, after)
			}
		})
	}
}

func TestConnectCancellation(t *testing.T) {
	for _, mode := range []string{"connect delivery", "frame delivery", "read"} {
		t.Run(mode, func(t *testing.T) {
			r := newRuntime(Options{Dir: t.TempDir()})
			if err := os.MkdirAll(filepath.Dir(r.o.path(podapi.VsockSocket)), 0o700); err != nil {
				t.Fatal(err)
			}
			l, err := net.Listen("unix", r.o.path(podapi.VsockSocket))
			if err != nil {
				t.Fatal(err)
			}
			defer l.Close()
			r.ctlEvents = make(chan ctlEvent, 1)
			if mode == "connect delivery" {
				r.ctlEvents = make(chan ctlEvent)
			}
			serverDone := make(chan struct{})
			handshake := make(chan struct{})
			go func() {
				defer close(serverDone)
				c, err := l.Accept()
				if err != nil {
					t.Error(err)
					return
				}
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				if _, err := bufio.NewReader(c).ReadString('\n'); err != nil {
					t.Error(err)
					return
				}
				if _, err := io.WriteString(c, "OK 1024\n"); err != nil {
					t.Error(err)
					return
				}
				if mode == "frame delivery" {
					if err := wire.NewConn(c).WriteJSON(wire.THello, wire.Hello{}); err != nil {
						t.Error(err)
						return
					}
				}
				close(handshake)
				var buf [1]byte
				if _, err := c.Read(buf[:]); err != io.EOF && !errors.Is(err, syscall.ECONNRESET) {
					t.Errorf("client connection not closed: %v", err)
				}
			}()
			r.start(func() { r.connect(0) })
			awaitWorker(t, handshake)
			if mode == "read" {
				select {
				case <-r.ctlEvents:
				case <-time.After(5 * time.Second):
					t.Fatal("connection not delivered")
				}
			}
			closeRuntime(t, r)
			awaitWorker(t, serverDone)
		})
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestRemovalCancellation(t *testing.T) {
	for _, mode := range []string{"result delivery", "HTTP request", "confirmation poll"} {
		t.Run(mode, func(t *testing.T) {
			r := newRuntime(Options{})
			r.removed = make(chan removeResult)
			entered := make(chan struct{})
			r.ch.hc.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
				if mode == "HTTP request" {
					select {
					case <-entered:
					default:
						close(entered)
					}
					<-req.Context().Done()
					return nil, req.Context().Err()
				}
				body := `{}`
				if strings.HasSuffix(req.URL.Path, "vm.info") {
					select {
					case <-entered:
					default:
						close(entered)
					}
					if mode == "confirmation poll" {
						body = `{"device_tree":{"data":{}}}`
					}
				}
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{}}, nil
			})
			r.execute([]Effect{{Kind: EffectRemoveDisk, Disk: podapi.Disk{ID: "data"}, Token: 1}})
			awaitWorker(t, entered)
			closeRuntime(t, r)
		})
	}
}

func TestRunBootFailureAndExitCleanup(t *testing.T) {
	before := inotifyFDs(t)
	o := Options{Dir: t.TempDir(), SkipNetwork: true, CH: "/not/a/vmm"}
	if err := Run(o); err == nil {
		t.Fatal("missing VMM should fail boot")
	}
	for _, failSecure := range []bool{false, true} {
		r := newRuntime(Options{Dir: t.TempDir(), SkipNetwork: true, CH: "/bin/true"})
		r.secureSockets = func() error {
			if failSecure {
				return errors.New("socket permission failure")
			}
			return nil
		}
		if err := r.run(); (err != nil) != failSecure {
			t.Fatalf("run: %v", err)
		}
		closeRuntime(t, r)
		select {
		case <-r.vmDone:
		default:
			t.Fatal("run returned without reaping VMM")
		}
		if r.vm.ProcessState == nil || r.Observed().Phase != podapi.PhaseExited {
			t.Fatal("VMM exit was not recorded")
		}
	}
	if after := inotifyFDs(t); after != before {
		t.Fatalf("Run leaked inotify descriptors: %d -> %d", before, after)
	}
}

func TestExecuteDiscardsEffectsAfterKill(t *testing.T) {
	r := newRuntime(Options{})
	defer r.close()
	called := false
	r.ch.hc.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		called = true
		return nil, context.Canceled
	})
	// Reconcile can return a pending policy followed by Kill on stop timeout.
	effects := []Effect{{Kind: EffectAddDisk, Disk: podapi.Disk{ID: "data"}}}
	effects = append(effects, r.kill()...)
	r.execute(effects)
	if called {
		t.Fatal("executed host operation after kill decision")
	}
}

func TestRuntimeElapsedClockPreservesDeadlines(t *testing.T) {
	r := newRuntime(Options{})
	defer r.close()
	epoch := r.clockEpoch
	wall := epoch.Round(0)
	var correction time.Duration
	// Model time.Since: elapsed time excludes wall-clock corrections even
	// though the wall reading itself can move backward or jump forward.
	r.elapsed = func(start time.Time) time.Duration {
		if start != epoch {
			t.Fatal("elapsed clock epoch changed")
		}
		return wall.Sub(start) - correction
	}
	advance := func(elapsed, shift time.Duration) {
		wall = wall.Add(elapsed + shift)
		correction += shift
	}
	n := &fakePolicyNetwork{err: errors.New("retry policy")}
	r.network = n
	r.reconcile()
	if n.calls != 1 || !r.networkRetryAt.Equal(epoch.Add(retryInterval)) {
		t.Fatalf("initial retry deadline: calls=%d retry=%v", n.calls, r.networkRetryAt)
	}
	if r.networkRetryAt != r.networkRetryAt.Round(0).UTC() {
		t.Fatal("machine retained noncanonical clock metadata")
	}
	advance(retryInterval-time.Nanosecond, -time.Hour)
	r.reconcile()
	if n.calls != 1 {
		t.Fatal("wall-clock correction changed the retry deadline")
	}
	advance(time.Nanosecond, 2*time.Hour)
	r.reconcile()
	if n.calls != 2 {
		t.Fatal("elapsed retry deadline was missed")
	}

	r.o.SkipNetwork = true
	r.execute(r.Apply(r.now(), Event{Kind: EventStop}))
	r.reconcile()
	if !r.stopSince.Equal(epoch.Add(retryInterval)) {
		t.Fatalf("stop started at wall time rather than elapsed time: %v", r.stopSince)
	}
	advance(stopTimeout-time.Nanosecond, -24*time.Hour)
	r.reconcile()
	if r.killSent {
		t.Fatal("stop timed out before its elapsed deadline")
	}
	advance(2*time.Nanosecond, 48*time.Hour)
	r.reconcile()
	if !r.killSent {
		t.Fatal("stop failed to time out after its elapsed deadline")
	}
}
