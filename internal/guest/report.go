package guest

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/Azure/blip/internal/podapi"
	"github.com/Azure/blip/internal/wire"
)

const (
	// ReportAddress is the guest loopback address of the report endpoint.
	// Workloads reach it through podapi.ReportEnv; it is never exposed outside
	// the VM.
	ReportAddress = "127.0.0.1:8002"
)

// reportInterval spaces accepted reports so two reports are never coalesced
// into one observation. It is a variable so tests can shorten it.
var reportInterval = 10 * time.Second

// reporter tracks the sequence and pacing of reports. Its lock is never held
// while taking Guest.mu.
type reporter struct {
	mu         sync.Mutex
	seq        uint64
	last       time.Time
	waiting    bool
	lastReport *wire.Report
}

// serveReport accepts one bounded report, waits its turn, and returns the
// sequence assigned to it. A report is acknowledged only after it has been
// handed to the runtime, so the workload can rely on it having been seen.
func (g *Guest) serveReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !g.running() {
		http.Error(w, "blip is not running", http.StatusConflict)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, podapi.MaxReportBytes))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			http.Error(w, "report is too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "read report", http.StatusBadRequest)
		return
	}
	if len(body) == 0 || !utf8.Valid(body) || len(trimSpace(body)) == 0 {
		http.Error(w, "report must be non-empty UTF-8 text", http.StatusBadRequest)
		return
	}
	seq, err := g.report(r, string(body))
	if err != nil {
		if errors.Is(err, errReportInFlight) {
			http.Error(w, "another report is waiting", http.StatusTooManyRequests)
			return
		}
		http.Error(w, "blip is not running", http.StatusConflict)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]uint64{"seq": seq})
}

var (
	errReportInFlight = errors.New("another report is waiting")
	errReportStopped  = errors.New("blip is not running")
)

// report accepts text, waiting until at least reportInterval has passed since
// the previous accepted report. At most one report waits at a time.
func (g *Guest) report(r *http.Request, text string) (uint64, error) {
	g.mu.Lock()
	rep := g.reporter
	g.mu.Unlock()
	if rep == nil {
		return 0, errReportStopped
	}
	rep.mu.Lock()
	if rep.waiting {
		rep.mu.Unlock()
		return 0, errReportInFlight
	}
	rep.waiting = true
	delay := reportInterval - time.Since(rep.last)
	rep.mu.Unlock()

	if delay > 0 {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-r.Context().Done():
			rep.mu.Lock()
			rep.waiting = false
			rep.mu.Unlock()
			return 0, r.Context().Err()
		case <-g.shutdownSignal():
			rep.mu.Lock()
			rep.waiting = false
			rep.mu.Unlock()
			return 0, errReportStopped
		}
	}
	if g.stopped() {
		rep.mu.Lock()
		rep.waiting = false
		rep.mu.Unlock()
		return 0, errReportStopped
	}

	rep.mu.Lock()
	rep.seq++
	seq := rep.seq
	report := &wire.Report{Seq: seq, Text: text, Time: time.Now().UTC()}
	rep.lastReport = report
	rep.last = report.Time
	rep.waiting = false
	rep.mu.Unlock()

	g.send(wire.TReport, *report)
	return seq, nil
}

// running reports whether a claim is active.
func (g *Guest) running() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.claim != nil && !g.stopping && g.exit == nil
}

// stopped reports whether a claim has ended or the guest is shutting down.
func (g *Guest) stopped() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.stopping || g.exit != nil
}

// shutdownSignal returns a channel closed when the guest starts shutting
// down. A Guest built directly in tests may not have one.
func (g *Guest) shutdownSignal() <-chan struct{} {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.shutdownCh
}

// lastReport returns the most recent accepted report, if any.
func (g *Guest) lastReport() *wire.Report {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.lastReportLocked()
}

// lastReportLocked is lastReport for callers that already hold Guest.mu.
func (g *Guest) lastReportLocked() *wire.Report {
	if g.reporter == nil {
		return nil
	}
	g.reporter.mu.Lock()
	defer g.reporter.mu.Unlock()
	return g.reporter.lastReport
}

func (g *Guest) startReporter() error {
	rep := &reporter{}
	g.mu.Lock()
	g.reporter = rep
	g.mu.Unlock()
	listener, err := net.Listen("tcp", ReportAddress)
	if err != nil {
		return err
	}
	server := &http.Server{
		Handler:           http.HandlerFunc(g.serveReport),
		ReadHeaderTimeout: 10 * time.Second,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	g.mu.Lock()
	g.reportServer = server
	g.mu.Unlock()
	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("report endpoint: %v", err)
		}
	}()
	return nil
}

// stopReporter stops accepting reports. Reports already waiting are released
// by the shutdown channel.
func (g *Guest) stopReporter() {
	g.mu.Lock()
	server := g.reportServer
	g.mu.Unlock()
	if server != nil {
		_ = server.Close()
	}
}

func trimSpace(b []byte) []byte {
	start, end := 0, len(b)
	for start < end && isSpace(b[start]) {
		start++
	}
	for end > start && isSpace(b[end-1]) {
		end--
	}
	return b[start:end]
}

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\r' || c == '\n'
}
