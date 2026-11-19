package guest

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Azure/blip/internal/podapi"
	"github.com/Azure/blip/internal/wire"
)

func reportGuest(t *testing.T) *Guest {
	t.Helper()
	old := reportInterval
	reportInterval = 0
	t.Cleanup(func() { reportInterval = old })
	g := newGuest(t.TempDir(), t.TempDir())
	g.claim = &wire.Claim{ID: "root"}
	g.reporter = &reporter{}
	return g
}

func postReport(g *Guest, body string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	g.serveReport(rec, httptest.NewRequest("POST", "/report", strings.NewReader(body)))
	return rec
}

func TestReportSequenceAndStatus(t *testing.T) {
	g := reportGuest(t)
	if rec := postReport(g, "building"); rec.Code != 200 || strings.TrimSpace(rec.Body.String()) != `{"seq":1}` {
		t.Fatalf("first report: %d %q", rec.Code, rec.Body)
	}
	if rec := postReport(g, "testing"); rec.Code != 200 || strings.TrimSpace(rec.Body.String()) != `{"seq":2}` {
		t.Fatalf("second report: %d %q", rec.Code, rec.Body)
	}
	if got := g.lastReport(); got == nil || got.Seq != 2 || got.Text != "testing" {
		t.Fatalf("last report %+v", got)
	}

	if rec := postReport(g, strings.Repeat("x", podapi.MaxReportBytes+1)); rec.Code != 413 {
		t.Errorf("oversized report: %d", rec.Code)
	}
	if rec := postReport(g, " \n\t"); rec.Code != 400 {
		t.Errorf("blank report: %d", rec.Code)
	}

	g.reporter.waiting = true
	if rec := postReport(g, "queued"); rec.Code != 429 {
		t.Errorf("concurrent report: %d", rec.Code)
	}
	g.reporter.waiting = false

	g.mu.Lock()
	g.exit = &wire.Exit{}
	g.mu.Unlock()
	if rec := postReport(g, "late"); rec.Code != 409 {
		t.Errorf("report after exit: %d", rec.Code)
	}
}

func TestReportPacing(t *testing.T) {
	g := reportGuest(t)
	reportInterval = 80 * time.Millisecond
	postReport(g, "one")
	start := time.Now()
	postReport(g, "two")
	if elapsed := time.Since(start); elapsed < 60*time.Millisecond {
		t.Fatalf("second report was not paced: %v", elapsed)
	}
}

// Pacing must be measured with the monotonic clock. An anchor stored as
// time.Now().UTC() loses its monotonic reading, so a guest wall-clock step
// (for example clock_settime from a root workload) changes the delay, accepts
// reports back-to-back, and their sequence numbers are overwritten before the
// observation write can see them.
func TestReportPacingAnchorUsesMonotonicClock(t *testing.T) {
	g := reportGuest(t)
	reportInterval = 10 * time.Second
	postReport(g, "one")

	g.reporter.mu.Lock()
	last := g.reporter.last
	report := g.reporter.lastReport
	g.reporter.mu.Unlock()
	if last.IsZero() {
		t.Fatal("pacing anchor was not recorded")
	}
	if last.Round(0) == last {
		t.Fatalf("pacing anchor %v carries no monotonic reading; a wall-clock step would bypass pacing", last)
	}
	if report == nil || !report.Time.Equal(last) {
		t.Fatalf("wire report time %v does not match pacing anchor %v", report, last)
	}
}

// A report posted to a path other than /report is not the documented endpoint:
// it must be rejected without consuming a sequence number.
func TestReportEndpointRejectsOtherPaths(t *testing.T) {
	g := reportGuest(t)
	for _, path := range []string{"/", "/other", "/report/extra", "/REPORT", "/report/"} {
		rec := httptest.NewRecorder()
		g.serveReport(rec, httptest.NewRequest("POST", path, strings.NewReader("x")))
		if rec.Code != http.StatusNotFound {
			t.Errorf("POST %s = %d, want 404", path, rec.Code)
		}
	}
	if got := g.lastReport(); got != nil {
		t.Fatalf("report accepted on a non-/report path: %+v", got)
	}
	if rec := postReport(g, "real"); rec.Code != 200 || strings.TrimSpace(rec.Body.String()) != `{"seq":1}` {
		t.Fatalf("report after rejected paths: %d %q", rec.Code, rec.Body)
	}
}

// Wrong methods and bodies on the documented path keep their status codes.
func TestReportEndpointStatusOnReportPath(t *testing.T) {
	g := reportGuest(t)
	rec := httptest.NewRecorder()
	g.serveReport(rec, httptest.NewRequest("GET", "/report", nil))
	if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != "POST" {
		t.Errorf("GET /report = %d allow %q, want 405 POST", rec.Code, rec.Header().Get("Allow"))
	}
	rec = httptest.NewRecorder()
	g.serveReport(rec, httptest.NewRequest("POST", "/report?x=1", strings.NewReader("ok")))
	if rec.Code != 200 {
		t.Errorf("POST /report?x=1 = %d, want 200", rec.Code)
	}
	if rec := postReport(g, ""); rec.Code != 400 {
		t.Errorf("empty body = %d, want 400", rec.Code)
	}
	if rec := postReport(g, strings.Repeat("x", podapi.MaxReportBytes+1)); rec.Code != 413 {
		t.Errorf("oversized body = %d, want 413", rec.Code)
	}
}

// The report endpoint binds its configured address; tests use port 0 and
// connect to whatever the listener reports.
func TestReportEndpointServes(t *testing.T) {
	g := reportGuest(t)
	addr, err := g.startReportServer("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer g.stopReporter()
	resp, err := http.Post("http://"+addr.String()+"/report", "text/plain", strings.NewReader("building"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK || strings.TrimSpace(string(body)) != `{"seq":1}` {
		t.Fatalf("report endpoint = %d %q", resp.StatusCode, body)
	}
}
