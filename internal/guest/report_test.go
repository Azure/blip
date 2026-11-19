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
