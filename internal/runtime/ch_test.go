package runtime

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Azure/blip/internal/podapi"
)

func TestRemoveDiskSleepRespectsContext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if strings.HasSuffix(req.URL.Path, "/vm.info") {
			_, _ = io.WriteString(w, `{"config":{"disks":[{"id":"data"}]}}`)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	transport := srv.Client().Transport
	c := &chClient{hc: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		req.URL.Scheme = "http"
		req.URL.Host = strings.TrimPrefix(srv.URL, "http://")
		return transport.RoundTrip(req)
	})}}
	ctx, cancel := context.WithCancel(context.Background())
	c.ctx = ctx
	time.AfterFunc(20*time.Millisecond, cancel)
	start := time.Now()
	err := c.removeDisk("data", time.Minute)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("removeDisk = %v, want context cancellation", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("cancellation took %v", elapsed)
	}
}

func TestCHTruncatedResponsesRequireConfirmation(t *testing.T) {
	const attached = `{"config":{"disks":[{"id":"data","path":"/dev/data","serial":"data","readonly":false}]}}`
	for _, tc := range []struct {
		name, operation, info string
		truncateInfo          bool
		wantError             bool
	}{
		{name: "raw 2xx read error", operation: "call", wantError: true},
		{name: "committed add confirmed", operation: "add", info: attached},
		{name: "uncommitted add", operation: "add", info: `{}`, wantError: true},
		{name: "add confirmation truncated", operation: "add", info: attached, truncateInfo: true, wantError: true},
		{name: "committed remove confirmed", operation: "remove", info: `{}`},
		{name: "remove still in device tree", operation: "remove", info: `{"device_tree":{"data":{}}}`, wantError: true},
		{name: "remove confirmation truncated", operation: "remove", info: `{}`, truncateInfo: true, wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var mu sync.Mutex
			var calls []string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				path := strings.TrimPrefix(req.URL.Path, "/api/v1/")
				mu.Lock()
				calls = append(calls, path)
				mu.Unlock()
				body, truncated := `{}`, true
				if path == "vm.info" {
					body, truncated = tc.info, tc.truncateInfo
				}
				if truncated {
					// The JSON prefix is valid, but the HTTP body ends early.
					// A successful decode must not hide the transport failure.
					w.Header().Set("Content-Length", fmt.Sprint(len(body)+10))
				}
				_, _ = io.WriteString(w, body)
			}))
			defer srv.Close()
			transport := srv.Client().Transport
			c := &chClient{hc: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				req.URL.Scheme = "http"
				req.URL.Host = strings.TrimPrefix(srv.URL, "http://")
				return transport.RoundTrip(req)
			})}}
			var err error
			first := "vm.add-disk"
			switch tc.operation {
			case "call":
				_, err = c.call(http.MethodPut, first, nil)
			case "add":
				err = c.addDisk(podapi.Disk{ID: "data", Device: "/dev/data"})
			case "remove":
				first = "vm.remove-device"
				err = c.removeDisk("data", time.Second)
			}
			if (err != nil) != tc.wantError || (tc.wantError && !errors.Is(err, io.ErrUnexpectedEOF)) {
				t.Fatalf("operation error = %v, want read error = %v", err, tc.wantError)
			}
			wantCalls := []string{first}
			if tc.operation != "call" {
				wantCalls = append(wantCalls, "vm.info")
			}
			mu.Lock()
			defer mu.Unlock()
			if !reflect.DeepEqual(calls, wantCalls) {
				t.Fatalf("confirmation calls = %v, want %v", calls, wantCalls)
			}
		})
	}
}
