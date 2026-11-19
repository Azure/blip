package blipchat

import (
	"net/http"
	"testing"
)

func TestChatServerHasBoundedTimeouts(t *testing.T) {
	srv := newChatServer(":0", http.NewServeMux())
	if srv.ReadHeaderTimeout <= 0 {
		t.Error("ReadHeaderTimeout is not set")
	}
	if srv.ReadTimeout <= 0 {
		t.Error("ReadTimeout is not set")
	}
	if srv.WriteTimeout <= 0 {
		t.Error("WriteTimeout is not set")
	}
	if srv.IdleTimeout <= 0 {
		t.Error("IdleTimeout is not set")
	}
	if srv.MaxHeaderBytes <= 0 || srv.MaxHeaderBytes > 1<<20 {
		t.Errorf("MaxHeaderBytes = %d, want a small positive bound", srv.MaxHeaderBytes)
	}
}
