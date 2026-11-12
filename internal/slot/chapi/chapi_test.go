package chapi

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"path/filepath"
	"testing"
)

func TestAddDiskAndInfo(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "ch.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	var got DiskConfig
	mux := http.NewServeMux()
	mux.HandleFunc("PUT /api/v1/vm.add-disk", func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&got)
		w.Write([]byte(`{"id":"blip-0123456789abcdef","bdf":"0000:00:06.0"}`))
	})
	var removed map[string]string
	mux.HandleFunc("PUT /api/v1/vm.remove-device", func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&removed)
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /api/v1/vm.info", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"state":"Running","memory_actual_size":1024,"config":{"disks":[{"path":"/run/blip/volumes/u1","id":"blip-0123456789abcdef","serial":"0123456789abcdef","readonly":false,"direct":true}]}}`))
	})
	mux.HandleFunc("PUT /api/v1/vm.shutdown", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not running", http.StatusInternalServerError)
	})
	srv := &http.Server{Handler: mux}
	go srv.Serve(l)
	defer srv.Close()

	c := New(sock)
	ctx := context.Background()
	info, err := c.AddDisk(ctx, VolumeDisk("/run/blip/volumes/u1", "0123456789abcdef", "data"))
	if err != nil || info.BDF != "0000:00:06.0" {
		t.Fatalf("add disk: %+v %v", info, err)
	}
	if got.Path != "/run/blip/volumes/u1" || !got.Direct || got.ReadOnly || got.Serial != "data" ||
		got.ID != "blip-0123456789abcdef" || got.ImageType != "Raw" || got.Sparse == nil || *got.Sparse {
		t.Fatalf("sent %+v", got)
	}
	if has, err := c.HasDisk(ctx, VolumeDiskID("0123456789abcdef")); err != nil || !has {
		t.Fatal("has disk", has, err)
	}
	if has, _ := c.HasDisk(ctx, "blip-other"); has {
		t.Fatal("unknown disk found")
	}
	if err := c.RemoveDevice(ctx, "blip-0123456789abcdef"); err != nil || removed["id"] != "blip-0123456789abcdef" {
		t.Fatal("remove", removed, err)
	}
	vi, err := c.Info(ctx)
	if err != nil || vi.State != "Running" {
		t.Fatalf("info: %+v %v", vi, err)
	}
	var ae *APIError
	if err := c.Shutdown(ctx); err == nil || !asAPIError(err, &ae) || ae.Status != 500 {
		t.Fatalf("shutdown: %v", err)
	}
}

func asAPIError(err error, target **APIError) bool {
	e, ok := err.(*APIError)
	if ok {
		*target = e
	}
	return ok
}
