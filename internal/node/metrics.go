package node

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// metrics are simple counters and gauges in the Prometheus text format.
type metrics struct {
	mu         sync.Mutex
	connected  bool
	commands   map[string]int // "<type>,<ok|error>"
	cmdSeconds map[string]float64
	// Snapshot bytes written to storage replicas (summed over targets).
	snapshotBytes int64
}

func (m *metrics) snapshotWrite(n int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.snapshotBytes += n
}

func (m *metrics) setConnected(b bool) {
	m.mu.Lock()
	m.connected = b
	m.mu.Unlock()
}

func (m *metrics) command(typ string, err error, d time.Duration) {
	typ = strings.TrimPrefix(typ, "*nodepb.Command_")
	res := "ok"
	if err != nil {
		res = "error"
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.commands == nil {
		m.commands, m.cmdSeconds = map[string]int{}, map[string]float64{}
	}
	m.commands[typ+","+res]++
	m.cmdSeconds[typ] += d.Seconds()
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// writeMetrics renders all metrics.
func (n *Node) writeMetrics(ctx context.Context, w *strings.Builder) {
	slots := n.slotInfos()
	var assigned int
	for _, s := range slots {
		if s.AllocationId != "" {
			assigned++
		}
	}
	n.mu.Lock()
	allocs := len(n.allocs)
	n.mu.Unlock()
	m := &n.metrics
	m.mu.Lock()
	fmt.Fprintf(w, "# TYPE blip_node_session_connected gauge\nblip_node_session_connected %d\n", b2i(m.connected))
	fmt.Fprintf(w, "# TYPE blip_node_commands_total counter\n")
	keys := make([]string, 0, len(m.commands))
	for k := range m.commands {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		typ, res, _ := strings.Cut(k, ",")
		fmt.Fprintf(w, "blip_node_commands_total{command=%q,result=%q} %d\n", typ, res, m.commands[k])
	}
	fmt.Fprintf(w, "# TYPE blip_node_command_seconds_total counter\n")
	tk := make([]string, 0, len(m.cmdSeconds))
	for k := range m.cmdSeconds {
		tk = append(tk, k)
	}
	sort.Strings(tk)
	for _, k := range tk {
		fmt.Fprintf(w, "blip_node_command_seconds_total{command=%q} %g\n", k, m.cmdSeconds[k])
	}
	fmt.Fprintf(w, "# TYPE blip_node_snapshot_written_bytes_total counter\nblip_node_snapshot_written_bytes_total %d\n", m.snapshotBytes)
	m.mu.Unlock()
	fmt.Fprintf(w, "# TYPE blip_node_slots gauge\n")
	fmt.Fprintf(w, "blip_node_slots{state=\"configured\"} %d\n", n.cfg.NodeConfig.Slots)
	fmt.Fprintf(w, "blip_node_slots{state=\"assigned\"} %d\n", assigned)
	fmt.Fprintf(w, "# TYPE blip_node_allocations gauge\nblip_node_allocations %d\n", allocs)
	fmt.Fprintf(w, "# TYPE blip_node_outbox_messages gauge\nblip_node_outbox_messages %d\n", n.out.len())
	c := n.capacity(ctx)
	if s := c.Storage; s != nil {
		fmt.Fprintf(w, "# TYPE blip_node_pool_data_percent gauge\nblip_node_pool_data_percent{pool=\"storage\"} %g\n", s.DataPercent)
		fmt.Fprintf(w, "# TYPE blip_node_pool_metadata_percent gauge\nblip_node_pool_metadata_percent{pool=\"storage\"} %g\n", s.MetadataPercent)
		fmt.Fprintf(w, "# TYPE blip_node_lvs gauge\nblip_node_lvs %d\n", s.LvCount)
	}
	if cc := c.Compute; cc != nil {
		fmt.Fprintf(w, "# TYPE blip_node_compute_pool_data_percent gauge\nblip_node_compute_pool_data_percent %g\n", cc.DataPercent)
		fmt.Fprintf(w, "# TYPE blip_node_memory_pressure gauge\nblip_node_memory_pressure %d\n", b2i(cc.MemoryPressure))
	}
}

// Handler serves /metrics and /healthz.
func (n *Node) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		var b strings.Builder
		n.writeMetrics(r.Context(), &b)
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		_, _ = w.Write([]byte(b.String()))
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok\n"))
	})
	return mux
}

// ServeMetrics runs the metrics server on addr until ctx ends.
func (n *Node) ServeMetrics(ctx context.Context, addr string) error {
	srv := &http.Server{Addr: addr, Handler: n.Handler(), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
