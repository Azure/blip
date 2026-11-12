package controller

import (
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

// Metrics listed in docs/controller.md (Metrics). They are served by the controller-runtime
// metrics server on --metrics-addr.
var (
	metricSlots = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "blip_slots", Help: "Slot pods per SKU and state (free, assigned).",
	}, []string{"sku", "state"})
	metricPoolSlots = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "blip_pool_slots", Help: "Slot pods per BlipPool and state (free, booting, assigned).",
	}, []string{"namespace", "pool", "state"})
	metricPoolDesiredFree = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "blip_pool_desired_free", Help: "Free slot target per BlipPool.",
	}, []string{"namespace", "pool"})
	metricPending = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "blip_pending_blips", Help: "Pending blips per reason.",
	}, []string{"reason"})
	metricQuotaUsed = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "blip_quota_used", Help: "Running blips per namespace and SKU.",
	}, []string{"namespace", "sku"})
	metricBootLatency = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name: "blip_claim_to_started_seconds", Help: "Time from slot claim to command start.",
		Buckets: prometheus.ExponentialBuckets(0.25, 2, 12),
	})
	metricStartLatency = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name: "blip_create_to_started_seconds", Help: "Time from Blip creation to command start.",
		Buckets: prometheus.ExponentialBuckets(0.25, 2, 14),
	})
	metricSnapshotLatency = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name: "blip_snapshot_seconds", Help: "Time from capture to a Ready snapshot; kind is the snapshot reason (shutdown, interval, derive, reschedule).",
		Buckets: prometheus.ExponentialBuckets(0.25, 2, 14),
	}, []string{"kind"})
	metricSnapshots = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "blip_snapshots_total", Help: "Snapshots by kind (reason: initial, shutdown, interval, derive, reschedule) and result (ready, failed, unavailable, deleted).",
	}, []string{"kind", "result"})
	metricSnapshotWrittenBytes = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "blip_snapshot_written_bytes_total", Help: "Bytes of captured snapshots written to storage replicas (summed over replicas).",
	})
	metricAttachments = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "blip_attachments", Help: "BlipVols with a claim (attached or being attached or released).",
	})
	metricHolds = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "blip_holds", Help: "BlipVol holds per kind.",
	}, []string{"kind"})
	metricPoolUsage = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "blip_storage_pool_percent", Help: "Thin pool usage per storage node (data, metadata, lvs).",
	}, []string{"node", "kind"})
	metricReplicaMissing = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "blip_replicas_missing", Help: "Content replicas that are missing or unsealed (repair backlog).",
	})
	metricScrubMismatch = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "blip_scrub_mismatches_total", Help: "Chunks that differed between replicas.",
	})
	metricRepairs = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "blip_repairs_total", Help: "Replica repairs by result.",
	}, []string{"result"})
	metricOrphans = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "blip_orphan_lvs", Help: "Unexpected LVs found in the last pass per node.",
	}, []string{"node"})
	metricReschedules = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "blip_reschedules_total", Help: "Failed attempts given a new attempt (spec.reschedule).",
	})
	metricNodesConnected = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "blip_nodes_connected", Help: "Nodes with a session.",
	})
)

func init() {
	metrics.Registry.MustRegister(metricSlots, metricPoolSlots, metricPoolDesiredFree, metricPending, metricQuotaUsed, metricBootLatency,
		metricStartLatency, metricSnapshotLatency, metricSnapshots, metricSnapshotWrittenBytes, metricAttachments,
		metricHolds, metricPoolUsage, metricReplicaMissing, metricScrubMismatch, metricRepairs, metricOrphans,
		metricNodesConnected, metricReschedules)
}
