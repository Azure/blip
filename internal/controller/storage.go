package controller

import (
	"context"
	"sort"

	"time"

	"google.golang.org/protobuf/types/known/timestamppb"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/example/blip/internal/api"
	v1 "github.com/example/blip/internal/api/v1alpha1"
	"github.com/example/blip/internal/proto/nodepb"
)

func (c *Controller) storageConfig(ctx context.Context) (*api.StorageConfig, error) {
	var cm corev1.ConfigMap
	if err := c.Get(ctx, types.NamespacedName{Namespace: c.opts.Namespace, Name: api.StorageConfigMap}, &cm); err != nil {
		return nil, err
	}
	return api.ParseStorageConfigMap(cm.Data)
}

// groupFullness is the highest fullness of any member with a known capacity.
func (c *Controller) groupFullness(g *api.StorageGroup) float64 {
	f := 0.0
	for _, n := range g.Nodes {
		info := c.nodes.Info(n)
		if info.Capacity != nil {
			if x := storageFullness(info.Capacity.Storage); x > f {
				f = x
			}
		}
	}
	return f
}

// connectedMembers returns the connected members of a group, sorted.
func (c *Controller) connectedMembers(g *api.StorageGroup) []string {
	var out []string
	for _, n := range g.Nodes {
		if c.nodes.Connected(n) {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

// leastFullGroup returns the least full group below the placement threshold
// with at least 2 connected members, skipping exclude.
func (c *Controller) leastFullGroup(cfg *api.StorageConfig, exclude string) *api.StorageGroup {
	var best *api.StorageGroup
	bestF := 0.0
	for i := range cfg.Groups {
		g := &cfg.Groups[i]
		if g.Name == exclude || len(c.connectedMembers(g)) < 2 {
			continue
		}
		f := c.groupFullness(g)
		if f >= c.opts.PlacementThreshold {
			continue
		}
		if best == nil || f < bestF {
			best, bestF = g, f
		}
	}
	return best
}

// hostPSK returns the PSK of a node's host NQN.
func (c *Controller) hostPSK(node string) (string, []byte) {
	nqn := api.HostNQN(node)
	return nqn, PSK(c.nodes.clusterKey, nqn)
}

func (c *Controller) exportCmd(content string, mode nodepb.ExportMode, host, allocID string, repairSealed bool) *nodepb.Command {
	nqn, psk := c.hostPSK(host)
	return &nodepb.Command{Op: &nodepb.Command_Export{Export: &nodepb.Export{
		ContentId: content, Mode: mode, HostNode: host, HostNqn: nqn, HostPsk: psk, AllocationId: allocID, RepairSealed: repairSealed,
	}}}
}

func unexportCmd(content, hostNQN string) *nodepb.Command {
	return &nodepb.Command{Op: &nodepb.Command_Unexport{Unexport: &nodepb.Unexport{ContentId: content, HostNqn: hostNQN}}}
}

func sealCmd(content string, owner *nodepb.ObjectRef) *nodepb.Command {
	return &nodepb.Command{Op: &nodepb.Command_Seal{Seal: &nodepb.Seal{ContentId: content, Blipvol: owner}}}
}

func deleteContentCmd(ids ...string) *nodepb.Command {
	return &nodepb.Command{Op: &nodepb.Command_DeleteContent{DeleteContent: &nodepb.DeleteContent{ContentIds: ids}}}
}

func ok(r *nodepb.CommandResult) bool {
	return r != nil && r.Status == nodepb.ResultStatus_RESULT_STATUS_OK
}

// sizeBytes returns the volume size from status, or the default.
func sizeBytes(bv *v1.BlipVol) int64 {
	if bv.Status.Size != nil {
		return bv.Status.Size.Value()
	}
	if bv.Spec.Size != nil {
		return bv.Spec.Size.Value()
	}
	return api.DefaultSizeBytes
}

func tsProto(t time.Time) *timestamppb.Timestamp { return timestamppb.New(t) }
