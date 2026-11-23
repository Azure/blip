// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package v1alpha1

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// Labels, annotations, and the finalizer shared by every component. Everything
// the controller, node agent, and CLI agree on lives here so a rename
// cannot drift between packages.
const (
	LabelPool             = "blip.dev/pool"
	LabelBlipUID          = "blip.dev/blip-uid"
	LabelWarm             = "blip.dev/warm"
	LabelEnrolled         = "blip.dev/enrolled"
	LabelHypervisorPrefix = "blip.dev/hypervisor-"
	LabelOwner            = "blip.dev/owner"
	// LabelShared marks an ownerless state that every blip in the namespace
	// may read or copy, like an imported image. A pre-populated git cache is
	// published this way so consumers can fork it instead of fetching history.
	LabelShared = "blip.dev/shared"
	// LabelParent scopes "blip gather" with no arguments to the forks of the
	// blip it runs in. Label values are limited to 63 characters, so a long
	// short name is hashed under a prefix that cannot be a legal Blip name;
	// AnnotationParent keeps the full name.
	LabelParent = "blip.dev/parent"

	// LabelBuild is the build recipe's name on every output state and build
	// Blip.
	LabelBuild = "blip.dev/build"
	// AnnotationBuildStatus is "running", "succeeded", or "failed" on an
	// output state.
	AnnotationBuildStatus = "blip.dev/build-status"

	// Chat sessions are BlipStates owned by one blipchat conversation. The
	// admission policies use these fields to scope chat agents to their own
	// tree and to authorize child profiles.
	LabelChatSession            = "chat.blip.dev/session"
	AnnotationChatProfile       = "chat.blip.dev/profile"
	AnnotationChatParent        = "chat.blip.dev/parent"
	AnnotationChatParentProfile = "chat.blip.dev/parent-profile"
	AnnotationChatRoot          = "chat.blip.dev/root"
	AnnotationChatDepth         = "chat.blip.dev/depth"
	AnnotationChatParentDepth   = "chat.blip.dev/parent-depth"

	// AnnotationParent is the full short name of the blip a fork was started
	// from, including names too long for LabelParent's hash.
	AnnotationParent          = "blip.dev/parent-name"
	AnnotationBlip            = "blip.dev/blip"
	AnnotationObserved        = "blip.dev/observed"
	AnnotationPrepareError    = "blip.dev/prepare-error"
	AnnotationForceRecover    = "blip.dev/force-recover-writer"
	AnnotationCollectMounts   = "blip.dev/collect-mounts"
	AnnotationTemplateHash    = "blip.dev/template-hash"
	AnnotationEnrollmentDrain = "blip.dev/enrollment-drain"
	AnnotationPinnedNode      = "blip.dev/pinned-node"
	// AnnotationRelocated marks a warm pod the pool created by moving a spare
	// to a hot node. Relocation cannot see free capacity, so a rejection of
	// such a pod backs the node off for longer than a rejected demand pod.
	AnnotationRelocated = "blip.dev/relocated"
	// AnnotationStopReason records why the controller set spec.stop, for the
	// client to report when it gathers the blip.
	AnnotationStopReason = "blip.dev/stop-reason"

	Finalizer = "blip.dev/finalizer"
)

// Git cache fields. A warm job publishes each refreshed clone as an ownerless
// shared state labelled LabelGitRepo, so consumers select the newest one and
// fork its filesystem instead of fetching history from the remote.
const (
	LabelGitRepo        = "git.blip.dev/repo"
	AnnotationGitURL    = "git.blip.dev/url"
	AnnotationGitBranch = "git.blip.dev/branch"
)

// parentLabelHash is the reserved prefix of a hashed ParentLabel. An
// underscore is legal in a Kubernetes label value but not in a DNS-1123 Blip
// name, so a hashed label can never equal a literal parent name. Without that
// separation, a short parent named exactly another parent's 63-character hash
// shared its blip.dev/parent label and a bare gather could delete the other
// parent's forks.
const parentLabelHash = "parent_"

// ParentLabel is the LabelParent value for a fork's short parent name.
// Kubernetes label values are at most 63 characters: names that fit are used
// as-is so existing selectors keep working, and longer names become a stable
// 63-character hash under the reserved parent_ prefix. AnnotationParent always
// carries the full name.
func ParentLabel(name string) string {
	if len(name) <= 63 {
		return name
	}
	sum := sha256.Sum256([]byte(name))
	return parentLabelHash + hex.EncodeToString(sum[:])[:56]
}

// OwnerPrefix is the prefix of every object name scoped to owner.
func OwnerPrefix(owner string) string { return owner + "." }

// OwnedBy reports whether name is scoped to owner.
func OwnedBy(name, owner string) bool { return strings.HasPrefix(name, OwnerPrefix(owner)) }

// Shared reports whether st is shared with every blip in its namespace: an
// imported image template or an ownerless state labelled LabelShared. An owned
// state is never shared, so an owner cannot publish its own data.
func Shared(st *BlipState) bool {
	if st.Labels[LabelOwner] != "" {
		return false
	}
	return st.Spec.Image != "" || st.Labels[LabelShared] == "true"
}

// Finished reports whether a blip has stopped and will not run again.
func Finished(b *Blip) bool {
	return b.Status.Phase == BlipSucceeded || b.Status.Phase == BlipFailed
}

// DesiredMounts returns the root state mounts this blip should have: unclaimed
// mounts and mounts already claimed by this blip.
func DesiredMounts(root *BlipState, b *Blip) []Mount {
	var mounts []Mount
	for _, m := range root.Spec.Mounts {
		if m.BlipUID == "" || m.BlipUID == string(b.UID) {
			mounts = append(mounts, m)
		}
	}
	return mounts
}

// CollectMountUse is one entry in AnnotationCollectMounts: the blip that holds
// a collected mount and the path it was collected into.
type CollectMountUse struct {
	BlipUID string `json:"blipUID"`
	Path    string `json:"path"`
}
