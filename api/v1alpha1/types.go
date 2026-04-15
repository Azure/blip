package v1alpha1

//go:generate controller-gen object paths=. output:dir=.
//go:generate controller-gen crd paths=. output:crd:dir=../../config/crd

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// BlipOwner represents a single authorization entry for the Blip SSH gateway.
// Each CR encodes exactly one of: an SSH public key, an OIDC provider
// configuration, or a GitHub Actions runner repo association.
//
// Exactly one of spec.sshKey, spec.oidc, or spec.actionsRepo must be set.
// This constraint is enforced by CEL validation rules on the CRD schema.
//
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=bo
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type BlipOwner struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   BlipOwnerSpec   `json:"spec"`
	Status BlipOwnerStatus `json:"status,omitempty"`
}

// BlipOwnerSpec defines the desired state of a BlipOwner.
// Exactly one of SSHKey, OIDC, or ActionsRepo must be set.
//
// +kubebuilder:validation:XValidation:rule="(has(self.sshKey) ? 1 : 0) + (has(self.oidc) ? 1 : 0) + (has(self.actionsRepo) ? 1 : 0) == 1",message="exactly one of sshKey, oidc, or actionsRepo must be set"
type BlipOwnerSpec struct {
	// SSHKey configures an explicitly allowed SSH public key.
	// +optional
	SSHKey *SSHKeySpec `json:"sshKey,omitempty"`

	// OIDC configures an OIDC provider for token-based authentication.
	// +optional
	OIDC *OIDCSpec `json:"oidc,omitempty"`

	// ActionsRepo associates a GitHub repository for Actions runner polling.
	// +optional
	ActionsRepo *ActionsRepoSpec `json:"actionsRepo,omitempty"`
}

// SSHKeySpec holds an SSH public key in authorized_keys format.
type SSHKeySpec struct {
	// PublicKey is the SSH public key in authorized_keys format
	// (e.g. "ssh-ed25519 AAAAC3... alice@laptop").
	// +kubebuilder:validation:MinLength=1
	PublicKey string `json:"publicKey"`
}

// OIDCSpec configures a single OIDC provider for token verification.
//
// +kubebuilder:validation:XValidation:rule="self.issuer.startsWith('https://')",message="issuer must start with https://"
// +kubebuilder:validation:XValidation:rule="!self.deviceFlow || (self.clientID != '' && self.deviceAuthURL != '' && self.tokenURL != '')",message="clientID, deviceAuthURL, and tokenURL are required when deviceFlow is true"
// +kubebuilder:validation:XValidation:rule="!has(self.deviceAuthURL) || self.deviceAuthURL == '' || self.deviceAuthURL.startsWith('https://')",message="deviceAuthURL must start with https://"
// +kubebuilder:validation:XValidation:rule="!has(self.tokenURL) || self.tokenURL == '' || self.tokenURL.startsWith('https://')",message="tokenURL must start with https://"
type OIDCSpec struct {
	// Issuer is the OIDC issuer URL (must be HTTPS).
	// +kubebuilder:validation:MinLength=1
	Issuer string `json:"issuer"`

	// Audience is the expected "aud" claim.
	// +kubebuilder:validation:MinLength=1
	Audience string `json:"audience"`

	// IdentityClaim is the JWT claim used as the user identity.
	// Defaults to "sub" if empty.
	// +optional
	IdentityClaim string `json:"identityClaim,omitempty"`

	// AllowedSubjects is a list of allowed subject patterns.
	// Supports glob patterns (e.g. "repo:my-org/*:*").
	// When empty, any valid token from this issuer is accepted.
	// +optional
	AllowedSubjects []string `json:"allowedSubjects,omitempty"`

	// DeviceFlow enables the OAuth2 Device Authorization Grant (RFC 8628).
	// +optional
	DeviceFlow bool `json:"deviceFlow,omitempty"`

	// ClientID is the OAuth2 client ID for device flow.
	// Required when deviceFlow is true.
	// +optional
	ClientID string `json:"clientID,omitempty"`

	// DeviceAuthURL is the OAuth2 device authorization endpoint (must be HTTPS).
	// Required when deviceFlow is true.
	// +optional
	DeviceAuthURL string `json:"deviceAuthURL,omitempty"`

	// TokenURL is the OAuth2 token endpoint for polling device flow completion (must be HTTPS).
	// Required when deviceFlow is true.
	// +optional
	TokenURL string `json:"tokenURL,omitempty"`

	// Scopes is the list of OAuth2 scopes to request during device flow.
	// +optional
	Scopes []string `json:"scopes,omitempty"`
}

// ActionsRepoSpec associates a GitHub repository for Actions runner polling.
//
// +kubebuilder:validation:XValidation:rule="self.repo.matches('^[a-zA-Z0-9._-]+/[a-zA-Z0-9._-]+$')",message="repo must be in 'owner/repo' format"
type ActionsRepoSpec struct {
	// Repo is the full "owner/repo" identifier (e.g. "my-org/my-repo").
	// +kubebuilder:validation:MinLength=1
	Repo string `json:"repo"`
}

// BlipOwnerStatus describes the observed state of a BlipOwner.
type BlipOwnerStatus struct {
	// Conditions represent the latest available observations of the
	// BlipOwner's state.
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// Fingerprint is the computed SHA256 fingerprint for SSHKey entries.
	// Empty for non-SSHKey types.
	// +optional
	Fingerprint string `json:"fingerprint,omitempty"`
}

// BlipOwnerList contains a list of BlipOwner resources.
//
// +kubebuilder:object:root=true
type BlipOwnerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []BlipOwner `json:"items"`
}
