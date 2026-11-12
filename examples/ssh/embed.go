// Package ssh embeds the RBAC manifests of this example. They are the
// canonical copies: `kubectl blip setup` applies them.
package ssh

import _ "embed"

// RBAC is rbac.yaml: the blip-ssh ServiceAccount, Role and RoleBinding.
//
//go:embed rbac.yaml
var RBAC []byte

// NestedRBAC is nested-rbac.yaml: the blip-ssh-nested Role and RoleBinding.
//
//go:embed nested-rbac.yaml
var NestedRBAC []byte
