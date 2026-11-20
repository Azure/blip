// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Package network compiles IPv4 egress policies into the runtime's wire form.
package network

import (
	"github.com/Azure/blip/internal/netpolicy"
)

// Policy and Rule are defined in netpolicy so packages that only describe
// rules (notably the VM runtime) need not import Kubernetes API types.
type (
	Policy = netpolicy.Policy
	Rule   = netpolicy.Rule
)
