package cli

import (
	"fmt"

	"k8s.io/apimachinery/pkg/api/resource"

	"github.com/Azure/blip/api/v1alpha1"
)

// parseSizeFlag validates --size before a state is created. Quantity.Value
// saturates at math.MaxInt64 for larger inputs, and the node rounds the value
// up to a device-mapper block; a saturated value overflows that rounding and
// reaches dmsetup as a bogus (formerly negative) length. Reject values that
// cannot be provisioned instead of silently clamping them.
func parseSizeFlag(value string) (*resource.Quantity, error) {
	size, err := resource.ParseQuantity(value)
	if err != nil {
		return nil, fmt.Errorf("invalid --size %q: %w", value, err)
	}
	if size.Sign() <= 0 {
		return nil, fmt.Errorf("invalid --size %q: must be positive", value)
	}
	if size.CmpInt64(v1alpha1.MaxStateSizeBytes) > 0 {
		max := resource.NewQuantity(v1alpha1.MaxStateSizeBytes, resource.BinarySI)
		return nil, fmt.Errorf("invalid --size %q: too large (maximum %s)", value, max.String())
	}
	return &size, nil
}
