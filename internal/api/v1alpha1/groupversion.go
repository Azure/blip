// Package v1alpha1 holds the Blip, BlipVol and BlipPool API types.
// +kubebuilder:object:generate=true
// +groupName=blip.example.com
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// GroupVersion is the API group and version of the Blip types.
var GroupVersion = schema.GroupVersion{Group: "blip.example.com", Version: "v1alpha1"}

var (
	// SchemeBuilder registers the types with a scheme.
	SchemeBuilder = runtime.NewSchemeBuilder(addKnownTypes)
	// AddToScheme adds the types to a scheme.
	AddToScheme = SchemeBuilder.AddToScheme
)

func addKnownTypes(s *runtime.Scheme) error {
	s.AddKnownTypes(GroupVersion, &Blip{}, &BlipList{}, &BlipVol{}, &BlipVolList{}, &BlipPool{}, &BlipPoolList{})
	metav1.AddToGroupVersion(s, GroupVersion)
	return nil
}
