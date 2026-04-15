// Package v1alpha1 defines the BlipOwner custom resource API types.
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var (
	// GroupVersion is the API group and version for BlipOwner.
	GroupVersion = schema.GroupVersion{Group: "blip.io", Version: "v1alpha1"}

	// SchemeBuilder is used to add types to the scheme.
	SchemeBuilder = runtime.NewSchemeBuilder(addKnownTypes)

	// AddToScheme adds the types in this group-version to the given scheme.
	AddToScheme = SchemeBuilder.AddToScheme
)

func addKnownTypes(scheme *runtime.Scheme) error {
	scheme.AddKnownTypes(GroupVersion,
		&BlipOwner{},
		&BlipOwnerList{},
	)
	metav1.AddToGroupVersion(scheme, GroupVersion)
	return nil
}

// Resource takes an unqualified resource and returns a Group qualified GroupResource.
func Resource(resource string) schema.GroupResource {
	return GroupVersion.WithResource(resource).GroupResource()
}
