/*
Copyright 2023.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// PolicyPublicKeySpec defines the desired state of PolicyPublicKey.
type PolicyPublicKeySpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// A base64 encoded public key used to verify Witness Policies.
	PublicKey []byte `json:"public_key"`
}

type PublickeyState string

const (
	// AppliedPublickey means that the public key has been created and will be enforced.
	AppliedPublickey PublickeyState = "Applied"

	// FailedPublickey means that there was an issue applying the public key.
	FailedPublickey PublickeyState = "Failed"

	// PendingPolicy means that the public key was created but is not yet applied.
	PendingPublickey PublickeyState = "Pending"
)

// PolicyPublicKeyStatus defines the observed state of PolicyPublicKey.
type PolicyPublicKeyStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file
	State PublickeyState `json:"state"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// PolicyPublicKey is the Schema for the policypublickeys API.
// +kubebuilder:printcolumn:name="State",type=string,JSONPath=".status.state",description="The state of the publickey"
type PolicyPublicKey struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   PolicyPublicKeySpec   `json:"spec,omitempty"`
	Status PolicyPublicKeyStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// PolicyPublicKeyList contains a list of PolicyPublicKey.
type PolicyPublicKeyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []PolicyPublicKey `json:"items"`
}

func init() {
	SchemeBuilder.Register(&PolicyPublicKey{}, &PolicyPublicKeyList{})
}
