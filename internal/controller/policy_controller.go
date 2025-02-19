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

package controller

import (
	"context"
	"encoding/json"
	"errors"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	witnessv1alpha1 "github.com/testifysec/archivista-data-provider/api/v1alpha1"
	shareddata "github.com/testifysec/archivista-data-provider/internal/shared_data"
	"github.com/testifysec/go-witness/dsse"
	witnessPolicy "github.com/testifysec/go-witness/policy"
)

// PolicyReconciler reconciles a Policy object.
type PolicyReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

//+kubebuilder:rbac:groups=witness.testifysec.com,resources=policies,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=witness.testifysec.com,resources=policies/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=witness.testifysec.com,resources=policies/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the Policy object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.16.0/pkg/reconcile
func (r *PolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx).WithName("policy-reconcile")

	var policy witnessv1alpha1.Policy
	if err := r.Get(ctx, req.NamespacedName, &policy); err != nil {
		logger.Error(err, "Unable to fetch Policy")
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	logger.Info("Reconciling Policy")

	// TODO: Add finalizer to delete policy from enforced list

	// No state - newly created
	if policy.Status.State == "" {
		policy.Status.State = witnessv1alpha1.PendingPolicy
		if err := r.Status().Update(ctx, &policy); err != nil {
			logger.Error(err, "Unable to update Policy")
			return ctrl.Result{}, err
		}
	}

	// Failed state - retry by pending
	if policy.Status.State == witnessv1alpha1.FailedPolicy {
		policy.Status.State = witnessv1alpha1.PendingPolicy
		if err := r.Status().Update(ctx, &policy); err != nil {
			logger.Error(err, "Unable to update Policy state")
			return ctrl.Result{}, err
		}
	}

	// Pending state - add to enforced list
	var pEnv dsse.Envelope
	var p witnessPolicy.Policy
	if policy.Status.State == witnessv1alpha1.PendingPolicy {
		logger.Info("Adding policy to enforced list")

		var failed bool
		if err := json.Unmarshal(policy.Spec.Policy, &pEnv); err != nil {
			logger.Error(err, "Invalid policy envelope")
			failed = true
		}

		if pEnv.PayloadType != witnessPolicy.PolicyPredicate {
			err := errors.New("unexpected policy predicate")
			logger.Error(err, "Invalid policy predicate")
			failed = true
		}

		if err := json.Unmarshal(pEnv.Payload, &p); err != nil {
			logger.Error(err, "Invalid policy format")
			failed = true
		}

		if failed {
			policy.Status.State = witnessv1alpha1.FailedPolicy
			if err := r.Status().Update(ctx, &policy); err != nil {
				logger.Error(err, "Unable to apply Policy")
				return ctrl.Result{}, err
			}
			return ctrl.Result{}, nil
		}
		shareddata.AddPolicy(policy.Name, pEnv)

		logger.Info("Policy added to enforced list", "policy steps", len(p.Steps))
		policy.Status.State = witnessv1alpha1.AppliedPolicy
		if err := r.Status().Update(ctx, &policy); err != nil {
			logger.Error(err, "Unable to update Policy")
			return ctrl.Result{}, err
		}
	}

	// Applied state - make sure it is in shared_data.
	if policy.Status.State == witnessv1alpha1.AppliedPolicy {
		if err := shareddata.UsePolicy(policy.Name, func(_ dsse.Envelope) {
		}); err != nil {
			// Policy not found in shared_data, retry.
			policy.Status.State = witnessv1alpha1.PendingPolicy
			if err := r.Status().Update(ctx, &policy); err != nil {
				logger.Error(err, "Unable to update Policy")
				return ctrl.Result{}, err
			}
		}
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *PolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&witnessv1alpha1.Policy{}).
		Complete(r)
}
