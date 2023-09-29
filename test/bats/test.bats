#!/usr/bin/env bats

load helpers

WAIT_TIME=120
SLEEP_TIME=1
GATEKEEPER_NAMESPACE=${GATEKEEPER_NAMESPACE:-gatekeeper-system}

teardown_file() {
  kubectl delete -f validation/
}

@test "gatekeeper-controller-manager is running" {
  wait_for_process ${WAIT_TIME} ${SLEEP_TIME} "kubectl -n ${GATEKEEPER_NAMESPACE} wait --for=condition=Ready --timeout=60s pod -l control-plane=controller-manager"
}

@test "gatekeeper-audit is running" {
  wait_for_process ${WAIT_TIME} ${SLEEP_TIME} "kubectl -n ${GATEKEEPER_NAMESPACE} wait --for=condition=Ready --timeout=60s pod -l control-plane=audit-controller"
}

@test "archivista-data-provider is running" {
  wait_for_process ${WAIT_TIME} ${SLEEP_TIME} "kubectl -n ${GATEKEEPER_NAMESPACE} wait --for=condition=Ready --timeout=60s pod -l run=archivista-data-provider"
}

@test "archivista data validation" {
  run kubectl apply -f config/samples/witness_v1alpha1_policy.yaml
  assert_success
  
  run kubectl apply -f config/samples/witness_v1alpha1_policypublickey.yaml
  assert_success
  
  run kubectl apply -f validation/archivista-data-provider-constraint-template.yaml
  assert_success
  #wait_for_process ${WAIT_TIME} ${SLEEP_TIME} "constraint_enforced constrainttemplate k8sexternaldatavalidation"

  run kubectl apply -f validation/archivista-data-provider-constraint.yaml
  assert_success
  #wait_for_process ${WAIT_TIME} ${SLEEP_TIME} "constraint_enforced k8sexternaldatavalidation deny-images-with-invalid-suffix"

  run kubectl run nginx --image=nginx:latest --dry-run=server
  # should deny pod admission if it's not in compliance with the policy
  # assert_failure

  run kubectl run nginx --image=nginx:b2888fc9cfe7cd9d6727aeb462d13c7c45dec413b66f2819a36c4a3cb9d4df75 --dry-run=server
  # should deny pod admission if it's not in compliance with the policy
  # assert_success
}
