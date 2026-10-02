#!/usr/bin/env bash
# Sourced by tests and helper scripts. Provides assert_disposable_cluster, which refuses to proceed
# unless the current kube context is the disposable kind cluster AND its live kube-system UID equals
# the identity recorded by scripts/demo-cluster.sh in $STATE_DIR/demo-cluster.json.
#
#   source scripts/demo-cluster-guard.sh
#   assert_disposable_cluster || exit 1

DEMO_CLUSTER_CONTEXT=${DEMO_CLUSTER_CONTEXT:-kind-local-ops-demo}
STATE_DIR=${LOCAL_OPS_STATE_DIR:-./local-state}

assert_disposable_cluster() {
  local cluster_json="${STATE_DIR}/demo-cluster.json"
  local current recorded live
  if [ ! -f "${cluster_json}" ]; then
    echo "assert_disposable_cluster: ${cluster_json} missing; run scripts/demo-cluster.sh up" >&2
    return 1
  fi
  current="$(kubectl config current-context 2>/dev/null || true)"
  if [ "${current}" != "${DEMO_CLUSTER_CONTEXT}" ]; then
    echo "assert_disposable_cluster: current context '${current:-<unset>}' is not '${DEMO_CLUSTER_CONTEXT}'" >&2
    return 1
  fi
  case "${current}" in
    *eks*|*prod*|*mainnet*)
      echo "assert_disposable_cluster: context '${current}' looks production-like; refusing" >&2
      return 1 ;;
  esac
  if command -v jq >/dev/null 2>&1; then
    recorded="$(jq -r '.kube_system_uid // empty' "${cluster_json}")"
  else
    recorded="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("kube_system_uid",""))' "${cluster_json}")"
  fi
  live="$(kubectl --context "${DEMO_CLUSTER_CONTEXT}" get ns kube-system -o jsonpath='{.metadata.uid}' 2>/dev/null || true)"
  if [ -z "${recorded}" ] || [ -z "${live}" ] || [ "${recorded}" != "${live}" ]; then
    echo "assert_disposable_cluster: live kube-system uid '${live:-<unreachable>}' != recorded '${recorded:-<none>}'" >&2
    return 1
  fi
  return 0
}
