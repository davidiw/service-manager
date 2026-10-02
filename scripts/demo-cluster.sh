#!/usr/bin/env bash
# Disposable local demo environment for the Local Operations MCP.
#
# Creates a kind cluster plus a local OCI registry, builds/pushes three demo images, deploys the
# native demo-app Deployment and the demo-helm Helm release, and records the approved cluster
# identity in $STATE_DIR/demo-cluster.json. Everything is local and disposable; the script refuses
# to operate on any kube context other than kind-local-ops-demo.
#
# Usage: scripts/demo-cluster.sh {up|down|status|images|break|reset}
set -euo pipefail

CLUSTER=local-ops-demo
CONTEXT="kind-${CLUSTER}"
REGISTRY_NAME=local-ops-registry
REGISTRY_PORT=5001
REGISTRY_HOST="localhost:${REGISTRY_PORT}"
IMAGE_REPO="${REGISTRY_HOST}/local-ops/demo-app"
STATE_DIR=${LOCAL_OPS_STATE_DIR:-./local-state}
KIND_NODE_IMAGE=${KIND_NODE_IMAGE:-kindest/node:v1.37.0}
KIND_NODE_DIGEST=${KIND_NODE_DIGEST:-sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5}
HEALTH_URL="http://127.0.0.1:30080/health"
HELM_HEALTH_URL="http://127.0.0.1:30081/health"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${ROOT}"

CLUSTER_JSON="${STATE_DIR}/demo-cluster.json"
IMAGES_JSON="${STATE_DIR}/demo-images.json"

log()  { printf '[demo-cluster] %s\n' "$*" >&2; }
warn() { printf '[demo-cluster] WARNING: %s\n' "$*" >&2; }
die()  { printf '[demo-cluster] ERROR: %s\n' "$*" >&2; exit 1; }

# Every docker/kind call goes through `sudo -g docker` because this shell may lack the docker group.
docker() { sudo -n -g docker docker "$@"; }
kind()   { sudo -n -g docker kind "$@"; }
kc()     { kubectl --context "${CONTEXT}" "$@"; }
hl()     { helm --kube-context "${CONTEXT}" "$@"; }

require_tools() {
  local t
  for t in sudo kubectl helm jq sed curl; do
    command -v "$t" >/dev/null 2>&1 || die "missing required tool: $t"
  done
  sudo -n -g docker docker version >/dev/null 2>&1 || die "docker is not reachable via 'sudo -g docker'"
  sudo -n -g docker kind version >/dev/null 2>&1 || die "kind is not reachable via 'sudo -g docker'"
}

assert_demo_context() {
  # Refuse to run against anything but the disposable kind cluster.
  local current
  current="$(kubectl config current-context 2>/dev/null || true)"
  [ "${current}" = "${CONTEXT}" ] || die "current kube context is '${current:-<unset>}', expected '${CONTEXT}'; refusing to continue"
  case "${current}" in
    *eks*|*prod*|*mainnet*) die "context '${current}' looks production-like; refusing" ;;
  esac
  kubectl config get-contexts -o name | grep -qx "${CONTEXT}" || die "context ${CONTEXT} not found in kubeconfig"
}

assert_recorded_identity() {
  # Every caller mutates the cluster: it must match the identity recorded when this script created it.
  # No record means the cluster was not created here (or the record was lost): refuse rather than trust it.
  [ -f "${CLUSTER_JSON}" ] || die "no recorded cluster identity in ${CLUSTER_JSON}; recreate the demo cluster with 'down' then 'up'"
  local recorded live
  recorded="$(jq -r '.kube_system_uid' "${CLUSTER_JSON}")"
  live="$(kc get ns kube-system -o jsonpath='{.metadata.uid}')"
  [ "${recorded}" = "${live}" ] || die "live kube-system UID ${live} != recorded ${recorded} in ${CLUSTER_JSON}; refusing"
}

registry_running() { [ "$(docker inspect -f '{{.State.Running}}' "${REGISTRY_NAME}" 2>/dev/null || true)" = "true" ]; }
registry_exists()  { docker inspect "${REGISTRY_NAME}" >/dev/null 2>&1; }
cluster_exists()   { kind get clusters 2>/dev/null | grep -qx "${CLUSTER}"; }

ensure_registry() {
  if registry_running; then
    log "registry container ${REGISTRY_NAME} already running"
  elif registry_exists; then
    log "starting existing registry container ${REGISTRY_NAME}"
    docker start "${REGISTRY_NAME}" >/dev/null
  else
    log "creating registry container ${REGISTRY_NAME} on 127.0.0.1:${REGISTRY_PORT}"
    docker run -d --restart=always -p "127.0.0.1:${REGISTRY_PORT}:5000" --network bridge --name "${REGISTRY_NAME}" registry:2 >/dev/null
  fi
  local i
  for i in $(seq 1 30); do
    curl -fsS "http://${REGISTRY_HOST}/v2/" >/dev/null 2>&1 && return 0
    sleep 1
  done
  die "registry did not become reachable at http://${REGISTRY_HOST}/v2/"
}

ensure_node_image() {
  if ! docker image inspect "${KIND_NODE_IMAGE}" >/dev/null 2>&1; then
    if docker image inspect "kindest/node@${KIND_NODE_DIGEST}" >/dev/null 2>&1; then
      log "tagging pre-pulled kindest/node@${KIND_NODE_DIGEST} as ${KIND_NODE_IMAGE}"
      docker tag "kindest/node@${KIND_NODE_DIGEST}" "${KIND_NODE_IMAGE}"
    else
      log "pulling ${KIND_NODE_IMAGE}"
      docker pull "${KIND_NODE_IMAGE}"
    fi
  fi
}

ensure_cluster() {
  if cluster_exists; then
    log "kind cluster ${CLUSTER} already exists"
    return 0
  fi
  ensure_node_image
  local cfg
  cfg="$(mktemp)"
  # kind's documented local-registry pattern: containerd mirror for localhost:5001 -> the registry
  # container on the kind docker network; NodePorts 30080/30081 are published on the host.
  cat >"${cfg}" <<KIND
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
name: ${CLUSTER}
containerdConfigPatches:
  - |-
    [plugins."io.containerd.grpc.v1.cri".registry.mirrors."${REGISTRY_HOST}"]
      endpoint = ["http://${REGISTRY_NAME}:5000"]
nodes:
  - role: control-plane
    extraPortMappings:
      - containerPort: 30080
        hostPort: 30080
        listenAddress: "127.0.0.1"
        protocol: TCP
      - containerPort: 30081
        hostPort: 30081
        listenAddress: "127.0.0.1"
        protocol: TCP
KIND
  log "creating kind cluster ${CLUSTER} (image ${KIND_NODE_IMAGE})"
  kind create cluster --name "${CLUSTER}" --image "${KIND_NODE_IMAGE}" --config "${cfg}" --wait 120s
  rm -f "${cfg}"
  # kind writes the kubeconfig as the invoking (sudo) user; make sure it is in this user's kubeconfig too.
  if ! kubectl config get-contexts -o name 2>/dev/null | grep -qx "${CONTEXT}"; then
    log "merging kubeconfig for ${CONTEXT} into ${KUBECONFIG:-$HOME/.kube/config}"
    local tmp merged
    tmp="$(mktemp)"; merged="$(mktemp)"
    kind get kubeconfig --name "${CLUSTER}" >"${tmp}"
    mkdir -p "$(dirname "${KUBECONFIG:-$HOME/.kube/config}")"
    KUBECONFIG="${KUBECONFIG:-$HOME/.kube/config}:${tmp}" kubectl config view --flatten >"${merged}"
    cp "${merged}" "${KUBECONFIG:-$HOME/.kube/config}"
    rm -f "${tmp}" "${merged}"
  fi
  kubectl config use-context "${CONTEXT}" >/dev/null
}

connect_registry_network() {
  # Connect the registry to the kind network so nodes can pull from http://local-ops-registry:5000.
  if [ "$(docker inspect -f '{{json .NetworkSettings.Networks.kind}}' "${REGISTRY_NAME}")" = "null" ]; then
    log "connecting ${REGISTRY_NAME} to the kind docker network"
    docker network connect kind "${REGISTRY_NAME}"
  fi
  # Documented local-registry-hosting ConfigMap (KEP-1755).
  cat <<CM | kc apply -f - >/dev/null
apiVersion: v1
kind: ConfigMap
metadata:
  name: local-registry-hosting
  namespace: kube-public
data:
  localRegistryHosting.v1: |
    host: "${REGISTRY_HOST}"
    help: "https://kind.sigs.k8s.io/docs/user/local-registry/"
CM
}

build_and_push_images() {
  log "building and pushing demo images to ${IMAGE_REPO}"
  local build_id
  build_id="$(date -u +%Y%m%dT%H%M%SZ)"
  docker build -q --build-arg VERSION=1.0.0        --build-arg BUILD="${build_id}-v1"       --build-arg FAIL=0 -t "${IMAGE_REPO}:v1"        demo/app >/dev/null
  docker build -q --build-arg VERSION=2.0.0        --build-arg BUILD="${build_id}-v2"       --build-arg FAIL=0 -t "${IMAGE_REPO}:v2"        demo/app >/dev/null
  docker build -q --build-arg VERSION=2.0.0-broken --build-arg BUILD="${build_id}-v2broken" --build-arg FAIL=1 -t "${IMAGE_REPO}:v2-broken" demo/app >/dev/null
  local tag
  for tag in v1 v2 v2-broken; do
    docker push -q "${IMAGE_REPO}:${tag}" >/dev/null
  done
  mkdir -p "${STATE_DIR}"
  local d1 d2 d3
  d1="$(docker inspect --format '{{index .RepoDigests 0}}' "${IMAGE_REPO}:v1")"
  d2="$(docker inspect --format '{{index .RepoDigests 0}}' "${IMAGE_REPO}:v2")"
  d3="$(docker inspect --format '{{index .RepoDigests 0}}' "${IMAGE_REPO}:v2-broken")"
  jq -n --arg v1 "$d1" --arg v2 "$d2" --arg v2b "$d3" --arg repo "${IMAGE_REPO}" --arg at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    '{repository: $repo, v1: $v1, v2: $v2, "v2-broken": $v2b, built_at: $at}' >"${IMAGES_JSON}"
  log "digests recorded in ${IMAGES_JSON}:"
  jq -r 'to_entries[] | select(.key|test("^v")) | "  \(.key): \(.value)"' "${IMAGES_JSON}" >&2
}

digest_ref() {
  local key="$1"
  [ -f "${IMAGES_JSON}" ] || die "${IMAGES_JSON} missing; run '$0 images' first"
  local ref
  ref="$(jq -r --arg k "$key" '.[$k] // empty' "${IMAGES_JSON}")"
  [ -n "${ref}" ] || die "no digest recorded for ${key} in ${IMAGES_JSON}"
  printf '%s' "${ref}"
}

deploy_native() {
  local ref
  ref="$(digest_ref v1)"
  log "applying demo/k8s/demo-app.yaml with image ${ref}"
  sed "s#image: ${IMAGE_REPO}:v1#image: ${ref}#" demo/k8s/demo-app.yaml | kc apply -f - >/dev/null
}

deploy_helm() {
  local ref
  ref="$(digest_ref v1)"
  log "installing helm release demo-helm with image.ref=${ref}"
  hl upgrade --install demo-helm catalog/demo/charts/demo-helm -n demo --create-namespace \
    --set-string "image.ref=${ref}" --wait --timeout 180s >/dev/null
}

write_cluster_identity() {
  mkdir -p "${STATE_DIR}"
  local uid server gitver
  uid="$(kc get ns kube-system -o jsonpath='{.metadata.uid}')"
  server="$(kubectl config view --minify --context "${CONTEXT}" -o jsonpath='{.clusters[0].cluster.server}')"
  gitver="$(kc version -o json | jq -r '.serverVersion.gitVersion')"
  jq -n --arg uid "$uid" --arg server "$server" --arg gitver "$gitver" --arg ctx "${CONTEXT}" --arg by "scripts/demo-cluster.sh" --arg at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    '{kube_system_uid: $uid, server: $server, git_version: $gitver, context: $ctx, created_by: $by, created_at: $at}' >"${CLUSTER_JSON}"
  log "approved cluster identity written to ${CLUSTER_JSON} (kube-system uid ${uid})"
}

wait_rollouts() {
  log "waiting for rollouts"
  kc -n demo rollout status deployment/demo-app --timeout=180s >/dev/null
  kc -n demo rollout status deployment/demo-helm --timeout=180s >/dev/null
  local i
  for i in $(seq 1 60); do
    if curl -fsS "${HEALTH_URL}" >/dev/null 2>&1 && curl -fsS "${HELM_HEALTH_URL}" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  warn "health endpoints not reachable from the host after 60s"
}

http_summary() {
  local url="$1" code
  code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "$url" 2>/dev/null || true)"
  printf '%s -> %s' "$url" "${code:-unreachable}"
  if [ "${code}" = "200" ]; then
    printf ' %s' "$(curl -s --max-time 3 "${url%/health}/version" 2>/dev/null || true)"
  fi
  printf '\n'
}

cmd_up() {
  require_tools
  ensure_registry
  # Trust-on-first-use must happen at most once per cluster incarnation: only a cluster this invocation
  # creates gets its identity (re)written. A cluster that already existed must match whatever identity is
  # already recorded (if any) before anything is deployed to it, and that recorded identity is left alone.
  local fresh_cluster=0
  cluster_exists || fresh_cluster=1
  ensure_cluster
  assert_demo_context
  if [ "${fresh_cluster}" = "0" ]; then
    assert_recorded_identity
  fi
  connect_registry_network
  build_and_push_images
  deploy_native
  deploy_helm
  if [ "${fresh_cluster}" = "1" ]; then
    write_cluster_identity
  else
    log "cluster already existed; recorded identity in ${CLUSTER_JSON} was verified and left unchanged"
  fi
  wait_rollouts
  log "ready."
  echo "health:  ${HEALTH_URL}"
  echo "version: http://127.0.0.1:30080/version"
  echo "helm:    ${HELM_HEALTH_URL}"
}

cmd_down() {
  require_tools
  if cluster_exists; then
    log "deleting kind cluster ${CLUSTER}"
    kind delete cluster --name "${CLUSTER}"
  else
    log "kind cluster ${CLUSTER} does not exist"
  fi
  if registry_exists; then
    log "removing registry container ${REGISTRY_NAME}"
    docker rm -f "${REGISTRY_NAME}" >/dev/null
  fi
  rm -f "${CLUSTER_JSON}" "${IMAGES_JSON}"
  log "removed ${CLUSTER_JSON} and ${IMAGES_JSON}"
}

cmd_status() {
  require_tools
  echo "cluster:   ${CLUSTER} $(cluster_exists && echo present || echo absent)"
  echo "context:   $(kubectl config current-context 2>/dev/null || echo '<unset>') (expected ${CONTEXT})"
  echo "registry:  ${REGISTRY_NAME} $(registry_running && echo running || echo stopped) http://${REGISTRY_HOST}/v2/ -> $(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "http://${REGISTRY_HOST}/v2/" 2>/dev/null || echo unreachable)"
  if curl -fsS --max-time 3 "http://${REGISTRY_HOST}/v2/local-ops/demo-app/tags/list" >/dev/null 2>&1; then
    echo "tags:      $(curl -s "http://${REGISTRY_HOST}/v2/local-ops/demo-app/tags/list" | jq -c '.tags')"
  fi
  if [ -f "${CLUSTER_JSON}" ]; then
    echo "identity:  recorded kube-system uid $(jq -r .kube_system_uid "${CLUSTER_JSON}") (${CLUSTER_JSON})"
    if cluster_exists; then
      echo "live uid:  $(kc get ns kube-system -o jsonpath='{.metadata.uid}' 2>/dev/null || echo unreachable)"
    fi
  else
    echo "identity:  ${CLUSTER_JSON} missing"
  fi
  if [ -f "${IMAGES_JSON}" ]; then
    echo "images:"
    jq -r 'to_entries[] | select(.key|test("^v")) | "  \(.key): \(.value)"' "${IMAGES_JSON}"
  fi
  if cluster_exists; then
    echo "rollouts:"
    kc -n demo get deploy -o custom-columns='  NAME:.metadata.name,READY:.status.readyReplicas,DESIRED:.spec.replicas,IMAGE:.spec.template.spec.containers[0].image' 2>/dev/null || echo "  (namespace demo not reachable)"
    echo "helm:      $(hl -n demo status demo-helm -o json 2>/dev/null | jq -r '"release demo-helm revision \(.version) status \(.info.status)"' || echo 'release demo-helm not found')"
  fi
  echo "health:    $(http_summary "${HEALTH_URL}")"
  echo "helm app:  $(http_summary "${HELM_HEALTH_URL}")"
}

cmd_images() {
  require_tools
  ensure_registry
  build_and_push_images
}

cmd_break() {
  require_tools
  assert_demo_context
  assert_recorded_identity
  local ref
  ref="$(digest_ref v2-broken)"
  warn "patching Deployment demo/demo-app to the BROKEN image ${ref} directly with kubectl (outside the server) to demonstrate a failed rollout in the kind-only context"
  kc -n demo set image deployment/demo-app "app=${ref}" >/dev/null
  log "patched; the new pods will crash on start. Observe with: kubectl --context ${CONTEXT} -n demo get pods ; restore with: $0 reset"
}

cmd_reset() {
  require_tools
  assert_demo_context
  assert_recorded_identity
  local ref
  ref="$(digest_ref v1)"
  log "patching Deployment demo/demo-app back to ${ref}"
  kc -n demo set image deployment/demo-app "app=${ref}" >/dev/null
  kc -n demo rollout status deployment/demo-app --timeout=180s >/dev/null
  log "demo-app restored to v1"
}

case "${1:-}" in
  up)     cmd_up ;;
  down)   cmd_down ;;
  status) cmd_status ;;
  images) cmd_images ;;
  break)  cmd_break ;;
  reset)  cmd_reset ;;
  *) echo "usage: $0 {up|down|status|images|break|reset}" >&2; exit 2 ;;
esac
