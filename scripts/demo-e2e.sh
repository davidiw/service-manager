#!/usr/bin/env bash
# End-to-end demo: disposable kind cluster -> server -> MCP client -> authorization -> review/YOLO ->
# operation -> health verification -> result retrieval, exercised by the opt-in integration suite, plus a
# human walkthrough of the browser review path. Nothing here touches any non-kind context.
set -euo pipefail
cd "$(dirname "$0")/.."
export LOCAL_OPS_STATE_DIR="${LOCAL_OPS_STATE_DIR:-./local-state}"
if ! scripts/demo-cluster.sh status >/dev/null 2>&1; then
  echo "== creating the disposable kind cluster + local registry (first run takes a few minutes)"
  scripts/demo-cluster.sh up
fi
scripts/demo-cluster.sh status
echo
echo "== opt-in integration suite against the disposable cluster"
echo "   (update v1->v2 through the review website, restart, explicit rollback, helm upgrade/rollback,"
echo "    broken image -> failed health without auto-rollback, duplicate submit, stale plan)"
LOCAL_OPS_INTEGRATION=1 uv run pytest tests/integration -q -p no:cacheprovider -m integration
echo
cat <<'TXT'
== manual browser walkthrough (optional)
  1. uv run local-ops init --config-dir ./local-config --state-dir ./local-state   # once; prompts for a reviewer password
  2. uv run local-ops serve --config ./local-config/server.yaml --catalog ./catalog/demo
  3. open http://127.0.0.1:8765/review and log in as reviewer
  4. set -a; . ./local-config/keys.env; set +a
     uv run python examples/mcp_client_example.py execution action_prepare \
       '{"service_id":"demo-app","binding_id":"demo-deployment","action":"update","desired_artifact":"localhost:5001/local-ops/demo-app:v2"}'
     -> approve the prepare request in the browser, then release its response (the exact plan)
  5. uv run python examples/mcp_client_example.py execution action_submit \
       '{"plan_id":"<from step 4>","plan_hash":"<from step 4>","idempotency_key":"demo-1"}'
     -> the request page shows before (v1 digest) / after (v2 digest), the strategic-merge patch, health checks;
        approve; watch the receipt appear; release the response; the client prints it.
  6. curl -s http://127.0.0.1:30080/version   # -> {"version": "2.0.0"}
  7. scripts/demo-cluster.sh down               # when finished
TXT
