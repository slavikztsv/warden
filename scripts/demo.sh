#!/usr/bin/env bash
# The demo, start to finish. Run ./scripts/demo.sh unprotected  (then) guarded
set -euo pipefail
PROFILE="${1:-guarded}"

mkdir -p data
python -c "from mocks.seed_db import seed_customers; seed_customers('data/customers.db', 10312)"

if [ "$PROFILE" = "unprotected" ]; then
  docker compose --profile unprotected up -d docstore mailer sinkhole
  docker compose --profile unprotected run --rm agent-runtime-unprotected
  echo "--- what reached attacker.example ---"
  curl -s localhost:8099/__received | head -c 600
else
  rm -f data/audit.jsonl
  docker compose --profile guarded up -d opa docstore mailer sinkhole broker
  sleep 3
  TOKEN=$(curl -s -X POST localhost:8081/v1/tokens -H 'content-type: application/json' \
    -d '{"agent_id":"triage-bot","task_id":"4711","purpose":"support-triage",
         "allowed_tools":["read_document","query_customers","http_fetch","send_email"],
         "data_classes":["public","internal"],"counterparties":["customer:8812"]}' \
    | python -c 'import json,sys; print(json.load(sys.stdin)["token"])')
  TASK_TOKEN="$TOKEN" docker compose --profile guarded run --rm agent-runtime
  echo "--- what reached attacker.example ---"
  curl -s localhost:8099/__received | head -c 600
  echo
  python -m cli.warden replay 4711
fi
