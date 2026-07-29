#!/usr/bin/env bash
# The demo, start to finish. Run ./scripts/demo.sh unprotected  (then) guarded
set -euo pipefail
PROFILE="${1:-guarded}"

mkdir -p data
python3 -c "from mocks.seed_db import seed_customers; seed_customers('data/customers.db', 10312)"

if [ "$PROFILE" = "unprotected" ]; then
  docker compose --profile unprotected up -d docstore mailer sinkhole
  docker compose --profile unprotected run --rm agent-runtime-unprotected
  echo "--- what reached attacker.example ---"
  curl -s localhost:8099/__received | head -c 600
else
  rm -f data/audit.jsonl

  # The keypair is generated HERE, outside every container, and handed out
  # split: broker-control gets the private half and is the only thing that can
  # mint; broker gets the public half and can only verify. Generating it inside
  # the broker (as an earlier version did) meant the enforcement point held a
  # signing key, so compromising the one service the agent can reach would have
  # handed over the ability to mint arbitrary tokens.
  if [ ! -f data/agent.key ]; then
    openssl genpkey -algorithm ed25519 -out data/agent.key
    chmod 600 data/agent.key
  fi
  openssl pkey -in data/agent.key -pubout -out data/agent.pub

  docker compose --profile guarded up -d opa docstore mailer sinkhole broker broker-control
  sleep 3
  # localhost:8081 is broker-control, published to the host. The agent runtime
  # cannot reach it: broker-control is on backend-net only.
  TOKEN=$(curl -s -X POST localhost:8081/v1/tokens -H 'content-type: application/json' \
    -d '{"agent_id":"triage-bot","task_id":"4711","purpose":"support-triage",
         "allowed_tools":["read_document","query_customers","http_fetch","send_email"],
         "data_classes":["public","internal"],"counterparties":["customer:8812"]}' \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')
  TASK_TOKEN="$TOKEN" docker compose --profile guarded run --rm agent-runtime
  echo "--- what reached attacker.example ---"
  curl -s localhost:8099/__received | head -c 600
  echo
  python3 -m cli.warden replay 4711
fi
