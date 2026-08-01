#!/usr/bin/env bash
# The demo, start to finish. Run ./demo/scripts/demo.sh unprotected  (then) guarded
# Invoke from the repo root: docker compose resolves docker-compose.yml
# against the current working directory, not against this script's location,
# and that file stays at the repo root.
set -euo pipefail
PROFILE="${1:-guarded}"
MODE="${2:-cassette}"

# `./demo/scripts/demo.sh guarded --live` drives the loop with a real model
# instead of the recorded transcript. The cassette stays the default: it is
# deterministic, needs no credential, and cannot fail in front of an audience.
AGENT_ARGS=""
if [ "$MODE" = "--live" ]; then
  AGENT_ARGS="--live"
  if [ -f .env ]; then set -a; . ./.env; set +a; fi
  if [ -z "${GEMINI_API_KEY:-}${ANTHROPIC_API_KEY:-}" ]; then
    echo "--live needs GEMINI_API_KEY or ANTHROPIC_API_KEY in .env" >&2
    exit 2
  fi
  echo "--- live model: the agent reaches its provider only because that host"
  echo "--- is on this purpose's egress_allow. Every call is still brokered."
fi
export AGENT_ARGS

mkdir -p data
python3 -c "from demo.mocks.seed_db import seed_customers; seed_customers('data/customers.db', 10312)"

if [ "$PROFILE" = "unprotected" ]; then
  # --build on every run.  Without it Compose reuses whatever image exists,
  # so a code change silently does not reach the containers: an image
  # predating the `subjects` field made the policy deny every db read as
  # input.malformed, the task never became tainted, and the PII POST to the
  # allowlisted internal endpoint went through -- with the chain reporting
  # itself intact.
  docker compose --profile unprotected up -d --build docstore mailer sinkhole
  docker compose --profile unprotected run --build --rm agent-runtime-unprotected
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

  docker compose --profile guarded up -d --build opa docstore mailer sinkhole broker broker-control
  sleep 3
  # localhost:8081 is broker-control, published to the host. The agent runtime
  # cannot reach it: broker-control is on backend-net only.
  TOKEN=$(curl -s -X POST localhost:8081/v1/tokens -H 'content-type: application/json' \
    -d '{"agent_id":"triage-bot","task_id":"4711","purpose":"support-triage",
         "allowed_tools":["read_document","query_customers","http_fetch","send_email"],
         "data_classes":["public","internal"],"counterparties":["customer:8812"]}' \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')
  TASK_TOKEN="$TOKEN" AGENT_ARGS="$AGENT_ARGS" \
    docker compose --profile guarded run --build --rm agent-runtime
  echo "--- what reached attacker.example ---"
  curl -s localhost:8099/__received | head -c 600
  echo
  python3 -m warden.cli.replay replay 4711
fi
