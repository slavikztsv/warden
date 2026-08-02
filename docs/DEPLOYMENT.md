# Deploying and developing

Running `warden` against real systems, and working on it. The
[README](../README.md) has the quick start; this is everything after that.


---

## Deployment

Two topologies ship, both Compose-based, and they differ only in profile —
never in agent code.

| | `--profile protected` | `--profile unprotected` |
|---|---|---|
| Broker, OPA, control plane | Running | Not started |
| Agent's networks | `agent-net` only, no gateway | `backend-net` + `egress-net` |
| Credentials at the agent | Task token, 5 minutes | Direct backend access |
| Audit | Every decision recorded | None |

`--profile unprotected` exists to demonstrate the failure mode. It is not a
degraded mode of the product; it is the control case, and it must never be run
against anything real.

### Required

- Run the broker with **one worker**. The row budget has no lock and relies on
  a single event loop.
- Keep the agent on a network with no gateway. Enforcement is bypassed entirely
  by any direct route to a protected system.
- Keep the signing key out of the enforcement point. The broker must load the
  public half only.
- Keep the minting endpoint off any network the agent can reach — it has no
  caller authentication.
- Mount the policy bundle read-only, and mount the same two files into both OPA
  and the broker so the recorded digest matches what was evaluated.
- Give the broker a writable audit path. It returns 503 and refuses to act
  when it cannot record.

### Recommended

- Forward the audit log to append-only storage off the broker's host.
- Restrict who can modify `authz.rego` and `data.json` — a purpose added
  without `pii_approved_sinks` silently weakens the data-flow control for that
  purpose only, with no error.
- Shorten the token TTL further for high-risk purposes.
- Scope each purpose's allowlist as narrowly as the task genuinely needs.

### Optional hardening

- Terminate TLS at the proxy to regain visibility into request paths — this
  deployment does not, so covert channels within an approved host remain out of
  scope.
- Add mTLS or an operator credential to the control plane, the next trust
  boundary out.
- Match egress destinations on host *and* port.

---

---

## Security validation

```bash
./scripts/fetch-opa.sh                                            # pinned OPA, once
~/.cache/warden/opa-1.19.0 test warden/policies/ demo/scenario/data.json -v
.venv/bin/pytest -v
```

Both paths must be passed to `opa test`: several cases deliberately evaluate
the shipped `data.json` instead of a mock.

| Check | Command | Asserts |
|---|---|---|
| Policy rules | `opa test warden/policies/ demo/scenario/data.json` | 53 rule cases, including the shipped data document |
| Full suite | `.venv/bin/pytest -v` | Broker, proxy, adapters, identity, audit chain, CLI, agent loop |
| The exploit | `.venv/bin/pytest tests/demo/test_injection_contained.py` | Runs the full attack and asserts the sinkhole received **zero bytes** |
| Audit integrity | `.venv/bin/warden verify-chain --audit tests/golden/audit-4711.jsonl` | `chain intact: 7 records`; exit 1 on tampering |
| Config coherence | `.venv/bin/warden config check --catalog demo/scenario/tools.toml --data demo/scenario/data.json` | Every catalogued tool has a policy target kind, and vice versa |
| Containment | `./tests/demo/test_isolation.sh` | `agent-net` has no gateway and exactly one reachable host. **Requires Docker; not run by CI** |

**The exploit is a regression test.** `tests/demo/test_injection_contained.py`
runs the real attack on every commit, so the security property is verified
continuously rather than demonstrated once. No test of any model provider calls
a real API.

Denied and allowed requests are both exercised directly, without an agent, in
Part 4 of [docs/WALKTHROUGH.md](WALKTHROUGH.md) — the broker driven
entirely with `curl`.

---

---

## Development

```bash
.venv/bin/pip install -e ./warden -e ./demo -e ./tools
.venv/bin/pip install pytest==9.1.1 pytest-asyncio==1.4.0
```

| Task | Command |
|---|---|
| Run the broker | `.venv/bin/warden serve --config <warden.toml>` |
| Run the control plane | `.venv/bin/warden control --config <control.toml>` |
| All tests | `.venv/bin/pytest -v` |
| Policy tests | `~/.cache/warden/opa-1.19.0 test warden/policies/ demo/scenario/data.json -v` |
| Config check | `.venv/bin/warden config check --catalog … --data …` |
| Replay a task | `.venv/bin/warden replay <task_id> --audit <path>` |
| Verify the chain | `.venv/bin/warden verify-chain --audit <path>` |

`serve` and `control` each take a config file. The two under
`demo/scenario/` name container paths (`/data/agent.pub`, `/policies`) because
Compose mounts them there, so running either on the host needs a config with
host paths — [warden/reference/README.md](../warden/reference/README.md) covers
what goes in one. Both fail loudly at boot on a bad config, before a socket is
opened.

Tests that need something external: `tests/demo/test_isolation.sh` and
`warden-demo up` need Docker; the Gemini and Anthropic client tests skip unless
`requirements-live.txt` is installed; `--live` runs need a provider key.
Everything else runs offline. There is no lint, format or type-check step
configured — [.github/workflows/ci.yml](../.github/workflows/ci.yml) runs the
policy tests, a config consistency check, and `pytest`.

---
