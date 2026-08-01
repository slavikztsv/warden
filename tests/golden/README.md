# Frozen baseline

Captured from `./scripts/demo.sh guarded` in **cassette mode** on a freshly
built image, before the product/demo seam refactor began. Cassette-guarded
produces seven records and no `CONNECT`; a `--live` run produces an extra
proxy record and a different count, so the mode matters.

`audit-4711.jsonl` is a real hash-chained log. Do not hand-edit it: the chain
verifies in `tests/test_golden_replay.py`, and an edit is indistinguishable
from tampering, which is the point.

`replay-4711.txt` is the exact stdout of

    python -m cli.warden replay 4711 --audit tests/golden/audit-4711.jsonl

**This pair is not a policy gate.** `warden replay` reads a recorded log; it
never constructs a policy input and never calls the PDP, so a refactor that
turned every deny into an allow would leave both files matching. The policy
gate is `tests/golden/decisions/`, asserted by
`tests/test_golden_decisions.py`.

Regenerate only when a change is *intended* to alter the log, and say so in
the commit message.

## What this catches that `opa test` cannot

`policies/authz_test.rego` mocks `data.purposes` and `data.limits` in almost
every case (its own R1c comment says as much), so the shipped `data.json`
document's shape is barely exercised by `opa test`. The decision corpus
evaluates the real, unmocked bundle, so it catches regressions in the data
document that 44/44 green `opa test` runs do not even attempt to see. Each
row below was reproduced directly -- the mutation applied, all three
commands run, then restored with `git checkout --` and `git status`
confirmed clean for the touched file:

| Break | `opa test` | decision corpus | replay |
|---|---|---|---|
| `data.json` limit → 10,000,000 | PASS 44/44 | **FAIL** (`demo-4-bulk-read`, `adversarial-1-mislabelled-db-target`) | PASS 3/3 |
| `attacker.example` added to `egress_allow` | PASS 44/44 | **FAIL** (`demo-5-exfil-to-attacker`) | PASS 3/3 |
| delete the four-name allowlist (R1b, `policies/authz.rego:168-174`) | PASS 44/44 | **FAIL** (`adversarial-2-undeclared-tool`) | PASS 3/3 |

`opa test` cannot see any of these because every case in `authz_test.rego`
supplies `data.purposes`/`data.limits` itself via `with`, so a change to the
*shipped* `data.json` never reaches a test. `warden replay` cannot see any of
them either, for the separate reason documented above: it reads a recorded
log and never calls the PDP. The decision corpus is evaluated against the
real `policies/` directory with no `with` overrides, so it is the only one
of the three that is sensitive to either kind of change.
