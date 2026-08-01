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

## Changed in Phase 2 (rekeying R5/R6/R7 onto target kind)

`policies/authz.rego` used to key R5 (`rows.bounded`), R6 (`mail.counterparty`)
and R7 (`rows.scope`) off `input.action.tool`. They now key off
`input.target.kind`, and the file contains no tool name at all. This is safe
only because R1b (added in the previous task) unconditionally and
fail-closed denies any `tool_call` whose `target.kind` disagrees with the
deployment's catalog -- if that guarantee ever weakens, these three rules
stop firing on a mislabelled call and nothing else catches it. It also
closes a latent hole: previously a *second* database tool would have escaped
the row budget entirely, because R5 named exactly one tool.

Three adversarial cases lost a second, redundant deny reason:

| case | was | now |
|---|---|---|
| `adversarial-1-mislabelled-db-target` | `input.malformed`, `rows.bounded` | `input.malformed` |
| `adversarial-3-mail-with-doc-target` | `input.malformed`, `mail.counterparty` | `input.malformed` |
| `adversarial-4-db-with-mail-target` | `input.malformed`, `rows.scope` | `input.malformed` |

Each is a call whose target kind disagrees with the catalog. Before the rekey
two rules fired independently; after it, R1b alone stands between the call and
an allow. The reported rule is unchanged in all three -- `input.malformed`
outranks everything -- so no audit record and no replay line moved, which is
why this needed measuring rather than watching for.

Eleven of the fourteen corpus cases are unchanged, including every demo
decision and `adversarial-7-tool-not-in-token` (it exercises `tools.allowed`,
which never depended on the tool-name form of R5/R6/R7).
