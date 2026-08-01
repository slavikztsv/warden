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
