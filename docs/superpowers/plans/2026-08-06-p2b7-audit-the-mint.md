# P2·B7 — audit the mint: implementation plan

Design: [2026-08-06-p2b7-audit-the-mint-design.md](../specs/2026-08-06-p2b7-audit-the-mint-design.md)

Two commits. Each ends all-five-gates green with a clean tree. Every proof-table
row is **made to fail first**, and the mutation must redden *that selector* —
not merely the suite somewhere.

**Gates, before every commit:**

```
.venv/bin/pytest -q                                 # 810 today; each commit states its new total
.venv/bin/ruff check .
.venv/bin/mypy warden --ignore-missing-imports
opa test warden/policies/ demo/scenario/data.json   # BOTH paths
.venv/bin/warden-demo explain --quiet-why           # 7 records after commit 1; 8 after commit 2
```

Plus, once per commit: `.venv/bin/warden-demo explain --matrix --quiet-why`
must run to completion (commit 2 makes `_steps_from` reachable by a tool-less
record; `--matrix` is the path that dies on it).

---

## Commit 1 — the control plane records what it grants

### Step 1.1 — `warden/broker/record_fields.py` (new, stdlib only)

Move `args_digest` (`spine.py:120-122`) and `_empty_state` (`spine.py:109-117`)
here verbatim; rename the latter `empty_task_state`. Keep both docstrings —
especially the fresh-dict-per-call warning, which now has a second caller.

`spine.py` imports both and drops its local definitions. Its two
`_empty_state()` call sites (`:494`, `:518`) become `empty_task_state()`.

Nothing else changes. `pytest -q` must still be 810.

**Mutation:** delete the `dict` construction and return a module-level constant
instead → `test_...` in `test_spine.py` covering the shared-mutable case must
redden. (If none exists, the docstring's warning is unguarded — write one.)

### Step 1.2 — `loader.py`: `audit_path`, and a TTL that must be positive

```python
@dataclass(frozen=True)
class ControlConfig:
    listen: tuple[str, int]
    private_key: Path
    audit_path: Path      # must name the SAME file as the broker's [audit].path
    issuer: str
    ttl_seconds: int
```

In `load_control_config`, sections in this order — **`control`, `identity`,
`audit`, `tokens`** — and after `_integer`:

```python
if ttl_seconds <= 0:
    raise ConfigError("tokens.ttl_seconds must be positive: a token minted "
                      "with a non-positive TTL is expired before it is issued")
```

**Tests first** (`test_config_loader.py`): `CONTROL_COMPLETE` gains
`[audit] path = "/data/audit.jsonl"`; new
`test_control_loads_every_field` assertion for `audit_path`;
`test_control_a_missing_audit_section_names_itself`;
`test_control_a_non_positive_ttl_refuses_to_load` (parametrised `0` and `-1`).

**Then** the fixture updates that unblock the rest: `test_key_split.py`'s
`write_control_toml` gains `audit_path: Path | None = None`, defaulting to
`tmp_path / "audit.jsonl"` — **never `/data/…`**, or `AuditLog.__init__`'s
`self.path.parent.mkdir(parents=True, exist_ok=True)` tries to create `/data`
inside `build()`. And `test_cli_config_errors.py`'s inline control.toml gains
`[audit]`, so `test_control_reports_a_missing_private_key_file_cleanly` reaches
the failure it is named for instead of stopping at `[audit]`.

Expect ~18 reds between the loader change and the fixture updates. That is the
measured number for this section order; a different number means a different
order.

### Step 1.3 — `control.py`: `record_mint`, and a route that fails closed

```python
MINT_UNAVAILABLE_MESSAGE = (
    "The control plane cannot record what it grants, so it is not granting "
    "anything. No token was issued."
)

def record_mint(audit, *, token: TaskToken, args_digest: str) -> dict:
    return audit.append(
        task_id=token.task_id, agent_id=token.agent_id, purpose=token.purpose,
        action={"type": "mint"},
        target={"kind": "token",
                "allowed_tools": list(token.allowed_tools),
                "data_classes": list(token.data_classes),
                "counterparties": list(token.counterparties),
                "delegated_from": token.delegated_from,
                "jti": token.jti, "exp": token.exp},
        args_digest=args_digest,
        decision="allow", rule="mint.unconditional",
        task_state=empty_task_state(),
        policy_bundle_digest="none",
    )
```

`create_control_app(*, signer: Signer, audit: AuditLog, issuer: str)` builds one
`Verifier(signer.public_key_pem(), issuer=issuer)` at construction, and the
route is:

```
now = int(time.time())            # ONE read, per spine.py:222-225
raw   = signer.mint(**request, now=now)
token = verifier.verify(raw, now=now)
try:    record_mint(audit, token=token, args_digest=args_digest(body))
except OSError:  raise HTTPException(503, MINT_UNAVAILABLE_MESSAGE)
return {"token": raw}
```

Never `str(exc)` — `_acquire`'s message contains the audit path.

`control_main.build()` constructs `AuditLog(config.audit_path)` and passes
`issuer=config.issuer` to both the `Signer` and `create_control_app`. It keeps
returning the app: six tests in `test_key_split.py` do `TestClient(build(...))`.

**Tests (proof rows 1–8, 11), each written to fail first**, in
`tests/warden/test_control_audit.py` (new) plus the `test_app.py` call-site fix.
Row 3 monkeypatches `Signer.mint` to emit a token whose `allowed_tools` differ
from the request's and asserts the record follows the **token**. Row 7 asserts
`str(tmp_path)` is absent from the 503 body. Row 8 builds the app with
`issuer="control-plane-a"` and asserts 200 plus one record — the blocker the
review caught.

### Step 1.4 — `replay.py`: the `mint` branch and the `⊕ GRANT` line

`_describe` gains, above the `tool =` fallthrough:

```python
if record["action"].get("type") == "mint":
    tools = record["target"].get("allowed_tools", [])
    return f"mint({len(tools)} tool{'' if len(tools) == 1 else 's'})"
```

`render_replay` emits the grant line **after** the record's own line, guarded on
the same type. Widen the `reason` comment at `:87`.

**Tests (rows 13, 14)** in `test_spine.py`, beside
`test_replay_renders_a_list_refusal` and `test_replay_renders_a_handshake_refusal`.

**Mutation:** change `mint` to `Mint` in the `_describe` branch → row 13's
selector must redden and `test_golden_replay.py` must stay green (it has no
mint record; if it reddens, the branch is firing on the wrong records).

### Step 1.5 — row 12: two processes, one chain

`tests/warden/test_audit.py`, copying the B6 pattern exactly: a module-level
triple-quoted script, `subprocess.Popen([sys.executable, "-c", SCRIPT, path,
n])`, all started before any is waited on. One child appends broker-shaped
`tool_call` records; one calls `record_mint` through a real `AuditLog`. Assert
dense seqs, `verify_chain() == (True, None)`, and exactly one `mint`.

**Mutation:** in a scratch copy, move `_head_from_tail` outside the flock →
must redden. (Do not mutate `audit.py` in place without committing first.)

### Step 1.6 — `tools/build_corpus.py` and `tests/demo/test_isolation.sh`

`build_corpus.py`: the defensive guard, commented as unreachable today; reword
the "a record states what was decided, not what the token permitted" comment at
`:24-26` to scope it to tool-call records.

`test_isolation.sh`: a positive liveness assertion before the isolation checks,
so a `broker-control` that fails to boot reddens instead of printing
"ok: minting … was blocked". This is the only CI job that boots that service and
commit 1 gives it two new ways to fail at boot.

### Step 1.7 — move the claims

`demo/scenario/control.toml` (+ the must-match comment), `demo/scenario/warden.toml`
(the matching comment), `WALKTHROUGH.md` (`:348-358`, `:528-540` → 9 records with
the mint + GRANT lines, `:1129` → 8), `ARCHITECTURE.md` (lifecycle step 1, the
"every allow, deny and unauthenticated probe" enumeration, the
`policy_bundle_digest`-in-every-record claim at `:352`), `DEPLOYMENT.md:72`,
`ROADMAP.md` (B7 done; what remains in § B), `warden/reference/README.md`
(author a control.toml section), `2026-07-29-…-design.md:146` (the stale
action-type list).

**Do not touch:** `README.md:139`, `DEPLOYMENT.md:195`, `tests/golden/*`,
`docs/evidence/*`, `WALKTHROUGH.md:836`, earlier phases' plan documents.

### Step 1.8 — gates, then commit

`warden-demo explain --quiet-why` must still report **7 records** after commit 1
— the explain path does not go through the control plane. If it reports 8,
something wired the demo's in-process mint early; that is commit 2.

---

## Commit 2 — the demo shows it

### Step 2.1 — `explain.py`

Construct `AuditLog` before stage ⓪ and record the mint through `NarratedAudit`
with `args_digest(grant)`. `NarratedAudit.append` branches on
`fields["action"]["type"] == "mint"`: `show()` lines only, **no `stage()`**, its
own `why`. Reword the SETUP banner's "empty, hash chain starts at 64 zeroes".

`_target_label` gains the `token` branch. `_steps_from` gains the `.get("tool")
or ["type"]` guard and a reworded docstring. The `audit records` cell counts
`tool_call` records against `dispatcher.calls` and adds the exactly-one-mint
check.

### Step 2.2 — tests (rows 15–18)

`test_explain_wrappers.py` drives `NarratedAudit` **and** `NarratedPDP` through
the real spine. `test_cli.py` gains the `_target_label` `token` case. New tests
for the mint narration, the guarded step reader, the matrix step line, and that
the demo's replay leads with the mint.

**Mutation for row 17:** delete the `mint` branch in `NarratedAudit.append` →
row 17's selector must redden while the rest of the demo suite stays green
(nothing else forces it, which is why the row exists).

### Step 2.3 — move the claims

`DEMO.md:142`, `WALKTHROUGH.md:663`, `:774`, `:688`, plus the note at `:691-696`
that records now exceed calls by one.

### Step 2.4 — gates, then commit

`warden-demo explain --quiet-why` → **8 records, 3 refusals, 1 record read**.
`--matrix --quiet-why` runs to completion.

---

## Traps this plan must not walk into

- **Commit before mutating.** `git checkout --` reverts an uncommitted
  implementation with the mutation, and reverts nothing at all on an untracked
  file.
- **Clear `__pycache__` after every revert.** CPython invalidates on (mtime in
  whole seconds, size); a same-second, same-size revert reruns the mutant.
  `find . -path ./.venv -prune -o -name '__pycache__' -type d -exec rm -rf {} +`
- **A green suite is not evidence.** Red *then* green, and confirm which
  selector went red.
- **A mutation string can redden by collision.** Vary it, and check which test
  caught it.
- **Never regenerate `tests/golden/audit-4711.jsonl`.**
- **`/data` is not a writable path in a test.** `AuditLog.__init__` mkdirs the
  parent.
