# P2·B7 — audit the mint

**Status:** approved design. Spiked against a real chain, then adversarially
reviewed before implementation — the review found four blockers in the first
draft and every one of them is folded in below. See *What the review changed*.
**Sequenced by:** [docs/ROADMAP.md](../../ROADMAP.md) § B, item B7 — the § B
exit criterion's last unmet clause that does not need rotation.
**Covers:** B7 only, in two commits (see *Scope, and why it is two commits*).
**Deliberately does not cover:** B2, B3, B4, B5, C2, and the process model —
and therefore § A's exit criterion, which still has nothing to start a second
worker with. See *What this does not do*.
**Verified against:** CPython 3.12 on ext4 under WSL2. Every number below was
measured: the record's field set, the chain verdict, the four candidate
renderings, the TTL race (4 failures in 20 000 mints), and the control plane's
import graph (7 modules today, 13 the wrong way, 8 the right way). Six of them
changed a decision.

---

## What this is

The audit log's pitch is that it records **what was authorised**, not what was
reported afterwards. The grant itself is the one authorisation it does not
contain. Ask the log "what was task 4711 allowed to do" and it cannot answer —
only "what did it try".

`POST /v1/tokens` signs an Ed25519 token naming the agent, the task, the
purpose, the allowed tools, the data classes and the counterparties, and writes
nothing anywhere:

```python
    @app.post("/v1/tokens")
    def mint_token(request: TokenRequest) -> dict:
        return {"token": signer.mint(...)}
```

That is the whole route ([control.py:38-49](../../../warden/broker/control.py)).
No log, no failure path, no record.

It matters more than "one missing row". `docs/THREAT_MODEL.md:134-147` records
that naming a fresh `task_id` **resets both the taint state and the row
budget**, and `docs/THREAT_MODEL.md:56-62` records that the endpoint
authenticates nobody. So the single most powerful action available in this
system is also the only one that leaves no trace. Every recorded refusal in the
log is measured against a grant the log never saw.

---

## What the review changed

B6 already found B7's plan defect (it was not independent of B6). This document
found its own, four of them, before a line of product code existed. They are
listed here rather than buried in the decisions because *the plan was wrong and
the implementation was not* is this project's pattern, and the point of writing
these down is to keep catching it earlier.

1. **`create_control_app(*, signer, audit)` would have 500'd on every
   non-default deployment.** `Signer` stores its issuer privately and exposes
   no accessor, so `Verifier(signer.public_key_pem())` gets the module default
   `"warden-broker"`. `tests/warden/test_key_split.py:393-404` builds a control
   plane with a *non-default* issuer and asserts 200. Measured: `issuer =
   'control-plane-a'` → **HTTP 500, records = 0**, and `TokenInvalid` is not an
   `OSError`, so decision 5's handler does not catch it. The route needs the
   issuer threaded through. **Decision 2.**
2. **A `ttl_seconds` the loader accepts makes the route fail intermittently.**
   `_integer` type-checks only, so `0` and `-1` both load. Verifying the token
   you just signed then fires the expiry check on it: `-1` fails every mint;
   `0` failed **4 of 20 000**. Two independent fixes, both taken. **Decisions 2
   and 7.**
3. **`WALKTHROUGH.md:539`'s "8 records" is not an unrelated eight.** Part 4
   starts a real `warden control` (`:361`), mints task 4711 through it with
   curl (`:407`), and replays the broker's own log (`:525`). It is a *fourth*
   family of counts, and the first draft filed it under "do not touch".
   **The four sevens.**
4. **Importing the shared record vocabulary from `spine.py` doubles the signing
   process's import graph.** Measured: 7 warden modules today, **13** if
   `control.py` reaches `spine`/`refusals` (dragging in `taint` and
   `adapters.base`), **8** via a stdlib-only module. No key material moves, so
   this is not a security violation — it is the enforcement stack loaded into
   the one process whose two module docstrings are entirely about staying
   minimal. **Decision 9.**

Three more the review caught, each folded into its decision: the demo's matrix
renders the mint as `mint(token)` (S1, decision 10); `task_state` is a **second**
sentinel and is false on a re-mint (decision 6); and proof rows 3 and 13 were
each wrong about their own catcher (*Proof table*).

---

## Scope, and why it is two commits

The roadmap's exit clause is *"B7's record appears in `warden replay` above the
first tool call"*. `warden replay` reads `data/audit.jsonl` — the file the
compose deployment shares between `broker` and `broker-control`. So the exit
clause is met by the **control plane** writing the record.

But `warden-demo explain` mints in-process
([explain.py:928-942](../../../demo/cli/explain.py)) with a throwaway
`Signer.generate()`, never touching `control_main.py`. It is also the only
executable end-to-end proof available on this machine, and the only gate that
catches `Narrated*` wrapper rot. A demo that shows a mint leaving no trace, in
a product whose pitch is that the log says what was authorised, understates the
product — the E2 failure, verbatim.

Both, therefore, and in this order:

| Commit | What | Numbers it moves |
|---|---|---|
| 1 | The control plane records what it grants | docker-demo `7 → 8`; hand-run curl walkthrough `8 → 9` |
| 2 | `warden-demo explain` records its own mint | the four explain tables, and the gate line |

Each is independently complete, independently green, and independently
revertible. Splitting them is not a hedge: commit 1 changes `warden/` and the
config surface; commit 2 changes `demo/` and four counters that were written
when the agent was the only writer.

---

## The four sevens

Conflating these is how a doc pass corrupts a claim it never meant to touch.
The first draft of this table had three rows and was wrong.

| # | Where the count comes from | Files | Fate |
|---|---|---|---|
| 1 | **Frozen golden.** `tests/golden/audit-4711.jsonl`, 7 lines, all `tool_call`, never regenerated | `README.md:139`, `DEPLOYMENT.md:195`, `tests/golden/replay-4711.txt:10`, `tests/golden/README.md:5` | **Never moves.** Do not "fix" it |
| 2 | **Docker demo.** `warden-demo up --profile protected` deletes the log, mints via `broker-control`, runs, replays | `WALKTHROUGH.md:1129` (7) | **→ 8 in commit 1** |
| 3 | **Hand-run curl walkthrough.** Part 4 starts a real `warden control` and curls `/v1/tokens` for task 4711, then replays the broker's own log | `WALKTHROUGH.md:539` (8) | **→ 9 in commit 1** |
| 4 | **Explain tables.** `warden-demo explain`, in-process mint | `DEMO.md:142` (7), `WALKTHROUGH.md:663` (7), `WALKTHROUGH.md:774` (7), `WALKTHROUGH.md:688` (8) | **each +1 in commit 2** |

Two counts nearby that **never move**, and must not be swept up:

- `tests/demo/test_cli.py:337` / `:363` — a synthetic 8 (7 tool calls plus a
  proxy `CONNECT`), built in-test from hand-fed records.
- `WALKTHROUGH.md:836` — "Forty-five audit records" is authorial prose about a
  frozen `--live` run held in `docs/evidence/`, whose artifacts are SHA-256
  pinned to each other. The matrix path prints no "audit records" cell at all.

And the word "seven" appears fourteen more times about **scenarios and rules**,
never records. A `sed` over "seven" breaks all of them.

---

## The ten decisions

### 1 · The mint reuses the thirteen body fields — the grant goes in `target`

The record body is one of the three interfaces
[ROADMAP F3](../../ROADMAP.md) says other people will depend on, and
`test_a_written_record_has_exactly_these_fields` was written last commit
specifically so that adding to it is a deliberate act. So: does the mint add a
fourteenth field, or fit inside the thirteen?

**It fits.** Measured — the spike's mint record's key set is byte-identical to
a tool call's, and the chain does not notice:

```
field set == ['action', 'agent_id', 'args_digest', 'decision', 'hash',
              'policy_bundle_digest', 'prev_hash', 'purpose', 'rule',
              'seq', 'target', 'task_id', 'task_state', 'ts']
verify_chain -> (True, None)
```

| Field | A mint's value | Sentinel? |
|---|---|---|
| `task_id` / `agent_id` / `purpose` | from the token | No — real |
| `action` | `{"type": "mint"}` | No — decision 3 |
| `target` | the grant | No — see below |
| `args_digest` | digest of the mint request | No — real |
| `decision` | `"allow"` | No — the grant was made |
| `rule` | `"mint.unconditional"` | No — decision 4 |
| `task_state` | `{"data_classes_held": [], "rows_charged_so_far": 0}` | **Yes** — decision 6 |
| `policy_bundle_digest` | `"none"` | **Yes** — decision 6 |

Two sentinels out of thirteen. Compare the existing `_refuse()` record, which
carries four (`task_id="-"`, `purpose="-"`, `agent_id="unauthenticated"`,
`args_digest="sha256:none"`) and is not thought of as a bent shape.

**`target` is the carrier because `target` already means "the thing this action
is about".** For a tool call it is a document, a query, a host, a recipient.
For a mint it is the authority granted. That is not a stretch of the word; it
is the word.

```json
"target": {"kind": "token",
           "allowed_tools": ["read_document", "query_customers", …],
           "data_classes": ["public", "pii"],
           "counterparties": ["customer:8812"],
           "delegated_from": null,
           "jti": "ffe4c16e…", "exp": 1786027002}
```

`kind: "token"` is deliberately none of `http`/`db`/`doc`/`mail`, so neither
renderer's target dispatch can present it as a tool call against a resource —
**provided both renderers get a branch**, which the first draft got wrong for
the demo's matrix (decision 10). `delegated_from` is always `null` today and is
carried anyway: it is part of the token, delegation is a live roadmap concept,
and a field added later is a record shape that changed. `exp` is the token's
own `int`, not an ISO string, because the record states what the token says.

The **token itself is never recorded.** `jti` and `exp` identify a grant;
the JWT is a bearer credential and `warden replay` prints what it is given.

**The loser: a fourteenth body field, `grant`.** It costs the F3 interface a
shape change, and — decisively — `_BODY_FIELDS` is written for *every* record,
so a `grant` key would be `null` on one hundred per cent of tool-call records
forever, in a log whose whole product is bytes people read. A field that is
empty in every record but one is not a field, it is a flag on a record type,
and the record type is already `action.type`.

**Also rejected: a separate mint log.** It forfeits the total order B6 bought —
and B6's own spec says so in advance (`2026-08-06-p2b6…:231-235`: one chain is
"what will make B7's exit criterion — the mint record appears *above* the first
tool call — mean something stronger than *two clocks happened to agree*").

### 2 · The grant is read from the verified token, under one clock read

`Signer.mint()` returns a string. `jti` and `exp` are generated *inside* it and
are not otherwise visible to the caller. Three ways to get them:

| Option | Cost |
|---|---|
| Decode the JWT unverified | A signature-skipping decode inside the one process that holds the signing key. No. |
| Grow `Signer` with a `mint_claims()` returning `(token, claims)` | Grows a key-material interface for a logging convenience |
| **Verify the token that was just signed** | **One Ed25519 verify (~µs), zero new interface** |

The third wins, and the reason is not cost. The record then states **what the
token says**, not what the request asked for. If those two ever diverge — a
`mint()` that drops a field, a claim that resolves differently than the config
implies — the record follows the token, which is the artifact the broker will
actually enforce against. A record built from the request would describe an
authority that was never issued.

It comes with two hazards the first draft missed, both measured, both fixed
here:

**(a) The verifier needs the configured issuer, and cannot get it from the
signer.** `Signer` keeps `self._issuer` private with no accessor (measured
public surface: `from_private_key_file`, `generate`, `mint`, `public_key_pem`),
and `Verifier.__init__` defaults to the module constant `"warden-broker"`. So
`create_control_app` grows a third keyword:

```python
def create_control_app(*, signer: Signer, audit: AuditLog, issuer: str) -> FastAPI:
```

and `control_main.build()` passes `config.issuer` to **both** the `Signer` and
the route's `Verifier`. Without it, `test_a_configured_issuer_mismatch_is_
rejected_end_to_end`'s deployment 500s: measured, `issuer='control-plane-a'` →
HTTP 500, zero records.

This also means **the self-verify catches a `Signer.mint()` bug, not a config
mismatch.** One `config.issuer` feeds both sides, so it cannot fire on an
issuer disagreement — the disagreement that matters is control.toml versus
warden.toml, in another process, which that end-to-end test exists to prove the
control plane *cannot* see. The first draft claimed the opposite; the claim was
vacuous and is deleted. (It also cited `explain.py:943` as the `issuer=` idiom.
That line is `Verifier(signer.public_key_pem()).verify(token)` — no issuer at
all. The demo works only because `Signer.generate()` and `Verifier(...)` share
the module default, which a configured control plane does not.)

**(b) One clock read for the whole mint.** `mint()` and `verify()` each read
`time.time()` independently, so with a short TTL the token can expire between
signing and verifying. Measured with `ttl_seconds = 0`: **4 failures in 200 000
mints**, `TokenInvalid("token expired")`, on a config the loader accepts today.
With `now` read once and passed to both — `mint(**request, now=now)` then
`verify(token, now=now)` — **0 failures in 200 000**.

That is exactly the discipline `spine.py:222-225` already states for the
serving path ("One clock read for the whole call … or a call could prune the
very reservation it just took"). Decision 7 closes the same hole from the other
end by refusing a non-positive TTL at load; both are taken, because one makes
the deployment sane and the other makes the route's two steps agree by
construction.

So `record_mint(audit, *, token: TaskToken, args_digest: str)` takes the
`TaskToken` — the parsed, verified grant — and nothing else. One function, in
`warden/broker/control.py`, called by the control route in commit 1 and by
`demo/cli/explain.py` in commit 2. **One place builds a mint record**; the
alternative is the demo growing its own copy, which is precisely the drift
`tests/test_seam.py` and `render_replay`-imported-from-`warden` exist to
prevent.

### 3 · `action` is `{"type": "mint"}` — no `tool` key

There are four action types today, not three: `tool_call`, `tool_list`,
`mcp_handshake` (all spine) and `egress` (the proxy). `egress` carries
`{"type": "egress", "tool": "CONNECT"}` — a type *and* a method, two facts.
`tool_list` and `mcp_handshake` carry a type alone, because there is one fact.

A mint has one fact. `{"type": "mint"}`.

That makes one live reader crash, and it was **already broken**:

```python
# demo/cli/explain.py:1228
"tool": record["action"]["tool"],
```

Confirmed in the spike: `KeyError: 'tool'`. A `tool_list` or `mcp_handshake`
record in a log the demo reads does the same thing today. `_steps_from` is
called at `explain.py:1274`, the `KeyError` is swallowed by the
`except Exception` at `:1486`, and then `_steps_from` is called **again at
`:1491` inside that handler**, where the second `KeyError` is uncaught — so
`warden-demo explain --matrix` dies.

It becomes `record["action"].get("tool") or record["action"]["type"]`, which
renders `mint`, `tool_list` and `mcp_handshake` under their own names and is
unchanged for everything with a tool. A latent-bug fix B7 makes reachable, not
a B7 workaround, and it is tested as such.

`tools/build_corpus.py:73` has the identical unguarded pair and gets the
identical guard, but honestly labelled: it reads only the frozen golden, which
is seven `tool_call` records and is never regenerated, and its
`len(records) != len(DEMO_CASES)` gate at `:87-89` returns 1 before
`policy_input()` is reached anyway. The guard there is **defensive and
unreachable today**. The first draft claimed B7 made it reachable; it does not.

**The loser: `{"type": "mint", "tool": "mint"}`** — one line, no reader
changes. It loses because it writes a false fact (`mint` is not a tool in any
catalog) into a durable artifact to avoid fixing a `KeyError` that is already
live.

### 4 · `rule` is `"mint.unconditional"`, and `decision` is `"allow"`

`decision` must be exactly the string `"allow"` or `replay.py:83-84` renders
the mint as a red `✗ … DENY`. It is also true: the grant was made.

`rule` is the interesting one. `replay.py:88` suppresses the rule only when it
is literally `"allow"`, so writing `rule="allow"` would render the cleanest
line — and would assert that a policy rule named `allow` fired. **Nothing
evaluated this mint.** The route has no caller authentication and no policy
bundle; that is a documented, deliberate out-of-scope boundary
(`THREAT_MODEL.md:56-62`), not an oversight, and the log should say so out
loud.

`mint.unconditional`, in the dotted style `proxy.unparseable` and
`proxy.method_not_allowed` already use, renders as:

```
  ✓ mint(4 tools)                          allow  mint.unconditional
```

An extra token on one line, in exchange for a record that does not claim a
review that did not happen. When C2 gives the control plane a policy, this
string becomes a real rule name and the change is visible in the log. The
comment at `replay.py:87` ("show the rule only when it carries information —
i.e. when it names why something was refused") gets its parenthetical widened;
the stated intent is already right.

### 5 · The mint fails closed: no record, no token, 503

This repo has three positions on a failed audit write, not two:

| Position | Where | Stated reason |
|---|---|---|
| Fail closed | `spine.py:342-350` (allow), `proxy.py:325-331` (authorize) | "If it cannot be logged, it cannot be done" |
| Best effort | `proxy.py:191-193`, `spine.py:496-497` | The outcome is a **refusal**, and there is **no channel** to report an unavailable log through |

The best-effort criterion is twofold and explicit (`spine.py:474-481`). **The
mint satisfies neither half.** Its answer can be "yes", and it is an ordinary
JSON route with a response body.

The cost of failing closed is not uniform across the three ways the append can
fail, and the first draft claimed it was:

- **Persistent (disk full, permissions, a read-only mount).** The control plane
  and the broker write one file. If it is unwritable the spine is *already*
  refusing every tool call with `AUDIT_UNAVAILABLE_ON_ALLOW`, and the proxy is
  already refusing every tunnel — so a token minted anyway can invoke nothing
  and tunnel nothing. Failing the mint costs nothing that was still available.
- **Contention (`_acquire`'s bounded 5 s timeout).** Here the argument above
  does **not** hold: `_acquire` raises only on `BlockingIOError` past the
  deadline, which is positive proof the log is writable and is being written.
  The spine is refusing nothing, and the token withheld would have worked for
  its whole TTL. This is a real cost, and failing closed is chosen anyway,
  because an unrecorded grant is the one thing B7 exists to remove. A transient
  503 on a route called once per task, against a broker whose honest append
  measures ~60 µs, is the cheap side of that trade.

The failure is `OSError`, the response is **503**, and the body is a fixed
constant — never `str(exc)`, whose `_acquire` wording contains the audit path
verbatim. `refusals.py` exists because the HTTP door leaked exactly that in a
503 for a whole task after the MCP door had stopped.

**The constant lives in `control.py`, not `refusals.py`** — decision 9.

**The loser: best-effort, mint anyway.** It would make the README's
unqualified "**Anything that goes wrong refuses.** … a log that cannot be
written: all refuse" (`README.md:173-174`) false, with the single most powerful
action in the system as its only counterexample.

**Ordering: mint → verify → record → return.** The token exists in memory
before the record is written, because `jti` and `exp` do not exist until it
does; but nothing has *happened* until the response goes out, so the record
still precedes the act. That is the spine's own shape (`_append` then
`execute`). The residual is the same one the spine has and names: a record that
was written for a response that never arrived. It errs toward over-recording,
which is the safe direction — see *What this does not do*.

### 6 · Two sentinels, and both say what they are

**`policy_bundle_digest` is the literal `"none"`.** `broker-control`'s volumes
are `./data:/data` and `control.toml` — no `/policies`. The broker binds
`authz.rego` and `data.json` specifically so it can compute
`policy_bundle_digest(bundle_roots)`, and that function *raises* on a missing
root (`policy_digest.py:61-62`) rather than hashing nothing.

Giving the control plane a real digest needs two bind mounts, a `[policy]`
section, and a startup hash. It would also be **a lie**: stamping the digest of
a bundle the control plane never evaluates claims the mint was decided under
it. `ARCHITECTURE.md:352`'s promise is "a decision can always be traced to the
exact bundle that produced it" — and no bundle produced this.

`"none"`, not `"sha256:none"`: the existing `args_digest="sha256:none"`
sentinel wears its field's prefix because arguments conceptually existed and
were deliberately not read, whereas here the bundle does not exist at all, and
a `sha256:`-prefixed value in a digest field reads like a digest. The mint's
own `args_digest` is real, so the two never appear on one record.

**`task_state` is `empty_task_state()`, and it is the *minter's* view.** This
is the sentinel the first draft called honest, and the review was right that it
is not. Task state is keyed by `task_id` and deliberately survives token
renewal (`taint.py:167-169`: "short-lived renewal must not truncate what a
longer one set"). So for a **re-mint** — a renewal against a task that has
already read 5001 rows and holds `pii` — the true state is
`{'data_classes_held': ['pii'], 'rows_charged_so_far': 5001}` and the mint
record will say `[]` and `0`. A durable, hash-chained claim that is not true of
the task, on exactly the re-mint path `THREAT_MODEL.md:134-147` calls the
escalation vector.

It is written anyway, because the alternatives are worse. `replay.py:79` is a
double hard subscript over `task_state["data_classes_held"]` executed for every
record before anything is printed — measured, `{}` raises `KeyError` and `"-"`
raises `TypeError`, both **after** `verify-chain` has reported the log intact.
So the shape is forced. And the control plane holds no task-state store; giving
it one would make the minter read state it has no business reading, over a
Redis the `backend-net` service is not configured for.

What is *not* forced is pretending it is a measurement. It is documented as a
sentinel here, commented as one at the call site, and pinned by a proof row
that mints twice against one live task. A reader who knows what
`action.type == "mint"` means knows the minter has no task state.

*(Rejected: a self-describing `{"data_classes_held": [], "rows_charged_so_far":
0, "measured": false}`. It gives one record type a different nested shape from
every other, which is the drift the body-shape pin test exists to prevent, and
`action.type` already says which record this is.)*

`replay.py` renders `policy_bundle_digest` nowhere — verified, `grep -c`
returns 0 — so neither sentinel can produce an ugly line.

### 7 · `[audit].path` is mandatory in control.toml, and `ttl_seconds` must be positive

The broker reads its audit path through a **mandatory** `[audit]` section
(`loader.py:272`, `:285`). The control plane gets the same, in the same shape,
with the same key name — and mandatory for the loader's own stated reason: "a
config it cannot fully understand must still refuse to start rather than mint
tokens under a guess."

**Section order is `control`, `identity`, `audit`, `tokens`** — matching where
the broker puts it, before `[tokens]`. This is not cosmetic: measured, checking
`[audit]` before `[tokens]` reddens **18** existing tests, after the whole load
**11**. An implementer who picks a different order gets a different failure set
and will wonder which is right.

**The loser: `_optional_section`** — the pattern used for `[mcp]` and
`[task_state]`, whose docstring scopes it precisely: "A surface that is off by
default is the opposite case." Auditing the mint is not a surface that is off
by default; it is the property B7 exists to add, and a control plane that
silently does not have it is the failure this whole document is about.
Optional also earns *no test coverage for free* — every existing fixture keeps
passing, which is the tell.

**`ttl_seconds` must be positive, enforced at load.** `_integer` type-checks
only, so `0` and `-1` both load today and both mint tokens that are expired or
expiring at the instant of issue. That was always a broken deployment; decision
2's self-verify is what makes it *visible*, as an intermittent 500. It becomes
a `ConfigError` at boot — the "quiet weakening this loader exists to turn into
a boot failure" that `_positive`'s own docstring describes. It stays
**mandatory** (an explicit check after `_integer`, not `_positive`'s
defaulted form), because `test_control_a_missing_tokens_section_names_itself`
already pins that a control.toml missing it must refuse to start rather than
mint under a default.

**The path is shared by configuration, not by construction.** `compose.yml:68`
and `:109` guarantee the *directory* (`./data:/data` into both). The *file* is
two independently authored `${VAR}`-interpolated strings that no code compares
— exactly the hazard `[tokens].issuer` already has, and which this repo treats
as first-class with matching warning comments in `control.toml:7-9`,
`warden.toml:10-12`, `loader.py:335-338` and `identity.py:59-65`. The audit
path gets the same treatment: a must-match comment on both tomls and on
`ControlConfig.audit_path`. A one-character typo silently produces the separate
mint log this document rejects, with no error at any boot — see *What this does
not do*.

### 8 · `warden replay` gets a `mint` branch and one `⊕ GRANT` line

Today a mint record renders `?()` — measured:

```
  ✓ ?()                                    allow  mint.unconditional
```

The same illegible line `tool_list` and `mcp_handshake` each needed a branch to
avoid, with the comment "inside the same hash chain as real decisions". This is
the third.

**The rendering was decided by measurement, not by taste.** Four candidates,
against the demo's real `:<38` column and its 76-character separator:

| | Rendering | Line length |
|---|---|---|
| A | `mint(read_document, query_customers, http_fetch, send_email)` | **90** — overflows the separator |
| B | `mint(4 tools)` | 68 |
| C | `mint(task 4711: 4 tools)` | 68 |
| D | `mint(task 4711)` | 68 |

A is out on the measurement. C and D repeat the task id the header already
prints. **B**, plus one indented continuation line carrying what B elides:

```
  ✓ mint(4 tools)                          allow  mint.unconditional
      ⊕ GRANT: read_document, query_customers, http_fetch, send_email
```

69 characters, under the separator. The precedent is exact: `⛔ TAINT` is
already an indented marker line for a fact too important to lose to the column
layout. It goes **after** the mint's own line, not before, because it
elaborates that line — where `⛔ TAINT` goes before its record because the state
snapshot it reports is the one taken *before* that call.

Data classes, counterparties, `jti` and `exp` stay in the record and are
rendered by nothing — exactly like `args_digest`, `policy_bundle_digest`, `ts`
and `seq`, which this renderer has never printed. `warden replay` is a summary;
the log is the record.

This cannot disturb `tests/golden/replay-4711.txt`, which is byte-pinned: the
branch fires only on `action.type == "mint"`, and the frozen chain has none.

### 9 · Shared record vocabulary moves to a stdlib-only module; the mint's refusal wording stays in `control.py`

Decision 2 needs `args_digest`, decision 6 needs an empty task state, and both
live in `spine.py` today (`args_digest` at `:120-122`, `_empty_state` at
`:109-117`). Duplicating either is a drift hazard with a live precedent — A2
changed what task state contains, this quarter.

Importing them from `spine.py` is worse than it looks. Measured, the
`broker-control` process's warden graph:

```
today                                     7 modules
+ spine (directly, or via refusals)      13 modules   <- adds taint, adapters.base
+ audit and a stdlib-only module          8 modules
```

Thirteen puts the whole enforcement stack — the taint store, the adapters base
— into the one process that holds the private signing key, whose two module
docstrings are entirely about staying minimal and topologically isolated. No
key material moves, so this is not a security violation. It is an unremarked
consequence, which is the thing this document is otherwise careful about.

So `args_digest` and `empty_task_state` move to **`warden/broker/record_fields.py`**,
which imports `hashlib` and `json` and nothing else. `spine.py` imports both
from there (its two call sites are unchanged); `control.py` imports both from
there. One definition, imported, without dragging the spine into the signer.
`_empty_state` loses its underscore in the move — it now has a caller outside
its own module — and keeps its docstring's warning about returning a **fresh
dict per call**, which gets more load-bearing with a second caller, not less.

`MINT_UNAVAILABLE_MESSAGE` stays in **`control.py`**, not `refusals.py`, for
the same reason and one better one. `refusals.py:26` is
`from warden.broker.spine import FAULT, Kind`, so importing it costs the same
thirteen modules. And its own docstring scopes it: "Two front doors render the
same Outcome — `app.py` over HTTP, `mcp.py` over MCP … A surface that owned its
own copy would be free to keep leaking after the other stopped." That file
exists because **two** surfaces shared one message and drifted. There is one
control plane, one surface, one message. The rule it encodes — never render
`str(exc)`; render a vetted constant — is honoured in the module that owns the
surface, and `refusals.py`'s docstring gains a sentence pointing at the second
home so a reader auditing "what do we tell callers" finds both.

### 10 · The demo's invariant is narrowed, and the matrix gets a `token` branch

`explain.py:1062-1069` prints `f"{len(records)} — MISMATCH vs {calls} calls"`
under this comment:

> every brokered call writes a record before it acts, so these two numbers must
> agree. If they ever diverge, a call reached the broker and left no trace.

A mint record makes it read `8 — MISMATCH vs 7 calls` — an audit trail that
*looks broken*, in the headline table, which is the exact inverse of what B7 is
for.

The invariant is not wrong; it is **stated over the wrong denominator**. What
it means is "every agent tool call left a record". Counting records whose
`action.type == "tool_call"` says exactly that. It does *not* keep every bit of
the old check's power, and saying so was the first draft's error: a duplicated
or missing **mint** becomes invisible to it, which is the one record type
commit 2 introduces. So the narrowed count is paired with a second, one-line
assertion — **exactly one `action.type == "mint"` record for the task** — which
restores what the narrowing gives away and pins the new behaviour where a
viewer can see it. The displayed count stays the honest total.

*(The narrowed form is true in the presence of the proxy, the MCP era gate and
the mint. It is not unconditionally true of "any non-agent writer": `spine.py:210`
records an unauthenticated probe as `{"type": "tool_call", …}` too. The demo
never produces one, and the comment says which writers it covers rather than
claiming a universal.)*

**And the matrix needs its own branch.** `_target_label` (`explain.py:1143-1155`)
falls through to `return str(kind)`, so decision 1's `kind: "token"` renders
the mint as **`mint(token)`** — measured — a tool call against a resource named
"token", in the same column as real calls, and a second name for a record
decision 8 already named `mint(4 tools)`. `_target_label` gets
`if kind == "token": return f"{n} tools"`, so both renderers say the same
thing. `tests/demo/test_cli.py:935-936` pins only the `{"kind": "future"}` and
`{}` fallbacks, so the branch breaks nothing and is added there.

---

## What changes

**Commit 1 — the control plane records what it grants**

| File | Change |
|---|---|
| `warden/broker/record_fields.py` | **new**, stdlib-only: `args_digest`, `empty_task_state` |
| `warden/broker/spine.py` | import both from there; `_empty_state` → `empty_task_state` at its two call sites |
| `warden/broker/control.py` | `record_mint()`; `create_control_app(*, signer, audit, issuer)`; mint → verify → record → return under one clock read; `MINT_UNAVAILABLE_MESSAGE`; 503 on `OSError` |
| `warden/broker/control_main.py` | `build()` constructs the `AuditLog` and threads `config.issuer` to both the `Signer` and the route's `Verifier` |
| `warden/broker/config/loader.py` | `ControlConfig.audit_path`; mandatory `[audit]` via `_section`, ordered `control, identity, audit, tokens`; `ttl_seconds` must be positive; must-match comment on `audit_path` |
| `warden/broker/refusals.py` | one sentence pointing at `control.py`'s constant |
| `warden/cli/replay.py` | `_describe` `mint` branch; the `⊕ GRANT` line in `render_replay`; widen the `reason` comment |
| `tools/build_corpus.py` | defensive `action["tool"]` guard; reword the "not what the token permitted" comment |
| `demo/scenario/control.toml` | `[audit] path = "/data/audit.jsonl"` + the must-match comment |
| `demo/scenario/warden.toml` | the matching must-match comment |
| `tests/warden/test_config_loader.py` | `CONTROL_COMPLETE` gains `[audit]`; new missing/malformed/positive-TTL tests |
| `tests/warden/test_key_split.py` | `write_control_toml` gains `audit_path`, defaulting to **`tmp_path/"audit.jsonl"`** — not `/data/…`, or `AuditLog.__init__`'s `parent.mkdir(parents=True)` tries to create `/data` inside `build()` |
| `tests/warden/test_cli_config_errors.py` | its inline control.toml gains `[audit]`, so the test reaches the private-key failure it is named for |
| `tests/warden/test_app.py` | `test_control_plane_mints_a_usable_token` takes `tmp_path` and passes `audit=` and `issuer=` |
| `tests/warden/test_audit.py` | the mint-record and two-writer tests (proof rows 1–4, 9) |
| `tests/warden/test_spine.py` | the `_describe` / `render_replay` mint tests (rows 10, 11) |
| `tests/demo/test_isolation.sh` | a positive liveness assertion — see below |
| docs | `WALKTHROUGH.md` (`:348-358` control.toml gains `[audit]` pointing at **`/tmp/wt/audit.jsonl`**, the same file as `:381`; `:528-540` gains the mint + GRANT lines and `8 → 9`; `:1129` `7 → 8`), `ARCHITECTURE.md` (lifecycle step 1, the "every allow, deny and unauthenticated probe" enumeration, the `policy_bundle_digest`-in-every-record claim), `DEPLOYMENT.md:72`, `ROADMAP.md`, `warden/reference/README.md` (**author** a control.toml section — it has none), the stale action-type list in `2026-07-29-…-design.md:146` |

`tests/demo/test_isolation.sh` is on the list because it is the **only CI job
that boots `broker-control`** (`ci.yml:123`), and its `check()` asserts that
minting *fails* — so "ok: minting via broker-control:8081 was blocked" prints
identically whether the network isolation worked or the service never started.
Commit 1 gives that service two new ways to fail at boot (a mandatory `[audit]`
section and an `AuditLog` construction inside `build()`), so the script gains a
positive liveness assertion before its isolation checks. It is also the
cheapest real-Docker version of proof row 9.

**Commit 2 — the demo shows it**

| File | Change |
|---|---|
| `demo/cli/explain.py` | construct the `AuditLog` before stage ⓪; call `record_mint` with `args_digest(grant)` imported from `record_fields`; `NarratedAudit.append` branches on `action.type == "mint"` — `show()` lines only, **no `stage()` call**, so the ⓪–⑪ sequence stays monotonic, with its own `why`; `_target_label` `token` branch; `_steps_from` guard and reworded docstring; the narrowed invariant plus the exactly-one-mint check; the SETUP banner's "empty" line |
| `tests/demo/test_explain_wrappers.py` | drive `NarratedAudit` **and** `NarratedPDP` through the real spine — the file passes a bare `AuditLog` at `:52` and a bare `PolicyDecisionPoint` at `:47-50`, so two of its five wrappers are uncovered by the regression test written to catch exactly this |
| `tests/demo/test_cli.py` | the `_target_label` `token` case beside its `{"kind": "future"}` / `{}` fallbacks |
| docs | `DEMO.md:142`, `WALKTHROUGH.md:663`, `:774`, `:688` (`8 → 9`, plus a line at `:691-696` saying records now exceed calls by one because the mint is recorded and is not a call) |

The `# 7 records, 3 refusals, 1 record read` gate line exists **only** in
completed phases' plan documents (`p2a6:33`, `p2a6:986`, `p2b6:104`). Those are
frozen, like the golden: B7's own plan carries the new line and the earlier
plans are not edited.

`NarratedAudit.append`'s mint branch is the one place in commit 2 where getting
it wrong is **silent**: the method reads only `seq`, `decision`, `rule`,
`prev_hash` and `hash`, all of which a mint record carries, so nothing forces
the branch. Measured, without it a mint prints
`⑧ THE DECISION IS RECORDED — BEFORE ANYTHING RUNS` *inside* stage ⓪, before
stage ① exists, under a `why` claiming "this write happens before the action
executes" about a mint after which nothing executes. And `--quiet-why` does not
hide it: only `why()` is gated on `SHOW_WHY` (`:232`); `stage()` and `show()`
are ungated. So the gate command prints the wrong banner while the counts look
right — hence a proof row, not a manual look.

**Unchanged, deliberately:** `warden/broker/audit.py` (zero interface change,
so `NarratedAudit` cannot rot), `tests/golden/*` (frozen), `README.md:139` and
`DEPLOYMENT.md:195` (frozen-golden sevens), `docs/evidence/*` and
`WALKTHROUGH.md:836` (a frozen `--live` transcript, SHA-256 pinned),
`compose.yml` (the mount already exists), the completed phases' plan documents.

---

## Proof table

Every row is a test, and every row must be **made to fail** before it counts —
including confirming that the mutation reddens *that selector*, not merely the
suite somewhere.

| # | Claim | Caught by |
|---|---|---|
| 1 | A mint record's key set is identical to a tool call's | `test_a_mint_record_has_the_same_fields_as_a_decision` |
| 2 | A mint record chains and verifies among tool-call records | `test_a_mint_record_chains_with_the_decisions_after_it` |
| 3 | The grant recorded is the **token's**, not the request's | `test_the_recorded_grant_follows_the_token_not_the_request` — monkeypatch `Signer.mint` to emit a token whose `allowed_tools` differ from the request's, assert `target.allowed_tools` follows the **token** |
| 4 | The mint record's sentinels are exactly the documented ones | `test_a_mint_record_carries_these_exact_fields` (whole-dict `action`, each principal field, `rule`, `policy_bundle_digest`, `task_state`) |
| 5 | A re-mint's `task_state` is the minter's view, not the task's | `test_a_remint_records_the_minters_empty_view` — charge a live task, mint again, assert `[]`/`0` |
| 6 | A mint the log refused is a mint that did not happen | `test_a_mint_that_cannot_be_recorded_returns_503_and_no_token` |
| 7 | …and its 503 does not leak the audit path | `test_the_mint_failure_does_not_name_the_audit_log` |
| 8 | A non-default `[tokens].issuer` still mints and records | `test_a_configured_issuer_still_mints_and_records` |
| 9 | A control.toml with no `[audit]` refuses to start | `test_control_config_without_audit_refuses_to_load` |
| 10 | A control.toml with `ttl_seconds = 0` refuses to start | `test_control_config_with_a_non_positive_ttl_refuses_to_load` |
| 11 | `create_control_app` cannot be built without a log | `test_the_control_app_requires_an_audit_log` |
| 12 | The control plane and the broker interleave on one file | `test_a_mint_and_broker_appends_produce_one_intact_chain` (**subprocess**, per the B6 pattern) |
| 13 | The mint record renders, above the first tool call | `test_replay_renders_a_mint` + `test_the_mint_record_is_rendered_first` |
| 14 | The grant line names the tools | `test_replay_shows_what_the_mint_granted` |
| 15 | A tool-less record does not crash the step reader | `test_steps_from_survives_a_record_with_no_tool` |
| 16 | The matrix names the mint the same way replay does | `test_the_matrix_step_line_for_a_mint` (`_target_label` + the rendered step) |
| 17 | The demo narrates a mint as a mint, not as stage ⑧ | `test_narrated_audit_narrates_a_mint_differently` |
| 18 | The demo's replay leads with the mint | `test_the_demo_replay_leads_with_the_mint` — `explain.py:1016-1018`'s block, the demo-side twin of row 13 |

Rows 3 and 13 in the first draft were each **wrong about their own catcher**,
which is this project's newest recorded trap and it fired immediately:

- Old row 3 proposed "mint with a TTL the request did not name". `TokenRequest`
  has six fields and no TTL, so that is *every* TTL, and `Signer.mint` copies
  every other field verbatim — request-built and token-built records are
  byte-identical today, and the only mutation that reddens the described test
  is omitting `exp`, which row 4 already pins. The restated row is the only
  construction in which "if those two ever diverge" is testable.
- Old row 13 named "commit 2's gate run, and `test_explain_wrappers`". Neither
  can fail on the claim: `ci.yml` never runs `warden-demo explain`, and
  `test_explain_wrappers` drives a **`Spine`**, which has no mint path at all.
  It is replaced by rows 16–18, each with a selector, and the gate run is
  listed as a manual check *outside* this table.

Row 12 is the one that would have been silently wrong before B6, and it must be
a **subprocess** test: `tests/` has no `__init__.py`, `pytest.ini` sets
`--import-mode=importlib` so a `spawn` child cannot re-import a test module,
and `fork` in a multi-threaded pytest process is a documented deadlock hazard.
`subprocess.Popen([sys.executable, "-c", SCRIPT])` is also the *stronger*
test — a fork would inherit the parent's memory, which is exactly where a
cache-based bug lives.

Row 4 exists because rows 1 and 2 both pass against a record whose `rule` says
`allow` and whose `policy_bundle_digest` is a real digest copied from
somewhere. The field *set* and the *chain* are insensitive to values; only an
explicit assertion pins them.

**Manual, outside the table:** `warden-demo explain --quiet-why` must report
**8 records, 3 refusals, 1 record read** after commit 2, and `--matrix` must
run to completion. Neither is in CI; both are in the gate list.

---

## What this does not do

- **It does not rotate anything.** § B's exit also wants a million-record log
  appending in constant time and verifying across rotation. That is B3/B4, and
  B3 is cheaper after B6 for the reason B6's spec records: the head comes from
  the file, so no process holds a stale head for a rotation to invalidate.
- **It does not authenticate the control plane.** `POST /v1/tokens` still
  authenticates nobody, and B7 does not narrow that — it makes the resulting
  grants *visible*, which is a different and smaller claim. A caller who can
  reach the endpoint can still mint anything; now the log says what they
  minted. `THREAT_MODEL.md:56-62` stands unchanged.
- **It does not attribute a tool call to the grant that authorised it.** Tool
  call records carry no `jti` (`spine.py:578-589`), so a task with two mint
  records — a renewal, or a retry after a response that never arrived — cannot
  be resolved call-by-call. The record-then-return ordering also leaves a
  durable `decision: "allow"` for a token nobody received, which is the safe
  direction to be wrong in and is the same residual the spine already has.
- **It does not make the two writers' paths verifiably the same file.** Under
  compose the directory is shared and the two `[audit].path` strings agree by
  convention and a must-match comment, exactly as `[tokens].issuer` does. A
  typo produces the separate mint log this document rejects, silently, at no
  boot. Comparing them needs something that reads both configs at once, and
  nothing does: `warden config check` takes `--catalog` and `--data` only.
- **It does not give the control plane a policy.** That is C2. Until then
  `rule` is `mint.unconditional` and `policy_bundle_digest` is `none`, and both
  say so.
- **It does not make `flock` work across hosts.** `flock` is per-kernel: two
  brokers plus a control plane on one host sharing a bind mount are covered;
  two hosts sharing one log over NFS are not. That is B5's problem, and it is
  not a shape to reach for here.
- **It does not deliver § A's exit.** Both pieces of shared state work; nothing
  starts the second worker that would share them. There is no `healthz`, no
  `readyz`, no `SO_REUSEPORT`, and `__main__.py` binds the proxy inside the
  same `asyncio.run` as uvicorn. Phase 3 is still the gate.
