# Roadmap: from reference implementation to production

The README ends its comparison table with a `❌` under **Production**, and the
[limitations](../README.md#known-limitations) say why. This document is the plan
for changing that column, and for the thing that has to land alongside it: making
`warden` usable by an agent whose code you do not own.

Two goals, deliberately stated as one document, because they trade against each
other. A front door that any off-the-shelf agent can walk through is worth very
little if what is behind it holds its security state in a Python dict that one
restart erases. Equally, a broker that survives restarts and scales to four
workers is worth very little if the only way to reach its tool API is to write
your own agent.

**Nothing here was built when this was written; one rung of it has been
since.** Rung 1 of the integration ladder below — the MCP front door — shipped
as P1 and is marked where it appears. Every other "today" claim in what
follows cites the file it was read from, so a reviewer can check it rather
than take it.

---

## What "production" would license us to say

The word is doing real work, so it is worth pinning. Today the README claims a
**reference implementation with a published threat model and stated limits**, and
every claim in it is backed by a run in the repository. "Production" would license
three additional claims, and they are the acceptance criteria for this whole plan:

1. **You can run more than one of it.** Two brokers behind a load balancer decide
   the same way, share one row budget, and write one verifiable audit chain.
2. **A restart is not a security event.** Task state and the audit chain survive
   the process. Today a restart silently resets every row budget and every
   data class held.
3. **An operator can see it and stop it.** Health, metrics, a way to revoke a
   task's authority mid-flight, and a containment property that CI proves rather
   than a reviewer eyeballs.

Anything that does not serve one of those three, or the integration goal, is
listed at the bottom as out of scope. This plan is not a wish list.

---

## Where the line actually is today

Six findings, each read from the source rather than from the limitations list.
Three of them are already documented; three are not, and they are the ones that
change the sequencing.

### Already stated in the README

**The row budget is process-local and unlocked.** ~~[`taint.py`](../warden/broker/taint.py)
holds a `defaultdict` of task state. Two workers do not share it; two requests
in one worker do not lock it.~~ **Half closed by P2·A.** Two requests in one
worker now do lock it, and more than lock it — a call charges its estimate
atomically before the decision. Two workers still do not share it, which is
A2.

**Containment is never tested.** `tests/demo/test_isolation.sh` needs Docker and
[CI](../.github/workflows/ci.yml) does not run it.

**The control plane authenticates nobody.**
[`control.py`](../warden/broker/control.py) says so in its own docstring: whoever
reaches it holds unlimited authority, and only the network layout makes that
acceptable.

### Not stated, found while planning this

**The safety of the row budget today is purchased with a global lock on the whole
process — and nobody wrote that lock.** `app.py`'s snapshot comment is right that
"everything from here to `record_read` is synchronous, so under a single worker
the read-decide-record sequence cannot interleave"
([`app.py:126`](../warden/broker/app.py)). What makes it synchronous is that
`pdp.decide()` uses a **blocking** `httpx.Client` inside an `async def` handler,
as do `audit.append()` and every adapter's `execute()`. The event loop cannot
reach another request during any of it.

That is a correctness win by accident and a throughput ceiling by construction:
the broker serves **one tool call at a time, per process**, and the egress proxy
shares that same loop. `authorize_connect` is likewise a plain synchronous
function called straight from the proxy's async handler
([`proxy.py:71`](../warden/broker/proxy.py)), so a slow backend read stalls every
`CONNECT` behind it, including tunnel setup for calls that have nothing to do with
it.

This reframes the concurrency work. It is not "add a lock so we can scale out".
It is **replace an implicit global serialization with an explicit per-task
critical section**, which is what then permits both real concurrency and more than
one worker. Doing the second without the first would be a regression.

**P2·A did the first, and not with a lock.** A per-task critical section
spanning `execute()` would have to be held across a network call — a
distributed lease needing fencing, where an expiry mid-call is a correctness
hole — and it would serialise a single task's tool calls, which is exactly what
an agent making parallel calls does not want. Charging the estimate before the
decision and settling it afterwards gets the same guarantee with no lock held
across anything slow: the store's atomic charge is the whole of the ordering.
A6 may now make the spine async without removing a control, because the control
is no longer the synchrony.

**A6 then did the second, and the ceiling above is gone — measured, not
asserted: eight concurrent tool calls against a backend taking 200ms each
finished in 1.66s before and 0.23s after.** Every call site —
both front doors' spine calls and the proxy's `authorize_connect` — now awaits
the still-synchronous sequence on a pool the broker owns, so a slow adapter no
longer stalls the loop that every other request and every `CONNECT` shares.
Two things did *not* change, and both matter: the spine is still synchronous
(so nothing that implements or wraps a broker interface had to move), and two
brokers still keep two budgets (that is A2). The paragraphs above are kept as
the account of why the work was sequenced this way, not as a description of
the code.

**The audit log is ~~O(n²)~~ ~~and is not crash-durable~~.** ~~`_head()` calls
`records()`, which reads and JSON-parses the entire file, on **every append**
([`audit.py:64`](../warden/broker/audit.py)). Ten thousand decisions means ten
thousand full-file parses.~~ **Closed by B1**, which landed in front of A6
because offloading onto a lock held across a growing file parse would have
relocated the ceiling rather than removed it: 0.76ms per append at 100
records, 37.1ms at 4000. ~~The head is now read once, on the first append, and
advanced by each write.~~ B6 then replaced B1's *mechanism* rather than
repairing it: the head comes from the file's **tail**, read under the lock, so
nothing is cached and the whole file is never parsed even once. ~~Separately,
`append()` calls `handle.flush()` with no `os.fsync()` — so "the decision is
written down **before** anything happens", the property the whole design turns
on, is durable against a process crash but not against a host loss. The claim
is stronger than the code.~~ **Closed by B2**, which put an `os.fsync` inside
the `flock` and made the level `[audit].durability`, defaulting to the safe
one — measured 16× (~107µs → ~1.7ms per append), flat in log size. ~~Its
`threading.Lock` is also process-local, so a second worker breaks the chain
rather than slowing it.~~ **Closed by B6.**

Two of those three strikethroughs are B2's doing only in the sense that
rewriting a paragraph forces you to read all of it. The `threading.Lock`
sentence and the head-cache sentence were falsified by **B6**, three commits
earlier, and survived because B6 rewrote the § B table row and not this
paragraph. They are struck rather than deleted, because a claim this document
made and stopped being true is part of the account.

**Task state is never evicted.** ~~`TaintTracker._tasks` is a `defaultdict`
that only ever grows; nothing removes a finished task. A long-lived broker leaks
one entry per task forever. Small, unglamorous, and a genuine availability
bug.~~ **Closed by P2·A (A5).** Entries carry an expiry set from the last
token's `exp` plus a configured grace, and a sweep drops them. The trade is
stated rather than hidden: a task silent for longer than the grace starts
clean.

### One drift risk worth naming separately

`policy_bundle_digest` is computed **once at startup**
([`__main__.py:65`](../warden/broker/__main__.py)) and stamped onto every audit
record. OPA can reload a bundle without the broker noticing. The result is an
audit log asserting a policy version that was not the one evaluated — quiet, and
corrosive to the exact artifact this system exists to produce. Whatever the
production policy-distribution story is, the broker must either read the digest
from OPA's own bundle status or refuse to serve when the two disagree.

---

## The integration ladder

The README's limitation is precise: *"the tool API needs an agent you can point at
it"*. Egress has no such limit, because the network contains it. So third-party
support is not one feature, it is four rungs, and a deployment picks the lowest
one that does what it needs.

| | Rung | What the agent's owner changes | Works with | Contained? |
|---|---|---|---|---|
| **0** | Egress proxy only | Five environment variables | Anything that honours proxy variables. **Works today.** | Yes — the network is the boundary |
| **1** | MCP front door | One entry in an MCP client config | Any MCP-capable agent speaking protocol revision `2026-07-28` — older revisions are refused with `-32022`. **Works today, off by default.** | Only where you control the agent's network |
| **2** | `warden run` launcher | Nothing — the launcher writes the config | Any MCP-capable agent, started by an operator | Same as rung 1 |
| **3** | Native tool API | Agent code calls `BROKER_URL` | Your own agent. **Works today.** | Yes |

**Rungs 1 and 2 do not contain a local agent, and the ladder should not imply
they do.** An agent running on an operator's own machine has a route to the
control plane — `compose.yml` publishes it to the host, and it authenticates
nobody by design, so the agent's shell can mint itself unlimited authority. The
containment argument in the threat model is topological, and that topology does
not exist on a laptop. Tool brokering, policy, budgets and audit all still
apply there; egress containment does not. Fixing it is § C1, not a doc change.

Rung 0 already ships and is the honest answer for a truly closed agent: it
contains the network without brokering a single tool. **Rung 1 now ships
too** — the MCP front door landed as P1, off by default; see
[docs/DEPLOYMENT.md](DEPLOYMENT.md#the-mcp-front-door) for turning it on —
and rung 3 already ships and is the most capable. **What remains of the plan
is rung 2**, the `warden run` launcher. The ladder overview is in
[2026-08-05-third-party-agent-integration-design.md](superpowers/specs/2026-08-05-third-party-agent-integration-design.md);
rung 1 is designed in full, and against a verified `mcp==2.0.0`, in
[2026-08-05-p1-mcp-front-door-design.md](superpowers/specs/2026-08-05-p1-mcp-front-door-design.md),
which is authoritative where the two disagree.

Three things about that design belong here, in the roadmap, because they are
decisions rather than details:

**The MCP surface is a front door on the existing spine, not a service in front of
it.** `verify → validate → describe → charge → decide → record → execute` is extracted once
and called by both `POST /v1/tools/{tool}/invoke` and MCP's `tools/call`. A
separate translating process would be free to drift from the thing it translates
for; a shared spine cannot, and a test pins that the two surfaces produce
byte-identical decisions for every case it drives — two reachable inputs where
they provably do not (a non-object `arguments` value, and an explicit
`args: null` against a tool schema with no required arguments) are pinned as
documented exceptions instead, not silently passed over; see
[docs/THREAT_MODEL.md](THREAT_MODEL.md).

**A refusal has to be legible to the model.** A policy denial is returned as a
*tool execution* error carrying the rule name, not a protocol error. The README's
best number depends on this: six of the seven scenarios still delivered their
email *after* being refused. An agent that receives a refusal it can read adapts;
one that receives a transport fault retries the same call.

**The front door contains nothing.** It is a convenience, and saying otherwise
would be the most dangerous sentence in this repository. Containment stays the
network layout. An agent reached through MCP can still have three other MCP
servers configured that `warden` has never heard of.

**Two small items were pulled forward out of later phases while P1 was in the
area, and one item planned inside P1 itself was struck.** The tool API's
`X-Warden-Rule` header — [the README](../README.md#integration)'s own
integration diagram already claimed the tool API set it, and it did not — and
a test pinning what a
*deny* records when the audit write itself fails, both landed during P1
rather than waiting for whichever later phase would otherwise have carried
them. In the other direction, the plan's Task 13 (an era-parity test between
the MCP handshake and modern protocol revisions) was struck: Task 11b's
decision to refuse the handshake era outright left no second era to hold
parity against, so the test became unwritable by construction. What survived
of it — a tool withheld from `tools/list` is still refused by rule, with a
record, when called anyway; the surface serves exactly one protocol era —
was folded into Task 12.

---

## Work, grouped

Sizes are rough: **S** ≈ days, **M** ≈ a week or two, **L** ≈ more than that.
Every item names its exit criterion, because this repository's convention is that
a claim ships with the run that produced it.

### A · Shared, durable task state

The load-bearing one. Everything in the "production" definition depends on it.

| | Work | Size |
|---|---|---|
| A1 | Extract a `TaskStateStore` interface; keep the in-memory one as the default for single-process runs and tests. **Done** — `TaintTracker` is gone; the interface is five methods, and `charge_id`/`now` are caller-supplied so A2's Lua script can implement it unchanged | S |
| A2 | Redis implementation with an atomic reserve-then-increment (one Lua script). **Done** — and narrower than this line said: the check does NOT move into the script. Selected by `[task_state].backend`, memory still the default. Two brokers now share one budget; four workers still need B6 and a process model | M |
| A3 | Change budget semantics from *count what was returned* to **reserve the estimate, then reconcile the actual**. **Done** — and it covers `data_classes_held` too, which this table never mentioned and which had the identical hole | M |
| A4 | Release a reservation when `execute()` fails, so a backend outage does not consume a task's budget. **Done** — and the data class is deliberately NOT released with it | S |
| A5 | TTL eviction keyed on token expiry, closing the unbounded-growth leak. **Done** — plus a second, shorter clock: a per-reservation deadline, so a broker killed mid-call self-heals in seconds rather than at task end | S |
| A6 | ~~Make the spine genuinely async: `httpx.AsyncClient` in the PDP, adapters off the loop via a threadpool, `authorize_connect` awaitable~~ **Done, by one mechanism instead of three** — every call site hands the still-synchronous spine to a threadpool the broker owns. The property this line wanted (nothing blocking the loop) is delivered; the interface churn it implied is not. See below | M |

**Exit:** four workers behind a load balancer, a concurrency test that fires N
simultaneous reads at one `task_id` and asserts the budget is honoured exactly
once, and the `report` scenario's numbers reproduced unchanged under all four.

**A2 has landed, and § A is now complete — but this exit criterion is not,
and the difference is worth stating rather than blurring.** Two brokers share
one budget: ten charges alternating across two independent clients are handed
a distinct prefix and commit one total, and pointing them at different
databases is what breaks it. What stood between that and *four workers behind a
load balancer* was **B6** and a **process model that does not exist**. § A was
one of three things this line needs.

**B6 has since landed, so it is now one of two, and the remaining one is the
one nobody has started.** Two brokers writing one audit file now share the
chain: `seq` and `prev_hash` are allocated under an `flock` on the log itself,
measured against four processes that previously turned 800 records into 451
sequence numbers and a chain broken at seq 52. The process model has not
moved — still no `healthz`, no `readyz`, no `SO_REUSEPORT`, and `__main__.py`
still binds the proxy inside the same `asyncio.run` as uvicorn. Both pieces of
*state* are now shareable and there is still no supported way to start the
second worker that would share them, which is Phase 3's job and not § B's.

Two of A2's five decisions were found by a spike failing rather than by
argument, which is why it was built against a live server before its design
was written down. The sharpest: `EXPIREAT` runs on Redis's wall clock while
`expires_at` is on the caller's injected clock, so the first version deleted
the key on every charge.

**The concurrency test exists and the numbers are unchanged.** Ten simultaneous reads at one `task_id` against a
50-row budget produce five allows and five `rows.bounded` refusals, asserted as
a prefix rather than a count, and the mutation that reverts the charge to a
plain read allows all ten. Sequential runs are arithmetically identical to the
old semantics — each call reconciles before the next charges — so every golden
decision and the `report` scenario reproduce exactly.

A3 was the one to argue about before building, and the argument is written down
in
[2026-08-06-p2a-task-state-store-design.md](superpowers/specs/2026-08-06-p2a-task-state-store-design.md)
with the alternatives it beat. Three of its six decisions depart from what this
section said, which is why they are recorded rather than assumed:

**A2's "reserve-check-increment" cannot put the check in the script.** The limit
is `data.limits.max_rows_per_task` — OPA's data, not the broker's. A Lua script
that checked it would need the budget in two places, which is the drift class D5
already names for the policy digest, and would make `rows.bounded` a decision
the store made rather than the decision function. The charge is an
unconditional atomic increment returning the state *before* it; OPA judges that
with arithmetic and a rego file that did not change.

**`data_classes_held` had the same hole and § A never mentioned it.** It guards
R4 `egress.pii_sink` — a PII read in flight while a concurrent egress sees "no
classes held" is a worse outcome than an overspent budget. It is charged at the
same point, from the tool's binding, which is knowable before `execute()` on all
four adapter kinds. It is monotonic under failure but not under refusal: a
denied call leaves no trace (or one refusal could poison a task deliberately),
while a failed `execute()` keeps the class and returns the rows.

**A6 was delivered as an offload, not as a conversion, and the roadmap line
above was wrong about the mechanism rather than about the goal.** Converting
`PolicyDecisionPoint`, the four adapters and `authorize_connect` to async
would change interfaces that other things implement and wrap — including the
four `Narrated*` wrappers in [demo/cli/explain.py](../demo/cli/explain.py),
which forward hand-written subsets and rot silently; commit `794d876` is that
bug. Two of the conversion's failure modes are also invisible to the gates:
`Spine._settle`'s `operation` parameter is unannotated, so a coroutine passed
through it is `Any` to `mypy` and its `except Exception: pass` swallows the
result; and a half-converted PDP is caught by `pdp.py`'s own `except TypeError`
and returns a *policy denial*, writing one into the tamper-evident chain for
every call while the broker reports healthy.

Awaiting the synchronous spine on a pool at each call site has neither mode,
and it makes A2's sync-versus-async client question moot before it is asked.
The cost is one roadmap line's literal wording. The pool is the broker's own
and sized by `[broker] worker_threads`, because asyncio's default executor is
`min(32, cpu_count + 4)` — invisible and machine-dependent, which is not a
limit this product gets to have undocumented.

**B1 was pulled forward out of § B to land first**, because without it A6
delivers nothing measurable: offloading onto `AuditLog`'s lock, which was held
across a full re-parse of the log on every append, would have moved the ceiling
rather than removed it. Measured before the change: 0.76ms per append at 100
records, 8.0ms at 1000, 37.1ms at 4000 — and 71.8s for 4000 appends.

**The field is now `rows_charged_so_far`.** The quantity is different and
non-monotonic — a concurrent call records a total that a later reconcile brings
back down — and a name promising otherwise sits in the one artifact whose pitch
is that it says what really happened. Version skew fails closed in both
directions: either half reading the other's spelling denies `input.malformed`.

### B · An audit log that survives production

| | Work | Size |
|---|---|---|
| B1 | ~~Cache the chain head in memory after one read at boot~~; stop re-parsing the file per append. **Done**, pulled in front of A6 — and read on the first *append* rather than "at boot", because `warden verify-chain` exists to be pointed at a corrupt log and [cli/replay.py](../warden/cli/replay.py) constructs the `AuditLog` before the guard that reports one. A constructor that parsed the file would make that tool traceback instead of doing its job | S |
| B2 | ~~`os.fsync` before returning from `append()`, with the durability level configurable and the default being the safe one~~. **Done.** `append()` returns only once the record is on the device, so README's "written down **before** anything happens" is true against a host loss and not only against a process crash — the doc change B2 makes is a *subtraction*. The level is `[audit].durability`, in **both** TOMLs, defaulting to `"fsync"`; unlike `[audit].path` and `[tokens].issuer` the two values need **not** agree, because a broker at `"flush"` with a control plane at `"fsync"` is a coherent tiering rather than a misconfiguration. Record 1 also fsyncs the parent **directory**: `fsync` on the file makes its contents durable and says nothing about the directory entry that makes it findable, so without it a power loss can lose the whole log including the record whose `append()` already returned. Measured 16× (~107µs → ~1.7ms), flat in log size, which puts the deployment's audit ceiling at ~590 records/second; `fdatasync` measured *indistinguishable* from `fsync` (1687µs against 1649µs — an append changes the file size, so the metadata flush happens anyway), so there is no third level | S |
| B3 | ~~Segment rotation with an anchor record carrying the previous segment's head hash, so a rotated chain still verifies end to end~~. **Done.** `append()` closes the active segment at `[audit].segment_bytes` — in **both** TOMLs, default 64 MiB (~122,000 records at the 547 bytes one measures), `0` to disable, and like `durability` the two values need **not** agree — and opens a new one whose first record anchors to it. The anchor needs no fourteenth field: the previous segment's head hash is `prev_hash`, the field every record already uses for exactly that, so on B7's precedent it is an ordinary record with `action.type = "anchor"` and thirteen body fields. What it adds is the previous segment's **name**, which is what makes archiving the oldest segment leave something verifiable behind rather than a first record linking to a hash nobody has. One invariant carries the design: `[audit].path` must never, at any instant, name a file with no records in it — so rotation writes the anchor into a staging file and `os.link`s, fsyncs, `os.replace`s, fsyncs, all under the `flock`. The naive order fails **silently**: rename the active file away, let `"a+b"` recreate it, and the tail read answers genesis, the log restarts at seq 1, and `verify_chain()` returns `(True, None)` over a log that now contains two chains. Every append also re-checks that the descriptor it locked is still the file `[audit].path` names — measured without it, four processes × 40 appends at a 4 KiB segment, three runs: 3 of 4 writers dead every run and either a chain BROKEN at seq 33 or a log that refuses to be read. Costs +6.4 µs per append at `flush` and ~2% at the `fsync` default; a rotating append is 6.7 ms, once per 122,582 records | M |
| B4 | Teach `warden verify-chain` about segments | S |
| B5 | A pluggable sink: the file, plus structured stdout for a log shipper, plus an optional append-only external store | M |
| B6 | ~~Multi-writer sequencing — either a dedicated writer, or move seq allocation into the same store as A2~~. **Done, and neither of those.** Both lose to the same fact: the chain is *content*-linked, so handing out a number is not the hard part. A Redis `INCR` cannot supply `prev_hash` at all; a Redis CAS on the head that succeeds and then dies before its file write leaves a `prev_hash` whose record **nobody has** — unrepairable by replay, backup or anything else. `seq` and `prev_hash` are now allocated under an `flock` on the log file itself: the only lock whose scope is exactly the resource, and the only one the kernel releases when the holder dies | M |
| B7 | ~~Audit the **mint**~~. **Done.** The control plane now appends a `mint` record — `action.type = "mint"`, `target.kind = "token"`, the grant itself in `target` — to the same chain the broker writes decisions into, *before* returning the token, and refuses to mint at all if it cannot record. It reuses the existing thirteen body fields with two honest sentinels (`policy_bundle_digest = "none"`, and a `task_state` that is the minter's view rather than the task's), so **zero interfaces changed**. `warden replay` renders it as `mint(N tools)` above the first tool call, with the granted tools on a `⊕ GRANT` line beneath | S |

**Exit:** a million-record log appends in constant time, verifies across rotation,
and B7's record appears in `warden replay` above the first tool call. **All three
clauses are now met by the library**: constant-time append by B6, verification
across rotation by B3 (`AuditLog.records()` and `verify_chain()` span every
segment, walked backward from the active one through the anchors), and B7's
record renders above the first tool call. What is **not** met is the *tool*:
`warden verify-chain` reports a segment problem through `replay.py`'s existing
"cannot read audit log" branch and exits **2**, where a tampered record exits 1
with `chain BROKEN` — so a hand-edited anchor is reported as unreadable rather
than as broken, and a pruned oldest segment is refused rather than verified from
the seq its anchor names. That mapping is exactly what **B4** is, and B3
deliberately did not do it: nothing tracebacks, and every message names the real
problem, which is what a commit that stops short owes the one after it.

B7 was small and disproportionately valuable, and it is done. The audit log's
whole pitch is that it says what was authorised rather than what was reported
afterwards, and the grant was the one authorisation it did not contain. It is
the record for the *most powerful* action in the system, too: naming a fresh
`task_id` resets both the taint state and the row budget (see
[THREAT_MODEL.md](THREAT_MODEL.md)), and that was the only thing here that left
no trace. B7 does not narrow who may mint — that is still topology, and still
out of scope — it makes what was minted visible.

**B7 was listed here as independent, and it was not.** The mint does not happen
in the broker: it happens in [control_main.py](../warden/broker/control_main.py),
a separate process deliberately kept off `agent-net`, which already shares
`./data:/data` with the broker. A mint record written into the same log is
therefore a *second writer by construction* — so B7 done before B6 would not
merely have needed it, it would have **created** the exact corruption B6 exists
to remove, and in the worst shape available: the control plane writes once per
task against the broker's constant traffic, so the breakage would have been
rare, intermittent, and indistinguishable from tampering. B7 is size S after
B6. Before it, it was a way to break the chain.

**B3 is cheaper after B6, not before**, which is also the reverse of how the
sequencing question was posed. Deriving the head from the file instead of from
process memory is exactly what a rotated segment needs — whoever appends next
reads the anchor record the rotation wrote, and no process holds a stale head
for rotation to invalidate. Doing B3 first would have meant two writers
rotating one segment set: strictly worse than two writers on one file.

**That prediction was half right, and B3 found the other half.** No process
holds a stale *head* — but a writer can still hold a stale *descriptor*: it opens
`[audit].path`, spins for the `flock`, and by the time it gets the lock another
writer has rotated, so the file it holds is a **closed segment whose size is
still over the threshold**. It therefore does not merely append into a closed
file, it tries to rotate it, and forks the segment tree. B6 moved the stale state
out of process memory and into the file layer rather than eliminating it, and the
fix is the same shape one level down: compare the locked descriptor's
`(st_dev, st_ino)` against the name's, every append, and reopen when they differ.
The paragraph above is kept because the sequencing conclusion still holds — this
was one check on top of B6, not a redesign of it.

### C · A control plane that can face a network

| | Work | Size |
|---|---|---|
| C1 | Caller authentication — mTLS as the default, since the caller is a service and there is already a keypair story | M |
| C2 | A **mint policy**: which caller may mint which purposes, which tools, and what maximum TTL. Route it through the existing PDP as a second decision path rather than writing new decision code | M |
| C3 | Revocation. Bearer tokens with a five-minute TTL are not revocable, and "stop this task now" is a thing operators need at 3am. A revoked-`jti`/`task_id` set in the shared store, checked at verify | M |
| C4 | Rate limits and request-size caps on both the control plane and the broker | S |
| C5 | TLS on the broker's tool API and proxy. The task token is a bearer credential and today it crosses the wire in plaintext | M |

**Exit:** the threat model's "nothing checks who calls the control plane" bullet is
replaced by a control that is tested, not a topology that is argued.

C2 matters more than it looks. Today a compromised orchestrator is a total
compromise — it can mint any purpose, any tools, any counterparties. Constraining
what a given caller may ask for turns that from total into bounded.

### D · Operability

| | Work | Size |
|---|---|---|
| D1 | `/healthz` and `/readyz`, where readiness genuinely means OPA reachable, audit path writable, catalog loaded, digest computed — and where "not ready" is the correct state when OPA is down, because this system refuses when it cannot decide | S |
| D2 | Prometheus metrics: decisions by rule and outcome, per-stage latency, budget utilisation per task, proxy connections, audit append latency | M |
| D3 | Structured operational logs with a request id, kept strictly separate from the audit log so nobody mistakes one for the other | S |
| D4 | Graceful shutdown that drains in-flight tunnels | S |
| D5 | Resolve the policy-digest drift risk: read the digest from OPA's bundle status, or refuse to serve on disagreement | M |
| D6 | A **denial budget** — end a task after N refusals. The `report` scenario is 41 refusals of an improvising model; in production that is cost, log volume and noise, and there is no reason a task that has been refused forty times should get a forty-first turn | S |

D6 is a new control rather than an operability fix, and it is listed here because
the motivation is operational. It should get its own rule name and its own row in
the README's table if it ships.

### E · Deployment and proof

| | Work | Size |
|---|---|---|
| E1 | Kubernetes manifests plus a Helm chart, with the containment property expressed as a `NetworkPolicy` — the direct analogue of `internal: true` | M |
| E2 | **Run the containment test in CI.** GitHub Actions has Docker; the compose profile and `tests/demo/test_isolation.sh` can both run there. **Done** — the script passes 8/8 and now gates the build | S |
| E3 | The same assertions against a `kind` cluster, so the `NetworkPolicy` is proven and not just written | M |
| E4 | A deployment checklist that fails closed: a `warden config check` extension that refuses a purpose declaring `egress_allow` without an explicit `pii_approved_sinks`, turning today's silent weakening into a boot error | S |

**Exit:** the README's "reviewed by eye, not proven by a test" bullet is deleted
— **met.** E2 was marked done when the job started passing, but the three docs
that told readers CI *never* ran it (README, DEPLOYMENT, DEMO) went on saying so
for four commits. A claim that understates the product is still a claim that
does not match the run behind it
because it stopped being true.

E2 is the highest value-per-hour item in this entire document. The single most
important security property of the system is the one nothing currently checks.

### F · Release engineering

| | Work | Size |
|---|---|---|
| F1 | `ruff` and `mypy` wired into CI. **Done, with one scope cut:** `mypy` runs non-strict over `warden/`, not strict. Strict reported 125 errors against 14 non-strict, which is a project rather than a gate; it stays open below | S |
| F2 | Separate the runtime pins from the test pins. **Done, and it was not a split:** the runtime half was a byte-identical restatement of `warden/pyproject.toml`'s dependencies, and nothing installed from the file. It is now `requirements-dev.txt`, test-only, and CI installs from it instead of pinning the same versions inline in a shell line | S |
| F1b | `mypy --strict` over `warden/`. 125 errors today against 14 non-strict, so it is deferred deliberately rather than skipped. Closing it would also close P1's carried annotation debt on `Spine.__init__` | M |
| F3 | Versioning, a changelog, and a stated compatibility policy for the token claims, the audit record shape, and the policy input document — all three are interfaces other people will depend on | S |
| F4 | Publish to PyPI with trusted publishing, and an image to GHCR with a pinned-digest base | M |
| F5 | SBOM, `pip-audit` in CI, Dependabot, and signed images | M |
| F6 | A security policy with a supported-versions table and a stated response window | S |

### G · Reach

Lower priority than the rest, and listed so it is not mistaken for forgotten.

| | Work | Size |
|---|---|---|
| G1 | Adapter kinds as entry-point plugins, so a fifth kind is an install rather than a fork of `warden/broker/adapters/registry.py`. The registry test keeps its meaning by asserting against the resolved set | M |
| G2 | A generic **OpenAPI adapter**: one binding per operation, `describe()` from the spec. Covers a large fraction of "we need a fifth kind" without a fifth kind | L |
| G3 | Per-tenant policy data, if anyone actually asks for it | L |

G2 over G1, if only one gets built. Most requests for a new adapter kind are
requests for a REST API that happens to have a schema.

---

## Sequencing

Two tracks, run in parallel, because they touch almost disjoint code and because
the integration work is what makes anyone care about the hardening work.

```
Phase 0  ──  gates                     F1 F2 · E2
Phase 1  ──  integration (track one)   MCP front door · warden run
Phase 2  ──  the core (track two)      A · B
Phase 3  ──  the boundary              C · D5 · E4
Phase 4  ──  operate it                D · E1 E3
Phase 5  ──  ship it                   F3 F4 F5 F6
```

**Phase 0 first, and it is small.** Lint, types, split requirements, and the
containment test in CI. Everything after it lands on a build that checks more than
it does today, and E2 in particular should not wait behind a refactor.

**Phase 1 and Phase 2 run at the same time.** The MCP surface calls the extracted
spine; the state work reimplements what the spine calls. They meet at one
interface, which is worth defining on day one and then leaving alone.

**Phase 1 ships as preview, not as production.** This is the sequencing decision
that matters, so it is stated rather than implied: an easy front door onto a
single-worker, in-memory broker invites exactly the deployment this repository
has spent its whole README refusing to pretend is safe. The MCP surface ships
carrying the same limitations block the rest of the product carries, and the
`❌ Production` in the comparison table does not move until Phase 3 is done.

**Phase 3 is where the claim changes.** After A, B and C, all three sentences in
"what production would license us to say" are true, and the column can move.

Phases 4 and 5 are what make it *supportable* rather than merely correct, and a
first real user will generate more useful pressure on their ordering than this
document can.

---

## Carried out of P1

P1 (the MCP front door) shipped with these known, triaged items. Each was raised
by a review, judged not to block the merge, and left deliberately. None is a
defect in what the branch claims; they are the honest remainder.

**Type and naming debt on the enforcement path.** `Spine.__init__`'s
collaborators are unannotated, a step down from the typed `create_app` they
replaced, in what is now the TCB's central class. The module-level
`UNAUTHENTICATED` rule string and `Kind.UNAUTHENTICATED` collide by name and
arrive in one import line in `app.py`. `loader.py`'s `_flag(section, table, key)`
and `schema.py`'s `_bool(table, key, where)` use `table` to mean different things
— deliberate duplication (the import cycle is real), confusing parameter names.
`check.py`'s `_mcp_problems` takes a `catalog_path` it never uses.

**One coupling that is safe for a reason living in another module.** The MCP
surface answers the SDK's internal schema lookup from the *unscoped* catalog,
pre-authentication and unrecorded. That is safe only because
`warden/broker/schema_json.py` emits no `x-mcp-header` opt-ins, so the SDK can
never derive a rejection from it — measured, not assumed. Nothing fails if that
changes. A comment in `schema_json.py` naming the consequence would make the
coupling greppable.

**Malformed-envelope rejections are not recorded.** A request refused for its
*shape* rather than its content — a bad `Accept`, a non-JSON `Content-Type`, a
routing-header mismatch — is rejected by the SDK before any warden handler runs,
with no audit record. Refusals of a named protocol revision *are* recorded, and
no document claims the envelope cases are. Closing it needs `ServerMiddleware`.

**Test-suite remainder.** The `inputSchema` property fixture covers seven of
eight reachable `(type, non_empty, null_is_absent)` combinations; the eighth was
verified correct by hand rather than by the suite. One totality test files
`Kind.LISTED` under protocol errors, where it does not belong. One test reaches
through two objects into a private `_catalog`. The stdio shim has no automated
test of the literal `stdio_server()` path — the residual is SDK-owned file-
descriptor diversion and JSON framing, with every hardening rule exercised before
it.

**Nothing guards the cross-references.** When the decision sequence moved from
`broker/app.py` to `broker/spine.py`, six source comments and one generated
diagram kept pointing at the old home. All are fixed, but the repo's stale-path
scan reads `.py` and `.md` only — it cannot see `.svg`, and it cannot use
`broker/app.py` as a needle because that file legitimately still exists. A scan
that could catch the next one needs to cover generated assets and prose.

---

## Explicitly out of scope

Named so they read as decisions rather than oversights.

- **A managed service, or a UI.** Both are products, not features, and the
  comparison table already points at three vendors for people who want one.
- **TLS interception at the proxy.** Still a stated limitation, still deliberate.
  Terminating TLS to read paths inside an approved host is a defensible option
  for a deployment to choose and a bad one to make the default.
- **An injection detector.** The README's first note exists to refuse this, and
  nothing in production readiness changes the argument.
- **Moving the model provider outside the data boundary.** The threat model
  explains why it is inside, and the honest answers — a model in the boundary, or
  redaction before results return — are deployment choices rather than broker
  features.
- **Per-string taint.** `taint.py`'s docstring already argues the case:
  summarising would launder the class. Task granularity is the design.
