# Third-party agent integration

**Status:** ladder overview. **Superseded for P1** by
[2026-08-05-p1-mcp-front-door-design.md](2026-08-05-p1-mcp-front-door-design.md),
which is authoritative wherever the two disagree.
**Occasioned by:** the README's own limitation — *"the tool API needs an agent you
can point at it"* — and the fix it names but does not build: an MCP server in
front of the broker.
**Companion:** [docs/ROADMAP.md](../../ROADMAP.md), which sequences this against
the production-readiness work.

> [!IMPORTANT]
> **Four claims below were wrong, and the P1 spec corrects them.** Kept rather
> than silently edited, because each was found by reading the code or the SDK
> rather than by rethinking the design.
>
> 1. **The spine signature.** `decide_and_execute(token, ...)` takes an
>    already-verified token, which strands `_refuse_unauthenticated` on each
>    surface — the one branch whose whole purpose is that a refusal must be
>    recorded. The spine must take the raw credential.
> 2. **`X-Warden-Rule`.** The tool API does not set it; only `proxy.py` does.
>    (`README.md`'s integration diagram is wrong about this too. P1 adds the
>    header rather than editing the diagram.)
> 3. **The parity test is a tautology** as described here: if both surfaces call
>    one function, "identical decisions" is true by construction. It has to
>    compare audit records and taint effects end to end instead.
> 4. **Rung 2 does not make the local case contained.** The stdio shim's target
>    deployment puts the agent on the operator's host, which is where the
>    unauthenticated minter is published. Renewal was also under-specified: a
>    `Client` captures its headers once at construction, so re-reading a token
>    file per request needs an explicit auth hook.

## The problem

`warden` has two enforcement surfaces and they have very different reach.

The **egress proxy** works with an agent nobody can modify. It needs five
environment variables, it is honoured by every HTTP client that reads
`HTTP_PROXY`, and the containment does not depend on the agent cooperating —
the network has no other way out. That half of the product is already
zero-intrusion.

The **tool API** does not. `POST /v1/tools/{tool}/invoke` with a bearer token is
a perfectly reasonable HTTP interface and no off-the-shelf agent speaks it.
Something has to call `BROKER_URL`, and today that something is code you wrote.
So the richest half of the policy — `tools.allowed`, `rows.bounded`,
`rows.scope`, `mail.counterparty`, the whole `describe()`/`execute()` split that
lets policy judge *whose records, how many rows* — is available only to
deployments willing to write an agent.

That is backwards. The deployments with the most to lose are the ones buying an
agent rather than building one.

## What "low intrusion" has to mean

Not a slogan. The measure is **how many artifacts the agent's owner has to
author**, and there are four rungs. A deployment picks the lowest one that does
what it needs, and the two middle rungs are what this design builds.

| Rung | Author | Reach | Status |
|---|---|---|---|
| 0 · egress only | 5 environment variables | Network containment. No tool brokering | **ships** |
| 1 · MCP front door | 1 MCP client config entry | Both surfaces | this design |
| 2 · `warden run` | nothing | Both surfaces, plus renewal | this design |
| 3 · native tool API | agent code | Both surfaces | **ships** |

Rung 2 is the interesting one. An operator types one command and a third-party
agent runs brokered, with no file the operator wrote by hand and no line of the
agent's code touched.

---

## Part 1 — The MCP surface

### It is a front door on the spine, not a service in front of it

The decisive structural choice. `warden` grows a third front door onto the
**same** `verify → snapshot → validate → decide → record → execute` sequence
that `POST /v1/tools/{tool}/invoke` already runs, in the same process.

The alternative — a separate MCP process that speaks HTTP to the broker — is
easier to build and worse in the way that matters. It would be free to drift:
to normalise an argument before forwarding, to retry a denial, to answer
`tools/list` from a stale copy of the catalog. Every one of those is a way for
what was judged and what was executed to disagree, which is the exact failure
[`adapters/base.py`](../../../warden/broker/adapters/base.py) exists to prevent
one layer down.

So the work starts with a refactor, and the refactor is most of the risk:

1. Extract the body of `invoke()` in
   [`app.py`](../../../warden/broker/app.py) into a transport-free function —
   call it `decide_and_execute(token, tool, args) -> Outcome` — where `Outcome`
   carries the decision, the rule, the result and the audit record that was
   written.
2. `POST /v1/tools/{tool}/invoke` becomes a thin HTTP rendering of `Outcome`.
3. `tools/call` becomes a thin MCP rendering of the same `Outcome`.
4. A test asserts the two renderings come from identical decisions for identical
   calls — the same discipline `tests/test_seam.py` applies to the product/demo
   boundary, pointed at a new seam.

Everything the surface-specific code may do is *render*. No surface may decide,
audit, or normalise.

### Transport and protocol revision

Two transports, because MCP clients split between them and each half of the
split matters here.

**Streamable HTTP**, served by the broker itself at a configurable path
(`[mcp] path = "/mcp"` in `warden.toml`, disabled by default). This is the real
surface. It is what a hosted or containerised agent connects to, and it is the
one that runs inside the trust boundary the rest of the design assumes.

**stdio**, served by a `warden mcp` subcommand that is a *forwarder and nothing
else*: it speaks stdio to the agent, forwards to the Streamable HTTP surface, and
contains no policy, no catalog, and no decision. Local agents — the editor and
CLI-shaped ones — overwhelmingly want stdio, and a shim that holds no authority
is a much smaller thing to reason about than a second enforcement point.

**Target revision: 2026-07-28**, with 2025-11-25 supported as a compatibility era
if the chosen SDK offers it. Two properties of 2026-07-28 are unusually good news
for this design, and one is a caution:

- It is **stateless**. The `initialize`/`initialized` handshake and the
  `Mcp-Session-Id` session are both gone, so a conformant server can sit behind an
  ordinary round-robin load balancer with no sticky routing. `warden`'s spine is
  already per-request with all state keyed by the token's `task_id`, so the
  protocol's session model and the broker's stop fighting each other. Note the
  asymmetry this exposes rather than hides: the *protocol* needs no stickiness,
  but the *row budget* does, which is precisely the shared-state work in
  [ROADMAP.md § A](../../ROADMAP.md).
- Tool `inputSchema` and `outputSchema` are **full JSON Schema 2020-12**, which is
  more than enough to express `[tools.<tool>.args]` losslessly.
- The caution: it is a **breaking** revision, and client adoption in the field
  will lag it. Supporting one era is much less work; supporting two is what makes
  rung 1 true for agents shipped before the migration. Decide before building,
  not after — it is listed as an open question below.

> These protocol details were read from the 2025-11-25 changelog and the
> TypeScript SDK's 2026-07-28 migration notes, not from the normative
> specification text. Confirm each one against the spec at implementation time.
> In particular the required Streamable HTTP headers (`MCP-Protocol-Version`,
> `Mcp-Method`, `Mcp-Name`) and the authorization requirements should be read in
> full rather than inferred from a summary.

### `tools/list`

Derived from the loaded `ToolCatalog`, **intersected with the token's
`allowed_tools`**. An agent is shown only what it may call.

That is a usability decision, not a security one, and the distinction has to
survive contact with the code. Enforcement stays exactly where it is: at
`tools/call`, via `tools.allowed`, on the shared spine. The filter on the list is
there so a model does not spend its turns discovering by refusal — the `report`
scenario's forty-one refusals are what that looks like — and it must never become
the thing anyone relies on. A test should assert that a tool omitted from the
list is still refused by rule, with a record, when called anyway.

**`tools/list` requires a valid token.** An unauthenticated catalog listing hands
out the deployment's tool names, descriptions and argument schemas, which
together are a map of the internal systems behind the broker. An unauthenticated
list attempt is recorded as a refusal, on the same argument
`_refuse_unauthenticated` already makes for the tool API: a probe that leaves no
trace is indistinguishable from a run that never happened.

An *authenticated* list writes no decision record. Nothing was authorised, no
action was taken, and audit-logging every client's periodic refresh would bury
the records that matter.

### Tools need descriptions, and the catalog has none

The gap that makes this more than plumbing. MCP tool definitions carry a
`description` — it is how a model knows what a tool is for — and
[`tools.toml`](../../../demo/scenario/tools.toml) has no such key today, because
nothing has ever needed one.

Two new optional keys on each tool, alongside `kind`:

```toml
[tools.query_customers]
kind        = "sql"
title       = "Customer lookup"
description = "Look up a customer record by id. Returns one row per match."
```

`warden config check` requires both when the MCP surface is enabled in the same
config, and does not mention them otherwise — so an existing deployment that
never turns MCP on is unaffected, and one that turns it on cannot half-configure
it. An empty description is a tool the model will misuse.

### Generating `inputSchema`

Mechanical, from the single source that already exists. `ArgSpec` in
[`config/schema.py`](../../../warden/broker/config/schema.py) carries five keys
and each maps cleanly:

| `[args]` | JSON Schema |
|---|---|
| `type = "string"` | `{"type": "string"}` |
| `type = "array"`, `items = "string"` | `{"type": "array", "items": {"type": "string"}}` |
| `non_empty = true` | `minLength: 1` / `minItems: 1` |
| `required = true` | name appears in `required` |
| `null_is_absent = true` | type widened to include `"null"` |
| `unknown_args = "reject"` | `additionalProperties: false` |

The risk is divergence, and it is a real one: MCP clients validate arguments
against the advertised schema before sending, so a schema that is *looser* than
`ArgSpec.accepts` produces calls the broker then refuses as `input.malformed`,
and one that is *tighter* produces calls the client refuses to make at all —
silently, with no record anywhere, which is the worse of the two.

So this gets a property test rather than a unit test: over generated argument
dictionaries, client-side JSON Schema validation and `ToolSchema.accepts` must
return the same verdict. Whichever direction it drifts, the test catches it.

### A denial must be legible to the model

The most consequential rendering decision in the design.

A policy denial is returned as a **tool execution error** — an error the model
receives as a tool result and can read — **not** as a protocol error. It carries
the rule name and the same message the HTTP surface puts in `X-Warden-Rule`:

```
Denied by policy rule rows.bounded.
The task's row budget is exhausted. A narrower query may succeed.
```

The README's best number depends on this working. **Six of the seven scenarios
still delivered their email** after being refused: refusal and a finished task
coexist, and they only coexist because the agent could tell what happened and
adapt. An agent that receives a transport fault instead retries the identical
call until something gives up.

This is also the direction MCP itself moved — 2025-11-25 reclassified input
validation failures from protocol errors to tool execution errors, for exactly
this reason — so the conformant rendering and the useful one are the same
rendering.

The three non-denial failures keep their current distinctions, because the
existing code went to some trouble to separate them and collapsing them at the
MCP boundary would undo it: `unauthenticated` stays a transport-level 401 with
`WWW-Authenticate`, `audit_unavailable` stays a retryable server-side failure,
and `backend_error` stays a tool execution error that names the backend rather
than the policy.

### Authorization

The task token, presented as `Authorization: Bearer`. It is already a signed,
audience-scoped, short-lived credential; MCP's OAuth machinery is built for
user-facing servers negotiating consent, and warden's tokens are machine-minted
per task by an orchestrator that has already decided.

The obligations that are worth taking on now:

- Return `WWW-Authenticate` on a 401, so conformant clients surface the failure
  as an auth problem rather than an outage.
- Never accept a token on the MCP surface that the tool API would reject. One
  `Verifier`, one code path — a second acceptance rule is a second bug.

Full OAuth 2.1 with protected-resource metadata is **deferred**, and stated as
deferred rather than quietly omitted. It becomes necessary the day someone wants
a public hosted agent to connect directly; it is unnecessary for every deployment
where an orchestrator mints and injects. Revisit it alongside
[ROADMAP.md § C](../../ROADMAP.md), which is where revocation lands anyway.

---

## Part 2 — `warden run`

Rung 1 still asks the operator to author an MCP client config with a token in it,
and to re-author it when the token expires five minutes later. Rung 2 removes
both.

```
warden run --control http://broker-control:8081 \
           --task 4711 --purpose support-triage \
           --tools read_document,query_customers \
           --counterparties customer:8812 \
           -- <the third-party agent, unchanged>
```

What it does, in order:

1. **Mints**, by calling the control plane with the operator's credential. This
   runs on the orchestrator's side of the boundary, which is the only place that
   credential may exist.
2. **Writes the token to a mode-0600 file**, not to the child's environment.
3. **Prepares the child's environment**: the proxy variables of rung 0, plus an
   MCP client config pointing at the broker's `/mcp`, generated in whatever
   layout the target agent expects.
4. **Runs the agent as a child process** and waits.
5. **Renews** at half the TTL, reusing the **same `task_id`**, rewriting the
   token file atomically.
6. **On exit, revokes** — once [ROADMAP.md § C3](../../ROADMAP.md) exists to
   revoke against.

### Why a token file rather than an environment variable

Because a running process's environment cannot be updated from outside it, and a
five-minute TTL against an agent session that runs for an hour needs renewal
twelve times. So the token lives in a file, `warden mcp` re-reads it before each
forwarded request, and renewal is an atomic rewrite the shim picks up without
restarting or being signalled. Re-reading a small local file per call is cheap
next to the broker round-trip it precedes.

This is the mechanism the README already describes as *"designed-for rather than
demonstrated"*: the budget and the data classes held live in the broker under
`task_id`, so renewing does not reset them. `warden run` is the thing that
finally demonstrates it.

### What it must not do

`warden run` holds a control-plane credential, and it starts a process that must
never have one. So: the child's environment is **constructed, not inherited** for
every warden-related variable. The control URL and the operator credential are
removed rather than merely not added. A test should assert that no variable
naming the control plane survives into the child.

It also must not learn anything about a scenario. Purpose, tools and
counterparties are flags. `tests/test_seam.py` scans every file under `warden/`
for demo strings and this new subcommand is squarely in scope.

---

## What this changes about the threat model

Four new statements, and one of them is a warning rather than a control.

**The front door contains nothing.** Rung 1 and rung 2 are convenience. An agent
reached over MCP can have four other MCP servers configured that `warden` has
never heard of, and can reach any of them. Containment remains what
[THREAT_MODEL.md](../../THREAT_MODEL.md) says it is: the network layout, with the
broker as the only route out. Making tool brokering easy will make it *look* like
the boundary to someone skimming, and the documentation has to say otherwise in
the same breath it advertises the feature.

**The stdio shim runs inside the agent's blast radius.** It is a child process of
an untrusted agent, so treat it as untrusted: it holds one task token, it holds
no key, it knows no control-plane URL, and it makes no decision. Worth pinning
with an import test in the shape of the existing seam test — the shim module must
not be able to import `Signer` or the control app.

**Renewal means the TTL is not a bound on a task's life.** Five minutes bounds
how long a *stolen* token is useful. It never bounded the task, and rung 2 makes
that visible by renewing on a timer. The controls that bound a task are the row
budget and the data-flow rules, both of which persist across renewal by design.

**A cached `tools/list` can be stale.** MCP clients may cache the list across a
policy change. Cosmetic, because enforcement is at `tools/call` and the stale
entry is refused by rule with a record. Worth stating so nobody reports it as a
bypass.

---

## Test plan

The repository's convention is that a claim ships with the run that produced it,
so these are the runs.

| | Asserts |
|---|---|
| Surface parity | REST and MCP produce identical decisions, rules and audit records for identical calls |
| Schema agreement | Generated JSON Schema and `ToolSchema.accepts` agree over generated arguments, in both directions |
| Denial legibility | A denied `tools/call` returns a tool execution error naming the rule, and the audit record is written |
| List is not enforcement | A tool filtered out of `tools/list` is still refused by `tools.allowed`, with a record, when called anyway |
| Unauthenticated list | Refused and **recorded**, with the same sentinel principal fields the tool API uses |
| Shim isolation | `warden mcp` imports nothing that can sign, and no control-plane URL reaches a child of `warden run` |
| Renewal | A task renewed across TTL boundaries keeps one row budget and one set of data classes held |
| Seam | Nothing under `warden/` names a scenario, including the new subcommands |

And one piece of evidence rather than a test: **a conformance matrix**, recorded
the way `docs/evidence/` records everything else. Which third-party agents were
actually driven end to end through the brokered path, at which protocol revision,
on which date. "Works with MCP-capable agents" is a claim about other people's
software and it ages; a dated matrix of what was run is the only honest form of
it.

---

## Open questions

1. **One protocol era or two?** Supporting 2026-07-28 alone is materially less
   work. Supporting 2025-11-25 as well is what makes rung 1 true for agents that
   have not migrated. This depends on the field, so it should be answered by
   looking at the clients a real deployment wants to use, not by preference.
2. **Should `tools/list` filter on more than `allowed_tools`?** A purpose whose
   `egress_allow` cannot reach a tool's backend makes that tool useless for the
   task, and showing it wastes turns. Against: the list would start encoding
   policy reasoning, which is the thing this design keeps out of the surfaces.
   Leaning against.
3. **Which MCP SDK, or none?** A dependency brings conformance and a migration
   treadmill; hand-rolling a stateless JSON-RPC surface is genuinely small now
   that sessions are gone. The answer probably differs for the HTTP surface
   (fewer moving parts, hand-rollable) and the stdio shim (more client quirks,
   worth a library).
4. **Does `warden run` generate config for specific agents, or one generic
   layout?** Per-agent generation is what makes rung 2 feel like zero intrusion,
   and it is also an open-ended maintenance commitment against other people's
   config formats. A small set, named and dated in the conformance matrix, is
   probably the honest middle.
5. **Does `outputSchema` buy anything?** Declaring one would let a client validate
   results structurally. The current `ToolResult` is `content` plus `rows`, and
   the MCP rendering should stay exactly at parity with the REST response rather
   than inventing a richer shape for one surface.
