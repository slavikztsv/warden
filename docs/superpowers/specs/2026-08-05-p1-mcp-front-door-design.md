# P1 — the MCP front door

**Status:** approved design, not yet implemented
**Supersedes, for P1 only:** [2026-08-05-third-party-agent-integration-design.md](2026-08-05-third-party-agent-integration-design.md),
which remains the four-rung ladder overview. Where the two disagree, this
document is correct.
**Sequenced by:** [docs/ROADMAP.md](../../ROADMAP.md) § P1.
**Verified against:** `mcp==2.0.0` / `mcp-types==2.0.0` (both published
2026-07-28), and a full read of `warden/broker/app.py` with its 32 tests.

---

## What P1 is

A third front door onto the existing enforcement spine, so an agent whose code
you do not own can call brokered tools. Concretely:

1. The `Outcome` refactor: extract `app.py`'s decision logic into a
   transport-free, fully synchronous spine.
2. A Streamable HTTP MCP surface, mounted in the broker process, **disabled by
   default**.
3. `warden mcp`, a stdio forwarder holding one task token and no authority.
4. `inputSchema` generated from the existing `[args]` vocabulary.
5. Two new tool-table keys, `description` and `title`, and the allowlist that
   makes a typo in either an error.

## What P1 claims

**Brokered tools for a containerised agent whose network the operator
controls.** That is the deployment where the containment argument in
[THREAT_MODEL.md](../../THREAT_MODEL.md) actually holds, and it is what the
conformance matrix will be about.

**The stdio shim ships as development and evaluation only.** Two reasons, both
verified rather than argued:

- A local agent runs on the operator's host, which is exactly where
  `compose.yml:112` publishes the control plane — `ports: ["8081:8081"]`. That
  service documents in its own source that it authenticates nobody, and the
  agent's shell tool can reach it. It could mint itself any authority, including
  a fresh `task_id` that resets the row budget. warden's containment argument is
  topological, and that topology does not exist on a laptop.
- With no renewer until P2, a 300s token (`identity.py:30`) kills a real
  client's session within five minutes. Real MCP clients connect once, list
  once, and cache for the session, so expiry landing on `tools/list` is
  unrecoverable — 2026-07-28 forbids the unsolicited `list_changed` that would
  fix it.

Neither is a reason to withhold the shim. Both are reasons not to call it
contained. `ROADMAP.md`'s ladder table gets this stated as plainly as rung 0's
limitation already is.

## What P1 is not

`warden run` and token renewal (P2), shared or durable task state (P3), audit
durability (P4), control-plane authentication (P5), OAuth 2.1 and
protected-resource metadata, and any change to `proxy.py`.

## Two items pulled in from adjacent work

Both because P1 makes leaving them alone wrong, not because they were forgotten.

**`X-Warden-Rule` on the tool API's deny response.** It does not exist today —
only `proxy.py` sets it (lines 228, 245, 267, 284) — yet `README.md:283`'s
integration diagram already tells readers the tool API does. One header, and a
published claim stops being false.

**A test for the deny-path audit-write failure.** `_write_deny_record`'s
`OSError` branch is reachable from all five deny call sites and has zero
coverage; only the allow path and the unauthenticated path are tested. P1
rewrites exactly that code, so "if it cannot be logged, it cannot be done" would
be unguarded precisely where it is being refactored. **This test is written
before the refactor starts.**

---

## §1 · The dependency

`mcp==2.0.0` requires `httpx2>=2.5.0`, `opentelemetry-api>=1.28.0`,
`starlette`, `uvicorn`, `sse-starlette`, `jsonschema`, `python-multipart`,
`pydantic>=2.12.0` and `pyjwt[crypto]`.

**There is no version conflict.** Those are floors, not pins: the tree already
has pydantic 2.13.4, uvicorn 0.52.0 and starlette 1.3.1. `httpx2` is a separate
distribution under a separate top-level name, so the deliberate `httpx==0.28.1`
pin survives untouched — the two coexist rather than one replacing the other.

There is still a **blast-radius** decision. `warden/pyproject.toml` pins four
dependencies against a comment asserting the enforcement point is deliberately
minimal, and this would add a second HTTP stack and a telemetry library to the
one process a subverted agent can reach on two ports. So:

- `mcp` is an **optional extra**, `warden[mcp]`, imported lazily in both the
  broker mount path and `_cmd_mcp`, with a boot-time `ConfigError` when
  `[mcp].enabled = true` and the extra is absent.
- **OpenTelemetry is explicitly neutralised** at broker startup, with a test.
  The SDK installs `_otel.py` as its outermost middleware; in any image that
  also carries `opentelemetry-sdk` with standard `OTEL_*` variables set, the
  enforcement point would begin emitting spans — tool names and request ids — to
  an OTLP endpoint. That is network egress from the broker that does not pass
  through its own proxy and does not appear in the audit log.

---

## §2 · The spine

### Signature

```python
handle_tool_call(credential: str | None, tool: str, args: dict | None, *, now: int) -> Outcome
list_tools(credential: str | None) -> ListOutcome
```

`credential` is the raw bearer string, or `None` when the header was absent or
did not start with `Bearer `. **The spine authenticates.** `Unauthenticated` is
an ordinary `Outcome` variant that owns its own audit write, including the
sentinel fields `task_id "-"`, `agent_id "unauthenticated"`, `purpose "-"`,
`target.kind "unknown"`, `args_digest "sha256:none"` that `warden replay`
already renders.

This is the correction to the earlier draft, which took an already-verified
token. Under that signature `_refuse_unauthenticated` — eighteen lines of
docstring arguing that an unrecorded 401 makes a probe indistinguishable from a
run that never happened, a defect fixed three times on the proxy — stays on the
surface, and the MCP front door gets a second copy. The copy that drifts would
be the one a third-party agent actually reaches.

It also forbids the SDK's `AuthSettings` / `TokenVerifier`, which reject in ASGI
middleware **before any handler runs** and would therefore write nothing.

### The spine is fully synchronous

`_parse_args` is the only `await` in `invoke()` today, which is why `app.py:126`
has to *explain* that the taint snapshot sits after it. Under this design each
surface performs its own async body or params extraction and hands the spine an
already-materialised `args`, so no `await` can exist between `taint.snapshot`
and `taint.record_read` — **not by discipline, but because the function contains
no `await` at all.** A comment becomes a structural guarantee.

The MCP handler is therefore `async def` and calls the spine directly, never via
`anyio.to_thread`. This is not optional: the SDK's high-level server runs plain
`def` handlers on a worker thread, which would move the critical section off the
event loop and make two concurrent calls for one `task_id` genuinely parallel —
both reading `rows_returned_so_far == 0`, both passing `rows.bounded`.

### `Outcome` is a closed, purely descriptive union

The spine performs **every** side effect: `audit.append`, `catalog.execute`,
`taint.record_read`. Rendering is pure and idempotent. Without that rule two
renderers can apply `record_read` twice, or in a different order relative to the
audit write, and the row budget drifts with no signal.

Variant identity must survive rendering, because HTTP status is not the carrier
of meaning: 403 covers six variants, 502 covers three that differ in audit
consequence, and 503 covers three with different causes.

| # | Variant | Trigger | HTTP today | Audit | Executed? |
|---|---|---|---|---|---|
| 1 | `Executed` | policy allowed, `execute()` returned | 200 `{content, rows}` | 1 allow | yes, `record_read` applied |
| 2 | `PolicyDenied` | `Decision(allow=False)` for any bundle rule | 403 | 1 deny | no |
| 3 | `PdpUnavailableDenied` | PDP unreachable or incoherent | 403 | 1 deny | no |
| 4 | `UnknownToolDenied` | `describe()` raised `UnknownTool` | 403 `tools.allowed` | 1 deny, `target.kind "unknown"` | no |
| 5 | `MalformedBodyDenied` | body not JSON / not an object / `args` not an object | 403 `input.malformed` | 1 deny, digest of literal `{}` | no |
| 6 | `SchemaInvalidDenied` | `catalog.validate()` false | 403 `input.malformed` | 1 deny | no |
| 7 | `DescribeClientErrorDenied` | `describe()` raised `ValueError`/`KeyError`/`TypeError`/`IndexError` | 403 `input.malformed` | 1 deny | no |
| 8 | `DescribeBackendFault` | `describe()` raised anything else | 502 | **zero records** | no |
| 9 | `Unauthenticated` | header absent/non-Bearer, or `TokenInvalid` | 401 | 1 sentinel | no |
| 10 | `AuditUnavailableOnUnauthenticated` | sentinel `append` raised `OSError` | 503, 401 suppressed | none | no |
| 11 | `AuditUnavailableOnAllow` | allow-path `append` raised `OSError` | 503 | none | **no — this is the point** |
| 12 | `AuditUnavailableOnDeny` | deny-path `append` raised `OSError`, from all five deny sites | 503 | none | no |
| 13 | `ExecuteFailedAfterDurableAllow` | `execute()` raised, allow already durable | 502 | exactly 1 allow, no second | **yes, partially** |
| 14 | `TaintRejectedAfterExecute` | `record_read` raised `ValueError` | 502 | exactly 1 allow | **yes, taint untouched** |

`ListOutcome` has three: `ListReturned` (no record), `ListUnauthenticated`
(records, with `action={"type": "tool_list"}`), `ListAuditUnavailable`.

That new action shape means teaching `warden/cli/replay.py` to render it —
`_describe` does `record["action"].get("tool", "?")` and would otherwise print
`?()` into the hash chain alongside real decisions.

### Invariants that become tests rather than comments

The code review surfaced 27. These are the ones a careless refactor kills
silently:

- **One snapshot, three consumers** — policy input, audit record, deny record.
  Taken exactly once, never re-read.
- **Audit strictly before execute.** On an allow-path audit `OSError`,
  `execute()` must not run. The existing test asserts `calls == []`, not merely
  the status code.
- **No second decision record once an allow is durable.** Both post-allow
  failure sites return a fault without writing again.
- **The execute guard is deliberately `except Exception`,** not
  `except httpx.HTTPError`. Narrowing it lets a non-httpx bug escape as a 500
  while the audit log already asserts an action that never happened.
- **`except` order around `describe()`:** `UnknownTool` → the four client-error
  types → `Exception`. `UnknownTool` is a plain `Exception` subclass, so the
  order is load-bearing.
- **The client-error tuple is exactly `(ValueError, KeyError, TypeError,
  IndexError)`** and was widened on purpose. Reverting to `ValueError` alone
  sends `KeyError` into the fault branch: a 502 with zero audit records, an
  agent probing with no trace.
- **`validate()` defers on unknown tools,** so an unknown tool surfaces from
  `describe()` as `tools.allowed`, not `input.malformed`.
- **Shape check precedes `describe()`,** so `describe()` and `execute()` are
  guaranteed to read the same args the same way.
- **`MalformedBodyDenied` audits the digest of the literal `{}`,** not of the
  real args.
- **The unauthenticated path never calls `taint.snapshot`** — `_tasks` is a
  `defaultdict`, so it would create a phantom task — and never reads the body.
- **A PDP outage is a 403, not a 5xx.** It flows through the ordinary deny path.
  Mapping it to a fault status in the new renderer would pass every existing
  test.
- **`decision.rule` is recorded on allows too,** as the string `"allow"`, so
  `Outcome` carries a rule for allows.
- **The 200 body is exactly `{content, rows}`.** `data_class` is consumed only
  by `record_read` and never returned.
- **Sentinel records share the hash chain with real decisions,** and a test
  interleaves allow / unauthenticated / allow and verifies the chain.
- **Only `OSError` is caught at all three audit sites.** Anything else escapes.
  Widening it is a real behaviour change in both directions and nothing tests it
  either way — so P1 does not widen it, and says so.

### Two deliberate, named changes

**The clock becomes injected.** Four tests patch `app_module.now` by assignment,
and `app.py:121` resolves it by module-global lookup. If the spine moves to its
own module those four tests silently stop covering token expiry on *both*
surfaces. Injecting the clock through the same wiring that carries the verifier
and PDP gives one patch point covering both, at the cost of editing four tests.

**The deny-path audit-failure test is written first**, before any refactoring.

### Where it lives

`warden/broker/spine.py`, with `app.py` reduced to route registration and HTTP
rendering. `proxy.py` is untouched, and the duplication between the spine and
`authorize_connect` is accepted and documented rather than fixed — the egress
path is the one nothing in CI currently covers, and it is not what P1 is for.

---

## §3 · The MCP surface

### Use the low-level `Server`

Not `MCPServer` (the v2 rename of `FastMCP`). Three forcing reasons: raw-dict
`inputSchema`, per-request `on_list_tools` — which the SDK source itself calls a
"visibility-scoped catalog" — and `async def` handlers.

In v2 the decorators are gone; handlers are constructor kwargs with a uniform
signature `async (ctx: ServerRequestContext, params) -> Result`:

```python
Server("warden", on_list_tools=list_tools, on_call_tool=call_tool)
```

Return values are no longer auto-wrapped: a handler must return the exact
protocol type. Attribute **reads** must be snake_case (`input_schema`,
`is_error`, `next_cursor`), though constructors still accept camelCase.

### Mounting, and three verified footguns

- `streamable_http_app()` returns a Starlette app whose route sits at
  `streamable_http_path` (default `/mcp`), so `Mount("/mcp", app=...)` yields
  `/mcp/mcp`. Pass `streamable_http_path="/"`.
- **The lifespan is mandatory.** A mounted sub-app's lifespan never runs, so the
  host app must enter `session_manager.run()` — and `session_manager` raises if
  touched before `streamable_http_app()` has been called, so ordering matters.
  Consequence for tests: the MCP tests must use `with TestClient(app)`, unlike
  all ten existing bare constructions.
- **DNS-rebinding protection auto-enables** when `host` is loopback and
  `transport_security is None`, returning HTTP 421 "Invalid Host header" behind
  a real hostname. Pass the real host explicitly.

`stateless_http=True`, which affects only the 2025-11-25 leg — 2026-07-28 is
inherently stateless. The cost is `ctx.elicit()` and server-initiated requests,
which warden does not use. Dual-era support comes free from one endpoint: the
`MCP-Protocol-Version` header routes it, with no flag.

### Authentication

Read the raw `Authorization` header off `ctx.request.headers` and hand it to the
spine. Not `get_access_token()`, and explicitly not `AuthSettings` /
`TokenVerifier`. The SDK's own docstring warns that headers are client-supplied
and never an identity assertion, which is exactly right — the spine verifies the
JWT signature, issuer and expiry.

**One accepted disclosure:** `server/discover` and `initialize` are
auto-registered by the SDK and answer unauthenticated. That reveals the server
exists and which revisions it speaks. It does not reveal the catalog, which
requires a token. Documented, not fixed.

### The rendering matrix

The rule: **policy outcomes the model can act on become tool-execution errors;
transport and availability outcomes become protocol errors; no exception text
ever reaches the model.**

| Outcome | `tools/call` |
|---|---|
| `Executed` | `CallToolResult`, at parity with the `{content, rows}` HTTP body |
| 2–7 (all denials) | `is_error=True`, naming the rule — the model-legible path |
| `ExecuteFailedAfterDurableAllow`, `TaintRejectedAfterExecute` | `is_error=True`, phrased **"the action may already have been performed; do not repeat it"**, carrying the durable allow record's `seq` as a correlation id |
| `DescribeBackendFault` | `is_error=True`, fixed text, no detail — nothing was audited |
| `Unauthenticated` | `MCPError`; plus HTTP 401 and `WWW-Authenticate` on the HTTP surface |
| `AuditUnavailableOn{Allow,Deny,Unauthenticated}` | `MCPError` — server unavailability is not a model-adaptable condition |

The post-execute row matters more than it looks. Both variants fire *after*
`catalog.execute()` ran — after the mail was sent. Rendered as an ordinary
"the call failed", the model retries; and because `record_read` never ran, the
retry consumes no row budget and `mail.counterparty` allows the same recipient
again. Duplicate sends, and mail is a shipped adapter kind.

`str(exc)` never reaches the model anywhere. On the execute path it is an httpx
message carrying internal hostnames, ports and database paths — on the HTTP
surface that reached first-party agent code; on MCP it reaches an untrusted
model, and it is also a channel by which a compromised backend injects text.

### `tools/list`

Derived from the loaded catalog, **intersected with the token's
`allowed_tools`**, computed per request. Authenticated listing writes **no**
record — nothing was authorised and no action was taken. Unauthenticated
listing returns `MCPError` and **does** write one, because `ListToolsResult` has
no `is_error` channel.

The filter is usability, never enforcement. A test asserts that a tool omitted
from the list is still refused by `tools.allowed`, with a record, when called
anyway.

### Every handler is wrapped

An unhandled exception is scrubbed to `-32603` on 2026-07-28 but emitted as
`{"code": 0, "message": str(exc)}` on the 2025-11-25 leg — an era-dependent
information leak. warden has two live sources: `audit.append` catches only
`OSError` at all three sites, and `pdp.decide` is not wrapped at all. On the
legacy leg an `OSError` from `AuditLog` would put the audit log's filesystem
path into the model's context.

So both handlers carry a top-level `except Exception` rendering a fixed,
text-free message and logging server-side. A test drives the same forced
exception at both eras and asserts the renderings are identical.

---

## §4 · The stdio shim

No SDK proxy helper exists — `Server` + `Client` composes in a few lines. Six
hardening rules, each pinned by a test:

1. **`trust_env=False`** on the upstream client. Otherwise the shim, a child of
   the agent, inherits `HTTP_PROXY` from rung 0, POSTs to `:3128` in
   absolute-form, and is 405'd by warden's own proxy — never reaching the
   broker, with every attempt audited as `proxy.method_not_allowed`.
2. **Per-request auth via an `httpx2.Auth` subclass that reads the token file**.
   `Client` captures headers once at construction, so "re-reads the token file
   before each request" is otherwise silently false — and would break only in
   P2, as "the session dies at the first renewal".
3. **No redirect following.** A 3xx relocates the `Authorization` header to
   another origin, and under P2 that token is renewed on a timer — a durable
   capability, not a five-minute leak.
4. **`https` required**, with an explicit `--allow-http` for loopback
   development.
5. **Response caching disabled.** `ListToolsResult` is a `CacheableResult` and
   client-side caching is on by default, which defeats token-scoped listing.
6. **Strip `_meta['io.modelcontextprotocol/serverInfo']`** from forwarded
   results, and never write the token to stdout or stderr. Note the v2 stdio
   hardening: while serving, fd 0 points at the null device and fd 1 at stderr.

The shim never exits on a 401 and never tears down its upstream, so a token file
rewritten later is picked up without a restart.

The token file must be mode 0600 and owned by the invoking user; anything
looser is refused.

---

## §5 · Configuration

### `[mcp]` in `warden.toml`

Three keys: `enabled` (bool, default `false`), `path` (string, default `/mcp`),
and `host` (string, no default) — the last passed straight to the SDK's
transport-security settings, because leaving it unset triggers the
DNS-rebinding behaviour described in §3. Three mechanical constraints:

- **The whole table must be optional.** `loader.py`'s `_section()` raises on an
  absent section, so `[mcp]` cannot be read through it — absent must be
  structural, not a comment, or roughly twenty loader tests and both compose
  profiles stop loading. A new `_optional_section` helper is needed.
- **`loader.py` has no `_bool`,** and cannot import `schema.py`'s: `schema.py`
  imports `ConfigError` from `loader.py`, so that direction is circular.
  Duplicate the four lines.
- **MCP config reaches `create_app` as its own parameter,** the way `catalog=`
  already does, and **never** through `BrokerComponents`.
  `as_proxy_kwargs()` returns `as_app_kwargs()` verbatim, and
  `authorize_connect` is keyword-only with no `**kwargs`, so any new key raises
  `TypeError` *inside every CONNECT*, at request time, while the broker still
  looks healthy. That is the trap `wiring.py`'s docstring describes, relocated
  rather than fixed. A test pins `as_app_kwargs()`'s exact key set.

`BrokerConfig` is frozen with nine fields and no defaults, and has exactly one
construction site, so a nested frozen `McpConfig` is added there and defaulted
inside the loader.

### `description` and `title`

New keys on `[tools.<tool>]`, required and non-empty when MCP is enabled.

**This exposes a live gap.** `load_catalog` reads only `kind` and `binding`;
`parse_tool_schema` reads only `args` and `unknown_args`. Neither iterates the
tool table, so `[tools.x] descriptoin = "..."` loads clean today and is silently
dropped. That is precisely the failure `_ARG_KEYS` and `_check_binding_keys`
already exist to prevent, one level up, and it gets materially worse with MCP: a
misspelt `descriptoin` advertises a tool to the model with no description. P1
adds a `_TOOL_KEYS` allowlist — `kind`, `binding`, `args`, `unknown_args`,
`description`, `title` — checked before anything else in the per-tool loop.

### `warden config check`

New checks, hard problems only when MCP is enabled: every tool declares a
non-empty `description` and `title`; every `[args]` schema is renderable to JSON
Schema; `[mcp].path` does not collide with the tool API's `/v1/` prefix.

Two signature constraints. New parameters must be **keyword-only with defaults
reproducing today's behaviour** — roughly eighteen tests call `check_catalog`
positionally. And **both CLI front doors must be updated**: `cli/main.py`'s
`_cmd_config_check` and `cli/replay.py`'s `config` command, which is the one CI
invokes. A test exists specifically because deleting one print loop once left
the whole suite passing.

### Generating `inputSchema`

Total, because the parser closes the vocabulary: `_TYPES` has exactly two
members and `items` must be `"string"` for an array.

| `[args]` | JSON Schema 2020-12 |
|---|---|
| `type = "string"` | `{"type": "string"}` |
| `type = "array"` | `{"type": "array", "items": {"type": "string"}}` |
| `non_empty` | `minLength: 1` / `minItems: 1` |
| `required` | name in `required` |
| `null_is_absent` | type widened to `["string", "null"]` |
| `unknown_args = "reject"` | `additionalProperties: false` |

`null_is_absent` uses a type array, not OpenAPI's `nullable: true`, which would
be *tighter* than `accepts()`. `minLength`/`minItems` stay in place alongside
the null union: 2020-12 applies them only to strings and arrays, matching
`accepts()`'s null short-circuit.

**The generator raises on an unmapped type** rather than emitting `{}`. `_TYPES`
is closed today; a third added later must fail loudly.

**Two legal combinations are unsound once advertised,** and the property test
passes both — so they become `config check` errors when MCP is on:

- `required = true` with `null_is_absent = true`. The schema is faithful, the
  wire is not: MCP clients and JSON serializers routinely drop null-valued
  properties, turning an accepted `{"body": null}` into `{}`, which `validate()`
  rejects as missing-required. Not fixable in the schema.
- `unknown_args = "allow"` on a tool whose adapter has a `fields` allowlist. The
  schema tells the model an extra argument is meaningful, warden accepts and
  audits it, and `execute()` silently drops it — the exact `cc` fail-open the
  args schema was written to close.

Every shipped tool uses the default `unknown_args = "reject"`, so neither bites
today. Both become reachable the day someone edits a manifest after enabling
MCP.

---

## §6 · Test plan

| | Asserts |
|---|---|
| Deny-path audit failure | **Written first.** `_write_deny_record`'s `OSError` yields 503 from all five deny sites |
| Surface parity | Both surfaces driven against the *same* `create_app` and *same* `AuditLog`, parameterised over every reachable variant; audit records equal on every field except `seq`, `ts`, `prev_hash`, `hash`; `taint.snapshot` advanced exactly once per allowed read |
| Rendering totality | Every `Outcome` variant has a defined rendering on each surface |
| Rendering idempotence | Rendering one `Outcome` twice adds no audit records and leaves `taint.snapshot` unchanged |
| Handler is async | The registered `on_call_tool` is a coroutine function |
| Concurrency | The mirror of `test_concurrent_reads_for_the_same_task_do_not_exceed_the_row_bound`, driven through `mcp.Client` |
| List is not enforcement | A tool filtered out of `tools/list` is still refused by `tools.allowed`, with a record |
| Unauthenticated list | Refused **and** recorded, with `action={"type": "tool_list"}`, and `warden replay` renders it |
| Schema agreement | Generated JSON Schema and `ToolSchema.accepts` agree over generated arguments, in both directions |
| Disabled by default | No MCP route exists, `POST /mcp` returns 404, and `as_app_kwargs()`'s key set is pinned |
| Enabling changes nothing else | With MCP on, the REST surface and proxy behave identically |
| Era parity | The same forced exception renders identically at both protocol revisions, with no exception text |
| Shim | `trust_env`, redirect refusal, token-file rotation between calls, token absent from stdout and stderr, refusal of a loose-mode token file |
| Seam | Nothing under `warden/` names a scenario, including the new module and subcommand |

CI drives the surface with the SDK's own client, fully offline. Real
third-party agents are run by hand and recorded, dated, in `docs/evidence/` —
"works with agent X" is a claim about other people's software, and a dated
matrix of what was actually run is the only honest form of it.

---

## §7 · Threat model additions

**The front door contains nothing.** Rung 1 is convenience. An agent reached
over MCP can have four other MCP servers configured that warden has never heard
of. Containment remains the network layout. Making tool brokering easy will make
it *look* like the boundary to someone skimming, so the documentation says
otherwise in the same breath that advertises it.

**The local path is uncontained**, for the reasons in "What P1 claims".

**Rule names in denials make the policy a zero-cost enumeration oracle aimed at
the model.** `DENY_PRECEDENCE` is deliberately ordered so each reported rule is
a *positive* assertion — its own comment says a `pii_sink` denial always means
the destination genuinely passed the allowlist. Fed to a model, `egress.pii_sink`
confirms allowlist membership, `rows.scope` is a per-subject `counterparties`
oracle, `mail.counterparty` the same for recipients, and `rows.bounded`
discloses the remaining budget by bisection. Denied calls never reach
`record_read`, and there is no rate limit anywhere in the repository, so probing
costs nothing.

This does not breach the containment claim: every probe is denied and recorded.
But a subverted model can map the boundary precisely and for free, and the audit
log renders N clean denials that look like a confused agent rather than a
search. P1 keeps the rule names — the design does not work without them — and
adds a **per-task denial counter** surfaced in the audit, so replay can show a
search as a search. An actual denial cap remains `ROADMAP.md` § D6.

---

## §8 · Constraints that will break the build

Literal, because each one is a red CI run.

- `tests/warden/test_seam_precursor.py`: no `.py` under `warden/broker/` may
  contain `read_document`, `query_customers`, `http_fetch` or `send_email`. No
  MCP docstring may illustrate `tools/list` with the demo's tool names.
- `tests/test_seam.py`: the bare substrings `4711`, `8812`, `attacker.example`,
  `docstore.internal`, `support-triage`, `triage-bot`, `refund`, `customers`,
  `demo/` are forbidden in every `.py`, `.rego`, `.toml` and `.json` under
  `warden/`. An example table called "customers" fails.
- `tests/test_docs_are_current.py`: `python -m broker` is a **prefix** match, so
  `python -m broker.mcp` fails. `python -m warden.broker` is safe. A mention of
  the policy file must carry its `warden/` prefix.
- `warden/pyproject.toml`'s `packages` list is explicit, and an unlisted
  subpackage fails at test collection rather than at build. So both new files
  are **modules inside the already-enumerated `warden.broker` package** —
  `warden/broker/spine.py` and `warden/broker/mcp.py` — rather than a new
  `warden/broker/mcp/` subpackage, which would have to be added to that list.
- `tests/warden/test_config_loader.py`'s complete fixture has no `[mcp]`, and
  all twenty broker-config tests must keep passing with it absent.
- `tests/warden/test_arg_schema.py` pins `ToolSchema` hashability, which
  constrains what may be added to `CatalogEntry`.

---

## §9 · What implementation must verify

Carried forward deliberately rather than assumed.

1. The exact conformance obligations of the 2026-07-28 Streamable HTTP headers
   (`MCP-Protocol-Version`, `Mcp-Method`, `Mcp-Name`) against the normative
   specification, not a summary.
2. Whether the SDK's params-validation error for a malformed `arguments` payload
   can be intercepted and routed into the spine as a recorded
   `MalformedBodyDenied`. It currently becomes a `-32602` protocol error with
   **zero audit records** — a probe with no trace, on the surface P1 exists to
   open. If `ServerMiddleware` is the only route, note that the SDK marks it
   provisional and pin the version.
3. Whether `WWW-Authenticate` without a `resource_metadata` parameter sends
   conformant clients into an OAuth discovery flow that cannot succeed. Either
   serve a minimal RFC 9728 document so they fail clearly, or omit the parameter
   and document that OAuth-discovering clients must use the shim.
4. Cursor stability for a per-caller-filtered, paginated `tools/list`.
5. That `mcp` as an optional extra genuinely resolves against the existing pins
   in a clean environment.

---

## §10 · Explicitly out of scope

- `warden run`, token minting and renewal — P2.
- Shared or durable task state, and any lock in `TaintTracker` — P3. P1 pins the
  existing invariant with tests rather than changing it.
- Audit durability and rotation — P4.
- Control-plane authentication — P5. Its absence is why the local path is
  documented as uncontained rather than fixed here.
- OAuth 2.1 and protected-resource metadata.
- Any change to `proxy.py`, including unifying it onto the spine.
- Widening the `except OSError` at the three audit sites. It is a real behaviour
  change in both directions and nothing tests it either way.
