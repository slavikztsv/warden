# Threat model

**Stance: prompt injection is assumed to succeed.** There is no classifier and
no guardrail model. The agent will be subverted; the control is that a
subverted agent holds no authority worth abusing. Injection is treated as a
confused-deputy problem, not a content problem.

## In scope

| Threat | Control |
|---|---|
| Prompt injection as confused deputy | Containment. Authority scoped below the damage threshold. |
| Credential theft from the agent | Nothing to steal — the runtime holds no long-lived credentials. |
| Out-of-band network bypass | No route exists. `agent-net` is `internal: true`, so Docker attaches no gateway. |
| Agent minting itself a broader token | The minting endpoint runs as its own service (`broker-control`) with no route from `agent-net` — it sits on `backend-net`, plus a host-published port for the demo's orchestrator. The broker — the one service the agent *can* reach — loads only the public key and cannot sign. |
| Bulk exfiltration | 50 rows per task, accumulated across calls; 5-minute token; purpose-scoped egress. |
| Data reaching an unapproved sink | Task-level taint (`egress.pii_sink`), independent of destination reputation. The model provider is the **only** approved HTTP PII sink — a deliberate boundary decision, argued below — so PII otherwise leaves only through the mail tool, to counterparties the task declared up front (`mail.counterparty`). |
| Log tampering to hide an attempt | Hash-chained audit records; any edit breaks the chain. |

- **Reads were bounded by volume, not by subject — now closed by `rows.scope`
  (R7).** `rows.bounded` caps how *many* customer records a task may read;
  nothing capped *which*. A support-triage task for `customer:8812` could read
  customer 9999's record: one row, inside the budget, inside policy, recorded
  as a clean allow. `counterparties` governed `mail.counterparty` alone and had
  never applied to database reads.

  Found by building `--task crosscheck`, not by reading the rules — a live
  model asked to "check a few other customers" read three records with zero
  refusals. `warden/broker/adapters/sql.py`'s `describe` now resolves a query
  into the subjects it names, and R7 denies any that the token did not
  declare. The same scenario now reads one record and refuses the other four
  calls.

  Two design notes worth stating. A read reaching an unbounded set (`plan=pro`,
  or no filter) reports the subject `"*"`, which can never appear in a
  counterparty list, so it is out of scope by construction rather than by a
  second rule. And R7 applies only when the task declared counterparties: a
  token naming no subjects has no subject scope to enforce, and `rows.bounded`
  remains its only read control. That is explicit, and it is a real residual —
  a purpose minted with an empty `counterparties` list gets volume limits only.

## Out of scope

- **Malicious runtime code / supply chain.** The runtime image is trusted. A
  compromised runtime can still misuse its own valid token within policy.
- **Covert channels inside allowed destinations.** No TLS interception: the
  proxy sees `CONNECT host:port` only. Data can be encoded into a URL path or
  a DNS-over-HTTPS query to an approved host.
- **The broker is the TCB** for enforcement. Compromise it and every decision
  it makes is worthless. It is kept small and single-purpose so it can be read
  end to end. It is *not* the TCB for identity: it holds only the public key,
  so a compromised broker still cannot mint a token, and every token it
  accepted remains attributable to the control plane that issued it.
- **Multi-agent delegation chains.** Not built. The token carries a
  `delegated_from` slot so the extension is sketchable.
- **Authenticating the control plane.** `POST /v1/tokens` has no caller
  authentication and lets its caller choose `task_id`, `purpose`,
  `allowed_tools` and `counterparties`. Anything that can reach it holds
  unlimited authority here. What keeps that acceptable is topology, not a
  check: it runs as its own service on `backend-net`, published to the
  host for the demo's orchestrator, with no route from `agent-net`. Adding
  mTLS or an operator credential is the next trust boundary out.

## Known limitations, found during implementation

These were discovered while building and reviewing, and are stated rather than
quietly fixed. Each is a real property of the system as shipped.

- **The row bound is concurrency-safe by construction only under a single
  worker, not by any lock.** The broker's handler is `async def`, and its only
  `await` (parsing the request body) runs *before* the taint snapshot is
  taken; everything from the snapshot through `taint.record_read` — decide,
  audit, execute, record — is synchronous. On a single-threaded event loop
  that makes the read-decide-record sequence atomic with respect to other
  requests: nothing can interleave inside it, because nothing yields control
  during it. This was found the hard way: an earlier version took the
  snapshot *before* the request body was parsed, putting that `await` inside
  what was supposed to be the critical section, so two concurrent calls for
  the same task could both read `rows_returned_so_far` before either recorded
  its own read — a live TOCTOU, not a latent one, and it would interleave on
  one worker, one event loop, no threads required. Moving the snapshot to
  after the last `await` closed it. The safety is still fragile: change the
  handler to `def` (Starlette then uses a threadpool), introduce an async
  HTTP client anywhere between the snapshot and `record_read`, or run a
  second worker, and the race reopens silently — no test would catch it
  short of the concurrency test added for this specific case. A structural
  fix needs a lock inside `TaintTracker`. **Single-worker deployment is a
  requirement, not a default: two workers share no lock, so the single-event-
  loop argument does not extend to them.**
- **The mail counterparty control was bypassable through the HTTP tool.**
  `mail.counterparty` guards `target.kind == "mail"`, and the shipped
  configuration listed `mailer.internal` in both `egress_allow` and
  `pii_approved_sinks` — so a PII-tainted
  `http_fetch("http://mailer.internal/send", body=<the customer rows>)` was
  `kind == "http"`: allowlisted, PII-approved, and governed by no counterparty
  rule. It evaluated to allow with an empty `deny_reasons`, i.e. a clean
  record in the audit log. Closed by emptying `pii_approved_sinks` of every
  host you can *send* data to — its single remaining entry is the model
  provider, a separate decision argued below. No test
  could have caught it: every case in `authz_test.rego` mocked `data`, so the
  shipped `data.json` was never evaluated. The tests that close it deliberately
  do not mock it.
- **The minting endpoint was reachable from the agent, and this document said
  it was not.** An earlier version generated the keypair inside the broker and
  served the control app from that same process on `0.0.0.0:8081`, while
  Compose attached `broker` to `agent-net`. `ports: ["8081:8081"]` publishes to
  the *host*; it does not restrict container-to-container reach, so
  `agent-runtime` could POST to `broker:8081` and mint itself any token it
  liked — including one naming a fresh `task_id`, which resets both the taint
  state and the row budget. Every other control in this document assumes the
  token bounds the agent, so this defeated all of them at once. Fixed by
  splitting minting into a `broker-control` service attached to `backend-net`
  only, and by generating the keypair outside every container so the broker
  loads the public half alone. **The enforcement point now holds no signing
  key**, which is strictly stronger than the original design: even a fully
  compromised broker cannot mint.
- **One of the two live clients is invisible to CI.** `google-genai` is not a
  dependency, so its tests skip in CI and nothing reaches a real API. The
  OpenRouter client is the exception: it speaks the OpenAI HTTP shape over
  `httpx`, needs no vendor package, and its request/response cycle is covered
  by tests that do run in CI — the provider with no SDK is the only one with
  continuous coverage. `GeminiClient` is driven by a stub that pins the request
  shape and the turn alternation but cannot prove the live API accepts it.

  That client once answered only the first tool call in a turn, and the defect
  was **not** theoretical — Gemini returns multi-call turns routinely, and
  dropping the extras produced a delayed, badly misleading symptom: the model's
  own turn was left holding a call that never received a response, and a turn
  or two later the reply degraded into a stray CJK glyph, the call restated as
  prose (`object:default_api:query_customers{…}`), or an empty turn. One live
  reply read `"巾 eyes open: query_customers returned: … Wait, was it returned
  in the result?"` — the model asking where the dropped result had gone.
  Diagnosed by dumping the raw parts rather than by reasoning about it, and
  initially misattributed to the model being too small. Now every call in a
  turn is queued, served one at a time without spending an extra turn, and
  answered in a single user turn matched by function name; tests cover it.
  **The cassette path the demo actually runs was never affected**, because a
  cassette yields exactly one step at a time — which is also why the bug
  survived so long.

  Relatedly, `MAX_TOKENS = 4096`
  is a ceiling on thinking *and* response text together, and the model this
  path targets runs adaptive thinking by default — a long reasoning turn can
  therefore truncate the answer.
- **The containment property is topological and is not exercised by CI.** The
  network isolation, the key split at the container level, and
  `tests/demo/test_isolation.sh` all require Docker. The Python suite proves the
  wiring (the broker builds a `Verifier` from a public-key file, holds no
  `Signer`, exposes no minting route; the control entrypoint signs with the
  private half and the broker's verifier accepts it) and reads the Compose file
  to pin `broker-control` off `agent-net` — but nothing here has run a
  container. Treat the Compose topology as reviewed, not as tested.
- **Egress destinations are matched by host, never by port.** An allowlisted
  `docstore.internal:22` is indistinguishable from `docstore.internal:443`, so
  an approved host exposes every port it listens on.
- **The proxy applies no capability check.** `allowed_tools` governs the tool
  API only; a token with an empty tool set can still open an authorized
  CONNECT. Egress is governed by destination and taint, not by capability.
- **Missing and malformed `Proxy-Authorization` are indistinguishable** in the
  log — both record `unauthenticated`. Deliberate: the security-relevant fact
  is that a CONNECT arrived without valid authority.
- **Once a tunnel is established, no further audit events occur** for that
  connection's lifetime. The decision is recorded; the traffic is not.
- **A failed audit write inside the proxy's refusal path is silent to the
  client**, where the same failure on the tool API returns 503. Asymmetric
  because a refusal must still happen even when it cannot be recorded. The
  proxy and the tool API are asymmetric a second way, deliberately: the proxy
  builds its own `target` dict inline from the CONNECT authority
  (`warden/broker/proxy.py`) rather than going through an adapter's
  `describe()`, so a CONNECT record carries six keys (`kind`, `host`, `port`,
  `path`, `estimated_rows`, `recipients`) where a tool-call record carries
  seven — the extra `subjects` key exists only for `ToolTarget`
  (`warden/broker/adapters/base.py`), because only a database read has
  subjects to name, and CONNECT has nothing to hand it.
- **The policy is only as good as its input.** Six fail-open paths were found
  and closed during development, all invisible to a passing test suite: in
  Rego, an undefined sub-expression makes a rule body undefined, an undefined
  body contributes no deny reason, and the rule silently does not fire. `R0`
  and `R1` exist to make unrecognized input deny explicitly. Adversarial
  evaluation with `opa eval`, not `opa test`, is what found them.

- **`--live` is now exercised, and what it showed matters.** On 2026-07-30 a
  live `gemini-3.1-flash-lite` agent read the poisoned document and **refused
  the injection**, naming it as likely malicious. That is a welcome outcome and
  it is deliberately not counted as a control: model refusal is probabilistic,
  unstated as a guarantee, and removed by a rephrasing or a different model.
  The recorded cassette is therefore treated as a *fixed adversarial model* —
  holding the attacker constant is how a boundary gets tested. In the same run
  the policy denied a benign mistake the model made on its own, emailing the
  address it read from the database rather than the declared counterparty.
  A turn returning multiple parallel tool calls
  is no longer unexercised — it turned out to be the common case on Gemini, and
  the adapter's handling of it is the bug described above. On 2026-08-02 the
  full ten-scenario matrix ran against a live `gemini-3.6-flash`: seven
  scenarios tripped a rule and three (`triage`, `inject-internal`,
  `inject-cc`) were declined by the model itself — recorded, then set aside,
  for the reason above. The frozen log and manifest of that run are in
  `docs/evidence/`.

- **The model provider is treated as inside the data boundary, deliberately.**
  `generativelanguage.googleapis.com` is the single entry in
  `pii_approved_sinks`. A remote-model agent cannot read a customer record and
  then reason about it without that record entering its context, so the
  provider is a processor or the agent is useless after its first PII read. This
  was not designed in — the taint rule denied the agent's own model call during
  a live protected run, forcing the choice. The alternatives are in-boundary
  inference (the sovereign-cloud answer) or redacting before the tool result
  returns. `authz_test.rego` pins the list at exactly one host so it cannot
  grow unnoticed, and asserts every other allowlisted host still refuses PII.

- **The model endpoint is an allowlisted destination, not a privileged one.**
  `generativelanguage.googleapis.com` is in `egress_allow` for the
  `support-triage` purpose so a live agent can reach its provider through the
  proxy, and its place in `pii_approved_sinks` (the single entry, above) is
  ordinary policy data — nothing in the rules names it. Changing vendors is
  a policy edit. The task token reaches the proxy as Basic credentials embedded
  in the proxy URL, because a third-party SDK owns its own HTTP client and will
  not set a Bearer header — `proxy_token()` accepts both forms and anything
  else is audited as `unauthenticated`.
