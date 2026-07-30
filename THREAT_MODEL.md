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
| Agent minting itself a broader token | The minting endpoint runs as its own service (`broker-control`) on `backend-net` only. The broker — the one service the agent *can* reach — loads only the public key and cannot sign. |
| Bulk exfiltration | 50 rows per task, accumulated across calls; 5-minute token; purpose-scoped egress. |
| Data reaching an unapproved sink | Task-level taint (`egress.pii_sink`), independent of destination reputation. No HTTP destination is an approved PII sink, so **PII never leaves over HTTP at all** — it leaves only through the mail tool, to counterparties the task declared up front (`mail.counterparty`). |
| Log tampering to hide an attempt | Hash-chained audit records; any edit breaks the chain. |

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
  check: it runs as its own service on `backend-net` only, published to the
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
  record in the audit log. Closed by approving no HTTP sink for PII at all,
  which is also the version of the rule that fits in one sentence. No test
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
- **`--live` is not covered by CI, and it answers only the first tool call in a
  turn.** The `anthropic` package is deliberately not a dependency, so nothing
  in the suite reaches the real API; `LiveClient` is driven by a stub that pins
  the request shape and the `tool_use`/`tool_result` alternation but cannot
  prove the API accepts it. Within that path, parallel tool use is unhandled:
  a turn returning two `tool_use` blocks gets a `tool_result` for the first
  only, and the API rejects the next request because the second is unanswered.
  Accepted rather than fixed — it is reachable only on the already-unexercised
  live path. **The cassette path the demo actually runs is unaffected**, because
  a cassette yields exactly one step at a time. Relatedly, `MAX_TOKENS = 4096`
  is a ceiling on thinking *and* response text together, and the model this
  path targets runs adaptive thinking by default — a long reasoning turn can
  therefore truncate the answer.
- **The containment property is topological and is not exercised by CI.** The
  network isolation, the key split at the container level, and
  `tests/test_isolation.sh` all require Docker. The Python suite proves the
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
  because a refusal must still happen even when it cannot be recorded.
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
  address it read from the database rather than the declared counterparty. See
  `docs/live-run-2026-07-30.md`. Still unexercised: a turn returning multiple
  parallel tool calls, where the adapter answers only the first.

- **The model endpoint is an allowlisted destination, not a privileged one.**
  `generativelanguage.googleapis.com` is in `egress_allow` for the
  `support-triage` purpose so a live agent can reach its provider through the
  proxy, and it is deliberately absent from `pii_approved_sinks`: an agent
  holding customer data cannot post it to the model either. Changing vendors is
  a policy edit. The task token reaches the proxy as Basic credentials embedded
  in the proxy URL, because a third-party SDK owns its own HTTP client and will
  not set a Bearer header — `proxy_token()` accepts both forms and anything
  else is audited as `unauthenticated`.
