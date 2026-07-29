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
| Bulk exfiltration | 50 rows per task, accumulated across calls; 5-minute token; purpose-scoped egress. |
| Data reaching an unapproved sink | Task-level taint (`egress.pii_sink`), independent of destination reputation. |
| Log tampering to hide an attempt | Hash-chained audit records; any edit breaks the chain. |

## Out of scope

- **Malicious runtime code / supply chain.** The runtime image is trusted. A
  compromised runtime can still misuse its own valid token within policy.
- **Covert channels inside allowed destinations.** No TLS interception: the
  proxy sees `CONNECT host:port` only. Data can be encoded into a URL path or
  a DNS-over-HTTPS query to an approved host.
- **The broker is the TCB.** Compromise it and the model collapses. It is kept
  small and single-purpose so it can be read end to end.
- **Multi-agent delegation chains.** Not built. The token carries a
  `delegated_from` slot so the extension is sketchable.
- **Authenticating the control plane.** Token minting is bound to a separate
  interface the agent cannot reach, but the caller itself is not
  authenticated. That is the next trust boundary out.

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
