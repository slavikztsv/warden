# Deploying `warden` against your own tools

This directory is not a folder of files to copy — there is nothing else
here, and that is deliberate (see "The shipped catalog is empty" below). It
is a description of what pointing `warden` at your own tools actually
involves, written against the one deployment this repo ships:
`demo/scenario/`. Read it alongside that directory; every file named below
has a real, working counterpart there.

`warden` itself carries no knowledge of any of this. It is a broker: a
policy decision point, a tool API, an egress proxy, and a hash-chained audit
log, wired together by whatever config you hand it. Everything scenario-
specific — which tools exist, what they're called, which hosts a purpose may
reach — lives in three files a deployment supplies from outside the product
tree. `tests/test_seam.py` enforces that direction structurally: the
`warden` package cannot import `demo`, and a scan
(`test_the_product_tree_holds_no_scenario_string`) fails the build if any
file under `warden/` ever contains one of this repo's own demo strings
(`support-triage`, `docstore.internal`, and so on).

## What a customer does

1. **Write `warden.toml`.** Five sections: where the broker listens, the
   public half of your keypair (never the private half — see
   `THREAT_MODEL.md`), where OPA lives and which policy bundle it evaluates,
   where the audit log goes, and the path to your tool catalog.
   `demo/scenario/warden.toml` is a complete, working example of the shape:

   ```toml
   [broker]
   listen       = "0.0.0.0:8080"
   proxy_listen = "0.0.0.0:3128"

   [identity]
   public_key = "/data/agent.pub"

   [policy]
   opa_url       = "http://opa:8181"
   decision_path = "warden/authz"
   bundle_roots  = ["/policies"]

   [audit]
   path = "/data/audit.jsonl"

   [tokens]
   issuer = "warden-broker"

   [catalog]
   tools = "/config/tools.toml"
   ```

2. **Declare your tools in `tools.toml`.** One `[tools.<name>]` table per
   tool. Each names an *adapter* kind — `docstore`, `sql`, `http` or `mail`
   (the full vocabulary is `warden/broker/adapters/registry.py`'s
   `TARGET_KIND_BY_ADAPTER`) — a `[tools.<name>.binding]` telling that
   adapter how to reach the real backend (`${VAR}` interpolates from the
   process environment), and a `[tools.<name>.args]` schema the broker
   validates before the adapter ever sees the call. `demo/scenario/tools.toml`
   is the worked example: four tools, one of each kind, each with the
   comments explaining what its binding fields mean and why its args are
   shaped the way they are.

3. **Mirror your tools' target kinds in `data.json`.** The policy never
   reasons about tool *names* — `warden/policies/authz.rego`'s R0 and R1b
   deny any call whose declared target kind disagrees with the catalog, and
   every other rule (R3 through R7) keys off `target.kind`
   (`doc`/`db`/`http`/`mail`), not off which tool produced it. `data.json`'s
   `"tools"` table is the map from your tool names to the target kind each
   one produces — the *only* place a tool name appears in policy input at
   all — alongside the purposes your tasks will declare (which hosts each
   purpose may reach, which of those are approved to receive data holding
   `pii`) and the per-task row-volume limit. `demo/scenario/data.json` is
   the worked example; it is under thirty lines.

4. **Check it's consistent, before you trust it.**

   ```bash
   DOCSTORE_URL=... DB_PATH=... MAILER_URL=...  \
   warden config check --catalog tools.toml --data data.json --opa http://localhost:8181
   ```

   (Whatever `${VAR}` names your own `tools.toml` bindings use belong on that
   command line — `warden config check` interpolates them exactly as
   `warden serve` will.) This cross-checks your catalog against your data
   document — every declared tool's target kind agrees, every adapter's
   unconditionally-dereferenced argument is marked required in its schema —
   and, when `--opa` is given, against a running policy bundle too. It is
   the same consistency `warden serve`'s startup silently depends on
   holding, made inspectable and CI-able on its own; see
   `warden/broker/config/check.py`.

5. **Run it.**

   ```bash
   warden serve --config warden.toml
   ```

## The shipped catalog is empty, on purpose

`warden` ships no `tools.toml` of its own — not an empty placeholder file in
this directory, not a checked-in zero-tool template, nothing at all.
`tests/test_seam.py::test_the_product_tree_ships_no_tool_catalog` asserts
this directly: there is no file named `tools.toml` anywhere under `warden/`.
An empty catalog is a broker that permits nothing, which is the correct
default for a deny-by-default system — the product must never boot already
knowing a tool exists. Every tool a deployment's broker can call is one that
deployment declared, in its own `tools.toml`, outside this tree.

`demo/scenario/` is not a special case carved out of that rule; it is an
ordinary deployment that happens to live in the same repository, wired
exactly the way any other deployment would be — a `warden.toml`, a
`tools.toml`, a `data.json`, handed to the same `warden serve` a customer
would run. Reading it is the fastest way to see what your own three files
should look like.
