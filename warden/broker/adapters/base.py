"""What an adapter is.

describe() is the policy information point: it produces everything the
decision needs WITHOUT performing the action. For a database read that means
a bounded COUNT -- bounded in the sense that no rows materialise, NOT that
the count is capped. The adapter returns the true cardinality; capping it
would change the number the demo quotes without changing any decision.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

DEFAULT_PORTS = {"http": 80, "https": 443}


class UnknownTool(Exception):
    """Raised for any tool outside the catalog. Deny-by-default at the edge."""


@dataclass(frozen=True)
class ToolTarget:
    kind: str
    host: str = ""
    port: int = 0
    path: str = ""
    estimated_rows: int = 0
    recipients: tuple[str, ...] = field(default=())
    # Which data subjects a database read names. `("*",)` means "not a
    # bounded set". It is deliberately a value that can never appear in a
    # token's counterparties, so an unbounded read is out of scope by
    # construction rather than by a second rule.
    subjects: tuple[str, ...] = field(default=())

    def as_dict(self) -> dict:
        return {
            "kind": self.kind,
            "host": self.host,
            "port": self.port,
            "path": self.path,
            "estimated_rows": self.estimated_rows,
            "recipients": list(self.recipients),
            "subjects": list(self.subjects),
        }


@dataclass(frozen=True)
class ToolResult:
    content: str
    rows: int = 0
    data_class: str | None = None


class Adapter(Protocol):
    target_kind: str

    # Names of instance attributes whose value is an argument name that
    # describe() dereferences UNCONDITIONALLY (args[name], not
    # args.get(name, ...)). `warden config check` (broker/config/check.py)
    # reads this off each concrete adapter class and requires the matching
    # schema entry to be `required = true` -- otherwise a call omitting that
    # argument makes describe() raise KeyError, which the broker's widened
    # client-caused branch (warden/broker/spine.py) audits as input.malformed
    # against the agent, for what is really a config-authoring defect. Declared as
    # data on each concrete class, next to the __init__ that sets the
    # attribute, rather than pattern-matched from source.
    REQUIRED_ARGS: tuple[str, ...] = ()

    # The execute()-time twin of REQUIRED_ARGS. describe() and execute() can
    # disagree about which arguments they dereference unconditionally --
    # DocstoreAdapter's describe() reads args.get(self._arg, ""), but its
    # execute() reads args[self._arg]. A manifest that leaves that arg
    # optional lets describe() (and therefore the policy decision) succeed on
    # a call that then KeyErrors in execute() -- AFTER the allow is durably
    # audited, so the log asserts an authorised action that never happened.
    # `warden config check` requires the matching schema entry to be
    # `required = true` for every name listed here, the same way it does for
    # REQUIRED_ARGS.
    EXECUTE_REQUIRED_ARGS: tuple[str, ...] = ()

    # Every instance attribute (not just the unconditionally-dereferenced
    # ones above) whose value is an argument name -- i.e. every binding key
    # that the adapter uses to pick WHICH key of `args` to read, whether via
    # args[name] or args.get(name, ...). `warden config check` requires each
    # one to name a key that [tools.<tool>.args] actually declares. Without
    # this, a binding like SqlAdapter's filter_arg can point at an argument
    # name the schema never mentions: with the schema's default
    # unknown_args = "reject", no valid call can ever populate that key, so
    # the adapter silently falls back to its "no filter" default on every
    # single call -- an unbounded read that policy then judges as if it were
    # a real, deliberate query. A superset of REQUIRED_ARGS and
    # EXECUTE_REQUIRED_ARGS (both of those are also argument-name attributes,
    # just ones held to the stricter `required = true` bar too).
    ARG_ATTRS: tuple[str, ...] = ()

    # The [binding] keys this adapter's __init__ actually reads. Enforced at
    # LOAD time (broker/config/catalog.py), not by `warden config check`: a
    # binding key this tuple does not list is a ConfigError before the
    # broker ever serves a request. The alternative -- silently ignoring it
    # -- is how omitting a tool's `data_class = "pii"` binding used to
    # disable the PII data-flow control with no error at all. Declared as
    # data on each concrete class, the same shape as REQUIRED_ARGS.
    BINDING_KEYS: tuple[str, ...] = ()

    # Every adapter is constructed exactly this way, by build_adapter() in
    # broker/adapters/registry.py, from the resolved [binding] table and the
    # one shared httpx client. Declared here because the registry types its
    # values as `type[Adapter]`, and without this the protocol claims adapters
    # take no arguments at all -- a contract every concrete adapter breaks.
    # `client` is untyped on purpose: the SQL adapter ignores it entirely and
    # defaults it, and the three HTTP-shaped ones want an httpx.Client, which
    # a Protocol cannot express as "optional for some implementers".
    def __init__(self, *, binding: dict, client) -> None: ...

    def describe(self, args: dict) -> ToolTarget: ...

    def execute(self, args: dict) -> ToolResult: ...
