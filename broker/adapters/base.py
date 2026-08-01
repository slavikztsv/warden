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
    # client-caused branch (broker/app.py) audits as input.malformed against
    # the agent, for what is really a config-authoring defect. Declared as
    # data on each concrete class, next to the __init__ that sets the
    # attribute, rather than pattern-matched from source.
    REQUIRED_ARGS: tuple[str, ...] = ()

    def describe(self, args: dict) -> ToolTarget: ...

    def execute(self, args: dict) -> ToolResult: ...
