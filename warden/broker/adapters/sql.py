"""Reads rows from a SQL table, counting before it reads.

describe() runs COUNT(*) and materialises nothing, so a query breaching the
row bound is denied before a single row exists in memory. That is the
security property; "bounded" refers to it, NOT to capping the count. The true
cardinality is returned, because the number is what the audit record and the
replay report.

Table and column names arrive from config and cannot be bound parameters, so
they are validated as identifiers ONCE at construction and quoted at use.
Values remain bound. Before this adapter they were literals in the source,
which is why the check is new rather than inherited.
"""

from __future__ import annotations

import json
import re
import sqlite3
from pathlib import Path

from warden.broker.adapters.base import ToolResult, ToolTarget
from warden.broker.config.loader import ConfigError

_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _identifier(value: object, where: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.match(value):
        raise ConfigError(f"{where} is not a SQL identifier: {value!r}")
    return value


def _quote(identifier: str) -> str:
    return f'"{identifier}"'


class SqlAdapter:
    target_kind = "db"

    # See HttpAdapter.REQUIRED_ARGS for what this is. describe() below reads
    # args.get(self._filter_arg, "") -- nothing here is dereferenced
    # unconditionally. (tools.toml still marks `filter` required, but that is
    # a POLICY choice -- an omitted filter would otherwise default to an
    # unbounded read judged by policy -- not a KeyError guard.)
    REQUIRED_ARGS: tuple[str, ...] = ()

    def __init__(self, *, binding: dict, client=None) -> None:
        self._db_path = Path(binding["db"])
        self._table = _identifier(binding.get("table"), "sql binding table")
        columns = binding.get("columns")
        if not isinstance(columns, list) or not columns:
            raise ConfigError("sql binding columns must be a non-empty array")
        self._columns = tuple(
            _identifier(column, "sql binding columns") for column in columns
        )
        self._subject_column = _identifier(
            binding.get("subject_column"), "sql binding subject_column"
        )
        self._subject_prefix = str(binding.get("subject_prefix", ""))
        self._subject_type = binding.get("subject_type", "string")
        if self._subject_type not in ("integer", "string"):
            raise ConfigError('sql binding subject_type must be "integer" or "string"')
        self._default_column = _identifier(
            binding.get("default_column"), "sql binding default_column"
        )
        self._unfiltered = tuple(binding.get("unfiltered", ["", "all", "*"]))
        self._filter_arg = binding.get("filter_arg", "filter")
        self._data_class = binding.get("data_class")

    @property
    def _subject_marker(self) -> str:
        return f"{self._subject_column}="

    def _coerce(self, raw: str):
        # int() raises ValueError, which broker/app.py maps to
        # input.malformed. Any other exception type would fall into the
        # backend-fault branch, which records nothing at all against the
        # agent.
        return int(raw) if self._subject_type == "integer" else raw

    def _where(self, expression: str) -> tuple[str, list]:
        if expression in self._unfiltered:
            return "", []
        if expression.startswith(self._subject_marker):
            value = self._coerce(expression[len(self._subject_marker):])
            return f" WHERE {_quote(self._subject_column)} = ?", [value]
        return f" WHERE {_quote(self._default_column)} = ?", [expression]

    def _subjects(self, expression: str) -> tuple[str, ...]:
        """The data subjects a filter names, as counterparty identifiers.

        Only a subject-column filter names a bounded set. Anything else
        reaches an unbounded one and says so with "*" rather than by
        enumerating -- resolving a plan into ids would mean reading the rows
        to decide whether the read is allowed.

        The prefix must join exactly to the token's counterparties. Writing
        it without its separator yields "customer42" against a declared
        "customer:42", so R7 rows.scope fires on the ALLOWED read: the
        task never becomes tainted, and the later egress to the allowlisted
        internal sink stops being denied.
        """
        if not expression.startswith(self._subject_marker):
            return ("*",)
        try:
            value = self._coerce(expression[len(self._subject_marker):])
        except ValueError:
            # Unreachable through describe(), which builds the WHERE clause
            # first and raises on the same input. Kept so this helper is
            # total: a pure function that raises for one input is a trap for
            # the next caller.
            return ("*",)
        return (f"{self._subject_prefix}{value}",)

    def describe(self, args: dict) -> ToolTarget:
        expression = args.get(self._filter_arg, "")
        clause, params = self._where(expression)
        connection = sqlite3.connect(self._db_path)
        try:
            cursor = connection.execute(
                f"SELECT COUNT(*) FROM {_quote(self._table)}{clause}", params
            )
            count = int(cursor.fetchone()[0])
        finally:
            connection.close()
        return ToolTarget(
            kind=self.target_kind,
            estimated_rows=count,
            subjects=self._subjects(expression),
        )

    def execute(self, args: dict) -> ToolResult:
        expression = args.get(self._filter_arg, "")
        clause, params = self._where(expression)
        selected = ", ".join(_quote(column) for column in self._columns)
        connection = sqlite3.connect(self._db_path)
        try:
            connection.row_factory = sqlite3.Row
            rows = connection.execute(
                f"SELECT {selected} FROM {_quote(self._table)}{clause}", params
            ).fetchall()
        finally:
            connection.close()
        payload = [dict(row) for row in rows]
        return ToolResult(
            content=json.dumps(payload), rows=len(payload), data_class=self._data_class
        )
