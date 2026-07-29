"""Describes a tool call as a policy target, then executes it.

describe() is the policy information point: it produces everything the
decision needs WITHOUT performing the action. For database reads that means a
bounded COUNT, so a query breaching the row bound is denied before any rows
are materialized.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

import httpx

TOOLS = ("read_document", "query_customers", "http_fetch", "send_email")
DEFAULT_PORTS = {"http": 80, "https": 443}


class UnknownTool(Exception):
    """Raised for any tool name outside TOOLS. Deny-by-default at the edge."""


@dataclass(frozen=True)
class ToolTarget:
    kind: str
    host: str = ""
    port: int = 0
    path: str = ""
    estimated_rows: int = 0
    recipients: tuple[str, ...] = field(default=())

    def as_dict(self) -> dict:
        return {
            "kind": self.kind,
            "host": self.host,
            "port": self.port,
            "path": self.path,
            "estimated_rows": self.estimated_rows,
            "recipients": list(self.recipients),
        }


@dataclass(frozen=True)
class ToolResult:
    content: str
    rows: int = 0
    data_class: str | None = None


def _where(filter_expr: str) -> tuple[str, list]:
    if filter_expr in ("", "all", "*"):
        return "", []
    if filter_expr.startswith("id="):
        return " WHERE id = ?", [int(filter_expr[3:])]
    return " WHERE plan = ?", [filter_expr]


class Backends:
    def __init__(
        self,
        *,
        docstore_url: str,
        db_path: Path,
        mailer_url: str,
        client: httpx.Client,
    ) -> None:
        self._docstore_url = docstore_url.rstrip("/")
        self._db_path = Path(db_path)
        self._mailer_url = mailer_url.rstrip("/")
        self._client = client

    def describe(self, tool: str, args: dict) -> ToolTarget:
        if tool not in TOOLS:
            raise UnknownTool(tool)
        if tool == "read_document":
            return ToolTarget(kind="doc")
        if tool == "send_email":
            return ToolTarget(kind="mail", recipients=tuple(args.get("to", [])))
        if tool == "http_fetch":
            parts = urlsplit(args["url"])
            return ToolTarget(
                kind="http",
                host=parts.hostname or "",
                port=parts.port or DEFAULT_PORTS.get(parts.scheme, 0),
                path=parts.path or "/",
            )
        return ToolTarget(kind="db", estimated_rows=self._count(args.get("filter", "all")))

    def _count(self, filter_expr: str) -> int:
        clause, params = _where(filter_expr)
        connection = sqlite3.connect(self._db_path)
        try:
            cursor = connection.execute(
                f"SELECT COUNT(*) FROM customers{clause}", params
            )
            return int(cursor.fetchone()[0])
        finally:
            connection.close()

    def execute(self, tool: str, args: dict) -> ToolResult:
        if tool not in TOOLS:
            raise UnknownTool(tool)
        if tool == "read_document":
            response = self._client.get(f"{self._docstore_url}/docs/{args['doc_id']}")
            response.raise_for_status()
            return ToolResult(content=response.text, data_class="public")
        if tool == "http_fetch":
            response = self._client.get(args["url"])
            response.raise_for_status()
            return ToolResult(content=response.text, data_class="public")
        if tool == "send_email":
            response = self._client.post(f"{self._mailer_url}/send", json=args)
            response.raise_for_status()
            return ToolResult(content="sent", data_class=None)
        return self._query(args.get("filter", "all"))

    def _query(self, filter_expr: str) -> ToolResult:
        clause, params = _where(filter_expr)
        connection = sqlite3.connect(self._db_path)
        try:
            connection.row_factory = sqlite3.Row
            rows = connection.execute(
                f"SELECT id, name, email, plan, balance FROM customers{clause}", params
            ).fetchall()
        finally:
            connection.close()
        payload = [dict(row) for row in rows]
        return ToolResult(
            content=json.dumps(payload), rows=len(payload), data_class="pii"
        )
