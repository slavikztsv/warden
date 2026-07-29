"""Two ways to reach a tool. The agent loop cannot tell them apart.

DirectDispatcher is the unprotected profile: the agent holds credentials and
talks to backends itself. BrokeredDispatcher is the guarded profile: it holds
a task token and asks the broker to act for it.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import httpx

TOOL_SCHEMAS = [
    {"name": "read_document", "description": "Read a document by id.",
     "input_schema": {"type": "object", "properties": {"doc_id": {"type": "string"}},
                      "required": ["doc_id"]}},
    {"name": "query_customers", "description": "Query the customer database.",
     "input_schema": {"type": "object", "properties": {"filter": {"type": "string"}},
                      "required": ["filter"]}},
    {"name": "http_fetch", "description": "Fetch a URL.",
     "input_schema": {"type": "object", "properties": {"url": {"type": "string"}},
                      "required": ["url"]}},
    {"name": "send_email", "description": "Send an email.",
     "input_schema": {"type": "object", "properties": {
         "to": {"type": "array", "items": {"type": "string"}},
         "subject": {"type": "string"}, "body": {"type": "string"}},
                      "required": ["to", "subject", "body"]}},
]


class BrokeredDispatcher:
    def __init__(self, *, broker_url: str, token: str, client: httpx.Client) -> None:
        self._url = broker_url.rstrip("/")
        self._token = token
        self._client = client

    def call(self, tool: str, args: dict) -> dict:
        response = self._client.post(
            f"{self._url}/v1/tools/{tool}/invoke",
            json={"args": args},
            headers={"Authorization": f"Bearer {self._token}"},
        )
        return response.json()


class DirectDispatcher:
    def __init__(
        self, *, docstore_url: str, db_path: Path, mailer_url: str, client: httpx.Client
    ) -> None:
        self._docstore_url = docstore_url.rstrip("/")
        self._db_path = Path(db_path)
        self._mailer_url = mailer_url.rstrip("/")
        self._client = client

    def call(self, tool: str, args: dict) -> dict:
        if tool == "read_document":
            return {"content": self._client.get(
                f"{self._docstore_url}/docs/{args['doc_id']}").text}
        if tool == "http_fetch":
            # Mirrors Backends.execute: a body makes it a POST. This is the
            # path that actually exfiltrates in the unprotected profile.
            body = args.get("body")
            if body is None:
                return {"content": self._client.get(args["url"]).text}
            return {"content": self._client.post(args["url"], content=body).text}
        if tool == "send_email":
            self._client.post(f"{self._mailer_url}/send", json=args)
            return {"content": "sent"}
        if tool == "query_customers":
            # Mirrors broker/backends.py::_where exactly. The two dispatchers
            # are different code by design, but they must read the SAME rows
            # for the same filter — otherwise the profiles differ in what the
            # agent sees, not just in what it is allowed to do, and the A/B
            # stops being a controlled comparison.
            filter_expr = args.get("filter", "all")
            if filter_expr in ("", "all", "*"):
                clause, params = "", []
            elif filter_expr.startswith("id="):
                clause, params = " WHERE id = ?", [int(filter_expr[3:])]
            else:
                clause, params = " WHERE plan = ?", [filter_expr]
            connection = sqlite3.connect(self._db_path)
            try:
                connection.row_factory = sqlite3.Row
                rows = connection.execute(
                    f"SELECT id, name, email, plan, balance FROM customers{clause}", params
                ).fetchall()
            finally:
                connection.close()
            payload = [dict(row) for row in rows]
            return {"content": json.dumps(payload), "rows": len(payload)}
        return {"error": "unknown_tool", "tool": tool}
