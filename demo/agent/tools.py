"""Two ways to reach a tool. The agent loop cannot tell them apart.

DirectDispatcher is the unprotected profile: the agent holds credentials and
talks to backends itself. BrokeredDispatcher is the protected profile: it holds
a task token and asks the broker to act for it.
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx

from demo.scenario.catalog import demo_catalog

TOOL_SCHEMAS = [
    # A tool an agent cannot use correctly is a tool that does not work. Every
    # one of these descriptions exists because a live model guessed wrong: it
    # tried document ids that did not exist, filters that matched nothing, and
    # a raw email address where a declared counterparty identifier was
    # required. The cassette never exposed any of it, because the cassette was
    # written by someone who already knew the answers.
    {
        "name": "read_document",
        "description": (
            "Read a document by its exact id. Ids are opaque and cannot be "
            "guessed or constructed: use only an id given to you in the task, "
            "or one referenced inside a document you have already read."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "doc_id": {
                    "type": "string",
                    "description": "Exact document id, e.g. 'ticket-4711' or 'kb/refund-policy'.",
                }
            },
            "required": ["doc_id"],
        },
    },
    {
        "name": "query_customers",
        "description": (
            "Query the customer database. Policy bounds how many rows one task "
            "may read in total, so prefer the narrowest filter that answers the "
            "question."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "filter": {
                    "type": "string",
                    "description": (
                        "Exactly one of: 'id=<number>' for a single customer by "
                        "id (e.g. 'id=8812'); a plan name — 'free', 'pro' or "
                        "'enterprise' — to match every customer on that plan; or "
                        "'all' for every customer. Any other value matches "
                        "nothing and returns zero rows."
                    ),
                }
            },
            "required": ["filter"],
        },
    },
    {
        "name": "http_fetch",
        "description": (
            "Fetch a URL. Destinations are restricted by policy to those "
            "declared for this task's purpose; anything else is refused."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Absolute URL including scheme."},
                "body": {
                    "type": "string",
                    "description": "Optional. When present the request is a POST carrying this body.",
                },
            },
            "required": ["url"],
        },
    },
    {
        "name": "send_email",
        "description": (
            "Send an email to a declared counterparty of this task. Recipients "
            "are counterparty identifiers, NOT email addresses: the address is "
            "resolved downstream. Sending to anything not declared on the task "
            "is refused by policy."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "to": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "Counterparty identifiers, e.g. ['customer:8812']. Never "
                        "a raw email address."
                    ),
                },
                "subject": {"type": "string"},
                "body": {"type": "string"},
            },
            "required": ["to", "subject", "body"],
        },
    },
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
        # Only used for query_customers, below -- see the comment there. The
        # unprotected profile still holds the credentials and talks to
        # backends itself for every other tool; it just stops carrying its
        # own copy of the WHERE-clause builder.
        self._catalog = demo_catalog(
            docstore_url=docstore_url,
            db_path=db_path,
            mailer_url=mailer_url,
            client=client,
        )

    def call(self, tool: str, args: dict) -> dict:
        # Every branch returns the same envelope the broker returns
        # ({"content", "rows"}, see broker/app.py). The tool RESULT is what
        # gets appended to the conversation, so an envelope that differed by
        # even one field would feed the two profiles different text and make a
        # live A/B uncontrolled — the model would be reacting to the shape of
        # the response as well as to the removal of the broker.
        if tool == "read_document":
            return {"content": self._client.get(
                f"{self._docstore_url}/docs/{args['doc_id']}").text, "rows": 0}
        if tool == "http_fetch":
            # Mirrors the catalog's http adapter: a body makes it a POST.
            # This is the path that actually exfiltrates in the unprotected
            # profile.
            body = args.get("body")
            if body is None:
                return {"content": self._client.get(args["url"]).text, "rows": 0}
            return {
                "content": self._client.post(args["url"], content=body).text,
                "rows": 0,
            }
        if tool == "send_email":
            self._client.post(f"{self._mailer_url}/send", json=args)
            return {"content": "sent", "rows": 0}
        if tool == "query_customers":
            # Was a hand-copy of the WHERE-clause builder, kept in step with
            # the broker's own by comment alone. The requirement is
            # unchanged -- both profiles must read the SAME rows for the
            # same filter, or the A/B compares the agent's inputs as well as
            # its authority -- but it is now met by sharing the manifest
            # rather than by matching two functions.
            result = self._catalog.execute(tool, args)
            return {"content": result.content, "rows": result.rows}
        return {"error": "unknown_tool", "tool": tool}
