"""Fetches an arbitrary URL. The egress-shaped adapter."""

from __future__ import annotations

from urllib.parse import urlsplit

from broker.adapters.base import DEFAULT_PORTS, ToolResult, ToolTarget


class HttpAdapter:
    target_kind = "http"

    # Read by `warden config check` (broker/config/check.py): the names of
    # instance attributes (set in __init__, below) whose value is an argument
    # name that describe() dereferences UNCONDITIONALLY. describe() below does
    # args[self._url_arg] -- no default -- so a call omitting that argument
    # raises KeyError there, which the broker's widened client-caused branch
    # then audits as input.malformed against the agent: a config-authoring
    # defect wearing an agent-caused reason. The checker reads the attribute
    # off a constructed instance (getattr) rather than assuming the arg is
    # named "url", so a binding that overrides url_arg is honoured too.
    REQUIRED_ARGS: tuple[str, ...] = ("_url_arg",)

    def __init__(self, *, binding: dict, client) -> None:
        self._url_arg = binding.get("url_arg", "url")
        self._body_arg = binding.get("body_arg", "body")
        self._data_class = binding.get("data_class")
        self._client = client

    def describe(self, args: dict) -> ToolTarget:
        parts = urlsplit(args[self._url_arg])
        return ToolTarget(
            kind=self.target_kind,
            host=parts.hostname or "",
            port=parts.port or DEFAULT_PORTS.get(parts.scheme, 0),
            path=parts.path or "/",
        )

    def execute(self, args: dict) -> ToolResult:
        # A body makes this a POST. Exfiltration is a write, not a read: with
        # a bare GET the sinkhole records zero bytes and the unprotected
        # profile's first beat has nothing to show.
        body = args.get(self._body_arg)
        url = args[self._url_arg]
        response = self._client.get(url) if body is None else self._client.post(url, content=body)
        response.raise_for_status()
        return ToolResult(content=response.text, data_class=self._data_class)
