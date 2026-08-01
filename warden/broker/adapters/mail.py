"""Sends mail to declared counterparties."""

from __future__ import annotations

from warden.broker.adapters.base import ToolResult, ToolTarget


class MailAdapter:
    target_kind = "mail"

    # See HttpAdapter.REQUIRED_ARGS for what this is. describe() below reads
    # args.get(self._recipients_arg, []), and execute()'s payload comprehension
    # is guarded by `if name in args` -- nothing here is dereferenced
    # unconditionally.
    REQUIRED_ARGS: tuple[str, ...] = ()

    def __init__(self, *, binding: dict, client) -> None:
        self._base_url = str(binding["base_url"]).rstrip("/")
        self._path = binding.get("path", "/send")
        self._recipients_arg = binding.get("recipients_arg", "to")
        # The ONLY keys that go on the wire. backends.py forwarded the whole
        # args dict, so an undeclared cc reached the mailer on a call whose
        # audited target.recipients was the approved one -- the policy judged
        # one recipient set and the action used another.
        self._fields = tuple(binding["fields"])
        self._data_class = binding.get("data_class")
        self._client = client

    def describe(self, args: dict) -> ToolTarget:
        return ToolTarget(
            kind=self.target_kind,
            recipients=tuple(args.get(self._recipients_arg, [])),
        )

    def execute(self, args: dict) -> ToolResult:
        payload = {name: args[name] for name in self._fields if name in args}
        response = self._client.post(f"{self._base_url}{self._path}", json=payload)
        response.raise_for_status()
        return ToolResult(content="sent", data_class=self._data_class)
