"""Reads a document from an HTTP document store."""

from __future__ import annotations

from warden.broker.adapters.base import ToolResult, ToolTarget


class DocstoreAdapter:
    target_kind = "doc"

    # Names of instance attributes (set in __init__, below) whose value is an
    # argument name that describe() dereferences UNCONDITIONALLY -- args[name],
    # not args.get(name, ...). Read by `warden config check`: if the schema
    # does not mark that argument required, describe() raises KeyError, and
    # the broker's widened client-caused branch (warden/broker/spine.py)
    # audits it as input.malformed against the agent, for what is really a
    # config-authoring defect. describe() below reads args.get(self._arg, ""),
    # so nothing here is dereferenced unconditionally.
    REQUIRED_ARGS: tuple[str, ...] = ()

    # execute() below, unlike describe(), reads args[self._arg] with no
    # default. A manifest that leaves that arg optional in the schema lets
    # describe() (and the policy decision built on it) succeed on a call that
    # then KeyErrors here -- AFTER the allow is already durably audited, so
    # the log asserts an authorised read that never actually happened. See
    # Adapter.EXECUTE_REQUIRED_ARGS.
    EXECUTE_REQUIRED_ARGS: tuple[str, ...] = ("_arg",)

    # Superset of the above: every attribute whose value names an argument,
    # required or not, so `warden config check` can require it to be a key
    # [tools.<tool>.args] actually declares. See Adapter.ARG_ATTRS.
    ARG_ATTRS: tuple[str, ...] = ("_arg",)

    # The [binding] keys this adapter's __init__ reads. See Adapter.BINDING_KEYS.
    BINDING_KEYS: tuple[str, ...] = ("base_url", "path_template", "arg", "data_class")

    def __init__(self, *, binding: dict, client) -> None:
        self._base_url = str(binding["base_url"]).rstrip("/")
        self._template = binding.get("path_template", "/docs/{doc_id}")
        self._arg = binding.get("arg", "doc_id")
        self._data_class = binding.get("data_class")
        self._client = client

    @property
    def data_class(self) -> str | None:
        return self._data_class

    def describe(self, args: dict) -> ToolTarget:
        # The BARE id, not the resolved request path. describe() and execute()
        # disagree here deliberately: the policy target names the document,
        # and resolving it would change what the replay prints and re-flow the
        # column padding on that line.
        return ToolTarget(kind=self.target_kind, path=str(args.get(self._arg, "")))

    def execute(self, args: dict) -> ToolResult:
        path = self._template.format(**{self._arg: args[self._arg]})
        response = self._client.get(f"{self._base_url}{path}")
        response.raise_for_status()
        return ToolResult(content=response.text, data_class=self._data_class)
