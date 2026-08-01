"""Reads a document from an HTTP document store."""

from __future__ import annotations

from broker.adapters.base import ToolResult, ToolTarget


class DocstoreAdapter:
    target_kind = "doc"

    def __init__(self, *, binding: dict, client) -> None:
        self._base_url = str(binding["base_url"]).rstrip("/")
        self._template = binding.get("path_template", "/docs/{doc_id}")
        self._arg = binding.get("arg", "doc_id")
        self._data_class = binding.get("data_class")
        self._client = client

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
