"""The agent loop. Byte-identical under both Compose profiles.

There is no branch here on whether a broker exists. The dispatcher is chosen
at startup from environment variables; the loop only knows how to call tools
and how to read the result.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import httpx

from agent.llm import Cassette, LiveClient
from agent.tools import BrokeredDispatcher, DirectDispatcher

SYSTEM_TASK = "Triage support ticket #4711 and reply to the customer."


def run_task(dispatcher, llm, task_id: str) -> list[dict]:
    transcript: list[dict] = []
    messages = [{"role": "user", "content": SYSTEM_TASK}]

    while True:
        step = llm.next_step(messages)
        transcript.append(step)
        if step["type"] == "final":
            print(f"[agent] {step['text']}")
            return transcript

        tool, args = step["tool"], step["args"]
        result = dispatcher.call(tool, args)
        if "error" in result:
            print(f"[agent] {tool} refused: {result.get('rule', result['error'])}")
        else:
            print(f"[agent] {tool} ok")
        messages.append({"role": "user", "content": json.dumps(result)[:2000]})


def main() -> None:
    client = httpx.Client(timeout=10.0)
    if os.environ.get("BROKER_URL"):
        dispatcher = BrokeredDispatcher(
            broker_url=os.environ["BROKER_URL"],
            token=os.environ["TASK_TOKEN"],
            client=client,
        )
    else:
        dispatcher = DirectDispatcher(
            docstore_url=os.environ["DOCSTORE_URL"],
            db_path=Path(os.environ["DB_PATH"]),
            mailer_url=os.environ["MAILER_URL"],
            client=client,
        )

    llm = (
        LiveClient(os.environ["ANTHROPIC_API_KEY"])
        if "--live" in sys.argv
        else Cassette(Path(os.environ.get("CASSETTE", "agent/cassettes/support-triage.json")))
    )
    run_task(dispatcher, llm, task_id=os.environ.get("TASK_ID", "4711"))


if __name__ == "__main__":
    main()
