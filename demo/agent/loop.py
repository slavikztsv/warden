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

from demo.agent.llm import Cassette, TracingLLM, live_client_from_env
from demo.agent.tools import BrokeredDispatcher, DirectDispatcher
from demo.scenario.task import PROMPT as SYSTEM_TASK


# The text a capped run's final step carries. Named rather than inlined so a
# caller can recognise a truncated transcript without string-matching a literal
# that lives in another module — explain's matrix does exactly that, and a
# silent drift between the two would turn a capped run back into a row that
# looks complete.
STOPPED_MARKER = "(stopped after"


def run_task(
    dispatcher, llm, task_id: str, task: str | None = None, max_steps: int | None = None
) -> list[dict]:
    # The task text is the operator's instruction, and it is deliberately a
    # parameter: an out-of-scope request can arrive because a document injected
    # one, because the agent has a bug, or because the operator simply asked for
    # too much. The broker cannot tell those apart and does not try -- the task
    # text is not part of any authorization decision, and does not appear in the
    # policy input document at all. Authority comes from the token.
    transcript: list[dict] = []
    messages = [{"role": "user", "content": task or SYSTEM_TASK}]
    refused = 0

    while True:
        # An agent loop with no ceiling runs until the model decides to stop.
        # The token expiring after five minutes is the only bound the system
        # otherwise has, and that is a bound on authority, not on effort. Off by
        # default so the demo is unchanged; the model sweep sets it, because a
        # model it has never run before may never choose to finish.
        if max_steps is not None and len(transcript) >= max_steps:
            step = {"type": "final", "text": f"{STOPPED_MARKER} {max_steps} steps)"}
            transcript.append(step)
            print(f"[agent] {step['text']}")
            return transcript
        step = llm.next_step(messages)
        transcript.append(step)
        if step["type"] == "final":
            # The cassette's closing line is fixed text, so it cannot know what
            # the environment allowed. Report the count observed at runtime
            # instead — otherwise the unprotected run, where nothing is refused,
            # still claims refusals and undercuts the demo's first beat.
            # This branches on results, never on which dispatcher is in use.
            note = f" ({refused} tool call{'s' if refused != 1 else ''} refused by policy)"
            print(f"[agent] {step['text']}{note if refused else ''}")
            return transcript

        tool, args = step["tool"], step["args"]
        try:
            result = dispatcher.call(tool, args)
        except Exception as exc:
            # A transport failure is data too, for the same reason a denial is.
            # If this raised, one profile would die where the other survived,
            # and the demo would read as "the broker broke the agent" rather
            # than "the policy worked". The loop must reach its final step in
            # both profiles no matter what the environment does.
            result = {"error": "transport_error", "message": str(exc)}
        if "error" in result:
            refused += 1
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
        live_client_from_env(os.environ)
        if "--live" in sys.argv
        else Cassette(Path(os.environ.get("CASSETTE", "demo/agent/cassettes/support-triage.json")))
    )
    # WARDEN_TRACE=1 prints the full conversation each turn. Off by default
    # because the trace contains everything the agent has read.
    if os.environ.get("WARDEN_TRACE"):
        llm = TracingLLM(llm)

    run_task(dispatcher, llm, task_id=os.environ.get("TASK_ID", "4711"))


if __name__ == "__main__":
    main()
