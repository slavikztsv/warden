"""Run the scenario with every stage narrated and explained.

    python -m cli.explain              # recorded model, full narration
    python -m cli.explain --pause      # wait for Enter between steps
    python -m cli.explain --live        # a real model instead of the recording
    python -m cli.explain --quiet-why   # drop the explanations, keep the data

This exists because the interesting part of the system is invisible. Running the
demo shows you decisions; it does not show you *how* each decision was reached —
what the policy was actually asked, what the broker knew that the policy could
not, when the audit record was written relative to the action, or the moment the
task started carrying customer data.

Everything here is the real code path: real OPA over HTTP, the real policy
bundle, the real broker app, the real hash-chained log, the real backends. The
narration is added by wrapping those components, never by reimplementing them —
so if this prints it, that is genuinely what happened. Only the model is
replayed, and `--live` removes even that.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import httpx
from fastapi.testclient import TestClient

from agent.llm import Cassette, live_client_from_env
from agent.loop import SYSTEM_TASK, run_task
from agent.tools import BrokeredDispatcher
from broker.app import create_app
from broker.audit import AuditLog
from broker.backends import Backends
from broker.identity import Signer, Verifier
from broker.pdp import PolicyDecisionPoint
from broker.policy_digest import policy_bundle_digest
from broker.taint import TaintTracker
from cli.warden import render_replay
from mocks import docstore, mailer, sinkhole
from mocks.seed_db import seed_customers

W = 76
SHOW_WHY = True
PAUSE = False


# --------------------------------------------------------------------------- #
#  output helpers
# --------------------------------------------------------------------------- #
def hr(char: str = "─") -> None:
    print(char * W)


def banner(text: str) -> None:
    print("\n" + "═" * W)
    print(f"  {text}")
    print("═" * W)


def stage(num: str, title: str) -> None:
    print(f"\n {num}  {title}")


def show(label: str, value: str, indent: int = 5) -> None:
    pad = " " * indent
    text = str(value)
    if "\n" in text:
        print(f"{pad}{label}:")
        for line in text.splitlines():
            print(f"{pad}  {line}")
    else:
        print(f"{pad}{label}: {text}")


def why(text: str) -> None:
    """The explanation. This is the whole reason the script exists."""
    if not SHOW_WHY:
        return
    words, line = text.split(), ""
    print("     ↳ ", end="")
    for word in words:
        if len(line) + len(word) > W - 12:
            print(line)
            print("       ", end="")
            line = ""
        line += word + " "
    print(line.rstrip())


def clip(text: str, limit: int = 220) -> str:
    text = str(text).replace("\n", " ⏎ ")
    return text if len(text) <= limit else text[:limit] + f" …[+{len(text)-limit}]"


def gate() -> None:
    if PAUSE:
        try:
            input("\n     [Enter] to continue ")
        except EOFError:
            pass


# --------------------------------------------------------------------------- #
#  narrating wrappers — these add commentary, never behaviour
# --------------------------------------------------------------------------- #
class NarratedPDP:
    """Wraps the policy client so the question and the answer are both visible."""

    def __init__(self, inner: PolicyDecisionPoint) -> None:
        self._inner = inner
        self.last_input: dict | None = None

    def decide(self, input_doc: dict):
        self.last_input = input_doc
        state = input_doc["task_state"]
        target = input_doc["target"]

        stage("⑤", "THE BROKER ADDS WHAT ONLY IT KNOWS")
        show("rows read so far this task", state["rows_returned_so_far"])
        show("data classes held", state["data_classes_held"] or "[] (nothing sensitive yet)")
        if target["kind"] == "db":
            show("rows this query would return", target["estimated_rows"])
            why(
                "That row count came from a COUNT(*) run BEFORE the real query. "
                "An oversized read is therefore refused without ever materialising "
                "a single row — the decision happens ahead of the data."
            )
        else:
            why(
                "OPA is a pure function and holds no memory between calls. Every "
                "accumulated fact a decision depends on lives here, in the "
                "enforcement point, and is passed in with each request."
            )

        stage("⑥", "THE POLICY IS ASKED")
        show("input document", json.dumps(input_doc, indent=2, sort_keys=True))
        why(
            "This JSON is the entire question. Who is asking, what they want to "
            "do, to what, and what has already happened. Nothing else is "
            "consulted — no session, no database, no hidden state."
        )

        decision = self._inner.decide(input_doc)

        stage("⑦", "THE POLICY ANSWERS")
        show("allow", decision.allow)
        show("reported rule", decision.rule)
        if decision.allow:
            why(
                "No rule objected. Note the direction: allow is defined as the "
                "absence of any objection, and separate rules exist purely to "
                "make an unrecognised request objectionable — otherwise 'nothing "
                "matched' would silently mean 'permitted'."
            )
        else:
            why(
                f"'{decision.rule}' is the highest-precedence rule that failed. "
                "The order is fixed so the audit log always names the same reason "
                "for the same request, and so that a pii_sink denial can only "
                "ever mean the destination genuinely passed the allowlist first."
            )
        return decision


class NarratedAudit:
    """Wraps the log so you can see the record, and see WHEN it is written."""

    def __init__(self, inner: AuditLog) -> None:
        self._inner = inner
        self.path = inner.path

    def append(self, **fields):
        record = self._inner.append(**fields)
        stage("⑧", "THE DECISION IS RECORDED — BEFORE ANYTHING RUNS")
        show("seq", record["seq"])
        show("decision", f"{record['decision']}  (rule: {record['rule']})")
        show("prev_hash", record["prev_hash"][:16] + "…")
        show("hash", record["hash"][:16] + "…")
        why(
            "This write happens before the action executes, not after. If the log "
            "cannot be written the action is refused — if it cannot be recorded, "
            "it does not happen. Each hash covers the previous one, so editing "
            "any earlier record breaks every hash after it."
        )
        return record

    def records(self):
        return self._inner.records()

    def verify_chain(self):
        return self._inner.verify_chain()


class NarratedBackends:
    """Wraps execution so the real side effect is visible."""

    def __init__(self, inner: Backends) -> None:
        self._inner = inner

    def describe(self, tool, args):
        target = self._inner.describe(tool, args)
        stage("④", "THE BROKER WORKS OUT WHAT IS BEING ASKED FOR")
        show("target kind", target.kind)
        if target.host:
            show("destination", f"{target.host}:{target.port}{target.path}")
        if target.recipients:
            show("recipients", list(target.recipients))
        if target.kind == "doc" and target.path:
            show("document", target.path)
        why(
            "The tool name alone is not enough to judge. The broker resolves the "
            "request into a concrete target — which host, which document, how "
            "many rows, which recipients — because the rules are written about "
            "targets, not about tool names."
        )
        return target

    def execute(self, tool, args):
        result = self._inner.execute(tool, args)
        stage("⑨", "THE BROKER EXECUTES, ON THE AGENT'S BEHALF")
        show("returned", clip(result.content))
        show("rows", result.rows)
        show("data class of this result", result.data_class or "none")
        why(
            "The agent never touched the backend itself. It holds no database "
            "credential and no network route — it asked, and the broker acted "
            "for it. That is why authorisation is possible at all."
        )
        return result


class NarratedTaint:
    """Wraps the taint tracker so state changes are announced."""

    def __init__(self, inner: TaintTracker) -> None:
        self._inner = inner

    def snapshot(self, task_id):
        return self._inner.snapshot(task_id)

    def record_read(self, task_id, *, data_class, rows):
        before = self._inner.snapshot(task_id)
        self._inner.record_read(task_id, data_class=data_class, rows=rows)
        after = self._inner.snapshot(task_id)
        if before != after:
            stage("⑩", "THE TASK'S STATE CHANGES")
            show("data classes held", f"{before['data_classes_held']} → {after['data_classes_held']}")
            show("rows read", f"{before['rows_returned_so_far']} → {after['rows_returned_so_far']}")
            if "pii" in after["data_classes_held"] and "pii" not in before["data_classes_held"]:
                why(
                    "This is the pivotal line of the whole run. From here on the "
                    "task is carrying customer data, and every later egress "
                    "decision is different because of it — including to "
                    "destinations that are on the approved list. Taint is tracked "
                    "for the whole task, not per value, so summarising or "
                    "re-encoding the data does not launder it."
                )


class NarratedLLM:
    """Wraps the model client to show the conversation and the reply."""

    def __init__(self, inner) -> None:
        self._inner = inner
        self.turn = 0

    def next_step(self, messages: list[dict]) -> dict:
        self.turn += 1
        banner(f"STEP {self.turn}")
        stage("①", "THE MODEL IS ASKED")
        show("messages in the conversation", len(messages))
        show("the task (message 1)", clip(messages[0]["content"], 160))
        if len(messages) > 1:
            show("latest tool result handed back", clip(messages[-1]["content"], 200))
        if self.turn == 3:
            why(
                "By now the poisoned article's text is in this conversation. The "
                "attacker's instruction and your instruction are both just text "
                "in the same context, arriving through the same channel. That is "
                "prompt injection — there is nothing here for the model to "
                "distinguish them by."
            )
        else:
            why(
                "The conversation is the task followed by every tool result, in "
                "order. That is all 'context' means, and it is why anything the "
                "agent reads becomes something the model reads."
            )

        step = self._inner.next_step(messages)

        stage("②", "THE MODEL REPLIES")
        if step["type"] == "tool_use":
            show("wants to call", step["tool"])
            show("with arguments", clip(json.dumps(step["args"]), 260))
            why(
                "A request, not an action. Nothing has happened yet — the model "
                "produced text naming a tool, and the runtime decides what to do "
                "with that."
            )
        else:
            show("final message", clip(step.get("text", ""), 400))
        return step


class NarratedDispatcher:
    """Wraps the agent's outbound call so the request is visible."""

    def __init__(self, inner: BrokeredDispatcher, token: str) -> None:
        self._inner = inner
        self._token = token

    def call(self, tool: str, args: dict) -> dict:
        stage("③", "THE AGENT ASKS THE BROKER")
        show("POST", f"/v1/tools/{tool}/invoke")
        show("Authorization", f"Bearer {self._token[:24]}…")
        why(
            "The agent presents the task token it was handed at start-up. It "
            "cannot mint a broader one: it holds no signing key, and the service "
            "that does mint runs on a network it has no route to."
        )
        result = self._inner.call(tool, args)
        stage("⑪", "WHAT THE AGENT IS TOLD")
        if "error" in result:
            show("refused", f"{result.get('rule', result['error'])}")
            why(
                "A refusal comes back as ordinary data, not an exception, so the "
                "agent keeps working and can report that it was not permitted. A "
                "denial that crashed the agent would look like the guard breaking "
                "the task."
            )
        else:
            show("result", clip(result.get("content", ""), 200))
        gate()
        return result


# --------------------------------------------------------------------------- #
#  runner
# --------------------------------------------------------------------------- #
def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def _start_opa() -> tuple[subprocess.Popen, str]:
    binary = shutil.which("opa") or str(Path.home() / ".local/bin/opa")
    if not Path(binary).exists():
        sys.exit("opa not found. See docs/WALKTHROUGH.md Part 0.")
    port = _free_port()
    process = subprocess.Popen(
        [binary, "run", "--server", f"--addr=127.0.0.1:{port}", "policies"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    url = f"http://127.0.0.1:{port}"
    for _ in range(80):
        try:
            httpx.get(f"{url}/health", timeout=0.25)
            return process, url
        except httpx.HTTPError:
            time.sleep(0.1)
    process.terminate()
    sys.exit("OPA did not start")


def main(argv: list[str] | None = None) -> int:
    global SHOW_WHY, PAUSE
    argv = sys.argv[1:] if argv is None else argv
    live = "--live" in argv
    PAUSE = "--pause" in argv
    SHOW_WHY = "--quiet-why" not in argv

    opa, opa_url = _start_opa()
    try:
        tmp = Path(tempfile.mkdtemp())
        db = tmp / "customers.db"
        seed_customers(db, 10312)
        sinkhole.RECEIVED.clear()
        mailer.OUTBOX.clear()

        banner("SETUP — what exists before the agent starts")
        show("policy bundle", f"policies/  digest {policy_bundle_digest(Path('policies'))[:22]}…", 5)
        show("policy engine", f"real OPA server at {opa_url}", 5)
        show("customer database", f"{db.name}, 10,312 synthetic records", 5)
        show("audit log", "empty, hash chain starts at 64 zeroes", 5)

        stage("⓪", "THE ORCHESTRATOR MINTS A TASK TOKEN")
        signer = Signer.generate()
        token = signer.mint(
            agent_id="triage-bot",
            task_id="4711",
            purpose="support-triage",
            allowed_tools=["read_document", "query_customers", "http_fetch", "send_email"],
            data_classes=["public", "internal"],
            counterparties=["customer:8812"],
        )
        claims = Verifier(signer.public_key_pem()).verify(token)
        show("purpose", claims.purpose)
        show("allowed tools", list(claims.allowed_tools))
        show("counterparties", list(claims.counterparties))
        show("expires in", f"{claims.exp - int(time.time())} seconds")
        why(
            "This is the initiator's job — a ticket webhook, a queue consumer, an "
            "admin UI. It declares what the task is FOR and the authority that "
            "purpose needs. The agent is handed the result; it never asks for it. "
            "Note there is no credential in here: no database password, no API "
            "key. Just a statement of intent, signed, expiring in five minutes."
        )
        gate()

        # real components, wrapped for narration only
        docstore_client = TestClient(docstore.app)
        mailer_client = TestClient(mailer.app)
        sinkhole_client = TestClient(sinkhole.app)

        def route(request: httpx.Request) -> httpx.Response:
            target = {
                "docstore.internal": docstore_client,
                "mailer.internal": mailer_client,
                "attacker.example": sinkhole_client,
            }[request.url.host]
            response = target.request(request.method, request.url.path, content=request.content)
            return httpx.Response(response.status_code, content=response.content)

        audit = NarratedAudit(AuditLog(tmp / "audit.jsonl"))
        pdp = NarratedPDP(PolicyDecisionPoint(opa_url, client=httpx.Client(timeout=5.0)))
        app = create_app(
            verifier=Verifier(signer.public_key_pem()),
            pdp=pdp,
            taint=NarratedTaint(TaintTracker()),
            audit=audit,
            backends=NarratedBackends(
                Backends(
                    docstore_url="http://docstore.internal",
                    db_path=db,
                    mailer_url="http://mailer.internal",
                    client=httpx.Client(transport=httpx.MockTransport(route)),
                )
            ),
            policy_digest=policy_bundle_digest(Path("policies")),
        )

        broker_client = TestClient(app)

        def to_broker(request: httpx.Request) -> httpx.Response:
            response = broker_client.post(
                request.url.path,
                content=request.content,
                headers={"Authorization": request.headers["authorization"]},
            )
            return httpx.Response(response.status_code, content=response.content)

        dispatcher = NarratedDispatcher(
            BrokeredDispatcher(
                broker_url="http://broker:8080",
                token=token,
                client=httpx.Client(transport=httpx.MockTransport(to_broker)),
            ),
            token,
        )

        llm = (
            live_client_from_env(os.environ)
            if live
            else Cassette(Path("agent/cassettes/support-triage.json"))
        )

        banner(f"THE TASK: {SYSTEM_TASK[:60]}…")
        run_task(dispatcher, NarratedLLM(llm), task_id="4711")

        banner("WHAT ACTUALLY HAPPENED")
        chain_ok, bad = audit.verify_chain()
        print(render_replay([r for r in audit.records() if r["task_id"] == "4711"], chain_ok=chain_ok), end="")
        hr()
        leaked = sum(len(b) for b in sinkhole.RECEIVED)
        show("bytes that reached attacker.example", leaked, 2)
        show("emails actually delivered", len(mailer.OUTBOX), 2)
        show("audit chain", "intact" if chain_ok else f"BROKEN at seq {bad}", 2)
        why(
            "The task completed and the attack did not. Those are not in tension: "
            "a control that also breaks the real work is not one anyone deploys."
        )
        return 0
    finally:
        opa.terminate()
        opa.wait(timeout=5)


if __name__ == "__main__":
    sys.exit(main())
