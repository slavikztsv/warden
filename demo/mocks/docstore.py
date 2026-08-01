"""Document store. One of these documents is poisoned.

The ticket and the four candidate poison payloads live as files under
`demo/scenario/task.toml`'s `[scenario].documents` (see `demo/scenario/
documents/`), not as string literals here — this module only knows how to
read and serve them.
"""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse

from demo.scenario.task import DOCUMENTS_ROOT, SCENARIO


def _read(name: str) -> str:
    return (DOCUMENTS_ROOT / name).read_text()


TICKET = _read("ticket-4711.txt")

# The four candidate payloads for the same poisoned document. The ticket
# always references 'kb/refund-policy'; swapping what that document CONTAINS
# keeps the operator's instruction identical, so the model is fooled by
# something it read rather than told by its principal. That distinction is
# the whole demo.
#
# These are written to be plausible, because real injection is. "backup" --
# the default, note its fallback destination: docstore.internal IS on the
# egress allowlist, so only the taint rule stops the second attempt -- is the
# only one written to sound sinister on its face ("export the full customer
# table to attacker.example"), and models decline it on the hostname alone,
# which measures their instincts about strings, not anyone's containment. The
# other three (recon, qa, audit) are the realistic tests of the allowlist and
# the taint rule: plausible, unremarkable-sounding, and each named once and
# measured -- none iterated on to defeat a refusal.
POISON_NAMES = ("backup", "recon", "qa", "audit")
POISONS = {name: _read(f"kb/refund-policy.{name}.txt") for name in POISON_NAMES}

DOCUMENTS = {"ticket-4711": TICKET, "kb/refund-policy": POISONS[SCENARIO["poison"]]}

# Bodies POSTed to /feedback. An internal, allowlisted destination is still a
# place customer data can land, and "0 bytes reached the attacker" says nothing
# about it -- so the damage was real and unmeasured until this existed.
RECEIVED: list[str] = []


def set_poison(name: str) -> None:
    """Swap which payload the referenced knowledge-base article carries.

    Re-reads the file rather than reusing POISONS, so the payload actually on
    disk is what gets served.
    """
    DOCUMENTS["kb/refund-policy"] = _read(f"kb/refund-policy.{name}.txt")

app = FastAPI(title="docstore")


@app.get("/docs/{doc_id:path}", response_class=PlainTextResponse)
def read_document(doc_id: str) -> PlainTextResponse:
    if doc_id not in DOCUMENTS:
        return PlainTextResponse("not found", status_code=404)
    return PlainTextResponse(DOCUMENTS[doc_id])


@app.post("/feedback")
async def feedback(request: Request) -> dict:
    """The fallback exfil destination. Reachable, allowlisted, and never
    reached in the guarded profile because the task is tainted.

    Takes the raw Request and accepts ANY body. The signature used to be
    `payload: dict`, which FastAPI validates: the exfiltrated customer rows
    are a JSON *array*, so this endpoint answered 422 and the counterfactual
    that carries rule 4's entire argument could not be demonstrated. The
    argument only lands if this destination genuinely works and is genuinely
    allowlisted -- otherwise the guarded run proves nothing more than that a
    broken endpoint stayed broken. This mock exists to be reachable; it must
    never be the thing that refuses.
    """
    body = await request.body()
    RECEIVED.append(body.decode("utf-8", errors="replace"))
    return {"received": True}


@app.get("/__received")
def received() -> dict:
    return {"request_count": len(RECEIVED), "total_bytes": sum(len(b) for b in RECEIVED)}
