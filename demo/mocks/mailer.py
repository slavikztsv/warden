"""Mail sink. Records what was sent so tests can assert the task completed."""

from __future__ import annotations

from fastapi import FastAPI

app = FastAPI(title="mailer")
OUTBOX: list[dict] = []


@app.post("/send")
def send(message: dict) -> dict:
    OUTBOX.append(message)
    return {"sent": True}


@app.get("/outbox")
def outbox() -> list[dict]:
    return OUTBOX
