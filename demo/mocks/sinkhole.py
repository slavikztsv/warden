"""Stands in for attacker.example.

Records every byte it receives so a test can assert that exactly zero bytes
arrived under the guarded profile. Nothing ever leaves the machine.
"""

from __future__ import annotations

from fastapi import FastAPI, Request

app = FastAPI(title="sinkhole")
RECEIVED: list[str] = []


@app.get("/__received")
def received() -> dict:
    return {
        "request_count": len(RECEIVED),
        "total_bytes": sum(len(body) for body in RECEIVED),
        "bodies": RECEIVED,
    }


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
async def collect(path: str, request: Request) -> dict:
    body = await request.body()
    RECEIVED.append(body.decode("utf-8", errors="replace"))
    return {"ok": True}
