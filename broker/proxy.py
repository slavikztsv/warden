"""Forward proxy on :3128 — the only egress path off agent-net.

We authorize on CONNECT host:port and do NOT intercept TLS. This is a
deliberate limitation: an approved destination remains a covert channel,
because we never see inside the tunnel. The proxy exists to make out-of-band
bypass attempts visible and denied, not to inspect content.
"""

from __future__ import annotations

import asyncio

from broker.audit import AuditLog
from broker.identity import TokenInvalid, Verifier
from broker.pdp import PolicyDecisionPoint
from broker.taint import TaintTracker

NO_TOKEN = "unauthenticated"


def parse_authority(authority: str) -> tuple[str, int]:
    host, _, port = authority.partition(":")
    return host, int(port) if port else 443


def authorize_connect(
    *,
    authority: str,
    token_str: str,
    verifier: Verifier,
    pdp: PolicyDecisionPoint,
    taint: TaintTracker,
    audit: AuditLog,
    policy_digest: str,
) -> tuple[bool, str]:
    host, port = parse_authority(authority)
    try:
        token = verifier.verify(token_str)
    except TokenInvalid:
        return False, NO_TOKEN

    state = taint.snapshot(token.task_id)
    target = {
        "kind": "http",
        "host": host,
        "port": port,
        "path": "",
        "estimated_rows": 0,
        "recipients": [],
    }
    decision = pdp.decide(
        {
            "principal": {
                "agent_id": token.agent_id,
                "task_id": token.task_id,
                "purpose": token.purpose,
                "allowed_tools": list(token.allowed_tools),
                "counterparties": list(token.counterparties),
            },
            "action": {"type": "egress", "args_digest": "sha256:none"},
            "target": target,
            "task_state": state,
        }
    )
    audit.append(
        task_id=token.task_id,
        agent_id=token.agent_id,
        purpose=token.purpose,
        action={"type": "egress", "tool": "CONNECT"},
        target=target,
        args_digest="sha256:none",
        decision="allow" if decision.allow else "deny",
        rule=decision.rule,
        task_state=state,
        policy_bundle_digest=policy_digest,
    )
    return decision.allow, decision.rule


async def _pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while chunk := await reader.read(65536):
            writer.write(chunk)
            await writer.drain()
    finally:
        writer.close()


def serve_proxy(host: str, port: int, **deps) -> asyncio.AbstractServer:
    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            request_line = await reader.readline()
            headers = {}
            while (line := await reader.readline()) not in (b"\r\n", b"\n", b""):
                name, _, value = line.decode("latin-1").partition(":")
                headers[name.strip().lower()] = value.strip()

            method, _, rest = request_line.decode("latin-1").partition(" ")
            authority = rest.split(" ")[0]
            token_str = headers.get("proxy-authorization", "").removeprefix("Bearer ")

            if method.upper() != "CONNECT":
                writer.write(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")
                await writer.drain()
                return

            allowed, rule = authorize_connect(
                authority=authority, token_str=token_str, **deps
            )
            if not allowed:
                writer.write(
                    f"HTTP/1.1 403 Forbidden\r\nX-Warden-Rule: {rule}\r\n\r\n".encode()
                )
                await writer.drain()
                return

            target_host, target_port = parse_authority(authority)
            upstream_reader, upstream_writer = await asyncio.open_connection(
                target_host, target_port
            )
            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await writer.drain()
            await asyncio.gather(
                _pipe(reader, upstream_writer),
                _pipe(upstream_reader, writer),
                return_exceptions=True,
            )
        finally:
            if not writer.is_closing():
                writer.close()

    return asyncio.start_server(handle, host, port)
