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
    """Split CONNECT's host:port. Never raises.

    An unparseable authority yields port 0, which matches no allowlist entry,
    so it denies. Raising here would drop the connection with no HTTP response
    and no audit record — failing closed, but invisibly, which is the one thing
    this component exists to prevent.
    """
    if authority.startswith("["):  # [::1]:443 — bracketed IPv6 literal
        host, _, rest = authority.partition("]")
        host, port = host[1:], rest.lstrip(":")
    elif ":" not in authority:
        host, port = authority, "443"
    else:
        host, _, port = authority.rpartition(":")
    try:
        return host, int(port) if port else 443
    except ValueError:
        return host, 0


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
    target = {
        "kind": "http",
        "host": host,
        "port": port,
        "path": "",
        "estimated_rows": 0,
        "recipients": [],
    }

    try:
        token = verifier.verify(token_str)
    except TokenInvalid:
        # Audit the unauthenticated attempt. This is the single most valuable
        # record the proxy produces: a CONNECT carrying no valid token is what
        # a bypass attempt looks like, and leaving it untraced would defeat the
        # component's whole purpose. There is no token to attribute it to, so
        # the principal fields carry sentinels.
        audit.append(
            task_id="-",
            agent_id="unauthenticated",
            purpose="-",
            action={"type": "egress", "tool": "CONNECT"},
            target=target,
            args_digest="sha256:none",
            decision="deny",
            rule=NO_TOKEN,
            task_state={"data_classes_held": [], "rows_returned_so_far": 0},
            policy_bundle_digest=policy_digest,
        )
        return False, NO_TOKEN

    state = taint.snapshot(token.task_id)
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


def _audit_refusal(*, audit, policy_digest: str, host: str, port: int, rule: str) -> None:
    """Record a refusal that never reached the policy.

    Denying without recording is the one failure mode this component cannot
    have. An unparseable request, an oversized header, or a non-CONNECT method
    is exactly what a probe looks like, and a bare socket close would leave the
    replay showing a clean run. Best-effort: if the audit write itself fails we
    still refuse, because refusing is not optional.
    """
    try:
        audit.append(
            task_id="-",
            agent_id="unauthenticated",
            purpose="-",
            action={"type": "egress", "tool": "CONNECT"},
            target={
                "kind": "http",
                "host": host,
                "port": port,
                "path": "",
                "estimated_rows": 0,
                "recipients": [],
            },
            args_digest="sha256:none",
            decision="deny",
            rule=rule,
            task_state={"data_classes_held": [], "rows_returned_so_far": 0},
            policy_bundle_digest=policy_digest,
        )
    except OSError:
        pass  # noqa: the refusal below still happens; losing the record is not a reason to allow


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
            # Parsing runs inside its own guard. asyncio's StreamReader raises
            # on a header line past its 64KiB limit, and that raise happens
            # before authorization is ever reached — which used to mean a bare
            # socket close with no HTTP response and no audit record.
            try:
                request_line = await reader.readline()
                headers = {}
                while (line := await reader.readline()) not in (b"\r\n", b"\n", b""):
                    name, _, value = line.decode("latin-1").partition(":")
                    headers[name.strip().lower()] = value.strip()

                method, _, rest = request_line.decode("latin-1").partition(" ")
                authority = rest.split(" ")[0]
                token_str = headers.get("proxy-authorization", "").removeprefix("Bearer ")
            except Exception:
                _audit_refusal(
                    audit=deps["audit"],
                    policy_digest=deps["policy_digest"],
                    host="",
                    port=0,
                    rule="proxy.unparseable",
                )
                writer.write(
                    b"HTTP/1.1 400 Bad Request\r\nX-Warden-Rule: proxy.unparseable\r\n\r\n"
                )
                await writer.drain()
                return

            if method.upper() != "CONNECT":
                # A non-CONNECT method is a probe. 405 alone left no trace.
                host, port = parse_authority(authority)
                _audit_refusal(
                    audit=deps["audit"],
                    policy_digest=deps["policy_digest"],
                    host=host,
                    port=port,
                    rule="proxy.method_not_allowed",
                )
                writer.write(
                    b"HTTP/1.1 405 Method Not Allowed\r\n"
                    b"X-Warden-Rule: proxy.method_not_allowed\r\n\r\n"
                )
                await writer.drain()
                return

            # A raise here would drop the connection with no response and no
            # record. Deny explicitly instead, so the attempt is still visible.
            try:
                allowed, rule = authorize_connect(
                    authority=authority, token_str=token_str, **deps
                )
            except Exception:
                allowed, rule = False, "proxy.error"

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
