"""Forward proxy on :3128 — the only egress path off agent-net.

We authorize on CONNECT host:port and do NOT intercept TLS. This is a
deliberate limitation: an approved destination remains a covert channel,
because we never see inside the tunnel. The proxy exists to make out-of-band
bypass attempts visible and denied, not to inspect content.
"""

from __future__ import annotations

import asyncio
import base64

from warden.broker.audit import AuditLog
from warden.broker.identity import TokenInvalid, Verifier
from warden.broker.pdp import PolicyDecisionPoint
from warden.broker.taint import TaintTracker

NO_TOKEN = "unauthenticated"


def proxy_token(header: str) -> str:
    """Pull the task token out of a Proxy-Authorization header.

    Two forms are accepted, because a proxy has to work with clients it does
    not control:

      · `Bearer <jwt>` — what our own code sends when it can set headers.
      · `Basic <base64 user:pass>` — what every proxy-aware HTTP client sends
        when the token is embedded in the proxy URL. That is the only way to
        authenticate a third-party SDK's internal HTTP client without patching
        it, and a model SDK is exactly that case.

    The username is ignored; the password carries the token. Anything else
    yields the empty string, which fails verification and is audited as
    `unauthenticated` like any other unauthorized CONNECT.
    """
    if header.startswith("Bearer "):
        return header.removeprefix("Bearer ")
    if header.startswith("Basic "):
        try:
            decoded = base64.b64decode(header.removeprefix("Basic "), validate=True)
            _, _, password = decoded.decode("utf-8").partition(":")
        except (ValueError, UnicodeDecodeError):
            return ""
        return password
    return ""


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
            task_state={"data_classes_held": [], "rows_charged_so_far": 0},
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
            task_state={"data_classes_held": [], "rows_charged_so_far": 0},
            policy_bundle_digest=policy_digest,
        )
    except OSError:
        # The refusal below still happens; losing the record is not a reason to allow.
        pass


async def _pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    """Copy one direction of an established tunnel.

    This deliberately does NOT close the peer when its own side reaches EOF.
    Closing it tore down the opposite direction mid-flight: on a keep-alive
    tunnel carrying several requests, the first side to finish sending killed
    the connection the response was still arriving on, and the caller received
    an empty reply. Found by running a live model through the proxy — the third
    request of a session came back with no content, every time, while the same
    agent talking directly to the same provider worked.

    Signal EOF instead, and let the handler close both sockets once both
    directions have finished.
    """
    try:
        while chunk := await reader.read(65536):
            writer.write(chunk)
            await writer.drain()
        if writer.can_write_eof():
            writer.write_eof()
    except (ConnectionError, OSError):
        # The peer is gone. The other direction observes the same thing and
        # ends on its own; there is nothing to recover and nothing to report.
        return


async def serve_proxy(host: str, port: int, **deps) -> asyncio.AbstractServer:
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
                token_str = proxy_token(headers.get("proxy-authorization", ""))
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
            except OSError:
                # The audit log itself failed. We cannot record, so we cannot
                # act — same rule as the broker's tool surface, and reported
                # distinctly rather than hidden behind a generic error.
                allowed, rule = False, "audit.unavailable"
            except Exception:
                allowed, rule = False, "proxy.error"

            if not allowed:
                status = "503 Service Unavailable" if rule == "audit.unavailable" else "403 Forbidden"
                writer.write(
                    f"HTTP/1.1 {status}\r\nX-Warden-Rule: {rule}\r\n\r\n".encode()
                )
                await writer.drain()
                return

            target_host, target_port = parse_authority(authority)
            try:
                upstream_reader, upstream_writer = await asyncio.open_connection(
                    target_host, target_port
                )
            except OSError:
                # The allow is already durably recorded. If the tunnel then
                # cannot be established, answer the client — an allow in the
                # log must never be paired with silence on the wire, or the
                # replay will show a connection that never happened.
                writer.write(
                    b"HTTP/1.1 502 Bad Gateway\r\n"
                    b"X-Warden-Rule: upstream.unreachable\r\n\r\n"
                )
                await writer.drain()
                return
            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await writer.drain()
            try:
                await asyncio.gather(
                    _pipe(reader, upstream_writer),
                    _pipe(upstream_reader, writer),
                    return_exceptions=True,
                )
            finally:
                # Both directions are done, so the upstream socket is ours to
                # close. _pipe no longer does it, precisely so that one
                # direction finishing cannot cut the other off.
                if not upstream_writer.is_closing():
                    upstream_writer.close()
        finally:
            if not writer.is_closing():
                writer.close()

    return await asyncio.start_server(handle, host, port)
