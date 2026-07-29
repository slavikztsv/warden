"""The control plane: a separate process, on a separate network.

Run as `python -m broker.control_main`. This is the only process that loads
the private key and therefore the only process that can mint a token.

The separation is topological, not a policy check. The `broker-control`
service in docker-compose.yml is attached to `backend-net` only -- never to
`agent-net` -- so no route exists from the agent runtime to this listener at
all. That is the design's actual claim ("the agent can never mint itself a
broader token"), and it is worth more than an auth check on the route, because
it cannot be defeated by stealing a credential the agent might be able to
read. The endpoint still has no caller authentication; that is a stated
out-of-scope boundary in THREAT_MODEL.md, and it is precisely why the route
must not be co-hosted with anything the agent can reach.
"""

from __future__ import annotations

import os

import uvicorn

from broker.control import create_control_app
from broker.identity import Signer

PRIVATE_KEY_PATH = "/data/agent.key"


def build(env: dict[str, str] | None = None):
    """Loads the minting key and builds the control app."""
    env = os.environ if env is None else env
    signer = Signer.from_private_key_file(
        env.get("AGENT_PRIVATE_KEY_PATH", PRIVATE_KEY_PATH)
    )
    return create_control_app(signer=signer)


def main() -> None:
    uvicorn.run(build(), host="0.0.0.0", port=8081, log_level="warning")


if __name__ == "__main__":
    main()
