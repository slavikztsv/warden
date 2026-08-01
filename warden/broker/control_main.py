"""The control plane: a separate process, on a separate network.

Run as `python -m warden.broker.control_main`. This is the only process that loads
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
from pathlib import Path

import uvicorn

from warden.broker.config.loader import ControlConfig, load_control_config
from warden.broker.control import create_control_app
from warden.broker.identity import Signer


def build(config: ControlConfig):
    """Loads the minting key and builds the control app."""
    signer = Signer.from_private_key_file(
        config.private_key, issuer=config.issuer, default_ttl_seconds=config.ttl_seconds
    )
    return create_control_app(signer=signer)


def main() -> None:
    config = load_control_config(
        Path(os.environ.get("WARDEN_CONTROL_CONFIG", "/config/control.toml")), os.environ
    )
    host, port = config.listen
    uvicorn.run(build(config), host=host, port=port, log_level="warning")


if __name__ == "__main__":
    main()
