FROM python:3.11-slim
WORKDIR /app
# curl and dnsutils are installed deliberately: tests/test_isolation.sh needs
# real tools inside the agent container to prove there is no route out.
RUN apt-get update && apt-get install -y --no-install-recommends curl dnsutils \
    && rm -rf /var/lib/apt/lists/*
COPY requirements.txt requirements-live.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Model SDKs are installed ONLY into the agent image, and only when asked for.
# The broker, broker-control, OPA-facing code and the mocks share this
# Dockerfile and must not carry a model SDK at all: the enforcement point has
# no business holding one, and requirements.txt stays the minimal set that CI
# proves the whole system runs on. Built with LIVE=1 for the two agent services
# so `--live` works in-container; left at 0 everywhere else.
ARG LIVE=0
RUN if [ "$LIVE" = "1" ]; then pip install --no-cache-dir -r requirements-live.txt; fi

# Copied to match the dotted import paths (warden.broker.*, demo.agent.*,
# demo.mocks.*, demo.scenario.*) rather than flattened to their old
# top-level names: every module inside warden/broker now imports its
# siblings as `warden.broker.*` (Task 20), so the package's own __init__.py
# has to land in the image alongside it or those imports fail. demo/scenario
# is needed too -- not for its warden.toml/control.toml/tools.toml (those
# reach the broker and broker-control containers as read-only bind mounts at
# /config/*, kept out of the image on purpose), but because
# demo/agent/tools.py's DirectDispatcher (the unprotected profile, which
# talks to backends directly with no broker in the loop) builds its own
# catalog from demo.scenario.catalog.demo_catalog(), which loads
# demo/scenario/tools.toml by a path relative to catalog.py's own location,
# not from the mount. No warden/cli or demo/cli here -- no container command
# reaches either; only serve, control_main, agent.loop and the three mock
# apps run in-container.
COPY warden/__init__.py warden/__init__.py
COPY warden/broker/ warden/broker/
COPY demo/__init__.py demo/__init__.py
COPY demo/agent/ demo/agent/
COPY demo/mocks/ demo/mocks/
COPY demo/scenario/ demo/scenario/
