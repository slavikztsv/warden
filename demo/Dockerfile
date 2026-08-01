FROM python:3.11-slim
WORKDIR /app

# The demo image. This builds docstore, mailer, sinkhole, agent-runtime and
# agent-runtime-unprotected in demo/compose.demo.yml. It contains BOTH trees
# by necessity, not by mistake: demo/cli/explain.py imports eight
# warden.broker modules and mounts the app in-process through TestClient,
# which is what makes its narration the real code path rather than a
# reimplementation of it. The seam is one-directional -- warden/Dockerfile's
# image contains none of this -- and that direction is what pip enforces
# (demo/pyproject.toml depends on warden; warden/pyproject.toml does not, and
# cannot, depend on warden-demo) and tests/test_seam.py checks.
#
# curl and dnsutils are deliberate: tests/demo/test_isolation.sh needs real
# tools inside the agent container to prove there is no route out.
RUN apt-get update && apt-get install -y --no-install-recommends curl dnsutils \
    && rm -rf /var/lib/apt/lists/*

COPY warden/ warden/
COPY demo/ demo/

# Model SDKs are installed ONLY when asked for, via LIVE=1 -- set by
# demo/compose.demo.yml on agent-runtime and agent-runtime-unprotected so
# `--live` works in-container, left at 0 (the default) everywhere else in
# this image, e.g. docstore/mailer/sinkhole, none of which touch a model.
ARG LIVE=0
RUN pip install --no-cache-dir ./warden \
    && if [ "$LIVE" = "1" ]; then pip install --no-cache-dir "./demo[live]"; \
       else pip install --no-cache-dir ./demo; fi
