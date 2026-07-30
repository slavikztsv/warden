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

COPY broker/ broker/
COPY agent/ agent/
COPY mocks/ mocks/
COPY cli/ cli/
