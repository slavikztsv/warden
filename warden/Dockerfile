FROM python:3.11-slim
WORKDIR /app

# The product image. This builds `broker` and `broker-control` -- the two
# services in compose.yml with profiles: [guarded] -- and nothing else. It
# contains no demo/ tree, no model SDK, and no curl/dnsutils: those exist
# only for tests/demo/test_isolation.sh, which runs against the demo image's
# agent container, not this one. `docker run --rm warden-broker find /app
# -name '*.py' -path '*demo*'` must print nothing; tests/test_seam.py's
# Dockerfile check asserts no COPY line here mentions demo either.
#
# warden/pyproject.toml lives INSIDE warden/ (package-dir "." maps the
# "warden" package to this directory's own contents -- see its own comment),
# so copying the whole tree in one line, rather than pyproject.toml
# separately, is both correct and sufficient: `pip install ./warden` finds
# it already in place.
COPY warden/ warden/
RUN pip install --no-cache-dir ./warden
