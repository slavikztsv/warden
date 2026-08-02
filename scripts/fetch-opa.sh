#!/usr/bin/env bash
# Downloads the pinned OPA into ~/.cache/warden/, where tools/opa_version.py
# looks first. Deliberately NOT ~/.local/bin: that is where an unpinned opa is
# already installed on some machines, and the point is to stop resolving to it.
set -euo pipefail
VERSION="$(python3 -c 'import sys; sys.path.insert(0, "."); from tools.opa_version import OPA_VERSION; print(OPA_VERSION)')"
DEST="$HOME/.cache/warden/opa-$VERSION"
mkdir -p "$(dirname "$DEST")"
if [ -x "$DEST" ]; then
  echo "already present: $DEST"
else
  curl -sSL -o "$DEST" \
    "https://openpolicyagent.org/downloads/v$VERSION/opa_linux_amd64_static"
  chmod +x "$DEST"
fi
# sed, NOT `head -1`: head exits after the first line and closes the pipe, opa
# takes SIGPIPE while writing its other seven lines, and the `set -o pipefail`
# above turns that into exit 141 -- failing CI at this step, before a single
# test ran, on commits that touched nothing near it. It is a race decided by
# whether opa finished writing first, so it struck about one push in five and
# looked like flakiness. sed reads to EOF, so the producer is never signalled.
"$DEST" version | sed -n '1p'

# CI consumes $OPA_BIN rather than restating the version or the path itself --
# that restatement is exactly the duplication this task exists to remove.
# GITHUB_ENV is unset for a plain local run (which is how this binary gets
# onto a dev machine in the first place), so this is a no-op there.
if [ -n "${GITHUB_ENV:-}" ]; then
  echo "OPA_BIN=$DEST" >> "$GITHUB_ENV"
fi
