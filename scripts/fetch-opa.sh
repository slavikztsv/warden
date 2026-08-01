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
  "$DEST" version | head -1
  exit 0
fi
curl -sSL -o "$DEST" \
  "https://openpolicyagent.org/downloads/v$VERSION/opa_linux_amd64_static"
chmod +x "$DEST"
"$DEST" version | head -1
