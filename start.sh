#!/usr/bin/env bash
# Called after a restart (and by install.sh): update the repo, then start the work if it is not already running.
SHARE="${1:?usage: start.sh SHARE}"
export PATH="/opt/homebrew/bin:/usr/local/bin:$HOME/.local/bin:$PATH"
HERE="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$HERE/out"
{
  echo "$(date '+%Y-%m-%dT%H:%M:%S') start (share $SHARE)"
  git -C "$HERE" pull --ff-only || echo "git pull failed (continuing with what is here)"
  bash "$HERE/run.sh" "$SHARE"
} >> "$HERE/out/start.log" 2>&1
tail -n 3 "$HERE/out/start.log"
