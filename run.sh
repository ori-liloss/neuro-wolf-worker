#!/usr/bin/env bash
# Neuro-Wolf worker (Linux / macOS). Usage: bash run.sh 2   (the share number this machine got)
set -euo pipefail
SHARE="${1:?usage: bash run.sh SHARE}"
HERE="$(cd "$(dirname "$0")" && pwd)"
if pgrep -f "$HERE/scripts/(gen_binaries|make_wolf_trajectories).py" >/dev/null 2>&1; then echo "already running; nothing to start."; exit 0; fi
WORKERS="${WORKERS:-$(( $(getconf _NPROCESSORS_ONLN) > 2 ? $(getconf _NPROCESSORS_ONLN) - 2 : 1 ))}"
[ -d "$HERE/exebench-share-$SHARE" ] || { echo "no exebench-share-$SHARE here"; exit 1; }
rm -rf "$HERE/exebench"; ln -s "$HERE/exebench-share-$SHARE" "$HERE/exebench"
case "$(uname -s)-$(uname -m)" in
  Linux-x86_64)  Z=zig-linux-x86_64-0.13.0;  SUM=d45312e61ebcc48032b77bc4cf7fd6915c11fa16e4aad116b66c9468211230ea ;;
  Linux-aarch64) Z=zig-linux-aarch64-0.13.0; SUM=041ac42323837eb5624068acd8b00cd5777dac4cf91179e8dad7a7e90dd0c556 ;;
  Darwin-arm64)  Z=zig-macos-aarch64-0.13.0; SUM=46fae219656545dfaf4dce12fb4e8685cec5b51d721beee9389ab4194d43394c ;;
  Darwin-x86_64) Z=zig-macos-x86_64-0.13.0;  SUM=8b06ed1091b2269b700b3b07f8e3be3b833000841bae5aa6a09b1a8b4773effd ;;
  *) echo "unsupported: $(uname -s)-$(uname -m)"; exit 1 ;;
esac
if [ ! -x "$HERE/zig/$Z/zig" ]; then
  echo "downloading $Z (ziglang.org)"
  mkdir -p "$HERE/zig"
  curl -fsSL -o "$HERE/zig/$Z.tar.xz" "https://ziglang.org/download/0.13.0/$Z.tar.xz"
  echo "$SUM  $HERE/zig/$Z.tar.xz" | (shasum -a 256 -c - 2>/dev/null || sha256sum -c -)
  tar -xJf "$HERE/zig/$Z.tar.xz" -C "$HERE/zig" && rm "$HERE/zig/$Z.tar.xz"
fi
export ZIG="$HERE/zig/$Z/zig" PYTHONUTF8=1
# Python packages go into this folder's own venv (works where the system Python has no pip, e.g. SteamOS,
# or refuses system-wide installs, e.g. Homebrew / Debian).
PY0="${PYTHON:-python3}"
VENV="$HERE/.venv"
if [ ! -x "$VENV/bin/python" ]; then
  "$PY0" -m venv "$VENV" >/dev/null 2>&1 || { rm -rf "$VENV"; "$PY0" -m venv --without-pip "$VENV" || rm -rf "$VENV"; }
fi
if [ -x "$VENV/bin/python" ]; then PY="$VENV/bin/python"; PIPX=""; else PY="$PY0"; PIPX="--user --break-system-packages"; fi
if ! "$PY" -m pip --version >/dev/null 2>&1; then
  echo "installing pip (bootstrap.pypa.io)"
  curl -fsSL -o "$HERE/get-pip.py" https://bootstrap.pypa.io/get-pip.py
  "$PY" "$HERE/get-pip.py" --quiet $PIPX
  rm -f "$HERE/get-pip.py"
fi
"$PY" -m pip install --quiet --disable-pip-version-check $PIPX lief capstone transformers jinja2
mkdir -p "$HERE/out" "$HERE/bins"
HALF=$(( WORKERS / 2 > 0 ? WORKERS / 2 : 1 ))
nohup nice -n 10 "$PY" -u "$HERE/scripts/gen_binaries.py" --out "$HERE/bins" --count 15000 --workers $HALF --shard "$SHARE" --shards 4 > "$HERE/out/bins.log" 2> "$HERE/out/bins.err" < /dev/null &
nohup nice -n 10 "$PY" -u "$HERE/scripts/make_wolf_trajectories.py" --bins "$HERE/bins" --out "$HERE/out/tools-share$SHARE.jsonl" --count 110000 --per-program 10 --workers $HALF --seed $((100 + SHARE)) > "$HERE/out/tools.log" 2> "$HERE/out/tools.err" < /dev/null &
sleep 15
if pgrep -f "$HERE/scripts/make_wolf_trajectories.py" >/dev/null && pgrep -f "$HERE/scripts/gen_binaries.py" >/dev/null; then
  echo "RUNNING. Progress: tail -f $HERE/out/tools.log. Copy out/tools-share$SHARE.jsonl back when it stops growing."
else
  echo "FAILED to start. Last errors:"; tail -n 15 "$HERE/out/bins.err" "$HERE/out/tools.err" 2>/dev/null; exit 1
fi
