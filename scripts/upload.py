"""Sends the new, complete lines of out/tools-share<N>.jsonl to the main PC's wolf_receiver.py, every few minutes.

Resumable: asks the receiver how many bytes it has and sends only what comes after. Stops by itself once the
trajectory maker has finished and everything is sent. The address: NEURO_WOLF_RECEIVER, else receiver.txt next to
this folder, else the default below.

  python upload.py --file out/tools-share1.jsonl
"""

import argparse
import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
DEFAULT = "http://192.168.7.14:8790"
CHUNK = 32 * 1024 * 1024


def receiver():
    if os.environ.get("NEURO_WOLF_RECEIVER"):
        return os.environ["NEURO_WOLF_RECEIVER"].rstrip("/")
    f = HERE / "receiver.txt"
    if f.exists() and f.read_text(encoding="utf-8").strip():
        return f.read_text(encoding="utf-8").strip().rstrip("/")
    return DEFAULT


def call(url, data=None):
    req = urllib.request.Request(url, data=data, method="POST" if data is not None else "GET")
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"{}")
        except ValueError:
            return e.code, {}


def sync(base, path):
    """Send everything up to the last complete line. Returns True when the receiver has all of it."""
    if not path.exists():
        return True
    code, body = call(f"{base}/size/{path.name}")
    if code != 200:
        raise OSError(f"receiver said {code} {body}")
    have = int(body["size"])
    with path.open("rb") as f:
        f.seek(0, 2)
        total = f.tell()
        while have < total:
            f.seek(have)
            data = f.read(CHUNK)
            cut = data.rfind(b"\n")
            if cut < 0:
                break  # the last line is still being written
            data = data[:cut + 1]
            code, body = call(f"{base}/append/{path.name}?offset={have}", data)
            if code == 409:
                have = int(body["size"])
                continue
            if code != 200:
                raise OSError(f"receiver said {code} {body}")
            have = int(body["size"])
            print(f"{time.strftime('%H:%M:%S')} sent up to {have} of {total} bytes", flush=True)
    return have >= total


def maker_running(path):
    marker = str(HERE / "scripts" / "make_wolf_trajectories.py")
    try:
        if os.name == "nt":
            import subprocess
            out = subprocess.run(["powershell", "-NoProfile", "-Command",
                                  "(Get-CimInstance Win32_Process -Filter \"Name like 'python%'\").CommandLine"],
                                 capture_output=True, text=True, timeout=60).stdout
        else:
            import subprocess
            out = subprocess.run(["ps", "-axo", "args="], capture_output=True, text=True, timeout=30).stdout
    except Exception:
        return True
    return marker.replace("\\", "/").lower() in out.replace("\\", "/").lower()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", required=True)
    ap.add_argument("--every", type=int, default=300)
    a = ap.parse_args()
    path = Path(a.file).resolve()
    base = receiver()
    print(f"uploading {path.name} to {base} every {a.every} s", flush=True)
    while True:
        running = maker_running(path)
        try:
            complete = sync(base, path)
        except Exception as e:
            print(f"{time.strftime('%H:%M:%S')} main PC not reachable ({e}); trying again later", flush=True)
            complete = False
        if complete and not running:
            print("all sent, the trajectory maker is done", flush=True)
            return
        time.sleep(a.every)


if __name__ == "__main__":
    main()
