"""Neuro-Wolf0.1: real, stripped Windows programs whose function names we know, for tool trajectories.

Each program links 6-14 real C functions from ExeBench (train_real_compilable), each compiled as its own
unit with its own declarations, plus a main that keeps them all (a table of their addresses). Undefined
callees get small stubs. The program is linked twice with the same flags: once with a map file (the
ground truth: address -> real name) and once stripped (-s), which is the file the agent works on.

  python gen_binaries.py --out D:\\neuro-models\\wolf01\\bins --count 20000 --shard 0 --shards 1

Output: <out>/<id>/prog.exe (stripped), <out>/<id>/names.json ({"0x140001450": "string_hash", ...},
plus "level", "functions" with each one's source). Held out: 1 program in 20 (by id) goes to <out>-heldout.
"""

import argparse
import json
import os
import random
import re
import shutil
import subprocess
import tempfile
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

EXEBENCH = Path(__file__).resolve().parent.parent / "exebench"
ZIG = os.environ["ZIG"]
TARGETS = [(["-target", "x86_64-linux-musl"], ".elf", ["-nostdlib", "-static", "-Wl,--entry=main"]), (["-target", "x86_64-windows-gnu"], ".exe", [])]
WARN = ["-w", "-Wno-error=implicit-function-declaration", "-Wno-error=int-conversion",
        "-Wno-error=incompatible-function-pointer-types", "-Wno-error=incompatible-pointer-types",
        "-Wno-error=implicit-int", "-Wno-error=return-type"]
LEVELS = ["O0", "O1", "O2", "Os"]


def zig(args, cwd, timeout=120):
    d = str(Path(__file__).resolve().parent.parent / "zigcache" / str(os.getpid()))  # one cache per worker: a shared one serialises on its lock
    os.environ["ZIG_GLOBAL_CACHE_DIR"] = d
    os.environ["ZIG_LOCAL_CACHE_DIR"] = d
    try:
        return subprocess.run([ZIG, "cc", *args], cwd=cwd, capture_output=True, text=True, timeout=timeout)
    except (subprocess.TimeoutExpired, OSError):
        return None


def build(job):
    pid, funcs, level, out, tix = job
    TARGET, ext, LINK = TARGETS[tix]
    if (Path(out) / f"p{pid:06d}" / "names.json").exists():  # built on an earlier run
        return 1
    work = Path(tempfile.mkdtemp(prefix="wolfbin"))
    try:
        objs, kept = [], []
        for i, f in enumerate(funcs):
            c = work / f"u{i}.c"
            c.write_text((f["deps"] or "") + "\n" + f["source"] + "\n", encoding="utf-8")
            r = zig([*TARGET, f"-{level}", "-g0", *WARN, "-c", c.name, "-o", f"u{i}.o"], work)
            if r and r.returncode == 0:
                objs.append(f"u{i}.o")
                kept.append(f)
        if len(kept) < 4:
            return None
        names = [f["name"] for f in kept]
        if len(set(names)) != len(names):
            return None
        decl = "".join(f"extern void {n}(void);\n" for n in names)
        table = ", ".join(f"(void *){n}" for n in names)
        (work / "main.c").write_text(
            f"int printf(const char *, ...);\n{decl}void *wolf_table[] = {{{table}}};\n"
            f"int main(int argc, char **argv) {{ printf(\"%d\\n\", (int)(sizeof wolf_table / sizeof *wolf_table)); "
            f"return argc > 99 ? ((int (*)(void))wolf_table[argc % {len(names)}])() : 0; }}\n", encoding="utf-8")
        stubs = set()
        for _ in range(6):  # link; give each undefined function a stub; try again
            (work / "stubs.c").write_text("".join(f"long long {s}() {{ return 0; }}\n" for s in sorted(stubs)),
                                          encoding="utf-8")
            r = zig([*TARGET, f"-{level}", "-g0", *WARN, "main.c", "stubs.c", *objs, *LINK, "-o", "full" + ext], work)
            if r is None:
                return None
            if r.returncode == 0:
                break
            missing = set(re.findall(r"undefined symbol: (\w+)", r.stderr))
            if not missing or missing <= stubs:
                return None
            stubs |= missing
        else:
            return None
        truth = {}
        import lief
        binary = lief.parse(str(work / ("full" + ext)))
        if binary is None:
            return None
        wanted = set(names)
        for sym in binary.symbols:
            name = sym.name[1:] if sym.name.startswith("_") and sym.name[1:] in wanted else sym.name
            if name not in wanted or not sym.value:
                continue
            va = sym.value
            if ext == ".exe":  # COFF symbols are section-relative
                try:
                    va = (binary.optional_header.imagebase
                          + binary.sections[sym.section_number - 1].virtual_address + sym.value)
                except Exception:
                    continue
            truth[hex(va)] = name
        if len(truth) < 4:
            return None
        # the same file without its symbol table (relinking with -s moves code, so names would not match)
        stripped = lief.parse(str(work / ("full" + ext)))
        if ext == ".elf":
            stripped.strip()
            stripped.write(str(work / ("prog" + ext)))
        else:
            r = subprocess.run([ZIG, "objcopy", "--strip-all", "full" + ext, "prog" + ext], cwd=work,
                               capture_output=True, text=True)
            if r.returncode != 0:
                return None
        check = lief.parse(str(work / ("prog" + ext)))
        if check is None or any(s.name in wanted for s in check.symbols):
            return None
        dest = Path(out) / f"p{pid:06d}"
        dest.mkdir(parents=True, exist_ok=True)
        shutil.copy2(work / ("prog" + ext), dest / ("prog" + ext))
        (dest / "names.json").write_text(json.dumps({
            "names": truth, "level": level, "stubs": sorted(stubs),
            "functions": [{"name": f["name"], "source": f["source"], "path": f["path"]} for f in kept],
        }, ensure_ascii=False, indent=1), encoding="utf-8")
        return len(truth)
    finally:
        shutil.rmtree(work, ignore_errors=True)


def functions(path):
    import compression.zstd as zstd
    for raw in zstd.decompress(path.read_bytes()).splitlines():
        try:
            t = json.loads(raw).get("text") or {}
        except ValueError:
            continue
        src, name = (t.get("func_def") or "").strip(), (t.get("fname") or "").strip()
        if (src and re.fullmatch(r"[A-Za-z_]\w*", name) and name != "main" and 120 < len(src) < 5000
                and not name.startswith("__")):
            yield {"source": src, "name": name, "deps": t.get("real_deps") or "", "path": t.get("path") or ""}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--count", type=int, default=20000)
    ap.add_argument("--shard", type=int, default=0)
    ap.add_argument("--shards", type=int, default=1)
    ap.add_argument("--workers", type=int, default=max(1, (os.cpu_count() or 2) // 2))
    a = ap.parse_args()
    rng = random.Random(500 + a.shard)
    files = sorted(EXEBENCH.glob("*.jsonl.zst"))[a.shard::a.shards]
    rng.shuffle(files)
    out, held = Path(a.out), Path(a.out + "-heldout")
    made, pid = 0, a.shard * 10_000_000
    with ProcessPoolExecutor(a.workers) as pool:
        for path in files:
            if made >= a.count:
                break
            pool_funcs = list(functions(path))
            rng.shuffle(pool_funcs)
            jobs = []
            while len(pool_funcs) >= 6:
                k = rng.randint(6, 14)
                group, pool_funcs = pool_funcs[:k], pool_funcs[k:]
                pid += 1
                jobs.append((pid, group, rng.choice(LEVELS), str(held if pid % 20 == 0 else out), 0))  # Linux ELF: ExeBench code is mostly Linux; the Windows target fails on its headers
            for n in pool.map(build, jobs, chunksize=2):
                made += 1 if n else 0
            print(f"{path.name}: {made} programs", flush=True)
    print("done", made)


if __name__ == "__main__":
    main()
