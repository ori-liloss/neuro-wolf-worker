"""Neuro-Wolf0.1: tool and agent trajectories on stripped programs whose real function names we know.

The programs come from gen_binaries.py (real ExeBench C functions, linked, symbols stripped). Every tool
result is the real toolkit (neuro_re.py) output on the real file; every answer is checked against the
ground truth: the hidden sub_ADDRESS functions get their real names, and a rewrite is the original source.
Same agent format as make_re_trajectories2.py (lead / research sub-agents, SPAWN ... ENDSPAWN, WAIT).

Kinds:
  name     info, functions, decompile 2-3 of the program's own functions, then the answer names each one
           (its real name) and rewrites the first as C (the original source).
  rewrite  "rewrite the function at 0x... as C": decompile it (and often xrefs), answer with the source.
  team     functions, then two research sub-agents each decompile and name their share; the lead puts the
           reports together. Each sub-agent's own run is a row too.

  python make_wolf_trajectories.py --bins D:\\neuro-models\\wolf01\\bins --out D:\\neuro-models\\wolf01\\gen\\tools\\t-00.jsonl --count 100000
"""

from __future__ import annotations

import argparse
import json
import os
import random
import re
import sys
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

SEEDS = Path(__file__).resolve().parent
sys.path.insert(0, str(SEEDS))
sys.path.insert(0, str(SEEDS.parent))
import make_re_trajectories2 as m2  # noqa: E402

agents = m2.agents
SOURCE = "wolf-tool-trajectories"
NAMES = ["decoder", "server", "tool", "util", "parser", "daemon", "firmware_tool", "sample", "app", "worker",
         "packer", "client", "updater", "loader", "probe", "engine", "agent", "helper", "bench", "convert"]
FOLDERS = ["bin", "samples", "test", "re", "target", "files", "work", "input", "dump", "build"]

NAME_EN = ["Reverse engineer {f}: what are its own functions, and what do they do?",
           "{f} has no symbols. Name its hidden functions.",
           "Find the program's own functions in {f} and give them real names.",
           "RE {f}: name the sub_ functions and rewrite the main one as C.",
           "What does {f} do? Name its functions from their code."]
NAME_HE = ["תעשה RE ל-{f}: מה הפונקציות שלו ומה הן עושות?",
           "ל-{f} אין סמלים. תן שמות לפונקציות המוסתרות שלו.",
           "תמצא את הפונקציות של התוכנה ב-{f} ותן להן שמות אמיתיים.",
           "תעשה RE ל-{f}: תן שמות לפונקציות sub_ ותכתוב את הראשית מחדש ב-C.",
           "מה {f} עושה? תן שמות לפונקציות שלו לפי הקוד."]
REWRITE_EN = ["Rewrite the function at {a} in {f} as clean C with real names.",
              "Decompile {a} in {f} and give me equivalent C.",
              "What does the function at {a} in {f} do? Write it as C."]
REWRITE_HE = ["תכתוב מחדש את הפונקציה ב-{a} ב-{f} כ-C נקי עם שמות אמיתיים.",
              "תעשה decompile ל-{a} ב-{f} ותן לי C שקול.",
              "מה עושה הפונקציה ב-{a} ב-{f}? תכתוב אותה ב-C."]


def place(r: random.Random, prog: Path):
    folder = r.choice(FOLDERS)
    shown = r.choice(NAMES) + r.choice(["", "", ".elf", "_x64", "2"])
    rel = f"{folder}/{shown}"
    real = str(prog)
    def show(text: str) -> str:
        return (text.replace(real.replace("\\", "/"), rel).replace(real, rel)
                .replace(str(prog.parent) + "\\", "").replace(prog.name, shown))
    return folder, shown, rel, real, show


def load(prog_dir: Path):
    prog = next((p for p in prog_dir.iterdir() if p.name.startswith("prog")), None)
    meta = json.loads((prog_dir / "names.json").read_text(encoding="utf-8"))
    src = {f["name"]: f["source"] for f in meta["functions"]}
    truth = {int(a, 16): n for a, n in meta["names"].items() if n in src}
    return prog, truth, src


def own_functions(ftext: str, truth: dict) -> list[dict]:
    out = []
    for f in m2.parse_functions(ftext):
        a = int(f["addr"], 16)
        if a in truth and f["size"] >= 40:  # tiny bodies (return 0) teach nothing
            f["real"] = truth[a]
            out.append(f)
    return out


def code_block(source: str) -> str:
    return f"```c\n{source.strip()}\n```"


def name_traj(r: random.Random, prog_dir: Path, he: bool):
    prog, truth, src = load(prog_dir)
    folder, shown, rel, real, show = place(r, prog)
    info = show(m2.tool("info", real))
    ftext = show(m2.tool("functions", real, "20"))
    own = own_functions(ftext, truth)
    if len(own) < 2:
        return None
    task = r.choice(NAME_HE if he else NAME_EN).format(f=shown)
    w = m2.Writer(agents.agent_system("research", "lead"), m2.frame(task, folder, shown, rel, he, False, m2.also_installed(r)))
    w.run(f"info {rel}", info)
    w.run(f"functions {rel} 20", ftext, 900)
    picked = own[: r.choice([2, 2, 3])]
    for f in picked:
        d = show(m2.tool("decompile", real, f["addr"]))
        if "function " not in d:
            return None
        w.run(f"decompile {rel} {f['addr']}", d, 700)
    first = picked[0]
    if he:
        lines = [f"`{shown}` הוא קוד מכונה (C/C++ שקומפל). הפונקציות של התוכנה עצמה, לפי הקוד שלהן:"]
        lines += [f"- `{f['name']}` ({f['addr']}) → `{f['real']}`" for f in picked]
        lines.append(f"\n`{first['real']}` ב-C:")
        lines.append(code_block(src[first["real"]]))
        lines.append("לא בדקתי: שאר הפונקציות ברשימה; כל אחת צריכה decompile משלה.")
    else:
        lines = [f"`{shown}` is {m2.built_line(info) or 'machine code'}. The program's own functions, from their code:"]
        lines += [f"- `{f['name']}` ({f['addr']}) → `{f['real']}`" for f in picked]
        lines.append(f"\n`{first['real']}` as C:")
        lines.append(code_block(src[first["real"]]))
        lines.append("Not checked: the other functions in the list; each needs its own decompile.")
    w.answer("\n".join(lines))
    return [{"messages": w.messages, "kind": "research", "source": SOURCE, "type": "wolf-name", "hl": "he" if he else "en"}]


def rewrite_traj(r: random.Random, prog_dir: Path, he: bool):
    prog, truth, src = load(prog_dir)
    folder, shown, rel, real, show = place(r, prog)
    for addr, name in r.sample(sorted(truth.items()), len(truth)):
        a = hex(addr)
        d = show(m2.tool("decompile", real, a))
        n = re.search(r"(\d+) instructions", d)
        if "function " in d and n and int(n.group(1)) >= 12:
            break
    else:
        return None
    task = r.choice(REWRITE_HE if he else REWRITE_EN).format(a=a, f=shown)
    w = m2.Writer(agents.agent_system("research", "lead"), m2.frame(task, folder, shown, rel, he, False, m2.also_installed(r)))
    w.run(f"decompile {rel} {a}", d, 900)
    if r.random() < 0.4:
        x = show(m2.tool("xrefs", real, a))
        if x.strip():
            w.run(f"xrefs {rel} {a}", x, 400)
    intro = (f"הפונקציה ב-{a} היא `{name}`. ב-C:" if he else f"The function at {a} is `{name}`. As C:")
    w.answer(intro + "\n" + code_block(src[name]))
    return [{"messages": w.messages, "kind": "research", "source": SOURCE, "type": "wolf-rewrite", "hl": "he" if he else "en"}]


def team_traj(r: random.Random, prog_dir: Path, he: bool):
    prog, truth, src = load(prog_dir)
    folder, shown, rel, real, show = place(r, prog)
    info = show(m2.tool("info", real))
    ftext = show(m2.tool("functions", real, "20"))
    own = own_functions(ftext, truth)
    if len(own) < 4:
        return None
    task = r.choice(NAME_HE if he else NAME_EN).format(f=shown)
    extra = m2.also_installed(r)
    lead_id = r.randint(20, 900)
    w = m2.Writer(agents.agent_system("research", "lead"), m2.frame(task, folder, shown, rel, he, False, extra))
    w.run(f"info {rel}", info)
    w.run(f"functions {rel} 20", ftext, 900)
    half = min(3, len(own) // 2)
    shares = [own[:half], own[half: 2 * half]]
    spawns, results, rows, reports = [], [], [], []
    for n, share in enumerate(shares):
        cid = lead_id + n + 1
        addrs = ", ".join(f["addr"] for f in share)
        title = f"decompile and name {addrs}"
        body = (f"Decompile {addrs} in {rel}, one at a time. For each one: what it does and its real name from the "
                f"code. Report one line per function.")
        spawns.append(f"SPAWN research {title}\n{body}\nENDSPAWN")
        results.append(f"spawned #{cid} research: {title}. WAIT {cid} returns its report.")
        child_task = agents.child_prompt("research", "research", title, body, lead_id, task, cid).split("\n", 1)[1]
        cw = m2.Writer(agents.agent_system("research", "child"), f"Task:\n{child_task}\n\nRepo files: {folder}/" + m2.re_line(rel, False, extra))
        lines = []
        for f in share:
            d = show(m2.tool("decompile", real, f["addr"]))
            if "function " not in d:
                return None
            cw.run(f"decompile {rel} {f['addr']}", d, 600)
            lines.append(f"{f['addr']} {f['name']} -> {f['real']}")
        report = "\n".join(lines + [f"Done: decompiled {len(share)} functions in {rel}; nothing changed."])
        cw.answer(report)
        rows.append({"messages": cw.messages, "kind": "research", "source": SOURCE, "type": "wolf-child", "hl": "en"})
        reports.append((cid, title, report))
    w.call("\n".join(spawns), results)
    wait = [f"{len(reports)} of {len(reports)} sub-agents finished."]
    for cid, title, report in reports:
        wait += [f"#{cid} research done ({r.randint(1800, 5200)} tokens): {title}", report]
    w.call("WAIT", ["\n".join(wait)])
    named = [l for _, _, rep in reports for l in rep.splitlines() if l.startswith("0x")]
    if he:
        text = [f"חילקתי את הפונקציות של `{shown}` לשני עוזרים, וכל אחד עשה להן decompile. השמות האמיתיים:"]
        text += [f"- {l}" for l in named]
        text.append("לא נבדק: שאר הפונקציות; אותה שיטה עובדת עליהן.")
    else:
        text = [f"Two sub-agents decompiled the program's own functions in `{shown}`. Their real names:"]
        text += [f"- {l}" for l in named]
        text.append("Not checked: the other functions; the same way works for them.")
    w.answer("\n".join(text))
    return [{"messages": w.messages, "kind": "research", "source": SOURCE, "type": "wolf-team", "hl": "he" if he else "en"}] + rows


MAKERS = [(name_traj, 0.45), (rewrite_traj, 0.25), (team_traj, 0.30)]


def one(job):
    prog_dir, seed, hebrew = job
    r = random.Random(seed)
    maker = r.choices([mk for mk, _ in MAKERS], [w for _, w in MAKERS])[0]
    return m2.fit(maker, r.random(), Path(prog_dir), r.random() < hebrew)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bins", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--count", type=int, default=100000)
    ap.add_argument("--per-program", type=int, default=6, help="trajectories per program (different kinds, functions, names)")
    ap.add_argument("--hebrew", type=float, default=0.3)
    ap.add_argument("--seed", type=int, default=77)
    ap.add_argument("--workers", type=int, default=max(1, (os.cpu_count() or 2) // 3))
    a = ap.parse_args()
    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    done_dirs = out.with_suffix(".done")
    finished = set(done_dirs.read_text(encoding="utf-8").split()) if done_dirs.exists() else set()
    r = random.Random(a.seed)
    rows = sum(1 for _ in out.open(encoding="utf-8")) if out.exists() else 0
    print(f"{len(finished)} programs done before, {rows} rows already", flush=True)
    import time
    with ProcessPoolExecutor(a.workers) as pool, out.open("a", encoding="utf-8", newline="\n") as f, \
            done_dirs.open("a", encoding="utf-8") as marks:
        idle = 0
        while rows < a.count:
            # gen_binaries.py keeps adding programs: take the new ones each round
            batch = [p for p in Path(a.bins).iterdir() if p.name not in finished and (p / "names.json").exists()]
            if len(batch) < 16:
                idle += 1
                if idle > 120:  # an hour with nothing new: the builder has stopped
                    break
                time.sleep(30)
                continue
            idle = 0
            r.shuffle(batch)
            batch = batch[:64]
            finished.update(p.name for p in batch)
            start = len(finished) - len(batch)
            jobs = [(str(p), r.random(), a.hebrew) for p in batch for _ in range(a.per_program)]
            for made in pool.map(one, jobs, chunksize=2):
                for row in made or []:
                    f.write(json.dumps(row, ensure_ascii=False) + "\n")
                    rows += 1
            f.flush()
            marks.write("\n".join(p.name for p in batch) + "\n")
            marks.flush()
            print(f"{start + len(batch)} programs: {rows} rows", flush=True)
    print("done", rows)


if __name__ == "__main__":
    main()
