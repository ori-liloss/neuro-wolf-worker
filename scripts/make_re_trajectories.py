"""Make reverse-engineering trajectories for Neuro's agent: real binaries, the real RE toolkit.

Each trajectory is a research task about a Windows binary (System32 programs and libraries, the
same toolkit Neuro Desktop and the neuro CLI ship: neuro-desktop/crates/neuro-agent/assets/
neuro_re.py). The model RUNs the toolkit the way a reverse engineer works: info, then imports and
strings, then functions and decompile of the entry point or the biggest function, and answers
only from what the tools printed: what the file is, what it can do (grouped from its imports),
the strings that matter, what its main code calls, and what is still unknown.

The first message has the exact frame the app sends (Task:, Repo files:, the Language line for
Hebrew, "Files you named" and the "Reverse engineering (...)" toolkit line), and every tool result
is the toolkit's real output, clipped the way the agent clips it. Nothing is copied from another
model. About a quarter of the tasks are in Hebrew. Rows never refuse: they only teach the work.

    python seeds/make_re_trajectories.py --count 3000 --seed 5 --out D:/neuro-models/datasets/re-tools/train.jsonl
    python seeds/make_re_trajectories.py --count 150 --seed 909 --out D:/neuro-models/datasets/re-tools/heldout.jsonl --heldout
"""

from __future__ import annotations

import argparse
import contextlib
import importlib.util
import io
import json
import os
import random
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import agents  # noqa: E402

SOURCE = "re-tool-trajectories-v1"
RESULT_CHARS = 700
TOOLKIT = Path(__file__).resolve().parent / "neuro_re.py"
# How the app runs it (tools/re.rs run_line): the real python and the toolkit next to Neuro's data.
RUN_TOOL = r'C:\Users\hayit\AppData\Local\Python\bin\python.exe "C:\Users\hayit\AppData\Local\Neuro\tools\neuro_re.py"'
SYSTEM32 = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32"

spec = importlib.util.spec_from_file_location("neuro_re", TOOLKIT)
nre = importlib.util.module_from_spec(spec)
spec.loader.exec_module(nre)


def tool(command: str, *args: str) -> str:
    """The toolkit's real output for one command, as RUN would return it (exit code when not 0)."""
    buf = io.StringIO()
    nre.MAX_LINES = 200
    code = 0
    with contextlib.redirect_stdout(buf):
        try:
            code = nre.main(["neuro_re.py", command, *args]) or 0
        except Exception as e:  # a broken file: what the script would print
            print(f"error: {e}")
            code = 1
    text = buf.getvalue().rstrip()
    if code:
        text += f"\nexit {code}"
    return agents.clip(text, 4000) if hasattr(agents, "clip") else text[:4000]


# What a group of imported functions lets a program do (from the import names the tool prints).
CAPABILITIES = [
    (r"ws2_32|WSAStartup|\bsocket\b|connect|\bsend\b|recv|getaddrinfo|WinHttp|InternetOpen|HttpSendRequest|URLDownload",
     "network", "רשת"),
    (r"Reg(Open|Create|Set|Query|Delete)Key|RegGetValue|RegSetValue", "the registry", "הרישום (Registry)"),
    (r"CreateProcess|ShellExecute|WinExec", "starting other programs", "הפעלת תוכניות אחרות"),
    (r"CreateFile|ReadFile|WriteFile|DeleteFile|CopyFile|MoveFile|FindFirstFile", "files", "קבצים"),
    (r"Crypt|BCrypt|NCrypt|CertOpen", "cryptography and certificates", "הצפנה ותעודות"),
    (r"CreateWindow|DialogBox|MessageBox|ShowWindow|GetMessage|DispatchMessage", "a window (GUI)", "חלון וממשק גרפי"),
    (r"VirtualAllocEx|WriteProcessMemory|CreateRemoteThread|ReadProcessMemory", "other processes' memory",
     "זיכרון של תהליכים אחרים"),
    (r"OpenProcess|TerminateProcess|EnumProcesses|CreateToolhelp32Snapshot", "other processes (open, list, end)",
     "תהליכים אחרים (פתיחה, רשימה, סגירה)"),
    (r"CreateService|OpenSCManager|StartService|ControlService", "Windows services", "שירותי Windows"),
    (r"LoadLibrary|GetProcAddress", "loading code at run time", "טעינת קוד בזמן ריצה"),
    (r"CreateThread|_beginthread|CreateThreadpool", "threads", "תהליכונים (threads)"),
    (r"Co(Initialize|CreateInstance)|OleInitialize", "COM objects", "אובייקטי COM"),
    (r"SetWindowsHookEx|GetAsyncKeyState|RegisterHotKey", "keyboard and window hooks", "האזנה למקלדת ולחלונות"),
    (r"AdjustTokenPrivileges|OpenProcessToken|LookupPrivilegeValue", "privileges", "הרשאות"),
    (r"EvtQuery|ReportEvent|EventWrite|TraceEvent", "event logging", "רישום אירועים"),
    (r"Gdi|BitBlt|CreateFont|SelectObject|DrawText", "drawing (GDI)", "ציור (GDI)"),
]
INTERESTING = re.compile(r"https?://|\\\\|[A-Za-z]:\\|\.dll|\.exe|\.sys|HKEY_|SOFTWARE\\|%[A-Za-z]+%|\{[0-9A-F-]{36}\}", re.I)

QUESTIONS_EN = ["What does {f} do?", "Reverse engineer {f} and tell me what it is for.", "Look inside {f}: what can it do?",
                "Analyze the binary {f}. What does its main code call?", "Explain {f} from its code, not from its name.",
                "What is {f}? Check its imports, strings and its main function."]
QUESTIONS_HE = ["מה הקובץ {f} עושה?", "תעשה הנדסה הפוכה ל-{f} ותסביר למה הוא משמש.", "תסתכל בתוך {f}: מה הוא יכול לעשות?",
                "תנתח את הקובץ {f}. למה הקוד הראשי שלו קורא?", "תסביר את {f} לפי הקוד שלו, לא לפי השם.",
                "מה זה {f}? תבדוק imports, strings ואת הפונקציה הראשית."]
LANGUAGE_HE = ("\n\nLanguage: the user wrote in Hebrew. Write the final answer and any question to the user in Hebrew; "
               "code, commands, file names and tool calls stay as they are.")


def re_line(path: str) -> str:
    """The toolkit line the app adds (tools/re.rs context_line)."""
    return (f"\n\nReverse engineering ({path}): RUN {RUN_TOOL} info {path} first, then imports / exports / functions "
            "(biggest first) / strings FILE 8 (strings FILE http keeps only strings with a word). To understand or rewrite code: decompile FILE entry|0xADDRESS|EXPORT "
            "prints the whole function with every call and string named; write it as C from that, then follow its calls "
            "(decompile them too) and xrefs FILE 0xADDRESS to see who calls it. Also: sections, disasm FILE ADDRESS COUNT, "
            "hexdump FILE OFFSET LEN, find FILE HEXBYTES. Explain only from what the tools print. Also installed: objdump, strings.")


def facts(info: str, imports: str, strings: str, func: str):
    """What the tool outputs show, as plain facts."""
    get = lambda k: (re.search(rf"^{k}: (.+)$", info, re.M) or [None, ""])[1]
    caps = []
    blob = imports + "\n" + func
    for pattern, en, he in CAPABILITIES:
        hits = sorted(set(m.group(0) for m in re.finditer(pattern, blob)))
        if hits:
            caps.append((en, he, hits[:3]))
    dlls = [l.split(" (")[0] for l in imports.splitlines() if l and not l.startswith(" ")]
    notable = []
    for line in strings.splitlines():
        text = line.split("  ", 1)[1] if "  " in line else line
        text = text.replace("  (utf-16)", "")
        lower = text.lower()
        if lower.startswith(("api-ms-", "ext-ms-")) or lower in {d.lower() for d in dlls}:
            continue  # an import's own DLL name says nothing new
        if INTERESTING.search(text) and len(text) < 120 and text not in notable:
            notable.append(text)
    head = func.splitlines()[0] if func else ""
    calls = (re.search(r"^calls: (.+)$", func, re.M) or [None, ""])[1]
    named_calls = [c for c in calls.split(", ") if "!" in c][:6]
    return {"machine": get("machine"), "size": get("size"), "entry": get("entry point"), "sections": get("sections"),
            "dlls": dlls, "caps": caps, "strings": notable[:5], "func": head, "calls": named_calls,
            "packed": get("high entropy \\(packed or compressed\\?\\)")}


def answer(f: dict, name: str, he: bool) -> str:
    lines = []
    if he:
        lines.append(f"`{name}` הוא קובץ PE ל-{f['machine']} בגודל {f['size']}, עם {len(f['dlls'])} ספריות מיובאות.")
        if f["caps"]:
            lines.append("לפי ה-imports הוא יכול לעבוד עם: " + "; ".join(f"{he_} ({', '.join(h)})" for _, he_, h in f["caps"]) + ".")
        if f["strings"]:
            lines.append("מחרוזות בולטות: " + ", ".join(f"`{s}`" for s in f["strings"]) + ".")
        if f["func"]:
            lines.append(f"הקוד הראשי שבדקתי ({f['func'].split(',')[0].replace('function ', '')}) קורא ל-"
                         + (", ".join(f"`{c}`" for c in f["calls"]) if f["calls"] else "פונקציות פנימיות בלבד") + ".")
        if f["packed"]:
            lines.append(f"אזורים עם אנטרופיה גבוהה ({f['packed']}): ייתכן שחלק מהקוד דחוס או מוצפן.")
        lines.append("מה שלא בדקתי: את רוב הפונקציות הפנימיות. כדי לדעת מה כל אחת עושה צריך decompile שלהן, אחת אחרי השנייה.")
    else:
        lines.append(f"`{name}` is a {f['machine']} PE file of {f['size']} with {len(f['dlls'])} imported libraries.")
        if f["caps"]:
            lines.append("From its imports it works with: " + "; ".join(f"{en} ({', '.join(h)})" for en, _, h in f["caps"]) + ".")
        if f["strings"]:
            lines.append("Notable strings: " + ", ".join(f"`{s}`" for s in f["strings"]) + ".")
        if f["func"]:
            lines.append(f"The main code I looked at ({f['func'].split(',')[0].replace('function ', '')}) calls "
                         + (", ".join(f"`{c}`" for c in f["calls"]) if f["calls"] else "only its own functions") + ".")
        if f["packed"]:
            lines.append(f"High-entropy sections ({f['packed']}): part of it may be compressed or encrypted.")
        lines.append("Not checked: most of its internal functions; each needs its own decompile to say what it does.")
    return "\n".join(lines)


def candidates(heldout: bool) -> list[Path]:
    files = sorted(p for p in SYSTEM32.iterdir() if p.suffix.lower() in (".exe", ".dll") and p.is_file()
                   and 20_000 < p.stat().st_size < 30_000_000)
    # A fixed split by name: held-out files are never in training.
    pick = [p for p in files if (hash_name(p.name) % 20 == 0) == heldout]
    return pick


def hash_name(name: str) -> int:
    import hashlib
    return int(hashlib.sha256(name.lower().encode()).hexdigest()[:8], 16)


def trajectory(r: random.Random, path: Path, he: bool) -> dict | None:
    folder = r.choice(["bin", "samples", "test", "re", "target", "files"])
    rel = f"{folder}/{path.name}"
    # The tools run on the real file; the transcript shows the path the task used.
    real = str(path)
    show = lambda text: text.replace(real.replace("\\", "/"), rel).replace(real, rel)
    info = show(tool("info", real))
    if "format: PE" not in info or "machine:" not in info:
        return None
    imports = show(tool("imports", real))
    strings = show(tool("strings", real, "8"))
    funcs = show(tool("functions", real, "8"))
    target = "entry"
    m = re.search(r"^(0x[0-9a-f]+)\s+\d+ bytes", funcs, re.M)
    if m and r.random() < 0.6:
        target = m.group(1)  # the biggest function: usually where the logic is
    func = show(tool("decompile", real, target))
    if func.startswith("error") or "function " not in func:
        return None
    task = r.choice(QUESTIONS_HE if he else QUESTIONS_EN).format(f=path.name)
    user = (f"Task:\n{task}\n\nRepo files: {folder}/"
            + (LANGUAGE_HE if he else "")
            + f"\n\nFiles you named: {path.name} is at {rel}."
            + re_line(rel))
    messages = [{"role": "system", "content": agents.agent_system("research")}, {"role": "user", "content": user}]

    def step(cmd: str, result: str, limit: int = RESULT_CHARS):
        messages.append({"role": "assistant", "content": f"RUN {RUN_TOOL} {cmd}"})
        # Shorter than the agent's 2400-character clip, so a whole trajectory fits a 3072-token row:
        # the start and the end of each result, as clip() keeps them.
        messages.append({"role": "user", "content": agents.tool_response(result, limit)})

    step(f"info {rel}", info)
    step(f"imports {rel}", imports)
    step(f"strings {rel} 8", strings)
    if target != "entry":
        step(f"functions {rel} 8", funcs, 450)
    step(f"decompile {rel} {target}", func)
    messages.append({"role": "assistant", "content": answer(facts(info, imports, strings, func), path.name, he)})
    return {"messages": messages, "kind": "research", "source": SOURCE, "type": "re-tools", "hl": "he" if he else "en"}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--count", type=int, default=3000)
    parser.add_argument("--seed", type=int, default=5)
    parser.add_argument("--hebrew", type=float, default=0.25)
    parser.add_argument("--heldout", action="store_true", help="use only the held-out files (1 in 20 by name)")
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    out = Path(args.out)
    if out.exists():
        raise SystemExit(f"{out} exists already; choose a new path (existing data is never overwritten).")
    r = random.Random(args.seed)
    files = candidates(args.heldout)
    r.shuffle(files)
    rows, tries = [], 0
    while len(rows) < args.count and tries < args.count * 3 and files:
        path = files[tries % len(files)]
        tries += 1
        try:
            row = trajectory(r, path, r.random() < args.hebrew)
        except Exception:
            row = None
        if row:
            rows.append(row)
        if tries % 100 == 0:
            print(f"  {len(rows)} trajectories ({tries} tries)", flush=True)
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_suffix(".partial")
    with open(tmp, "w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
    tmp.replace(out)
    print(f"wrote {len(rows)} trajectories from {len(files)} files to {out}")


if __name__ == "__main__":
    main()
