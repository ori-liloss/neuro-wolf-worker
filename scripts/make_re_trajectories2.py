"""Reverse-engineering trajectories, version 2: the toolkit and the frame Neuro sends since 2026-11-18.

What changed from make_re_trajectories.py (v1):
- The "Reverse engineering (...)" line names the real file in every command (v1 had FILE and
  entry|0xADDRESS|EXPORT placeholders, which the model copied into PowerShell), and has a .NET form.
- RE tasks run as a lead: the lead system prompt and the "Team mode is on" note, as the app sends.
- Three kinds of trajectory:
  native  info, imports, strings, functions (each with the calls and strings it uses), decompile of
          the biggest function and often one function it calls; the answer names the hidden
          sub_ADDRESS functions from what they call.
  team    a big native file: functions, then two research sub-agents each decompile their share
          (SPAWN ... ENDSPAWN, WAIT), and the answer puts their findings together. Each sub-agent's
          own trajectory is a row too (the child prompt, its decompiles, its report).
  dotnet  a .NET assembly: info, types, decompile entry and a class through ILSpy; the answer says
          it is C#, what the classes do, and how to get the whole project (project FILE src_out).
Every tool result is the toolkit's real output on a real file (System32 and the .NET Framework on
this machine), clipped so a trajectory fits a 3072-token row. Held-out files (1 in 20 by name) never
appear in training. Rows never refuse: they only teach the work.

    python seeds/make_re_trajectories2.py --count 6000 --seed 21 --out D:/neuro-models/datasets/re-tools/train-v2.jsonl
    python seeds/make_re_trajectories2.py --count 200 --seed 919 --heldout --out D:/neuro-models/datasets/re-tools-heldout/heldout-v2.jsonl
"""

from __future__ import annotations

import argparse
import json
import os
import random
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))
import agents  # noqa: E402
import make_re_trajectories as v1  # noqa: E402

SOURCE = "re-tool-trajectories-v2"
RESULT_CHARS = 620
RUN_TOOL = v1.RUN_TOOL
# Every row must fit the trainer's --max-length (3072 tokens, the system prompt included): longer rows are
# dropped by the trainer without a word. A row is made at full size, measured with the model's own tokenizer,
# and made again with shorter tool results (SCALE) until it fits.
MAX_TOKENS = 2950
SCALES = (1.0, 0.8, 0.62, 0.48, 0.36)
SCALE = 1.0
TOKENIZER = None


def tokens(messages: list[dict]) -> int:
    global TOKENIZER
    if TOKENIZER is None:
        from transformers import AutoTokenizer
        TOKENIZER = AutoTokenizer.from_pretrained(str(Path(__file__).resolve().parent.parent / "tokenizer"))
    text = TOKENIZER.apply_chat_template(messages, tokenize=False)
    return len(TOKENIZER(text, add_special_tokens=False)["input_ids"])


_tool_cache: dict = {}


def tool(command: str, *args: str) -> str:
    """The toolkit's output, once per call (a row made again at a smaller size runs nothing twice)."""
    key = (command, args)
    if key not in _tool_cache:
        _tool_cache[key] = v1.tool(command, *args)
        if len(_tool_cache) > 4000:
            _tool_cache.pop(next(iter(_tool_cache)))
    return _tool_cache[key]
nre = v1.nre
SYSTEM32 = v1.SYSTEM32
FRAMEWORK = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "Microsoft.NET"

LANGUAGE_HE = v1.LANGUAGE_HE
EXTRAS = ["objdump", "radare2", "upx", "7-Zip", "dotnet", "gcc", "MSVC cl"]


def also_installed(r: random.Random) -> str:
    pick = [e for e in EXTRAS if r.random() < 0.4]
    return f" Also installed: {', '.join(pick)}." if pick else ""


def ghidra_sentence(f: str) -> str:
    """tools/re.rs, when Ghidra is installed (appended to the machine-code road)."""
    return (f" Ghidra is installed and runs from the toolkit: ghidra {f} lists the functions Ghidra found (the biggest first, "
            f"with their calls), ghidra {f} FUN_00401000 (or 0xADDRESS, or entry) prints that function as Ghidra pseudo-C, which "
            f"you rewrite as clean C with real names, and ghidra {f} all writes every function's pseudo-C to {f}.ghidra.c to READ "
            f"or GREP. The first ghidra command on a file takes a few minutes (Ghidra analyses it once); later ones take seconds.")


def re_line(path: str, dotnet: bool, extra: str, ghidra: bool = False) -> str:
    """tools/re.rs context_line, word for word."""
    t = RUN_TOOL
    f = path
    if dotnet:
        how = (f"{f} is a .NET program (IL, not machine code): its original source comes back as C#, so do not disassemble it. "
               f"RUN {t} types {f} for its classes. The other commands run the same way (RUN {t} then the command): "
               f"decompile {f} entry (the class with Main), decompile {f} Namespace.Class (or Namespace.Class.Method) for each "
               f"class you need. To rewrite or rebuild it: project {f} src_out writes the whole program as a C# project; READ its "
               f"files, fix what does not build, and RUN dotnet build src_out.")
    else:
        how = (f"RUN {t} info {f} first: it says what built the file and what to run next. The other commands run the same way "
               f"(RUN {t} then the command): imports {f}, strings {f} 8 (strings {f} http keeps only strings with a word) and "
               f"functions {f}: every function, the biggest first, with the calls and strings it uses; the unnamed ones "
               f"(sub_ADDRESS) are the program's own logic. To understand or rewrite code: decompile {f} entry, or decompile {f} "
               f"0xADDRESS, prints a whole function with every call and string named; write it as C from that and give it a name "
               f"from what it does, then decompile the sub_ functions it calls and xrefs {f} 0xADDRESS to see who calls it. Also: "
               f"sections, disasm {f} 0xADDRESS 40, hexdump {f} 0x400 256, find {f} \"48 8b 05\"."
               + (ghidra_sentence(f) if ghidra else ""))
    return (f"\n\nReverse engineering ({path}): {how} Many functions or classes: SPAWN research sub-agents, each with its own "
            f"list (they can RUN the same commands), and put their findings together. Explain only from what the tools print.{extra}")


TEAM_LEAD_NOTE = agents.TEAM_LEAD_NOTE

# A name for a hidden function from what it calls (the first rule that matches wins).
NAME_RULES = [
    (r"_initterm|__set_app_type|__getmainargs|__p___argv|_cexit", "crt_startup", "אתחול ה-C runtime"),
    (r"GetSystemTimeAsFileTime|QueryPerformanceCounter.*GetTickCount|GetTickCount.*QueryPerformanceCounter", "init_security_cookie", "אתחול ה-security cookie"),
    (r"RoGetActivationFactory|RoActivateInstance|WindowsCreateString", "activate_winrt_class", "הפעלת מחלקת WinRT"),
    (r"OutputDebugString|IsDebuggerPresent", "debug_trace", "הדפסת מידע לדיבאגר"),
    (r"FormatMessage", "format_error_message", "ניסוח הודעת שגיאה"),
    (r"CreateEvent|InitializeCriticalSection|InitializeSRWLock|CreateMutex|CreateSemaphore|OpenSemaphore|OpenMutex|OpenEvent", "init_sync_objects", "יצירת אירועים ונעילות"),
    (r"MapViewOfFile|CreateFileMapping|OpenFileMapping", "map_shared_memory", "מיפוי זיכרון משותף"),
    (r"CreateWindow|RegisterClass", "create_main_window", "יצירת החלון הראשי"),
    (r"GetMessage|DispatchMessage|TranslateMessage", "message_loop", "לולאת ההודעות של החלון"),
    (r"DefWindowProc|BeginPaint|EndPaint", "window_proc", "טיפול בהודעות החלון"),
    (r"DialogBox|MessageBox|CreateDialog", "show_dialog", "הצגת דיאלוג"),
    (r"WSAStartup|\bsocket\b|\bconnect\b|getaddrinfo|WinHttp|InternetOpen|HttpSendRequest", "network_request", "פעולת רשת"),
    (r"CreateProcess|ShellExecute|WinExec", "start_process", "הפעלת תהליך"),
    (r"OpenSCManager|CreateService|StartService|ControlService|RegisterServiceCtrlHandler|StartServiceCtrlDispatcher", "service_main", "ניהול שירות Windows"),
    (r"RegSetValue|RegCreateKey|RegDeleteKey|RegDeleteValue", "write_registry", "כתיבה ל-Registry"),
    (r"RegOpenKey|RegQueryValue|RegGetValue|RegEnumKey", "read_registry", "קריאה מה-Registry"),
    (r"WriteFile|CopyFile|MoveFile|DeleteFile", "write_file", "כתיבת קובץ"),
    (r"CreateFile|ReadFile|MapViewOfFile|CreateFileMapping|FindFirstFile", "read_file", "קריאת קובץ"),
    (r"BCrypt|Crypt|NCrypt|CertOpen", "crypto_operation", "פעולת הצפנה"),
    (r"CreateThread|_beginthread|CreateThreadpool|SubmitThreadpoolWork", "start_worker_thread", "הפעלת thread"),
    (r"CoCreateInstance|CoInitialize|OleInitialize", "create_com_object", "יצירת אובייקט COM"),
    (r"LoadLibrary|GetProcAddress", "load_function_at_runtime", "טעינת פונקציה בזמן ריצה"),
    (r"EventWrite|EtwEventWrite|TraceLogging|ReportEvent|EventRegister", "log_event", "רישום אירוע"),
    (r"GetCommandLine|CommandLineToArgv", "parse_command_line", "פענוח שורת הפקודה"),
    (r"\bv?s[n]?w?printf|_vsnwprintf|_snwprintf|StringCch", "format_string", "בניית מחרוזת"),
    (r"printf|WriteConsole|fputs|puts", "print_output", "הדפסת פלט"),
    (r"HeapAlloc|RtlAllocateHeap|malloc|LocalAlloc|GlobalAlloc|VirtualAlloc", "allocate_buffer", "הקצאת זיכרון"),
    (r"HeapFree|free|LocalFree|GlobalFree|VirtualFree", "free_buffer", "שחרור זיכרון"),
    (r"wcscmp|_wcsicmp|lstrcmpi|CompareString|strcmp|_stricmp", "compare_strings", "השוואת מחרוזות"),
    (r"EnterCriticalSection|AcquireSRWLock|WaitForSingleObject", "synchronized_access", "גישה עם נעילה"),
    (r"SetUnhandledExceptionFilter|UnhandledExceptionFilter|RaiseException", "handle_exception", "טיפול בחריגה"),
]


def noun(strings: list[str]) -> str:
    """A name part from the strings a function uses: "m_hFireCompletionEvent" -> "fire_completion_event"."""
    for s in strings:
        m = re.search(r"\b(?:m_h|m_p|m_|p|h|sz|g_)?([A-Z][a-z]+(?:[A-Z][a-z]+)+)\b", s)
        if m:
            words = re.findall(r"[A-Z][a-z]+", m.group(1))[:3]
            return "_".join(w.lower() for w in words)
    return ""


def function_name(calls: list[str], strings: list[str]) -> tuple[str, str, bool]:
    """(name, Hebrew description, sure) for a function from its calls and strings."""
    blob = " ".join(calls)
    # Helpers every program calls (sprintf, HeapFree, a lock) say little: they name the function only when
    # nothing more telling is there.
    weak = {"format_string", "allocate_buffer", "free_buffer", "compare_strings", "synchronized_access", "print_output",
            "handle_exception"}
    for pattern, name, he in NAME_RULES:
        if name not in weak and re.search(pattern, blob):
            part = noun(strings)
            if part and part not in name:
                return f"{name.split('_')[0]}_{part}", f"{he} ({part.replace('_', ' ')})", True
            return name, he, True
    # No known group: the first real API it calls, as words ("PdhEnumMachinesHW" -> "enum_machines").
    crt = re.compile(r"^(mem|str|wcs|_|sprintf|swprintf|printf|malloc|free|operator|thunk_|guard_|Heap|Local|Global|"
                     r"GetLastError|SetLastError|GetProcessHeap|GetCurrentProcess|GetCurrentThread|CloseHandle|Enter|Leave|Initialize|Delete|Acquire|Release)", re.I)
    for c in calls:
        if c.startswith(("sub_", "FUN_", "_o_", "_", "?")) or "::" in c or crt.match(c):
            continue
        core = re.sub(r"^(Pdh|Rtl|Nt|Zw|Wnf|Etw|Tdh|Sxs|Wer|Csr|Ldr|Bl)", "", c)
        core = re.sub(r"(Ex)?(W|A|HW|H)$", "", core)
        words = re.findall(r"[A-Z][a-z]+|[A-Z]+(?![a-z])", core)[:3]
        if len(words) >= 2:
            return "_".join(w.lower() for w in words), f"קוראת ל-{c}", False
    for pattern, name, he in NAME_RULES:
        if name in weak and re.search(pattern, blob):
            return name, he, True
    for c in calls:
        if c.startswith(("sub_", "FUN_", "_o_", "_", "?")) or "::" in c:
            continue
        core = re.sub(r"^(Pdh|Rtl|Nt|Zw|Wnf|Etw|Tdh|Sxs|Wer|Csr|Ldr)", "", c)
        core = re.sub(r"(Ex)?(W|A|HW|H)$", "", core)
        words = re.findall(r"[A-Z][a-z]+|[A-Z]+(?![a-z])", core)[:3]
        if len(words) >= 2:
            name = "_".join(w.lower() for w in words)
            return name, f"קוראת ל-{c}", False
    for s in strings:
        word = re.sub(r"[^A-Za-z0-9]+", "_", s).strip("_").lower()
        if 3 <= len(word) <= 24:
            return f"handle_{word}", f"טיפול ב-\"{s}\"", False
    return "helper", "פונקציית עזר פנימית", False


def parse_functions(text: str) -> list[dict]:
    """The rows of the functions command: address, size, name and what it uses."""
    rows = []
    for line in text.splitlines():
        m = re.match(r"(0x[0-9a-f]+)\s+(\d+) bytes\s+(\S+)(?:\s+\|\s+(.*))?$", line)
        if not m:
            continue
        hint = m.group(4) or ""
        calls = []
        strings = re.findall(r'"([^"]+)"', hint)
        cm = re.search(r"calls ([^|]+)", hint)
        if cm:
            calls = [c.strip(" .") for c in cm.group(1).split(",") if c.strip(" .")]
        fm = re.search(r"-> ([^|]+)", hint)
        callees = [c.strip(" .") for c in fm.group(1).split(",")] if fm else []
        rows.append({"addr": m.group(1), "size": int(m.group(2)), "name": m.group(3), "calls": calls, "callees": callees,
                     "strings": strings})
    return rows


def decompile_facts(text: str) -> dict:
    head = text.splitlines()[0] if text else ""
    calls = (re.search(r"^calls: (.+)$", text, re.M) or [None, ""])[1]
    strings = (re.search(r"^strings: (.+)$", text, re.M) or [None, ""])[1]
    calls = [] if calls == "none" else [c.strip() for c in calls.split(", ")]
    strs = [] if strings == "none" else re.findall(r"'([^']*)'", strings)
    m = re.match(r"function (\S+) at (0x[0-9a-f]+), (\d+) bytes", head)
    return {"name": m.group(1) if m else "?", "addr": m.group(2) if m else "?", "size": int(m.group(3)) if m else 0,
            "calls": calls, "strings": strs}


class Writer:
    """One conversation in the agent's format."""

    def __init__(self, system: str, user: str):
        self.messages = [{"role": "system", "content": system}, {"role": "user", "content": user}]

    def run(self, cmd: str, result: str, limit: int = RESULT_CHARS):
        self.messages.append({"role": "assistant", "content": f"RUN {RUN_TOOL} {cmd}"})
        self.messages.append({"role": "user", "content": agents.tool_response(result, max(200, int(limit * SCALE)))})

    def call(self, text: str, results: list[str]):
        self.messages.append({"role": "assistant", "content": text})
        self.messages.append({"role": "user", "content": "\n".join(agents.tool_response(r, 2400) for r in results)})

    def answer(self, text: str):
        self.messages.append({"role": "assistant", "content": text})


def frame(task: str, folder: str, name: str, rel: str, he: bool, dotnet: bool, extra: str, ghidra: bool = False) -> str:
    return (f"Task:\n{task}\n\n{TEAM_LEAD_NOTE}\n\nRepo files: {folder}/"
            + (LANGUAGE_HE if he else "")
            + f"\n\nFiles you named: {name} is at {rel}."
            + re_line(rel, dotnet, extra, ghidra))


GHIDRA_EN = ["Reverse engineer {f} with Ghidra and name its hidden functions.", "Use Ghidra on {f}: what do its main functions do?",
             "Decompile the biggest functions of {f} with Ghidra and explain them.", "RE {f} with ghidra: name the FUN_ functions."]
GHIDRA_HE = ["תעשה RE ל-{f} עם ghidra ותן שמות לפונקציות המוסתרות.", "תשתמש ב-ghidra על {f}: מה עושות הפונקציות הראשיות שלו?",
             "תעשה decompile עם ghidra לפונקציות הגדולות של {f} ותסביר אותן.", "תעשה RE ל-{f}: מה עושות פונקציות ה-FUN_?"]


def ghidra_list(text: str) -> list[dict]:
    rows = []
    for line in text.splitlines():
        m = re.match(r"([0-9a-f]{6,})\s+(\d+) bytes\s+(\S+)(?:\s+\|\s+calls (.*))?$", line)
        if m:
            calls = [c.strip(" .") for c in (m.group(4) or "").split(",") if c.strip(" .")]
            rows.append({"addr": m.group(1), "size": int(m.group(2)), "name": m.group(3), "calls": calls})
    return rows


def pseudo_facts(text: str) -> tuple[list[str], list[str]]:
    head = (re.search(r"^// \S+ at \S+\s+\|\s+calls (.*)$", text, re.M) or [None, ""])[1]
    calls = [c.strip(" .") for c in head.split(",") if c.strip(" .")]
    strings = re.findall(r'L?"([^"\n]{4,60})"', text) + [s.replace("_", " ") for s in re.findall(r"\bs_(\w{4,40}?)_[0-9a-f]{6,}", text)]
    return calls, strings


def ghidra_traj(r: random.Random, path: Path, he: bool) -> list[dict] | None:
    """Reverse engineering through Ghidra from the toolkit: its function list, the pseudo-C of the biggest
    function and of one it calls, and names for them from what they call."""
    folder, rel, real, show = place(r, path)
    info = show(tool("info", real))
    if "format: PE" not in info or "machine:" not in info or ".NET" in info:
        return None
    listing = show(tool("ghidra", real, "12"))
    funcs = ghidra_list(listing)
    if len(funcs) < 3:
        return None
    extra = also_installed(r)
    task = r.choice(GHIDRA_HE if he else GHIDRA_EN).format(f=path.name)
    w = Writer(agents.agent_system("research", "lead"), frame(task, folder, path.name, rel, he, False, extra, ghidra=True))
    if r.random() < 0.5:
        w.run(f"info {rel}", info)
    w.run(f"ghidra {rel} 12", listing, 760)
    first = funcs[0] if r.random() < 0.7 else r.choice(funcs[:4])
    p1 = show(tool("ghidra", real, first["name"]))
    if "no function at" in p1 or "error" in p1[:20]:
        return None
    w.run(f"ghidra {rel} {first['name']}", p1, 900)
    seen = [(first, *pseudo_facts(p1))]
    callee = next((c for c in seen[0][1] if c.startswith("FUN_")), None)
    if callee and r.random() < 0.55:
        p2 = show(tool("ghidra", real, callee))
        if "no function at" not in p2:
            w.run(f"ghidra {rel} {callee}", p2, 600)
            seen.append(({"addr": callee[4:], "name": callee}, *pseudo_facts(p2)))
    lines = []
    shown = {s[0]["name"] for s in seen}
    rows = [(f["name"], f["addr"], calls or f.get("calls", []), strs) for f, calls, strs in seen]
    rows += [(f["name"], f["addr"], f["calls"], []) for f in funcs if f["name"] not in shown and f["name"].startswith("FUN_")][: max(0, 6 - len(rows))]
    built = built_line(info)
    if built.startswith("native machine code"):
        built = ""  # the default line says nothing about this file
    lines.append((f"`{path.name}` נבנה עם: {built}. השמות לפי מה ש-Ghidra מראה שכל פונקציה קוראת:" if he else
                  f"`{path.name}` was built with: {built}. Names from what Ghidra shows each function calls:") if built else
                 ("השמות לפי מה ש-Ghidra מראה שכל פונקציה קוראת:" if he else "Names from what Ghidra shows each function calls:"))
    for name, addr, calls, strs in rows:
        new, he_desc, sure = function_name([c for c in calls if not c.startswith("FUN_")], strs)
        why = ", ".join(calls[:4]) or ", ".join(f'"{s}"' for s in strs[:2]) or ("רק פונקציות פנימיות" if he else "only internal functions")
        if he:
            lines.append(f"- `{name}` (0x{addr}) → `{new}`: {he_desc} ({why}){'' if sure else ' — לא בטוח'}")
        else:
            lines.append(f"- `{name}` (0x{addr}) → `{new}`: {new.replace('_', ' ')} ({why}){'' if sure else ' — not sure'}")
    lines.append("לא נבדק: שאר הפונקציות; `ghidra FILE all` כותב את כולן לקובץ אחד." if he else
                 "Not checked: the other functions; `ghidra FILE all` writes all of them to one file.")
    w.answer("\n".join(lines))
    return [{"messages": w.messages, "kind": "research", "source": SOURCE, "type": "re-tools-ghidra", "hl": "he" if he else "en"}]


def drop_ghidra_project(path: Path) -> None:
    """The generator analyses thousands of files: their Ghidra projects are not kept."""
    import hashlib
    import shutil
    digest = hashlib.sha256(path.read_bytes()).hexdigest()[:16]
    base = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "Neuro" / "ghidra-projects"
    for p in (base / f"p{digest}.gpr", base / f"p{digest}.rep"):
        if p.is_dir():
            shutil.rmtree(p, ignore_errors=True)
        elif p.exists():
            p.unlink(missing_ok=True)


NATIVE_EN = ["What does {f} do?", "Reverse engineer {f}: name its main functions and say what each does.",
             "Look inside {f}. What are the hidden sub_ functions doing?", "Analyze {f} from its code and tell me what it is for.",
             "Find the important functions in {f} and explain them.", "RE {f}: which language was it written in and what does it do?"]
NATIVE_HE = ["מה הקובץ {f} עושה?", "תעשה הנדסה הפוכה ל-{f}: תן שמות לפונקציות הראשיות ותסביר מה כל אחת עושה.",
             "תסתכל בתוך {f}. מה עושות הפונקציות הנסתרות (sub_)?", "תנתח את {f} לפי הקוד שלו ותגיד למה הוא משמש.",
             "תמצא את הפונקציות החשובות ב-{f} ותסביר אותן.", "תעשה RE ל-{f}: באיזו שפה הוא נכתב ומה הוא עושה?"]
DOTNET_EN = ["Reverse engineer {f} and tell me what language it is written in.", "What does {f} do? Show me its main code.",
             "Decompile {f} and explain its classes.", "RE {f}: can I get its source code back?"]
DOTNET_HE = ["תעשה RE ל-{f} ותגיד באיזו שפה הוא כתוב.", "מה {f} עושה? תראה לי את הקוד הראשי שלו.",
             "תעשה decompile ל-{f} ותסביר את המחלקות שלו.", "תעשה RE ל-{f}: אפשר לקבל בחזרה את קוד המקור?"]


def built_line(info: str) -> str:
    return (re.search(r"^built with: (.+)$", info, re.M) or [None, ""])[1]


def native_answer(name: str, info: str, imports: str, funcs: list[dict], decs: list[dict], he: bool) -> str:
    machine = (re.search(r"^machine: (.+)$", info, re.M) or [None, "?"])[1]
    built = built_line(info)
    caps = []
    for pattern, en, he_ in v1.CAPABILITIES:
        hits = sorted(set(m.group(0) for m in re.finditer(pattern, imports)))
        if hits:
            caps.append((en, he_, hits[:3]))
    named = []
    seen = set()
    for d in decs:
        n, h, sure = function_name(d["calls"], d["strings"])
        named.append((d["addr"], d["name"], n, h, sure, d["calls"][:4], d["strings"][:2]))
        seen.add(d["addr"])
    for f in funcs:
        if f["addr"] in seen or not f["name"].startswith("sub_") or len(named) >= 6:
            continue
        n, h, sure = function_name(f["calls"], f["strings"])
        named.append((f["addr"], f["name"], n, h, sure, f["calls"][:4], f["strings"][:2]))
    lines = []
    if he:
        lines.append(f"`{name}` הוא קובץ PE ל-{machine}. נבנה עם: {built}.")
        if caps:
            lines.append("לפי ה-imports הוא עובד עם: " + "; ".join(f"{h} ({', '.join(x)})" for _, h, x in caps[:5]) + ".")
        lines.append("הפונקציות הנסתרות ושמות לפי מה שהן קוראות:")
        for addr, old, n, h, sure, calls, strs in named:
            why = ", ".join(calls) if calls else (", ".join(f'"{s}"' for s in strs) if strs else "קוראת רק לפונקציות פנימיות")
            lines.append(f"- `{old}` ({addr}) → `{n}`: {h} ({why}){'' if sure else ' — לא בטוח'}")
        lines.append("לא בדקתי: את שאר הפונקציות. כל אחת צריכה decompile משלה כדי לדעת בדיוק.")
    else:
        lines.append(f"`{name}` is a {machine} PE file. Built with: {built}.")
        if caps:
            lines.append("From its imports it works with: " + "; ".join(f"{en} ({', '.join(x)})" for en, _, x in caps[:5]) + ".")
        lines.append("The hidden functions, named from what they call:")
        for addr, old, n, h, sure, calls, strs in named:
            why = ", ".join(calls) if calls else (", ".join(f'"{s}"' for s in strs) if strs else "only its own functions")
            en = n.replace("_", " ")
            lines.append(f"- `{old}` ({addr}) → `{n}`: {en} ({why}){'' if sure else ' — not sure'}")
        lines.append("Not checked: the other functions; each needs its own decompile to say exactly.")
    return "\n".join(lines)


def files(heldout: bool, dotnet: bool) -> list[Path]:
    if dotnet:
        found = []
        for p in list((FRAMEWORK / "Framework64" / "v4.0.30319").glob("*.exe")) + list((FRAMEWORK / "assembly" / "GAC_MSIL").glob("*/*/*.dll")):
            try:
                if 15_000 < p.stat().st_size < 8_000_000:
                    found.append(p)
            except OSError:
                pass
    else:
        found = [p for p in SYSTEM32.iterdir() if p.suffix.lower() in (".exe", ".dll") and p.is_file()
                 and 20_000 < p.stat().st_size < 30_000_000]
    found = sorted(found)
    return [p for p in found if (v1.hash_name(p.name) % 20 == 0) == heldout]


def place(r: random.Random, path: Path):
    folder = r.choice(["bin", "samples", "test", "re", "target", "files", "work", "input"])
    rel = f"{folder}/{path.name}"
    real = str(path)
    show = lambda text: text.replace(real.replace("\\", "/"), rel).replace(real, rel).replace(str(path.parent) + "\\", "")
    return folder, rel, real, show


def native(r: random.Random, path: Path, he: bool) -> list[dict] | None:
    folder, rel, real, show = place(r, path)
    info = show(tool("info", real))
    if "format: PE" not in info or "machine:" not in info or ".NET" in info:
        return None
    imports = show(tool("imports", real))
    strings = show(tool("strings", real, "8"))
    ftext = show(tool("functions", real, "12"))
    funcs = parse_functions(ftext)
    if len(funcs) < 3:
        return None
    extra = also_installed(r)
    task = r.choice(NATIVE_HE if he else NATIVE_EN).format(f=path.name)
    w = Writer(agents.agent_system("research", "lead"), frame(task, folder, path.name, rel, he, False, extra))
    w.run(f"info {rel}", info)
    w.run(f"imports {rel}", imports, 500)
    if r.random() < 0.5:
        w.run(f"strings {rel} 8", strings, 500)
    w.run(f"functions {rel} 12", ftext, 760)
    first = funcs[0] if r.random() < 0.7 else r.choice(funcs[:4])
    d1 = show(tool("decompile", real, first["addr"]))
    if "function " not in d1:
        return None
    w.run(f"decompile {rel} {first['addr']}", d1)
    decs = [decompile_facts(d1)]
    sub = re.findall(r"; (sub_[0-9a-f]+)", d1)
    if sub and r.random() < 0.55:
        target = "0x" + sub[0][4:]
        d2 = show(tool("decompile", real, target))
        if "function " in d2:
            w.run(f"decompile {rel} {target}", d2, 520)
            decs.append(decompile_facts(d2))
    w.answer(native_answer(path.name, info, imports, funcs, decs, he))
    return [{"messages": w.messages, "kind": "research", "source": SOURCE, "type": "re-tools-native", "hl": "he" if he else "en"}]


def team(r: random.Random, path: Path, he: bool) -> list[dict] | None:
    folder, rel, real, show = place(r, path)
    info = show(tool("info", real))
    if "format: PE" not in info or "machine:" not in info or ".NET" in info:
        return None
    ftext = show(tool("functions", real, "12"))
    funcs = [f for f in parse_functions(ftext) if f["name"].startswith("sub_")]
    if len(funcs) < 6:
        return None
    extra = also_installed(r)
    task = r.choice(NATIVE_HE if he else NATIVE_EN).format(f=path.name)
    lead_id = r.randint(20, 900)
    w = Writer(agents.agent_system("research", "lead"), frame(task, folder, path.name, rel, he, False, extra))
    w.run(f"info {rel}", info)
    w.run(f"functions {rel} 12", ftext, 760)
    shares = [funcs[0:3], funcs[3:6]]
    spawns, results, rows, reports = [], [], [], []
    for n, share in enumerate(shares):
        cid = lead_id + n + 1
        addrs = ", ".join(f["addr"] for f in share)
        title = f"decompile {addrs.split(', ')[0]} and the next two"
        body = (f"Decompile {addrs} in {rel}, one at a time. For each one: what it calls, the strings it uses, what it does, "
                f"and a name for it. Report one line per function.")
        spawns.append(f"SPAWN research {title}\n{body}\nENDSPAWN")
        results.append(f"spawned #{cid} research: {title}. WAIT {cid} returns its report.")
        # The sub-agent's own trajectory: its prompt, its decompiles, its report.
        child_task = agents.child_prompt("research", "research", title, body, lead_id, task, cid)
        child_task = child_task.split("\n", 1)[1]  # the [kind:research] head is read by the app, not shown
        cw = Writer(agents.agent_system("research", "child"), f"Task:\n{child_task}\n\nRepo files: {folder}/" + re_line(rel, False, extra))
        lines = []
        for f in share:
            d = show(tool("decompile", real, f["addr"]))
            if "function " not in d:
                return None
            cw.run(f"decompile {rel} {f['addr']}", d, 600)
            facts = decompile_facts(d)
            name, he_desc, sure = function_name(facts["calls"], facts["strings"])
            why = ", ".join(facts["calls"][:4]) or ", ".join(f'"{s}"' for s in facts["strings"][:2]) or "only internal calls"
            lines.append(f"{f['addr']} {f['name']} -> {name}: {name.replace('_', ' ')} ({why}){'' if sure else ' (not sure)'}")
        report = "\n".join(lines + [f"Done: decompiled {len(share)} functions in {rel}; nothing changed."])
        cw.answer(report)
        rows.append({"messages": cw.messages, "kind": "research", "source": SOURCE, "type": "re-tools-child", "hl": "en"})
        reports.append((cid, title, report))
    w.call("\n".join(spawns), results)
    wait = [f"{len(reports)} of {len(reports)} sub-agents finished."]
    for cid, title, report in reports:
        wait.append(f"#{cid} research done ({r.randint(1800, 5200)} tokens): {title}")
        wait.append(report)
    w.call("WAIT", ["\n".join(wait)])
    # The lead's answer: the sub-agents' names, put together.
    named = [line for _, _, rep in reports for line in rep.splitlines() if line.startswith("0x")]
    built = built_line(info)
    if he:
        text = [f"`{path.name}` נבנה עם: {built}. חילקתי את 6 הפונקציות הגדולות לשני עוזרים, וכל אחד עשה להן decompile:"]
        text += [f"- {l}" for l in named]
        text.append("לא נבדק: הפונקציות הקטנות יותר; אותה שיטה עובדת עליהן.")
    else:
        text = [f"`{path.name}` was built with: {built}. Two sub-agents decompiled the six biggest functions:"]
        text += [f"- {l}" for l in named]
        text.append("Not checked: the smaller functions; the same way works for them.")
    w.answer("\n".join(text))
    return [{"messages": w.messages, "kind": "research", "source": SOURCE, "type": "re-tools-team", "hl": "he" if he else "en"}] + rows


def cs_members(text: str) -> list[str]:
    found = []
    for m in re.finditer(r"^\s*(?:public|internal|protected|private)(?:\s+(?:static|override|virtual|abstract|async|sealed|new|extern|unsafe))*\s+[\w<>\[\],.? ]+\s+(\w+)\s*\(", text, re.M):
        if m.group(1) not in found and m.group(1) not in ("if", "while"):
            found.append(m.group(1))
    return found


def dotnet(r: random.Random, path: Path, he: bool) -> list[dict] | None:
    folder, rel, real, show = place(r, path)
    info = show(tool("info", real))
    if ".NET assembly" not in info:
        return None
    types = show(tool("types", real))
    names = [l.split(" ", 1)[1] for l in types.splitlines()[1:] if l.startswith(("Class ", "Struct ", "Interface ", "Enum ", "Delegate "))]
    classes = [l.split(" ", 1)[1] for l in types.splitlines()[1:] if l.startswith("Class ")]
    if len(classes) < 2:
        return None
    extra = also_installed(r)
    task = r.choice(DOTNET_HE if he else DOTNET_EN).format(f=path.name)
    w = Writer(agents.agent_system("research", "lead"), frame(task, folder, path.name, rel, he, True, extra))
    if r.random() < 0.5:
        w.run(f"info {rel}", info)
    w.run(f"types {rel}", types, 900)
    entry = None
    if path.suffix.lower() == ".exe":
        entry = show(tool("decompile", real, "entry"))
        if "error" in entry[:40] or len(entry) < 40:
            entry = None
        else:
            w.run(f"decompile {rel} entry", entry, 800)
    plain = [c for c in classes if not re.search(r"SR$|Resources?$|Strings?$|Settings$|AssemblyRef|FXAssembly|ThisAssembly|CommonResStrings|Generated|Exception$|Attribute$|Messages$", c)] or classes
    rich = [c for c in plain if re.search(r"Main|Window|Form|Program|Manager|Handler|Service|Client|Server|Engine|Editor|Controller|Provider|Reader|Writer|Parser|Builder|Loader", c)]
    target = r.choice((rich or plain)[:6])
    body = show(tool("decompile", real, target))
    if body.startswith(("no type", "ilspycmd", "error")):
        return None
    w.run(f"decompile {rel} {target}", body, 900)
    members = cs_members(body)[:8]
    ui = "WPF" if "System.Windows.Controls" in body or "System.Windows.Markup" in body else "Windows Forms" if "System.Windows.Forms" in body else None
    main_cls = (re.search(r"the entry point Main is in (\S+)", entry or "") or [None, None])[1]
    if he:
        text = [f"`{path.name}` הוא קובץ .NET: הקוד שלו נכתב ב-C# (או בשפת .NET אחרת) ונשמר כ-IL, ולכן ILSpy מחזיר אותו כמעט בדיוק כ-C#."]
        text.append(f"יש בו {len(names)} טיפוסים, למשל: " + ", ".join(f"`{c}`" for c in plain[:6]) + ".")
        if main_cls:
            text.append(f"נקודת הכניסה (`Main`) נמצאת ב-`{main_cls}`.")
        if ui:
            text.append(f"הממשק בנוי ב-{ui}.")
        text.append(f"המחלקה `{target}` כוללת: " + (", ".join(f"`{m}`" for m in members) if members else "שדות ותכונות בלבד") + ".")
        text.append(f"לקבל את כל הקוד כפרויקט: `project {rel} src_out` ואז `dotnet build src_out`. לא הרצתי את זה כאן.")
    else:
        text = [f"`{path.name}` is a .NET assembly: its code was written in C# (or another .NET language) and stored as IL, so ILSpy gives it back almost exactly as C#."]
        text.append(f"It has {len(names)} types, for example: " + ", ".join(f"`{c}`" for c in plain[:6]) + ".")
        if main_cls:
            text.append(f"The entry point (`Main`) is in `{main_cls}`.")
        if ui:
            text.append(f"Its UI is {ui}.")
        text.append(f"`{target}` has: " + (", ".join(f"`{m}`" for m in members) if members else "fields and properties only") + ".")
        text.append(f"For all of the code as a project: `project {rel} src_out`, then `dotnet build src_out`. Not run here.")
    w.answer("\n".join(text))
    return [{"messages": w.messages, "kind": "research", "source": SOURCE, "type": "re-tools-dotnet", "hl": "he" if he else "en"}]


def fit(maker, seed: float, path: Path, he: bool) -> list[dict] | None:
    """The trajectory at the largest size whose every row fits MAX_TOKENS (the same choices at each
    size: the same seed). Rows that never fit are left out."""
    global SCALE
    kept: dict[int, dict] = {}
    try:
        for scale in SCALES:
            SCALE = scale
            made = maker(random.Random(seed), path, he)
            if not made:
                return None
            for i, row in enumerate(made):
                if i not in kept and tokens(row["messages"]) <= MAX_TOKENS:
                    kept[i] = row
            if len(kept) == len(made):
                break
    except Exception:
        return None
    finally:
        SCALE = 1.0
    if 0 not in kept:
        return None  # the main row (the lead's) must be there
    return [kept[i] for i in sorted(kept)]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--count", type=int, default=6000)
    parser.add_argument("--seed", type=int, default=21)
    parser.add_argument("--hebrew", type=float, default=0.3)
    parser.add_argument("--heldout", action="store_true")
    parser.add_argument("--out", required=True)
    parser.add_argument("--ghidra", action="store_true", help="only Ghidra trajectories (native files, slower: Ghidra analyses each)")
    args = parser.parse_args()
    out = Path(args.out)
    if out.exists():
        raise SystemExit(f"{out} exists already; choose a new path (existing data is never overwritten).")
    r = random.Random(args.seed)
    pools = {"native": files(args.heldout, False), "dotnet": files(args.heldout, True)}
    for p in pools.values():
        r.shuffle(p)
    print(f"files: {len(pools['native'])} native, {len(pools['dotnet'])} .NET", flush=True)
    makers = [("native", native, 0.55), ("team", team, 0.2), ("dotnet", dotnet, 0.25)]
    rows, tries, at = [], 0, {"native": 0, "dotnet": 0}
    tmp = out.with_suffix(".partial")
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(tmp, "w", encoding="utf-8", newline="\n") as handle:
        while len(rows) < args.count and tries < args.count * 4:
            tries += 1
            pick = r.random()
            name, maker, _ = makers[0] if pick < 0.55 else makers[1] if pick < 0.75 else makers[2]
            if args.ghidra:
                name, maker = "ghidra", ghidra_traj
            pool = pools["dotnet" if name == "dotnet" else "native"]
            if not pool:
                continue
            path = pool[at["dotnet" if name == "dotnet" else "native"] % len(pool)]
            at["dotnet" if name == "dotnet" else "native"] += 1
            he, seed = r.random() < args.hebrew, r.random()
            made = fit(maker, seed, path, he)
            if args.ghidra:
                drop_ghidra_project(path)
            for row in made or []:
                rows.append(row)
                handle.write(json.dumps(row, ensure_ascii=False) + "\n")
            if tries % (5 if args.ghidra else 50) == 0:
                print(f"  {len(rows)} rows ({tries} tries)", flush=True)
                handle.flush()
    tmp.replace(out)
    kinds = {}
    for row in rows:
        kinds[row["type"]] = kinds.get(row["type"], 0) + 1
    print(f"wrote {len(rows)} rows to {out}: {kinds}")


if __name__ == "__main__":
    main()
