"""Neuro's reverse-engineering helper: what a binary is, what it was built with, and what is inside.

Run it with RUN, for example:
  python neuro_re.py info FILE              format, arch, what it was built with, entry, hashes, what to run next
  python neuro_re.py imports FILE           imported libraries and functions
  python neuro_re.py exports FILE           exported functions
  python neuro_re.py sections FILE          sections with addresses, sizes, entropy
  python neuro_re.py strings FILE [MIN] [WORD]   ASCII and UTF-16 strings with file offsets
  python neuro_re.py functions FILE [COUNT] [WORD]   functions (the biggest first) with the calls and strings each one uses
  python neuro_re.py decompile FILE [entry|0xADDRESS|EXPORT]   a whole native function, every call and string named
  python neuro_re.py xrefs FILE 0xADDRESS   who calls or loads an address (or "text": who uses that string)
  python neuro_re.py disasm FILE [ADDRESS|entry|EXPORT] [COUNT]   instructions (x86, x64, ARM, ARM64)
  python neuro_re.py hexdump FILE OFFSET [LENGTH]
  python neuro_re.py find FILE HEXBYTES     file offsets of a byte pattern ("48 8b 05")
.NET (C#, VB.NET) programs, through ILSpy (ilspycmd):
  python neuro_re.py types FILE [WORD]      the classes, structs, interfaces and enums
  python neuro_re.py decompile FILE TYPE[.METHOD]   the original C# of a class or one method
  python neuro_re.py project FILE OUTDIR    the whole program as a C# project you can build (dotnet build OUTDIR)
Ghidra (when installed) and Unity:
  python neuro_re.py ghidra FILE [COUNT|FUN_ADDRESS|0xADDRESS|entry|all]   functions, or Ghidra pseudo-C of one or all
  python neuro_re.py il2cpp GAME_FOLDER    a Unity IL2CPP game: every class and method with its address (Il2CppDumper)
  python neuro_re.py assets GAME_DATA [list|export|settings] [OUTDIR]   a Unity game's textures, models, sounds, texts, settings
  python neuro_re.py unreal GAME_FOLDER [list|unpack|legacy] [OUTDIR] [AES_KEY]   an Unreal game's .pak/.utoc content
  python neuro_re.py builderrors PROJECT_FOLDER   dotnet build with the errors grouped (fix a decompiled project step by step)
  python neuro_re.py doctor [--fix]        every tool this toolkit uses: what works, and repair what pip and dotnet can

PE files are read directly; ELF and Mach-O through lief; disassembly with capstone (objdump otherwise).
Output is plain text, cut to stay readable.
"""

import hashlib
import math
import os
import re
import shutil
import struct
import subprocess
import sys
import time
import zipfile

MAX_LINES = 200
# The tools Neuro installs (upx, 7z) answer by name here too.
for _dir in (r"D:\liliai\tools\bin", os.path.join(os.path.expanduser("~"), ".dotnet", "tools")):
    if os.path.isdir(_dir) and _dir not in os.environ.get("PATH", ""):
        os.environ["PATH"] = _dir + os.pathsep + os.environ.get("PATH", "")
EXEC = 0x20000000  # section flag: executable (ELF / Mach-O sections are given the same flag)


def out(lines):
    lines = list(lines)
    for line in lines[:MAX_LINES]:
        print(line)
    if len(lines) > MAX_LINES:
        print(f"... {len(lines) - MAX_LINES} more lines (narrow it: a WORD for strings, a COUNT for disasm, one TYPE.METHOD for .NET)")


def read(path):
    with open(path, "rb") as f:
        return f.read()


def kind_of(data):
    if data[:2] == b"MZ":
        return "PE"
    if data[:4] == b"\x7fELF":
        return "ELF"
    if data[:4] == b"\xca\xfe\xba\xbe" and struct.unpack_from(">H", data, 6)[0] >= 45 and struct.unpack_from(">I", data, 4)[0] > 30:
        return "Java class"
    if data[:4] in (b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe"):
        return "Mach-O"
    if data[:4] == b"PK\x03\x04":
        return "ZIP"
    if len(data) > 16 and data[2:4] == b"\r\n":
        return "Python bytecode"
    if data[:4] == b"\0asm":
        return "WebAssembly"
    return "unknown"


def entropy(chunk):
    if not chunk:
        return 0.0
    counts = [0] * 256
    for b in chunk:
        counts[b] += 1
    n = len(chunk)
    return -sum(c / n * math.log2(c / n) for c in counts if c)


# ---------------------------------------------------------------- PE without pefile

class MiniPE:
    """Enough of a PE to name sections, map addresses and read imports and exports."""

    def __init__(self, data):
        self.data = data
        pe = struct.unpack_from("<I", data, 0x3C)[0]
        if data[pe:pe + 4] != b"PE\0\0":
            raise ValueError("not a PE file")
        self.machine, nsec, self.timestamp = struct.unpack_from("<HHI", data, pe + 4)
        opt_size = struct.unpack_from("<H", data, pe + 20)[0]
        opt = pe + 24
        magic = struct.unpack_from("<H", data, opt)[0]
        self.is64 = magic == 0x20B
        self.entry_rva = struct.unpack_from("<I", data, opt + 16)[0]
        self.image_base = struct.unpack_from("<Q", data, opt + 24)[0] if self.is64 else struct.unpack_from("<I", data, opt + 28)[0]
        dirs = opt + (112 if self.is64 else 96)
        self.dirs = [struct.unpack_from("<II", data, dirs + 8 * i) for i in range(16)]
        self.sections = []
        sec = opt + opt_size
        for i in range(nsec):
            name, vsize, va, rsize, raw = struct.unpack_from("<8sIIII", data, sec + 40 * i)
            chars = struct.unpack_from("<I", data, sec + 40 * i + 36)[0]
            self.sections.append((name.rstrip(b"\0").decode("latin-1"), va, vsize, raw, rsize, chars))
        self._found = None

    @property
    def dotnet(self):
        return bool(self.dirs[14][0])

    def offset(self, rva):
        for _, va, vsize, raw, rsize, _ in self.sections:
            if va <= rva < va + max(vsize, rsize):
                return raw + (rva - va)
        return None

    def cstr(self, rva):
        off = self.offset(rva)
        if off is None:
            return "?"
        end = self.data.find(b"\0", off)
        return self.data[off:end].decode("latin-1")

    def imports(self):
        rva, size = self.dirs[1]
        result = []
        if not rva:
            return result
        off = self.offset(rva)
        while off is not None:
            orig, _, _, name_rva, first = struct.unpack_from("<IIIII", self.data, off)
            if not name_rva:
                break
            dll = self.cstr(name_rva)
            names = []
            thunk = self.offset(orig or first)
            step, flag = (8, 1 << 63) if self.is64 else (4, 1 << 31)
            while thunk is not None:
                value = struct.unpack_from("<Q" if self.is64 else "<I", self.data, thunk)[0]
                if not value:
                    break
                names.append(f"ordinal {value & 0xFFFF}" if value & flag else demangle(self.cstr((value & 0x7FFFFFFF) + 2)))
                thunk += step
            result.append((dll, names))
            off += 20
        return result

    def pdata(self):
        """(start rva, end rva) of every function in the exception directory (.pdata, x64/ARM64)."""
        rva, size = self.dirs[3]
        off = self.offset(rva) if rva else None
        result = []
        if off is None:
            return result
        entry = 12 if self.machine == 0x8664 else 8
        for i in range(size // entry):
            if entry == 12:
                begin, end, _ = struct.unpack_from("<III", self.data, off + 12 * i)
            else:  # ARM64: begin and packed data; the length is in the low bits (in 4-byte units)
                begin, info = struct.unpack_from("<II", self.data, off + 8 * i)
                end = begin + ((info >> 2) & 0x7FF) * 4 if info & 3 else begin + 4
            if begin and end > begin:
                result.append((begin, end))
        return sorted(set(result))

    def functions(self):
        """Every function: from .pdata when the file has it, else found from call targets and
        prologues (32-bit programs have no .pdata)."""
        found = self.pdata()
        if found or self.dotnet:
            return found
        if self._found is None:
            self._found = discover_functions(self)
        return self._found

    def iat(self):
        """Import address table slot (va) -> "dll!function"."""
        slots = {}
        rva, _ = self.dirs[1]
        off = self.offset(rva) if rva else None
        step = 8 if self.is64 else 4
        while off is not None:
            orig, _, _, name_rva, first = struct.unpack_from("<IIIII", self.data, off)
            if not name_rva:
                break
            dll = self.cstr(name_rva).lower().removesuffix(".dll")
            thunk = self.offset(orig or first)
            i = 0
            while thunk is not None:
                value = struct.unpack_from("<Q" if self.is64 else "<I", self.data, thunk)[0]
                if not value:
                    break
                flag = (1 << 63) if self.is64 else (1 << 31)
                name = f"ord{value & 0xFFFF}" if value & flag else demangle(self.cstr((value & 0x7FFFFFFF) + 2))
                slots[self.image_base + first + i * step] = f"{dll}!{name}"
                thunk += step
                i += 1
            off += 20
        return slots

    def exports(self):
        rva, _ = self.dirs[0]
        if not rva:
            return []
        off = self.offset(rva)
        nfuncs, nnames, funcs, names, ords = struct.unpack_from("<IIIII", self.data, off + 20)
        base = struct.unpack_from("<I", self.data, off + 16)[0]
        result = []
        for i in range(nnames):
            name_rva = struct.unpack_from("<I", self.data, self.offset(names) + 4 * i)[0]
            ordinal = struct.unpack_from("<H", self.data, self.offset(ords) + 2 * i)[0]
            func = struct.unpack_from("<I", self.data, self.offset(funcs) + 4 * ordinal)[0]
            result.append((self.cstr(name_rva), base + ordinal, func))
        return result

    def symbols(self):
        return {}


# ---------------------------------------------------------------- ELF and Mach-O through lief

class LiefBin:
    """ELF / Mach-O with the same face as MiniPE (addresses are virtual addresses, base 0)."""

    def __init__(self, data, path):
        import lief  # optional
        self.data = data
        b = lief.parse(path)
        if b is None:
            raise ValueError("lief could not parse it")
        if isinstance(b, lief.MachO.FatBinary):
            b = b.at(0)
        self.b = b
        self.image_base = 0
        self.timestamp = 0
        self.dotnet = False
        self.entry_rva = b.entrypoint
        arch = str(getattr(b.header, "machine_type", getattr(b.header, "cpu_type", ""))).upper()
        self.is64 = "64" in arch
        if "AARCH64" in arch or "ARM64" in arch:
            self.machine = 0xAA64
        elif "ARM" in arch:
            self.machine = 0x1C0
        elif "X86_64" in arch or "X86-64" in arch:
            self.machine = 0x8664
        else:
            self.machine = 0x14C
        self.sections = []
        for s in b.sections:
            flags = 0x40000000
            text = str(getattr(s, "flags", "")) + str(getattr(s, "flags_list", ""))
            if "EXECINSTR" in text or s.name in (".text", "__text", ".plt", "__stubs") or "PURE_INSTRUCTIONS" in text:
                flags |= EXEC
            self.sections.append((s.name, s.virtual_address, s.size, s.offset, s.size, flags))
        self.dirs = [(0, 0)] * 16

    def offset(self, rva):
        for _, va, vsize, raw, rsize, _ in self.sections:
            if va <= rva < va + vsize and raw:
                return raw + (rva - va)
        return None

    def symbols(self):
        names = {}
        for s in getattr(self.b, "symbols", []):
            if s.value and s.name:
                names[s.value] = s.name
        return names

    def functions(self):
        result = []
        for f in getattr(self.b, "functions", []):
            size = getattr(f, "size", 0) or 0
            if f.address:
                result.append((f.address, f.address + (size or 16)))
        if not result:
            result = discover_functions(self)
        return sorted(set(result))

    def imports(self):
        names = [f.name for f in getattr(self.b, "imported_functions", [])]
        libs = [str(l) for l in getattr(self.b, "libraries", [])]
        return [(", ".join(libs) or "(dynamic)", names)] if names else []

    def exports(self):
        return [(f.name, 0, f.address) for f in getattr(self.b, "exported_functions", [])]

    def iat(self):
        slots = {}
        for r in getattr(self.b, "pltgot_relocations", []):
            if r.has_symbol and r.symbol.name:
                slots[r.address] = r.symbol.name
        return slots


def load_bin(data, path=None):
    kind = kind_of(data)
    if kind == "PE":
        return MiniPE(data)
    if kind in ("ELF", "Mach-O"):
        try:
            return LiefBin(data, path)
        except ImportError:
            raise ValueError("ELF and Mach-O need lief: pip install lief")
    raise ValueError(f"{kind} is not a native program; run info for what to use")


load_pe = load_bin

MACHINES = {0x14C: "x86 (32-bit)", 0x8664: "x64", 0xAA64: "ARM64", 0x1C0: "ARM", 0x1C4: "ARM Thumb-2"}
MSVC_OPERATORS = {"2": "operator new", "3": "operator delete", "4": "operator=", "8": "operator==", "9": "operator!=",
                  "A": "operator[]", "H": "operator+", "Y": "operator+=", "_U": "operator new[]", "_V": "operator delete[]"}


def demangle(name):
    """A short C++ name for an MSVC-decorated one: "?Compare@CHString@@QBEHPBG@Z" -> "CHString::Compare",
    "??0CHString@@QAE@XZ" -> "CHString::CHString" (the constructor). Other names come back as they are."""
    if not name.startswith("?") or "@" not in name:
        return name
    try:
        if name.startswith("??"):
            code = name[2:4] if name[2] == "_" else name[2]
            rest = name[2 + len(code):]
            if rest.startswith("@"):  # a global operator: "??_V@YAXPAX@Z" is operator delete[]
                return MSVC_OPERATORS.get(code, "operator")
            scope = rest.split("@@")[0].split("@")
            cls = "::".join(reversed([s for s in scope if s]))
            last = scope[0] if scope else ""
            what = {"0": last, "1": "~" + last}.get(code, MSVC_OPERATORS.get(code, "operator"))
            return f"{cls}::{what}" if cls else what
        parts = [p for p in name[1:].split("@@")[0].split("@") if p]
        return "::".join(reversed(parts)) if parts else name
    except IndexError:
        return name


def disassembler(machine):
    import capstone
    if machine == 0x8664:
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    elif machine == 0xAA64:
        md = capstone.Cs(capstone.CS_ARCH_AARCH64 if hasattr(capstone, "CS_ARCH_AARCH64") else capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    elif machine == 0x1C0:
        md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
    elif machine == 0x1C4:
        md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
    else:
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.skipdata = True
    return md


def discover_functions(pe):
    """Functions of a program without a function table: the targets of direct calls that land in
    code, plus standard prologues (push ebp; mov ebp, esp / sub rsp). Each one ends where the next
    begins (at most 64 KB)."""
    if pe.machine not in (0x14C, 0x8664):
        return []
    starts = {}
    code = []
    for name, va, vsize, raw, rsize, chars in pe.sections:
        if chars & EXEC and rsize:
            code.append((pe.image_base + va, pe.data[raw:raw + min(vsize or rsize, rsize)]))
    def in_code(a):
        return any(b <= a < b + len(c) for b, c in code)
    for base, chunk in code:
        for m in re.finditer(rb"\xe8", chunk):
            i = m.start()
            if i + 5 > len(chunk):
                break
            target = base + i + 5 + struct.unpack_from("<i", chunk, i + 1)[0]
            if in_code(target):
                starts[target] = starts.get(target, 0) + 1
        for m in re.finditer(rb"(?<=[\xcc\x90\xc3])(?:\x55\x8b\xec|\x55\x89\xe5|\x8b\xff\x55\x8b\xec|\x48\x83\xec|\x40\x53\x48\x83\xec|\x48\x89\x5c\x24)", chunk):
            starts[base + m.start()] = starts.get(base + m.start(), 0) + 2
    entry = pe.image_base + pe.entry_rva
    starts[entry] = 9
    for name, _, rva in pe.exports():
        starts[pe.image_base + rva] = 9
    good = sorted(a for a, n in starts.items() if n >= 2 or (n == 1 and prologue_at(pe, a)))
    result = []
    for i, a in enumerate(good):
        end = good[i + 1] if i + 1 < len(good) else a + 4096
        result.append((a - pe.image_base, min(end, a + 65536) - pe.image_base))
    return result


def prologue_at(pe, va):
    off = pe.offset(va - pe.image_base)
    head = pe.data[off:off + 5] if off is not None else b""
    return head.startswith((b"\x55\x8b\xec", b"\x55\x89\xe5", b"\x8b\xff\x55", b"\x48\x83\xec", b"\x48\x89\x5c", b"\x40\x53", b"\x53\x56\x57", b"\x56\x57"))


# ---------------------------------------------------------------- what built it

def built_with(data, pe=None, path=""):
    """What made this file and how to get at its code: (language/tooling, the commands to use)."""
    name = os.path.basename(path)
    if pe is not None and getattr(pe, "dotnet", False):
        return ("a .NET assembly (managed code: C#, VB.NET or F#). The original source comes back almost exactly as C#",
                [f"types {name}", f"decompile {name} Namespace.Class", f"project {name} src_out   (then: dotnet build src_out)"])
    head = data[:4 * 1024 * 1024]
    found = []
    folder = os.path.dirname(os.path.abspath(path)) if path else "."
    if pe is not None and (b"UnrealEngine" in data or b"/Script/Engine" in data or b"FEngineLoop" in data
                           or re.search(rb"UE[45]-[A-Za-z]", data) or name.lower().endswith("-shipping.exe")):
        game = folder
        for _ in range(4):  # <Game>/Binaries/Win64/<Game>-Win64-Shipping.exe: the game folder is 3 up
            if any(os.path.isdir(os.path.join(game, d, "Content", "Paks")) for d in os.listdir(game)) or os.path.isdir(os.path.join(game, "Content", "Paks")):
                break
            game = os.path.dirname(game)
        return ("an Unreal Engine game (C++). The game's code is native in this .exe: functions / ghidra / decompile on it "
                "(Unreal names classes in strings: strings FILE U and strings FILE A find them). Its content (maps, meshes, "
                "textures, blueprints, settings) is in .pak / .utoc files under Content/Paks",
                [f"unreal {game} list", f"unreal {game} unpack", f"ghidra {name}"])
    if pe is not None and any(d.lower() == "unityplayer.dll" for d, _ in pe.imports()):
        managed = [os.path.join(n, "Managed") for n in os.listdir(folder) if n.endswith("_Data") and
                   os.path.isfile(os.path.join(folder, n, "Managed", "Assembly-CSharp.dll"))]
        if os.path.isfile(os.path.join(folder, "GameAssembly.dll")):
            return ("a Unity game built with IL2CPP: this .exe is only Unity's launcher. The game's C# was compiled to native "
                    "code in GameAssembly.dll; its class and method names are in <Game>_Data/il2cpp_data/Metadata/"
                    "global-metadata.dat. il2cpp recovers them all (dump.cs with every method's address)",
                    ["il2cpp .", "then: READ il2cpp_out/dump.cs, GREP it for a class", "ghidra GameAssembly.dll 0xADDRESS"])
        if managed:
            m = managed[0].replace(os.sep, "/")
            return (f"a Unity game built with Mono: this .exe is only Unity's launcher (UnityPlayer.dll is the engine). The "
                    f"game's own code is C# in {m}/: Assembly-CSharp.dll first, then the other DLLs there that are not "
                    f"UnityEngine.*, Mono's or System's. They decompile back to C# almost exactly",
                    [f"types {m}/Assembly-CSharp.dll", f"decompile {m}/Assembly-CSharp.dll Namespace.Class",
                     f"project {m}/Assembly-CSharp.dll game_src"])
        return ("a Unity game: this .exe is only Unity's launcher; look for <Game>_Data/Managed/Assembly-CSharp.dll (Mono) "
                "or GameAssembly.dll (IL2CPP) for the game's code", [])
    if pe is not None and any(s[0].startswith("UPX") for s in pe.sections):
        found.append(("packed with UPX: unpack it first, then look again", [f"upx -d {name} -o unpacked_{name}"]))
    elif pe is not None and not pe.imports() and any(entropy(data[s[3]:s[3] + s[4]]) > 7.2 for s in pe.sections):
        found.append(("packed or protected: no imports and compressed or encrypted data, so this is a loader that unpacks "
                      "the real program in memory when it runs. What the tools show now (strings, functions) is mostly the "
                      "loader. Look at the loader's code to see how it unpacks (decompile / ghidra on the entry point), and "
                      "check the resources and the files next to it for the real payload",
                      [f"decompile {name} entry", f"ghidra {name} entry", f"sections {name}", f"strings {name} 8"]))
    if b"PyInstaller" in head or b"_MEIPASS" in data or b"pyi-runtime-tmpdir" in data:
        found.append(("Python packed with PyInstaller: the code is .pyc inside it",
                      [f"pyinstxtractor {name}  (pip install pyinstxtractor-ng: pyinstxtractor-ng {name})", "then decompile the .pyc files (pycdc, or decompyle3 for 3.8 and older)"]))
    if b"Go build ID" in data or b"runtime.gopanic" in data:
        found.append(("Go (the function names are in .gopclntab: strings FILE main. finds them)", [f"strings {name} main.", f"functions {name}"]))
    if b"/rustc/" in data or b"rust_panic" in data:
        found.append(("Rust (panic paths name the source files: strings FILE .rs)", [f"strings {name} .rs", f"functions {name}"]))
    if b"Embarcadero" in data or b"Borland" in data or b"TObject" in head and b"System.SysUtils" in data:
        found.append(("Delphi / C++Builder (form resources hold the UI: strings FILE TForm)", [f"strings {name} TForm"]))
    if b"AU3!" in data or b"AutoIt" in head:
        found.append(("an AutoIt script compiled to an exe (the script is inside: autoit-ripper extracts it)", ["pip install autoit-ripper; autoit-ripper " + name + " out"]))
    if b"Nullsoft" in head:
        found.append(("an NSIS installer (7-Zip opens it: the files and the install script)", [f"7z x {name} -oextracted"]))
    if b"Inno Setup" in head:
        found.append(("an Inno Setup installer (innoextract unpacks it)", [f"innoextract {name}"]))
    if b"electron" in data.lower()[:8 * 1024 * 1024] and b"app.asar" in data:
        found.append(("Electron: the app is JavaScript in resources/app.asar next to the exe", ["npx asar extract resources/app.asar app_src"]))
    if pe is not None and not found:
        dlls = " ".join(d.lower() for d, _ in pe.imports())
        if "qt5core" in dlls or "qt6core" in dlls:
            found.append(("C++ with Qt", []))
        elif "msvcp" in dlls or "vcruntime" in dlls or "msvcr" in dlls or "ucrtbase" in dlls or "api-ms-win-crt" in dlls:
            found.append(("C/C++ built with Microsoft Visual C++" + (" (the msvcp C++ library: C++)" if "msvcp" in dlls else ""), []))
        elif b"libgcc" in data or b"mingw" in data.lower():
            found.append(("C/C++ built with GCC (MinGW)", []))
        elif b"GCC: (" in data:
            found.append(("C/C++ built with GCC", []))
    if not found:
        return ("native machine code (C/C++ or similar): decompile its functions to C", [])
    return ("; ".join(f for f, _ in found), [c for _, cs in found for c in cs])


# ---------------------------------------------------------------- commands

def cmd_info(path):
    data = read(path)
    kind = kind_of(data)
    name = os.path.basename(path)
    lines = [f"file: {path}", f"size: {len(data):,} bytes", f"format: {kind}",
             f"sha256: {hashlib.sha256(data).hexdigest()}", f"md5: {hashlib.md5(data).hexdigest()}"]
    pe = None
    if kind == "PE":
        try:
            pe = MiniPE(data)
        except (ValueError, struct.error, IndexError) as e:
            lines.append(f"the file is there and starts like a PE (MZ), but its headers do not parse ({e}): "
                         "truncated, packed or not really a PE. strings and hexdump still work.")
            out(lines)
            return
        lines += [f"machine: {MACHINES.get(pe.machine, hex(pe.machine))}", f"image base: {pe.image_base:#x}",
                  f"entry point: {pe.image_base + pe.entry_rva:#x} (rva {pe.entry_rva:#x})",
                  f"sections: {', '.join(s[0] for s in pe.sections)}"]
        imps = pe.imports()
        lines.append(f"imports: {len(imps)} DLLs, {sum(len(n) for _, n in imps)} functions ({', '.join(d for d, _ in imps[:12])}{' ...' if len(imps) > 12 else ''})")
        exps = pe.exports()
        if exps:
            lines.append(f"exports: {len(exps)} ({', '.join(e[0] for e in exps[:10])}{' ...' if len(exps) > 10 else ''})")
        packed = [s[0] for s in pe.sections if entropy(data[s[3]:s[3] + s[4]]) > 7.2]
        if packed:
            lines.append(f"high entropy (packed or compressed?): {', '.join(packed)}")
    elif kind == "ELF":
        cls = {1: "32-bit", 2: "64-bit"}.get(data[4], "?")
        machine = struct.unpack_from("<H", data, 18)[0]
        lines.append(f"class: {cls}, machine: {({3: 'x86', 62: 'x86-64', 40: 'ARM', 183: 'AArch64'}).get(machine, machine)}")
        try:
            pe = LiefBin(data, path)
            lines.append(f"entry point: {pe.entry_rva:#x}; {len(pe.functions())} functions; {len(pe.symbols())} symbols")
        except Exception:
            pe = None
    elif kind == "ZIP":
        with zipfile.ZipFile(path) as z:
            names = z.namelist()
        classes = [n for n in names if n.endswith(".class")]
        lines.append(f"entries: {len(names)} ({', '.join(names[:8])}{' ...' if len(names) > 8 else ''})")
        if classes or any(n.endswith("classes.dex") for n in names):
            lines.append("built with: Java / Kotlin (a .jar or .apk): decompile the classes (jadx for .apk and .dex, CFR or javap -c -p for .class)")
        lines.append(f"next: python -m zipfile -e {name} unzipped   then look at the files")
        out(lines)
        return
    elif kind == "Java class":
        lines.append(f"built with: Java (class file version {struct.unpack_from('>H', data, 6)[0]}): javap -c -p {name}, or CFR for Java source")
        out(lines)
        return
    elif kind == "Python bytecode":
        lines.append(f"built with: Python (.pyc): decompile with pycdc {name}, or python -m dis to see the bytecode")
        out(lines)
        return
    what, commands = built_with(data, pe, path)
    lines.append(f"built with: {what}")
    if pe is not None and getattr(pe, "dotnet", False):
        lines.append("note: the x86 entry is only a jump into the .NET runtime; disasm, functions and xrefs do not apply. Use types / decompile TYPE / project.")
        if not ilspy():
            lines.append("ilspycmd (the C# decompiler) is not installed yet: " + ILSPY_INSTALL)
    main = guess_main(pe) if pe is not None and not getattr(pe, "dotnet", False) and hasattr(pe, "iat") else None
    if main:
        lines.append(f"main: {main:#x} (sub_{main:x}), found from the startup code: the program's own code starts here. "
                     f"decompile {name} main shows it; the startup before it is compiler runtime code.")
    nxt = commands or ([f"decompile {name} main"] if main else []) + [f"functions {name}", f"imports {name}", f"strings {name} 8"]
    # One command per line: the model copies a line, and "a / b / c" on one line ran as one broken command.
    lines.append("next (each line is one command; RUN them one at a time with this toolkit):")
    lines.extend(f"  {c}" for c in nxt)
    out(lines)


def cmd_imports(path):
    pe = load_bin(read(path), path)
    lines = []
    for dll, names in pe.imports():
        lines.append(f"{dll} ({len(names)})")
        lines.extend(f"  {n}" for n in names)
    out(lines or ["no imports"])


def cmd_exports(path):
    pe = load_bin(read(path), path)
    out([f"{name}  ordinal {o}  {pe.image_base + rva:#x}" for name, o, rva in pe.exports()] or ["no exports"])


def cmd_sections(path):
    data = read(path)
    pe = load_bin(data, path)
    lines = ["name      address            vsize      raw size   entropy  flags"]
    for name, va, vsize, raw, rsize, chars in pe.sections:
        flags = "".join(f for bit, f in ((0x20000000, "x"), (0x40000000, "r"), (0x80000000, "w")) if chars & bit)
        lines.append(f"{name:<9} {pe.image_base + va:#018x} {vsize:#010x} {rsize:#010x} {entropy(data[raw:raw + rsize]):5.2f}    {flags}")
    out(lines)


def cmd_strings(path, minimum="6", word=None):
    data = read(path)
    if not minimum.isdigit():  # "strings FILE http": a word, with the default length
        minimum, word = "6", minimum
    n = int(minimum)
    found = []
    for m in re.finditer(rb"[\x20-\x7e]{%d,}" % n, data):
        found.append((m.start(), m.group().decode("ascii")))
    for m in re.finditer(rb"(?:[\x20-\x7e]\x00){%d,}" % n, data):
        found.append((m.start(), m.group().decode("utf-16-le") + "  (utf-16)"))
    found.sort()
    if word:
        found = [f for f in found if word.lower() in f[1].lower()]
    try:
        pe = load_bin(data, path)
    except Exception:
        pe = None
    def where(off):
        va = file_va(pe, off) if pe is not None else None
        return f"{off:#010x}  va {va:#x}" if va else f"{off:#010x}"
    lines = [f"{where(off)}  {text}" for off, text in found]
    if lines and pe is not None:
        lines.append("(xrefs FILE \"some text\" finds the code that uses a string)")
    out(lines or ["no strings"])


def file_va(pe, off):
    """The virtual address of a file offset, or None when it is outside every section."""
    for _name, sva, vsize, raw, rsize, _chars in getattr(pe, "sections", []):
        if raw <= off < raw + max(rsize, 1):
            return pe.image_base + sva + (off - raw)
    return None


def string_va(pe, text):
    """Every va where a string holding text (ascii or utf-16) starts."""
    needle = text.encode("ascii", "ignore")
    found = []
    for pat in (needle, text.encode("utf-16-le")):
        if not pat:
            continue
        for m in re.finditer(re.escape(pat), pe.data):
            start = m.start()
            step = 2 if pat is not needle else 1
            while start >= step and 0x20 <= pe.data[start - step] < 0x7f and (step == 1 or pe.data[start - 1] == 0):
                start -= step
            va = file_va(pe, start)
            if va and va not in found:
                found.append(va)
    return found[:8]


def cmd_hexdump(path, offset="0", length="256"):
    data = read(path)
    start, size = int(offset, 0), min(int(length, 0), 4096)
    lines = []
    for at in range(start, min(start + size, len(data)), 16):
        chunk = data[at:at + 16]
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{at:08x}  {chunk.hex(' '):<47}  {text}")
    out(lines)


def cmd_find(path, pattern):
    data = read(path)
    needle = bytes.fromhex(pattern.replace(" ", ""))
    hits = [m.start() for m in re.finditer(re.escape(needle), data)][:100]
    out([f"{h:#010x}" for h in hits] or ["not found"])


def inline_values(path, text):
    """Ghidra's pseudo-C with what each DAT_/PTR_ name holds written right after it, as a comment:
    DAT_140075c18/*"gravity"*/, DAT_0040407c/*0.985f*/. Then GREP finds a string or a number in the
    decompiled code, and a constant is read instead of guessed."""
    try:
        pe = load_bin(read(path), path)
    except Exception:
        return text
    cache = {}

    def value(h):
        if h in cache:
            return cache[h]
        va = int(h, 16)
        shown = None
        off = pe.offset(va - pe.image_base) if va >= pe.image_base else None
        if off is not None and off + 8 <= len(pe.data):
            s = string_at(pe, va)
            raw = pe.data[off:off + 8]
            if s and len(s) >= 3 and re.fullmatch(r"[\x20-\x7e]+", s):
                shown = '"' + s[:48].replace("*/", "* /") + '"'
            else:
                ptr = struct.unpack_from("<Q" if getattr(pe, "machine", 0) in (0x8664, 0xAA64) else "<I", raw)[0]
                target = string_at(pe, ptr) if pe.image_base <= ptr < pe.image_base + 0x40000000 else None
                if target and len(target) >= 3 and re.fullmatch(r"[\x20-\x7e]+", target):
                    shown = '->"' + target[:48].replace("*/", "* /") + '"'
                else:
                    f32 = struct.unpack_from("<f", raw)[0]
                    f64 = struct.unpack_from("<d", raw)[0]
                    def nice(v):
                        return v == v and v not in (float("inf"), float("-inf")) and 1e-6 <= abs(v) <= 1e9 and len(f"{v:.6g}") <= 11
                    if nice(f32):
                        shown = f"{f32:.6g}f"
                    elif nice(f64):
                        shown = f"{f64:.10g}"
        cache[h] = shown
        return shown

    def sub(m):
        v = value(m.group(2))
        return m.group(0) if v is None else f"{m.group(0)}/*{v}*/"

    text = re.sub(r"\b(_?DAT_|PTR_[A-Za-z0-9_]*?_?)([0-9a-fA-F]{6,16})\b(?!/\*)", sub, text)
    # The C runtime's own helpers (MinGW's __main, atexit and constructor walkers, security cookies) are
    # marked where they are called, so the program's own functions are the ones followed.
    slots = pe.iat() if hasattr(pe, "iat") else {}
    runtime = {}

    def rt(m):
        h = m.group(1)
        if h not in runtime:
            runtime[h] = runtime_function(pe, slots, int(h, 16))
        return f"{m.group(0)}/*C runtime: skip*/" if runtime[h] else m.group(0)

    return re.sub(r"\bFUN_([0-9a-fA-F]{6,16})\b(?!/\*)(?=\s*\()", rt, text)


def runtime_function(pe, slots, va, depth=2):
    """A C runtime helper: it calls the runtime's own imports (atexit, _initterm, _onexit, the cookie and
    exception helpers), names libgcc / mingw, or only calls such helpers (up to depth levels down)."""
    try:
        b, e = function_bounds(pe, va)
        b = va
        ins = instructions(pe, b, min(e, b + 2048))
    except Exception:
        return False
    imports, own = [], []
    for i in ins:
        if not is_call(i[2]) and not (i[2] == "jmp" and not i[3].startswith(("qword", "dword", "["))):
            continue
        t = target_of(i)
        if t is None or t == va:
            continue
        name = import_called(pe, slots, t)
        if name:
            imports.append(name)
        elif is_call(i[2]):
            own.append(t)
    marks = ("atexit", "_onexit", "initterm", "__register_frame", "__deregister_frame", "__security", "_crt_",
             "__set_app_type", "__getmainargs", "_amsg_exit", "SetUnhandledExceptionFilter", "_cexit")
    if any(m in n for n in imports for m in marks):
        return True
    _, _, strings = uses(pe, b, min(e, b + 2048), slots, {})
    if any(w in s for s in strings for w in ("libgcc", "ingw", "__register_frame", "runtime error")):
        return True
    if imports or not own or depth == 0:
        return False
    return all(runtime_function(pe, slots, t, depth - 1) for t in own[:6])


def constant_values(path, text):
    """What Ghidra's DAT_xxxxxxxx names hold, read from the file: a float or double constant (12.5, 0.985),
    a short string, or an integer. Lines to put under the pseudo-C, so numbers are read, not guessed."""
    try:
        pe = load_bin(read(path), path)
    except Exception:
        return []
    names = sorted(set(re.findall(r"\b_?DAT_([0-9a-fA-F]{6,16})\b", text)))
    lines = []
    for h in names[:40]:
        va = int(h, 16)
        off = pe.offset(va - pe.image_base) if va >= pe.image_base else None
        if off is None or off + 8 > len(pe.data):
            continue
        raw = pe.data[off:off + 8]
        s = string_at(pe, va)
        if s and len(s) >= 3 and re.fullmatch(r"[\x20-\x7e]+", s):
            lines.append(f"  DAT_{h} = \"{s[:60]}\"")
            continue
        f32 = struct.unpack_from("<f", raw)[0]
        f64 = struct.unpack_from("<d", raw)[0]
        i32 = struct.unpack_from("<i", raw)[0]
        def nice(v):
            return v == v and v not in (float("inf"), float("-inf")) and 1e-6 <= abs(v) <= 1e9 and len(f"{v:.6g}") <= 9
        values = []
        if nice(f32):
            values.append(f"float {f32:.6g}")
        if nice(f64):
            values.append(f"double {f64:.10g}")
        values.append(f"int {i32}")
        lines.append(f"  DAT_{h} = " + " / ".join(values))
    if lines:
        lines = ["", "Values of the DAT_ constants above, read from the file (a float or double used in arithmetic is the number shown):"] + lines
    return lines


def apphost_dll(path):
    """A .NET app's launcher (notes.exe next to notes.dll): the real code is in the .dll."""
    try:
        data = read(path)
    except Exception:
        return None
    if not path.lower().endswith(".exe") or b"hostfxr" not in data and "hostfxr".encode("utf-16-le") not in data:
        return None
    dll = os.path.splitext(path)[0] + ".dll"
    if os.path.isfile(dll):
        try:
            if MiniPE(read(dll)).dotnet:
                return dll
        except Exception:
            return None
    return None


def not_native(pe, path):
    if getattr(pe, "dotnet", False):
        name = os.path.basename(path)
        print(f"{name} is a .NET assembly: its code is IL, not machine code, so this does not apply. "
              f"Use: types {name} / decompile {name} Namespace.Class / project {name} src_out")
        return True
    return False


def cmd_disasm(path, where="entry", count="40"):
    data = read(path)
    pe = load_bin(data, path)
    if not_native(pe, path):
        return
    count = int(count)
    va = resolve_target(pe, where)
    if va is None:
        print(f"no export or symbol named {where}; give an address (0x...) or 'entry'")
        return
    off = pe.offset(va - pe.image_base)
    if off is None:
        print(f"{va:#x} is not inside a section of the file")
        return
    code = data[off:off + count * 15]
    try:
        md = disassembler(pe.machine)
        out(f"{i.address:#x}:  {i.bytes.hex(' '):<24} {i.mnemonic} {i.op_str}" for _, i in zip(range(count), md.disasm(code, va)))
        return
    except ImportError:
        pass
    objdump = shutil.which("objdump")
    if not objdump or pe.machine not in (0x14C, 0x8664):
        print("no disassembler: install capstone (pip install capstone)")
        return
    tmp = os.path.join(os.environ.get("TEMP", "."), "neuro_re_code.bin")
    with open(tmp, "wb") as f:
        f.write(code)
    arch = "i386:x86-64" if pe.machine == 0x8664 else "i386"
    run = subprocess.run([objdump, "-D", "-b", "binary", "-m", arch, "-M", "intel", f"--adjust-vma={va:#x}", tmp],
                         capture_output=True, text=True, errors="replace")
    lines = [l for l in run.stdout.splitlines() if re.match(r"\s+[0-9a-f]+:", l)]
    out(lines[:count] or [run.stderr.strip() or "objdump printed nothing"])


def resolve_target(pe, where):
    """entry | 0xADDRESS (or an rva) | sub_ADDRESS | an export or symbol name -> va, or None."""
    where = where.strip()
    if where in ("entry", "start"):
        return pe.image_base + pe.entry_rva
    m = re.fullmatch(r"(?:sub_|fun_|loc_)?((?:0x)?[0-9a-fA-F]+)h?", where, re.I)
    if m and (where.lower().startswith(("0x", "sub_", "fun_", "loc_")) or re.fullmatch(r"[0-9a-fA-F]{5,}", where)):
        va = int(m.group(1), 16)
        return va + pe.image_base if va < pe.image_base else va
    for name, _, rva in pe.exports():
        if name.lower() == where.lower():
            return pe.image_base + rva
    for va, name in pe.symbols().items():
        if name == where or name.lstrip("_") == where.lstrip("_"):
            return va
    if where.lower() in ("main", "wmain", "winmain", "wwinmain"):
        return guess_main(pe) or pe.image_base + pe.entry_rva
    return None


def function_bounds(pe, va):
    """The function that holds va: from the function table (or the found functions), else up to a
    ret followed by padding (int3 / nop), at most 4 KB."""
    rva = va - pe.image_base
    for begin, end in pe.functions():
        if begin <= rva < end:
            if begin != rva and end - begin > 4096:
                break
            return pe.image_base + begin, pe.image_base + end
    off = pe.offset(rva)
    chunk = pe.data[off:off + 4096]
    if pe.machine in (0x14C, 0x8664):
        for m in re.finditer(rb"\xc3(?:\xcc|\x90){1,}|\xc2..(?:\xcc|\x90){1,}", chunk, re.S):
            return va, va + m.start() + (1 if chunk[m.start()] == 0xC3 else 3)
    return va, va + len(chunk)


def instructions(pe, start, end):
    """(address, bytes hex, mnemonic, operands) for start..end."""
    off = pe.offset(start - pe.image_base)
    if off is None:
        raise ValueError(f"{start:#x} is not inside the file's sections (an address from another module, or a typo): "
                         f"pick one from functions FILE, or use ghidra FILE FUN_ADDRESS")
    code = pe.data[off:off + (end - start)]
    md = disassembler(pe.machine)
    return [(i.address, i.bytes.hex(" "), i.mnemonic, i.op_str) for i in md.disasm(code, start)]


def string_at(pe, va):
    off = pe.offset(va - pe.image_base)
    if off is None or off >= len(pe.data):
        return None
    raw = pe.data[off:off + 200]
    m = re.match(rb"[\x20-\x7e]{4,}", raw)
    if m:
        return m.group().decode("ascii")
    m = re.match(rb"(?:[\x20-\x7e]\x00){4,}", raw)
    if m:
        return m.group().decode("utf-16-le")
    return None


def target_of(ins):
    addr, raw, mnem, ops = ins
    m = re.search(r"\[rip ([+-]) 0x([0-9a-f]+)\]", ops)
    if m:  # rip-relative, forward or backward ("lea rax, [rip - 0x7c1]")
        disp = int(m.group(2), 16)
        return addr + len(raw.split()) + (disp if m.group(1) == "+" else -disp)
    if mnem in ("call", "jmp", "bl", "b", "blx") or mnem.startswith(("j", "b.", "cb", "tb")):
        m = re.fullmatch(r"#?(0x[0-9a-f]+)", ops)
        if m:
            return int(m.group(1), 16)
    m = re.search(r"\[0x([0-9a-f]+)\]|(?<![\w\[])#?0x([0-9a-f]{5,})", ops)
    if m:
        return int(m.group(1) or m.group(2), 16)
    return None


def annotate(pe, ins, slots, names):
    """An instruction with what it refers to: an imported function, a function, or a string."""
    addr, raw, mnem, ops = ins
    note = ""
    target = target_of(ins)
    if target is not None:
        if target in slots:
            note = slots[target]
        elif target in names:
            note = names[target]
        else:
            text = string_at(pe, target)
            if text:
                note = '"' + text[:60] + '"'
    return f"{addr:#x}:  {mnem} {ops}" + (f"    ; {note}" if note else "")


def known_names(pe):
    names = {pe.image_base + rva: name for name, _, rva in pe.exports()}
    names.update({va: n for va, n in pe.symbols().items() if va not in names})
    names.setdefault(pe.image_base + pe.entry_rva, "entry")
    for begin, _ in pe.functions():
        names.setdefault(pe.image_base + begin, f"sub_{pe.image_base + begin:x}")
    return names


def is_call(mnem):
    return mnem in ("call", "bl", "blx", "blr")


MAIN_ARGS = ("__getmainargs", "__wgetmainargs", "__p___argv", "__p___wargv", "__p___argc", "_get_initial_narrow_environment",
             "_get_initial_wide_environment", "__p__environ", "__p__wenviron", "_initterm")
EXITS = ("exit", "_exit", "_cexit", "_c_exit", "ExitProcess")


def import_called(pe, slots, t):
    """The import a call reaches: directly through its slot, or through a jmp [slot] thunk (MinGW)."""
    if t in slots:
        return slots[t].split("!")[-1]
    try:
        first = instructions(pe, t, t + 8)[:1]
    except Exception:
        return None
    if first and first[0][2] == "jmp":
        s = target_of(first[0])
        if s in slots:
            return slots[s].split("!")[-1]
    return None


def plausible_main(pe, slots, va):
    """Not a C runtime helper: no runtime calls ("_initterm", "__set_app_type") and no "runtime error" text."""
    try:
        b, e = function_bounds(pe, va)
        b = va  # the found bounds may start at an earlier function when they were merged
        imports, _, strings = uses(pe, b, e, slots, {})
        calls = sum(1 for i in instructions(pe, b, min(e, b + 4096)) if is_call(i[2]))
    except Exception:
        return True
    if e - b < 24 or calls == 0:  # a stub, a getter or a leaf helper, not a program's main
        return False
    if runtime_code(imports) or any(w in x for x in strings for w in ("runtime error", "ingw", "libgcc", "__register_frame")):
        return False
    if imports == ["GetModuleHandleW"] or imports == ["GetModuleHandleA"]:  # __scrt_is_managed_app
        return False
    return not any(i in ("_onexit", "atexit", "_crt_atexit", "_register_onexit_function", "SetUnhandledExceptionFilter") for i in imports)


def rust_main(pe, va):
    """Rust's main is a small wrapper that passes the program's real main (a code address loaded with
    lea) to std::rt::lang_start. That code address, or va itself for anything else."""
    if b"/rustc/" not in pe.data and b"rust_panic" not in pe.data:
        return va
    try:
        start, end = function_bounds(pe, va)
        ins = instructions(pe, start, min(end, start + 120))
    except Exception:
        return va
    if len(ins) > 30 or sum(1 for i in ins if is_call(i[2])) != 1:
        return va
    called = next((target_of(i) for i in ins if is_call(i[2])), None)
    for i in ins:
        if i[2] != "lea":
            continue
        t = target_of(i)
        if t is None or t == called:
            continue
        off = pe.offset(t - pe.image_base)
        in_code = any(pe.image_base + sva <= t < pe.image_base + sva + max(vsize, rsize) and chars & EXEC
                      for _n, sva, vsize, _raw, rsize, chars in pe.sections)
        if off is not None and in_code:
            return t
    return va


def guess_main(pe):
    found = guess_main_raw(pe)
    return rust_main(pe, found) if found else found


def guess_main_raw(pe):
    """main / wmain / WinMain: the C runtime startup gets argc and argv (or the environment), then calls the
    program's main, then exit with what it returned. The last own function called after the arguments, before
    exit, in the startup reached from the entry point."""
    try:
        slots = pe.iat()
        todo, seen = [(pe.image_base + pe.entry_rva, 0)], set()
        starts = {pe.image_base + b for b, _ in pe.functions()}
        while todo:
            va, depth = todo.pop(0)
            if va in seen or depth > 3 or len(seen) > 40:
                continue
            seen.add(va)
            start, end = function_bounds(pe, va)
            ins = instructions(pe, start, min(end, start + 8192))
            # The first own function called after the last argument getter (MSVC: __p___argv, __p___argc,
            # then main; MinGW: the same through thunks), confirmed by an exit call after it.
            # MSVC loads argc / argv / envp with __p___argc and friends and calls main right after them;
            # MinGW gets them earlier, and main is the last own call before exit.
            since_args, near, last_own, own, window = None, None, None, [], []
            for n, i in enumerate(ins):
                tail = i[2] == "jmp" and not i[3].startswith(("qword", "dword", "["))
                if not is_call(i[2]) and not tail:
                    continue
                t = target_of(i)
                # A jump inside the function is a branch; only a jump to another function's start goes on there.
                if t is None or t == start or (tail and start < t < end and t not in starts):
                    continue
                name = import_called(pe, slots, t)
                if name:
                    if any(a in name for a in MAIN_ARGS) or name in ("GetCommandLineA", "GetCommandLineW", "GetStartupInfoW", "GetStartupInfoA"):
                        since_args, near, last_own, window = n, None, None, []
                    elif since_args is not None and any(name == e or name.endswith(e) for e in EXITS):
                        found = [c for c in (near, last_own) if c]
                        if found:
                            def size(va):
                                try:
                                    b, e = function_bounds(pe, va)
                                    return e - va if b <= va < e and e - va < 4096 else 0
                                except Exception:
                                    return 0
                            return max(found, key=size)
                else:
                    own.append(t)  # a call or a tail jump into another function: the startup may go on there
                    if since_args is not None and is_call(i[2]) and plausible_main(pe, slots, t):
                        if near is None and n - since_args <= 8:
                            near = t
                        last_own = t
                        window.append(t)
            todo += [(t, depth + 1) for t in own]
    except Exception:
        return None
    return None


def in_code(pe, va):
    """va is inside an executable section of the program."""
    return any(pe.image_base + sva <= va < pe.image_base + sva + max(vsize, rsize) and chars & EXEC
               for _n, sva, vsize, _raw, rsize, chars in getattr(pe, "sections", []))


def uses(pe, start, end, slots, names):
    """The imported calls, called functions and strings of start..end."""
    try:
        ins = instructions(pe, start, min(end, start + 8192))
    except ImportError:
        return [], [], []
    imports, funcs, strings = [], [], []
    for i in ins:
        t = target_of(i)
        if t is None:
            continue
        if t in slots:
            n = slots[t].split("!")[-1]
            if n not in imports:
                imports.append(n)
        elif is_call(i[2]) and t != start and (t in names or in_code(pe, t)):
            n = names.get(t, f"sub_{t:x}")  # a call to an unnamed function of the program counts too
            if n not in funcs:
                funcs.append(n)
        else:
            s = string_at(pe, t)
            if s and len(s) >= 5 and re.search(r"[A-Za-z]{3}", s) and s not in strings:
                strings.append(s[:40])
    return imports, funcs, strings


def cmd_functions(path, count="40", word=None):
    pe = load_bin(read(path), path)
    if not_native(pe, path):
        return
    if not count.isdigit():
        count, word = "40", count
    names = known_names(pe)
    funcs = pe.functions()
    source = "the function table (.pdata)" if getattr(pe, "pdata", lambda: [])() else "symbols" if pe.symbols() else "call targets and prologues (no function table)"
    lines = [f"{len(funcs)} functions, from {source}. The unnamed ones (sub_ADDRESS) are what the program does: "
             "name each one from the calls and strings it uses, then decompile it."]
    slots = pe.iat()
    rows = [(pe.image_base + b, e - b) for b, e in funcs] or [(va, 0) for va in sorted(names)]
    if word:
        rows = [r for r in rows if word.lower() in names.get(r[0], "").lower()]
    rows.sort(key=lambda r: -r[1])  # the biggest first: they usually hold the logic
    for va, size in rows[:int(count)]:
        imports, called, strings = uses(pe, va, va + size, slots, names)
        hint = []
        if imports:
            hint.append("calls " + ", ".join(imports[:5]) + (" ..." if len(imports) > 5 else ""))
        if called:
            hint.append("-> " + ", ".join(called[:4]) + (" ..." if len(called) > 4 else ""))
        if strings:
            hint.append(", ".join('"' + s + '"' for s in strings[:2]))
        lines.append(f"{va:#x}  {size:6} bytes  {names.get(va, '')}" + ("  | " + " | ".join(hint) if hint else ""))
    out(lines)


RUNTIME = ("__set_app_type", "__getmainargs", "__wgetmainargs", "__p___argv", "__p___wargv", "_initterm", "_except_handler",
           "SetUnhandledExceptionFilter", "UnhandledExceptionFilter", "__security_init_cookie", "_amsg_exit", "__crtUnhandledException",
           "_controlfp", "_configthreadlocale", "__p__commode", "__p__fmode", "_cexit", "__dllonexit", "_onexit",
           "GetSystemTimeAsFileTime", "QueryPerformanceCounter", "IsProcessorFeaturePresent", "_crt_debugger_hook")


def runtime_code(imports):
    """The calls look like the C runtime's startup or exception code (two or more of its helpers)."""
    hits = [i for i in imports if any(r.lower() in i.lower() for r in RUNTIME)]
    return len(hits) >= 2 or (hits and len(imports) <= 2)


def cmd_decompile(path, where="entry", *rest):
    data = read(path)
    if kind_of(data) == "PE":
        pe = MiniPE(data)
        if pe.dotnet:
            return dotnet_decompile(path, where)
    pe = load_bin(data, path)
    va = resolve_target(pe, where)
    if va is None:
        print(f"no export or symbol named {where}; give an address (0x...), 'entry', or pick one from: functions {os.path.basename(path)}")
        return
    start, end = function_bounds(pe, va)
    if where.lower() in ("main", "wmain", "winmain", "wwinmain") and start < va < end:
        start = va  # main was found exactly; the found bounds may begin at the function before it
    try:
        ins = instructions(pe, start, end)
    except ImportError:
        print("decompile needs capstone: pip install capstone")
        return
    slots, names = pe.iat(), known_names(pe)
    imports, called, strings = uses(pe, start, end, slots, names)
    inside = (f"note: {va:#x} is inside this function (it starts at {start:#x}), so this is the same function as "
              f"decompile {os.path.basename(path)} {start:#x}: an address in the middle does not give a different function. "
              f"To see one part of it, use disasm {os.path.basename(path)} {va:#x} 40.") if start < va < end else None
    lines = [f"function {names.get(start, f'sub_{start:x}')} at {start:#x}, {end - start} bytes, {len(ins)} instructions",
             f"calls: {', '.join(imports + called) if imports or called else 'none'}",
             f"strings: {', '.join(repr(s) for s in strings) if strings else 'none'}", ""]
    if inside:
        lines.insert(1, inside)
    if runtime_code(imports):
        main = guess_main(pe)
        where_main = (f"main is at {main:#x}: decompile {os.path.basename(path)} main" if main else
                      f"main is the function the startup calls right after {'__wgetmainargs' if any('wgetmainargs' in i for i in imports) else '__getmainargs/__p___argv'} with argc and argv")
        lines.insert(1, f"note: this is compiler runtime code (startup, exception or security helpers), not what the program does. "
                        f"Do not follow it further: {where_main}; the rest of the logic is in the biggest functions (functions {os.path.basename(path)}).")
    global MAX_LINES
    # With Ghidra installed, its decompiler gives real pseudo-C (types, loops, conditions): that, not the raw
    # instructions. "decompile FILE ADDRESS asm" still gives the instructions.
    # A huge file Ghidra has not analysed yet would hold this command for up to 40 minutes: the
    # instructions now, and the way to get Ghidra's pseudo-C.
    big_unanalysed = len(data) > 40_000_000 and not os.path.isfile(os.path.join(
        os.environ.get("LOCALAPPDATA", os.path.expanduser("~")), "Neuro", "ghidra-projects",
        f"p{hashlib.sha256(data).hexdigest()[:16]}.ok"))
    if big_unanalysed:
        print(f"(this file is {len(data) // 1_000_000} MB: Ghidra's one-time analysis takes up to 40 minutes, so this is "
              f"the instructions. RUN ghidra {os.path.basename(path)} once to analyse it; after that decompile gives pseudo-C)")
    if "asm" not in rest and kind_of(data) == "PE" and ghidra_home() and not big_unanalysed:
        pseudo = ghidra_run(path, "one", target=f"0x{start:x}")
        if pseudo and "no function at" not in pseudo and "did not finish" not in pseudo:
            MAX_LINES = 400
            out(lines[:3] + ["Ghidra's pseudo-C (the value of each DAT_ name is in a /*comment*/ after it):", ""] + inline_values(path, pseudo).splitlines() + constant_values(path, pseudo) +
                ["", "Rewrite this as clean C: real names for the function, its variables and types (from the calls and",
                 "strings above), keep every branch and loop. Then decompile the sub_/FUN_ functions it calls the same way.",
                 f"(decompile {os.path.basename(path)} 0x{start:x} asm shows the instructions)"])
            return
    lines += [annotate(pe, i, slots, names) for i in ins]
    lines += ["", "Write this function as C: name it and its variables from what it does (the calls and",
              "strings above), keep every branch and loop, and mark what you are unsure of.",
              "Then decompile the sub_ functions it calls the same way."]
    MAX_LINES = 400
    out(lines)


def cmd_xrefs(path, where):
    pe = load_bin(read(path), path)
    if not_native(pe, path):
        return
    va = resolve_target(pe, where)
    if va is None:
        places = string_va(pe, where.strip("\"'"))
        if not places:
            print(f"cannot place {where}: not an address, a name, or text found in the file")
            return
        if len(places) > 1:
            print(f"the text is at {len(places)} places: " + ", ".join(f"{p:#x}" for p in places))
        for p in places:
            print(f"string at {p:#x}:")
            xrefs_to(pe, p)
        return
    xrefs_to(pe, va)


def xrefs_to(pe, va):
    data = pe.data
    hits = []
    for name, sva, vsize, raw, rsize, chars in pe.sections:
        if not chars & EXEC:  # executable sections only
            continue
        chunk = data[raw:raw + rsize]
        base = pe.image_base + sva
        if pe.machine in (0xAA64, 0x1C0, 0x1C4):
            try:
                for i in disassembler(pe.machine).disasm(chunk, base):
                    if target_of((i.address, i.bytes.hex(" "), i.mnemonic, i.op_str)) == va:
                        hits.append((i.address, i.mnemonic))
            except ImportError:
                pass
            continue
        for m in re.finditer(rb"[\xe8\xe9]", chunk):  # call / jmp rel32
            i = m.start()
            if i + 5 > len(chunk):
                break
            rel = struct.unpack_from("<i", chunk, i + 1)[0]
            if base + i + 5 + rel == va:
                hits.append((base + i, "call" if chunk[i] == 0xE8 else "jmp"))
        if pe.machine == 0x8664:
            for m in re.finditer(rb"(?:[\x48\x4c])?\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]", chunk):  # lea r, [rip+x]
                i = m.start()
                op = i + len(m.group())
                if op + 4 > len(chunk):
                    break
                disp = struct.unpack_from("<i", chunk, op)[0]
                if base + op + 4 + disp == va:
                    hits.append((base + i, "lea"))
        else:  # 32-bit: the address as an absolute operand (push imm32, mov r, imm32, call [addr])
            needle = struct.pack("<I", va)
            for m in re.finditer(re.escape(needle), chunk):
                hits.append((base + m.start(), "ref"))
    names = known_names(pe)
    funcs = [(pe.image_base + b, pe.image_base + e) for b, e in pe.functions()]
    def owner(a):
        for b, e in funcs:
            if b <= a < e:
                return names.get(b, f"sub_{b:x}")
        return "?"
    lines = [f"{a:#x}  {kind:4} in {owner(a)}" for a, kind in hits[:100]]
    # Data that points at it: a table of names, a vtable, a list of handlers. Each entry is shown with its
    # neighbours (what each holds), and the code that loads the table is looked up too.
    table = data_refs(pe, va)
    if table:
        lines.append(f"pointed to from data ({len(table)}): a table entry; the words around it:")
        for at, around in table[:6]:
            lines.append(f"  {at:#x}: " + " | ".join(around))
        for at, _ in table[:2]:
            start = table_start(pe, at)
            users = [f"{a:#x} {k} in {owner(a)}" for a, k in code_refs(pe, start)[:5]]
            if users:
                lines.append(f"  the table starting at {start:#x} is used by: " + "; ".join(users))
    out(lines or [f"nothing calls, loads or points to {va:#x} directly (it may be reached through a computed address)"])


def code_refs(pe, va):
    """Code that loads va (lea / absolute operand), without the full xrefs output."""
    data = pe.data
    hits = []
    for name, sva, vsize, raw, rsize, chars in pe.sections:
        if not chars & EXEC:
            continue
        chunk = data[raw:raw + rsize]
        base = pe.image_base + sva
        if pe.machine == 0x8664:
            for m in re.finditer(rb"(?:[\x48\x4c])?\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]", chunk):
                op = m.start() + len(m.group())
                if op + 4 <= len(chunk) and base + op + 4 + struct.unpack_from("<i", chunk, op)[0] == va:
                    hits.append((base + m.start(), "lea"))
        else:
            for m in re.finditer(re.escape(struct.pack("<I", va)), chunk):
                hits.append((base + m.start(), "ref"))
    return hits


def data_refs(pe, va):
    """Places in the non-code sections that hold va as a pointer, with the pointer-sized words around."""
    size = 8 if pe.machine in (0x8664, 0xAA64) else 4
    needle = struct.pack("<Q" if size == 8 else "<I", va)
    found = []
    for name, sva, vsize, raw, rsize, chars in pe.sections:
        if chars & EXEC:
            continue
        chunk = pe.data[raw:raw + rsize]
        for m in re.finditer(re.escape(needle), chunk):
            if m.start() % size:
                continue
            at = pe.image_base + sva + m.start()
            around = []
            for k in range(-1, 3):
                o = m.start() + k * size
                if 0 <= o and o + size <= len(chunk):
                    around.append(describe_word(pe, chunk[o:o + size], size))
            found.append((at, around))
            if len(found) >= 20:
                return found
    return found


def describe_word(pe, raw, size):
    """One pointer-sized word: a pointer to a string, to code, a float pair, or a number."""
    v = struct.unpack("<Q" if size == 8 else "<I", raw)[0]
    if pe.image_base <= v < pe.image_base + 0x40000000:
        s = string_at(pe, v)
        if s and len(s) >= 2 and re.fullmatch(r"[\x20-\x7e]+", s):
            return f'->"{s[:32]}"'
        return f"->{v:#x}"
    f = struct.unpack_from("<f", raw)[0]
    if f == f and 1e-4 <= abs(f) <= 1e7 and len(f"{f:.6g}") <= 9:
        return f"{f:.6g}f" + (f",{struct.unpack_from('<f', raw, 4)[0]:.6g}f" if size == 8 else "")
    return str(v if v < 1 << 31 else v - (1 << (size * 8)))


def table_start(pe, at):
    """Walk back from a table entry while the words before it are pointers into the program."""
    size = 8 if pe.machine in (0x8664, 0xAA64) else 4
    fmt = "<Q" if size == 8 else "<I"
    off = pe.offset(at - pe.image_base)
    if off is None:
        return at
    steps = 0
    while off - size >= 0 and steps < 4096:
        v = struct.unpack_from(fmt, pe.data, off - size)[0]
        if not (pe.image_base <= v < pe.image_base + 0x40000000) and v != 0:
            if steps and (struct.unpack_from(fmt, pe.data, off - 2 * size)[0] if off >= 2 * size else 0) == 0:
                break
            # a table of structs mixes pointers and numbers: allow one non-pointer between pointers
            prev = struct.unpack_from(fmt, pe.data, off - 2 * size)[0] if off >= 2 * size else 0
            if not (pe.image_base <= prev < pe.image_base + 0x40000000):
                break
        off -= size
        steps += 1
    return at - (steps * size)


# ---------------------------------------------------------------- .NET through ILSpy

ILSPY_INSTALL = "RUN dotnet tool install -g ilspycmd --version 8.2.0.7535   (needs the .NET SDK: winget install Microsoft.DotNet.SDK.8)"


def ilspy():
    home = os.path.expanduser("~")
    for p in (shutil.which("ilspycmd"), os.path.join(home, ".dotnet", "tools", "ilspycmd.exe"), os.path.join(home, ".dotnet", "tools", "ilspycmd")):
        if p and os.path.isfile(p):
            return p
    return None


def run_ilspy(args, timeout=600):
    exe = ilspy()
    if not exe:
        print("ilspycmd (ILSpy's C# decompiler) is not installed. Install it, then run this again:\n" + ILSPY_INSTALL)
        return None
    env = dict(os.environ, DOTNET_ROLL_FORWARD="Major")  # the 8.x tool runs on any newer runtime
    run = subprocess.run([exe] + args, capture_output=True, text=True, encoding="utf-8", errors="replace", env=env, timeout=timeout)
    if run.returncode != 0 and not run.stdout.strip():
        print("ilspycmd failed: " + (run.stderr.strip()[-1500:] or f"exit {run.returncode}"))
        return None
    return "\n".join(l for l in run.stdout.splitlines() if "latest version" not in l.lower())


def dotnet_types(path):
    text = run_ilspy(["-l", "cisde", path])
    if text is None:
        return None
    # Compiler-made helper types (lambdas, closures: "<>c", "<Main>d__0") are not the program's own.
    return [l.strip() for l in text.splitlines() if l.strip() and "<" not in l]


def cmd_types(path, word=None):
    types = dotnet_types(path)
    if types is None:
        return
    if word:
        types = [t for t in types if word.lower() in t.lower()]
    name = os.path.basename(path)
    out([f"{len(types)} types. decompile {name} Namespace.Class gives the C# of one; project {name} src_out writes them all."] + types)


def dotnet_decompile(path, where):
    name = os.path.basename(path)
    global MAX_LINES
    MAX_LINES = 400
    types = dotnet_types(path)
    if types is None:
        return
    full = [t.split(" ", 1)[1] for t in types if " " in t]
    if where in ("entry", "main", "Main", ""):
        # The class with the entry point: decompile them all once and find static Main.
        text = run_ilspy([path])
        if text is None:
            return
        m = re.search(r"static\s+(?:async\s+)?(?:void|int|Task(?:<int>)?)\s+Main\s*\(", text)
        if not m:
            print(f"no Main method found (a WPF app starts in App.xaml: decompile {name} the App class). Types:")
            out(full)
            return
        where = enclosing_type(text, m.start(), full) or where
        print(f"// the entry point Main is in {where}")
    method = None
    if where not in full:
        if "." in where and where.rsplit(".", 1)[0] in full:
            where, method = where.rsplit(".", 1)
        else:
            near = [t for t in full if t.lower().endswith("." + where.lower()) or t.lower() == where.lower()]
            if len(near) == 1:
                where = near[0]
            else:
                near = [t for t in full if where.lower() in t.lower()]
                print(f"no type named {where}. " + ("Did you mean: " + ", ".join(near[:20]) if near else f"See: types {name}"))
                return
    text = run_ilspy(["-t", where, path])
    if text is None:
        return
    if method:
        part = method_text(text, method)
        if not part:
            print(f"{where} has no method {method}; its members:")
            out(l.strip() for l in text.splitlines() if re.match(r"\s{4,8}(public|private|protected|internal)\b", l))
            return
        text = part
    lines = text.splitlines()
    if len(lines) > MAX_LINES:
        lines.append(f"// {len(lines)} lines in all. For the rest: decompile {name} {where}.METHOD, or project {name} src_out and READ the files.")
    out(lines)


def enclosing_type(text, pos, full):
    head = text[:pos]
    ns = re.findall(r"^namespace\s+([\w.]+)", head, re.M)
    cls = re.findall(r"^\s*(?:[\w]+\s+)*(?:class|struct)\s+(\w+)", head, re.M)
    if not cls:
        return None
    guess = (ns[-1] + "." if ns else "") + cls[-1]
    return guess if guess in full else next((t for t in full if t.endswith("." + cls[-1])), None)


def method_text(text, method):
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if re.search(r"\b" + re.escape(method) + r"\s*(<[^>]*>)?\s*\(", line) and not line.strip().endswith(";") and not re.search(r"\b(new|return|=)\b", line.split("(")[0]):
            start = i
            while start > 0 and lines[start - 1].strip().startswith("["):
                start -= 1
            depth, seen = 0, False
            for j in range(i, len(lines)):
                depth += lines[j].count("{") - lines[j].count("}")
                seen = seen or "{" in lines[j]
                if seen and depth <= 0:
                    return "\n".join(lines[start:j + 1])
                if not seen and lines[j].strip().endswith(";"):
                    return "\n".join(lines[start:j + 1])
    return None


FRAMEWORK_REFS = re.compile(r"^(System|Microsoft\.(CSharp|VisualBasic|Win32)|mscorlib|WindowsBase|PresentationCore|PresentationFramework|UIAutomation|ReachFramework|netstandard|Accessibility)\b")


def link_references(csproj, bindir):
    """The libraries the program uses that are not part of .NET: linked from the program's own folder
    when they are there (a HintPath), named as missing when not, so the build has what it needs."""
    with open(csproj, encoding="utf-8-sig") as f:
        text = f.read()
    linked, missing = [], []

    def fix(m):
        name = m.group(1)
        if FRAMEWORK_REFS.match(name):
            return m.group(0)
        for ext in (".dll", ".exe"):
            dll = os.path.join(bindir, name + ext)
            if os.path.isfile(dll):
                linked.append(name)
                return f'<Reference Include="{name}">\n      <HintPath>{dll}</HintPath>\n    </Reference>'
        missing.append(name)
        return m.group(0)

    text = re.sub(r'<Reference Include="([^"]+)"\s*/>', fix, text)

    # ILSpy writes a HintPath relative to the folder it ran in ("Managed/UnityEngine.CoreModule.dll"), but the
    # build reads it relative to the project's folder: every reference then looks missing. Make each one absolute.
    projdir = os.path.dirname(os.path.abspath(csproj))

    def absolute(m):
        hint = m.group(1).strip()
        name = m.group(2) if m.lastindex and m.lastindex >= 2 else ""
        if os.path.isabs(hint) and os.path.isfile(hint):
            return m.group(0)
        for candidate in (os.path.join(projdir, hint), os.path.abspath(hint), os.path.join(bindir, os.path.basename(hint))):
            if os.path.isfile(candidate):
                linked.append(os.path.splitext(os.path.basename(candidate))[0])
                return f"<HintPath>{os.path.abspath(candidate)}</HintPath>"
        missing.append(os.path.basename(hint))
        return m.group(0)

    text = re.sub(r"<HintPath>([^<]+)</HintPath>", absolute, text)
    with open(csproj, "w", encoding="utf-8") as f:
        f.write(text)
    lines = []
    linked = list(dict.fromkeys(linked))
    if linked:
        lines.append(f"linked {len(linked)} libraries from the program's folder (absolute paths in the project): "
                     f"{', '.join(linked[:10])}{' ...' if len(linked) > 10 else ''}")
    if any(n.startswith("UnityEngine") for n in linked):
        lines.append("Unity does not need to be installed: the engine's DLLs (UnityEngine.*) are linked from the game's own "
                     "Managed folder. Reading the decompiled C# is the reverse engineering; to build it, run builderrors on "
                     "the project folder and fix the errors file by file (decompiled code rarely builds on the first try).")
    if missing:
        lines.append(f"not found next to the program (the build fails without them): {', '.join(missing)}. They ship with the "
                     "original program: copy those DLLs next to it and run project again, or use their NuGet package if one exists. "
                     "Do not remove code that uses them.")
    return lines


def cmd_project(path, outdir="src_out"):
    os.makedirs(outdir, exist_ok=True)
    text = run_ilspy(["-p", "-o", outdir, path], timeout=1800)
    if text is None:
        return
    files = []
    for root, _, names in os.walk(outdir):
        for n in names:
            files.append(os.path.relpath(os.path.join(root, n), outdir))
    proj = [f for f in files if f.endswith((".csproj", ".vbproj"))]
    code = [f for f in files if f.endswith(".cs")]
    lines = [f"wrote {len(files)} files to {outdir} (full path: {os.path.abspath(outdir)}): {len(code)} C# files" + (f", project {proj[0]}" if proj else "")]
    if proj:
        lines += link_references(os.path.join(outdir, proj[0]), os.path.dirname(os.path.abspath(path)))
    # Paths as READ takes them: from the folder the command ran in, with forward slashes.
    lines += [os.path.join(outdir, f).replace(os.sep, "/") for f in sorted(code, key=lambda f: (f.count(os.sep), f))[:120]]
    lines.append(f"next: READ the files; dotnet build {outdir} to build it (an old .NET Framework project may need its targeting pack)")
    out(lines)


CS_HINTS = {
    "CS0246": "a type or namespace is not found: a reference is missing (link the DLL) or a using is wrong",
    "CS0234": "a namespace member is missing: usually a missing reference DLL",
    "CS0012": "a type is defined in an assembly that is not referenced: add that reference",
    "CS0103": "a name does not exist here: often a decompiler leftover or a missing using",
    "CS1061": "no such member: the referenced DLL is a different version, or a cast is lost in decompiling",
    "CS0102": "duplicate member: decompiler output (property and backing field, or two partial copies); remove one",
    "CS0111": "duplicate method: remove the copy",
    "CS0029": "cannot convert type: add the cast the decompiler dropped",
    "CS0266": "explicit conversion needed: add the cast",
    "CS1503": "argument type mismatch: add the cast or fix the overload",
    "CS0122": "inaccessible: the member is internal/private in the referenced DLL (InternalsVisibleTo or reflection)",
    "CS0518": "a predefined type is missing: the project's target framework does not match (set TargetFramework, or reference the program's own mscorlib/netstandard)",
    "CS0433": "the same type in two assemblies: remove one reference (often a framework facade vs the program's own copy)",
    "CS8124": "decompiler syntax (tuple element names) the target language version does not accept: raise LangVersion",
    "CS0570": "a member uses a feature C# cannot express: leave it out or rewrite it",
    "CS1069": "a type was moved to another assembly: add that reference",
}


def cmd_builderrors(folder="src_out", count="25"):
    """builderrors PROJECT_FOLDER: dotnet build, with the errors grouped by code and file, the most common first,
    so a decompiled project can be fixed step by step."""
    run = subprocess.run(["dotnet", "build", folder, "-nologo", "-v", "q", "-clp:NoSummary"], capture_output=True, text=True,
                         errors="replace", timeout=1800, stdin=subprocess.DEVNULL)
    text = run.stdout + run.stderr
    errors = {}
    for m in re.finditer(r"^\s*(.+?)\((\d+),\d+\): error (CS\d+|MSB\d+|NETSDK\d+): (.+?)(?: \[.*\])?$", text, re.M):
        errors.setdefault((m.group(1), m.group(2), m.group(3)), m.group(4))
    other = [l.strip() for l in text.splitlines() if re.search(r"\berror\b", l) and not re.search(r"\(\d+,\d+\): error", l)]
    if run.returncode == 0 and not errors:
        print("build succeeded: 0 errors")
        return
    by_code, by_file = {}, {}
    for (path, _, code) in errors:
        by_code[code] = by_code.get(code, 0) + 1
        by_file[path] = by_file.get(path, 0) + 1
    root = os.path.abspath(folder)
    short = lambda p: os.path.relpath(p, os.getcwd()).replace(os.sep, "/") if os.path.isabs(p) and p.startswith(root[:3]) else p.replace(os.sep, "/")
    lines = [f"{len(errors)} errors in {len(by_file)} files" + (f" (+{len(set(other))} project errors)" if other else "")]
    if other:
        lines += ["project errors (fix these first):"] + [f"  {l[:300]}" for l in list(dict.fromkeys(other))[:5]]
    lines.append("by error code, the most common first:")
    for code, n in sorted(by_code.items(), key=lambda x: -x[1])[:10]:
        example = next(msg for (p, l, c), msg in errors.items() if c == code)
        lines.append(f"  {code} x{n}: {example[:150]}" + (f"  -> {CS_HINTS[code]}" if code in CS_HINTS else ""))
    lines.append("files with the most errors:")
    lines += [f"  {short(p)}: {n}" for p, n in sorted(by_file.items(), key=lambda x: -x[1])[:8]]
    lines.append("first errors (file:line):")
    for (p, l, c), msg in list(errors.items())[:int(count)]:
        lines.append(f"  {short(p)}:{l} {c} {msg[:160]}")
    lines.append("next: fix the most common code first (one EDIT can clear many), then builderrors again.")
    out(lines)


# ---------------------------------------------------------------- Ghidra (headless)

GHIDRA_SCRIPT = "NeuroGhidra.java"  # written next to this file by Neuro


def ghidra_home():
    """Ghidra's folder: GHIDRA_INSTALL_DIR, else a ghidra_* folder in the usual places."""
    env = os.environ.get("GHIDRA_INSTALL_DIR")
    if env and os.path.isfile(os.path.join(env, "support", "analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless")):
        return env
    roots = [r"D:\liliai\tools", os.path.join(os.environ.get("LOCALAPPDATA", ""), "Neuro"), os.path.expanduser("~"),
             r"C:\ghidra", r"C:\Program Files", r"C:\tools", "/opt", "/usr/local"]
    found = []
    for root in roots:
        try:
            for name in os.listdir(root):
                path = os.path.join(root, name)
                if name.lower().startswith("ghidra") and os.path.isdir(os.path.join(path, "support")):
                    found.append(path)
        except OSError:
            pass
    return sorted(found)[-1] if found else None


def java_home(ghidra):
    """A JDK new enough for this Ghidra (application.java.min): JAVA_HOME when it is one, else a jdk-NN
    folder next to Ghidra."""
    need = 21
    try:
        with open(os.path.join(ghidra, "Ghidra", "application.properties"), encoding="utf-8") as f:
            m = re.search(r"^application\.java\.min=(\d+)", f.read(), re.M)
            need = int(m.group(1)) if m else need
    except OSError:
        pass
    version = lambda text: int((re.search(r"(?:jdk|java)-?(\d+)", text, re.I) or [0, 0])[1])
    env = os.environ.get("JAVA_HOME")
    if env and version(env) >= need:
        return env
    parent = os.path.dirname(ghidra)
    for name in sorted(os.listdir(parent), key=version, reverse=True):
        if version(name) >= need and os.path.isdir(os.path.join(parent, name, "bin")):
            return os.path.join(parent, name)
    return env


def plain_copy(path, digest):
    """The file under a path with no spaces or brackets (a hard link when it is on the same drive, else a
    copy), for tools whose launch scripts cannot take such paths. The file name stays the same."""
    src = os.path.abspath(path)
    if not re.search(r"[\s()&^%!]", src):
        return src
    folder = os.path.join(os.environ.get("LOCALAPPDATA", os.path.expanduser("~")), "Neuro", "ghidra-input", digest)
    os.makedirs(folder, exist_ok=True)
    dest = os.path.join(folder, re.sub(r"[\s()&^%!]", "_", os.path.basename(src)))
    if not os.path.isfile(dest):
        try:
            os.link(src, dest)
        except OSError:
            shutil.copy2(src, dest)
    return dest


def drop_ghidra_project(projects, project):
    """A project that did not finish (no .ok mark) goes, so the next call imports the program again."""
    for name in (project + ".gpr", project + ".ok"):
        try:
            os.remove(os.path.join(projects, name))
        except OSError:
            pass
    shutil.rmtree(os.path.join(projects, project + ".rep"), ignore_errors=True)


class ProjectLock:
    """One Ghidra run per project at a time: two helpers decompiling the same file at once made the second
    Ghidra abort on the locked project. The lock is a locked byte in a file, so it goes away with its
    process even when that process dies."""

    def __init__(self, path):
        self.path = path
        self.f = None

    def __enter__(self):
        self.f = open(self.path, "a+b")
        waited = 0
        while True:
            try:
                if os.name == "nt":
                    import msvcrt
                    self.f.seek(0)
                    msvcrt.locking(self.f.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(self.f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                return self
            except OSError:
                if waited == 0:
                    print("(another Neuro command is using Ghidra on this file; waiting for it to finish)", flush=True)
                if waited > 5400:
                    raise
                time.sleep(2)
                waited += 2

    def __exit__(self, *exc):
        try:
            if os.name == "nt":
                import msvcrt
                self.f.seek(0)
                msvcrt.locking(self.f.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.f.fileno(), fcntl.LOCK_UN)
        except OSError:
            pass
        self.f.close()
        return False


def ghidra_run(path, mode, target="entry", limit=60):
    """A Ghidra answer for path. A program analysed before is served by a Ghidra that stays open (it
    starts once, then each command takes about a second instead of 7-25 s); otherwise, and whenever
    that fails, one analyzeHeadless run (ghidra_locked), one at a time per file."""
    data = read(path)
    digest = hashlib.sha256(data).hexdigest()[:16]
    projects = os.path.join(os.environ.get("LOCALAPPDATA", os.path.expanduser("~")), "Neuro", "ghidra-projects")
    os.makedirs(projects, exist_ok=True)
    port_file = os.path.join(projects, f"p{digest}.port")
    text = ghidra_ask(port_file, mode, target, limit)
    if text is not None:
        return text
    with ProjectLock(os.path.join(projects, f"p{digest}.neurolock")):
        text = ghidra_ask(port_file, mode, target, limit)  # started by another command meanwhile
        if text is not None:
            return text
        analysed = os.path.isfile(os.path.join(projects, f"p{digest}.ok")) and os.path.isfile(os.path.join(projects, f"p{digest}.gpr"))
        if analysed and os.environ.get("NEURO_GHIDRA_SERVER", "1") != "0" and ghidra_serve(path, digest, projects, port_file, len(data)):
            text = ghidra_ask(port_file, mode, target, limit)
            if text is not None:
                return text
        return ghidra_locked(path, mode, target, limit)


def ghidra_ask(port_file, mode, target, limit):
    """Ask the Ghidra that stays open for this file (its port is in port_file). None when there is none."""
    import socket
    try:
        port = int(open(port_file).read().strip())
    except (OSError, ValueError):
        return None
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=3) as s:
            s.settimeout(2700 if mode == "all" else 600)
            s.sendall(f"{mode}\t{target}\t{limit}\n".encode("utf-8"))
            chunks = []
            while True:
                b = s.recv(65536)
                if not b:
                    break
                chunks.append(b)
    except OSError:
        try:
            os.remove(port_file)  # it ended (idle) or died: the next command starts a new one
        except OSError:
            pass
        return None
    text = b"".join(chunks).decode("utf-8", "replace")
    return text if text.strip() else None


def ghidra_serve(path, digest, projects, port_file, size):
    """Start a Ghidra that stays open on this analysed program and answers on a local port (it ends
    itself after 10 minutes with no command, 5 for a big program). True once it is listening."""
    home = ghidra_home()
    script_dir = os.path.dirname(os.path.abspath(__file__))
    if not home or not os.path.isfile(os.path.join(script_dir, GHIDRA_SCRIPT)):
        return False
    name = os.path.basename(path)
    if re.search(r"[\s()&^%!]", os.path.abspath(path)):
        name = re.sub(r"[\s()&^%!]", "_", name)
    headless = os.path.join(home, "support", "analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless")
    argv = [headless, projects, f"p{digest}", "-process", name, "-noanalysis", "-scriptPath", script_dir,
            # Idle minutes before it ends: its Java heap is 3-12 GB, so a big program's server goes sooner.
            "-postScript", GHIDRA_SCRIPT, "serve", port_file, "300" if size > 40_000_000 else "600", "0"]
    env = dict(os.environ)
    jdk = java_home(home)
    if jdk:
        env["JAVA_HOME"] = jdk
        env["PATH"] = os.path.join(jdk, "bin") + os.pathsep + env.get("PATH", "")
    env.setdefault("GHIDRA_HEADLESS_MAXMEM", "12G" if size > 40_000_000 else "6G" if size > 8_000_000 else "3G")
    try:
        os.remove(port_file)
    except OSError:
        pass
    flags = 0
    if os.name == "nt":
        flags = subprocess.CREATE_NEW_PROCESS_GROUP | 0x08000000  # its own group, no console window
    log = open(os.path.join(projects, f"p{digest}-serve.log"), "w")
    try:
        subprocess.Popen(argv, env=env, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, creationflags=flags)
    except OSError:
        return False
    for _ in range(240):  # up to 2 minutes for Java and the project to open
        time.sleep(0.5)
        try:
            if open(port_file).read().strip().isdigit():
                return True
        except OSError:
            pass
    return False


def ghidra_locked(path, mode, target="entry", limit=60):
    """Run the Neuro script in Ghidra on path; the program is analysed once and kept in a project
    (one per file content), so later calls take seconds."""
    home = ghidra_home()
    if not home:
        print("Ghidra is not installed. Install it (https://github.com/NationalSecurityAgency/ghidra/releases, unzip) "
              "with a JDK 21 next to it, or set GHIDRA_INSTALL_DIR. Until then use decompile / functions from this toolkit.")
        return None
    script_dir = os.path.dirname(os.path.abspath(__file__))
    if not os.path.isfile(os.path.join(script_dir, GHIDRA_SCRIPT)):
        print(f"error: {GHIDRA_SCRIPT} is missing next to the toolkit ({script_dir}); restart Neuro to write it again")
        return None
    data = read(path)
    digest = hashlib.sha256(data).hexdigest()[:16]
    projects = os.path.join(os.environ.get("LOCALAPPDATA", os.path.expanduser("~")), "Neuro", "ghidra-projects")
    os.makedirs(projects, exist_ok=True)
    project = f"p{digest}"
    # A project counts as analysed only after a run that worked (the .ok mark): a failed import leaves an
    # empty project, and "-process" on it fails at once, every time.
    ok_mark = os.path.join(projects, project + ".ok")
    analysed = os.path.isfile(ok_mark) and os.path.isfile(os.path.join(projects, project + ".gpr"))
    if not analysed:
        drop_ghidra_project(projects, project)
    out_file = os.path.join(projects, f"{project}-{os.getpid()}.txt")
    headless = os.path.join(home, "support", "analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless")
    argv = [headless, projects, project]
    size = len(data)
    if analysed:
        # The program is named after the file Ghidra imported (plain_copy keeps the name, minus brackets).
        name = os.path.basename(path)
        if re.search(r"[\s()&^%!]", os.path.abspath(path)):
            name = re.sub(r"[\s()&^%!]", "_", name)
        argv += ["-process", name, "-noanalysis"]
    else:
        # analyzeHeadless.bat breaks on "(" and ")" in its arguments ("Program Files (x86)": ") was
        # unexpected at this time"): it imports a link to the file from a plain folder instead.
        argv += ["-import", plain_copy(path, digest)]
        if size > 40_000_000:
            # A huge program (a game's 150 MB exe): analysis is stopped after 40 minutes and what was found
            # so far is kept, so functions and decompiling work instead of nothing.
            argv += ["-analysisTimeoutPerFile", "2400"]
    argv += ["-scriptPath", script_dir, "-postScript", GHIDRA_SCRIPT, mode, out_file, target, str(limit)]
    env = dict(os.environ)
    jdk = java_home(home)
    if jdk:
        env["JAVA_HOME"] = jdk
        env["PATH"] = os.path.join(jdk, "bin") + os.pathsep + env.get("PATH", "")
    # Ghidra's 2 GB default heap is far too small for a big program (the JVM dies, exit 255).
    if "GHIDRA_HEADLESS_MAXMEM" not in env:
        env["GHIDRA_HEADLESS_MAXMEM"] = "12G" if size > 40_000_000 else "6G" if size > 8_000_000 else "3G"
    if not analysed:
        minutes = "up to 40 minutes" if size > 40_000_000 else "a few minutes"
        print(f"(Ghidra is analysing {os.path.basename(path)} ({size // 1_000_000} MB) for the first time: this takes "
              f"{minutes}; later commands on it take seconds)", flush=True)
    try:
        run = subprocess.run(argv, capture_output=True, text=True, errors="replace", env=env, timeout=5400,
                             stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        drop_ghidra_project(projects, project)
        print("error: Ghidra ran for 90 minutes without finishing; use decompile / functions from this toolkit for this file")
        return None
    if not os.path.isfile(out_file):
        lines = (run.stdout + run.stderr).splitlines()
        reason = [l for l in lines if re.search(r"ERROR|Exception|OutOfMemory|error|SEVERE|not found|Failed", l)]
        tail = "\n".join((reason or lines)[-12:])[-1800:]
        drop_ghidra_project(projects, project)
        print(f"error: Ghidra did not produce output (exit {run.returncode}). Its last messages:\n{tail}\n"
              "Meanwhile decompile / functions / disasm from this toolkit work on this file.")
        return None
    with open(ok_mark, "w") as f:
        f.write("ok")
    with open(out_file, encoding="utf-8", errors="replace") as f:
        text = f.read()
    os.remove(out_file)
    return text


def cmd_ghidra(path, what="list", extra=None):
    """ghidra FILE: Ghidra's functions, the biggest first. ghidra FILE entry|0xADDRESS|FUN_x|NAME: one function's
    pseudo-C. ghidra FILE all [COUNT]: every function's pseudo-C written to FILE.ghidra.c."""
    try:
        if MiniPE(read(path)).dotnet:  # IL, not machine code: Ghidra's decompiler cannot read it
            not_native(MiniPE(read(path)), path)
            return
    except Exception:
        pass
    global MAX_LINES
    name = os.path.basename(path)
    if what.isdigit() and len(what) >= 6:  # "ghidra FILE 140042410": an address written without 0x
        what = "0x" + what
    if what.isdigit():  # "ghidra FILE 20": the list, that many
        what, extra = "list", what
    if what in ("list", "functions"):
        text = ghidra_run(path, "list", limit=int(extra) if extra and extra.isdigit() else 60)
        if text is not None:
            out(text.splitlines() + [f"next: ghidra {name} FUN_ADDRESS (or 0xADDRESS) for one function's pseudo-C; "
                                     f"ghidra {name} all for every function in {name}.ghidra.c"])
        return
    if what == "all":
        limit = int(extra) if extra and extra.isdigit() else 3000
        text = ghidra_run(path, "all", limit=limit)
        if text is None:
            return
        dest = name + ".ghidra.c"
        text = inline_values(path, text)
        with open(dest, "w", encoding="utf-8") as f:
            f.write(text)
        count = len(re.findall(r"^// \S+ at [0-9a-f]+", text, re.M))
        print(f"wrote the pseudo-C of {count} functions to {dest} (full path: {os.path.abspath(dest)}; {len(text.splitlines())} lines). READ it in parts "
              f"(READ {dest} 1-200), or GREP it for a call or a string.")
        return
    text = ghidra_run(path, "one", target=what)
    if text is not None:
        MAX_LINES = 400
        out(inline_values(path, text).splitlines() + constant_values(path, text) + ["", "This is Ghidra's pseudo-C. Rewrite it as clean C: real names for the function, its "
                                     "variables and types, and keep every branch. Then follow the FUN_ functions it calls."])


# ---------------------------------------------------------------- Unity IL2CPP

def il2cpp_dumper():
    home = os.path.expanduser("~")
    for p in (shutil.which("Il2CppDumper"), r"D:\liliai\tools\Il2CppDumper\Il2CppDumper.exe",
              os.path.join(os.environ.get("LOCALAPPDATA", ""), "Neuro", "Il2CppDumper", "Il2CppDumper.exe"),
              os.path.join(home, "Il2CppDumper", "Il2CppDumper.exe")):
        if p and os.path.isfile(p):
            return p
    return None


def cmd_il2cpp(folder=".", outdir="il2cpp_out"):
    """il2cpp GAME_FOLDER: Il2CppDumper on GameAssembly.dll and global-metadata.dat -> outdir/dump.cs (every class,
    field and method with its address), outdir/DummyDll/ (the types as .NET DLLs), script.json (names for Ghidra)."""
    folder = os.path.abspath(folder)
    if os.path.isfile(folder):
        folder = os.path.dirname(folder)
    binary = next((os.path.join(folder, n) for n in ("GameAssembly.dll", "libil2cpp.so", "UserAssembly.dll")
                   if os.path.isfile(os.path.join(folder, n))), None)
    meta = None
    for root, _, names in os.walk(folder):
        if "global-metadata.dat" in names:
            meta = os.path.join(root, "global-metadata.dat")
            break
    if not binary or not meta:
        print(f"not an IL2CPP game folder: GameAssembly.dll {'found' if binary else 'missing'}, global-metadata.dat "
              f"{'found' if meta else 'missing'}. A Mono Unity game has <Game>_Data/Managed/Assembly-CSharp.dll instead: "
              "use types / decompile / project on it.")
        return
    exe = il2cpp_dumper()
    if not exe:
        print("Il2CppDumper is not installed: download Il2CppDumper-net6-win from https://github.com/Perfare/Il2CppDumper/releases, "
              r"unzip it to D:\liliai\tools\Il2CppDumper and set RequireAnyKey to false in its config.json.")
        return
    os.makedirs(outdir, exist_ok=True)
    env = dict(os.environ, DOTNET_ROLL_FORWARD="Major")
    run = subprocess.run([exe, binary, meta, os.path.abspath(outdir)], capture_output=True, text=True, errors="replace",
                         env=env, timeout=1800, stdin=subprocess.DEVNULL)
    text = (run.stdout + run.stderr).strip().splitlines()
    dump = os.path.join(outdir, "dump.cs")
    if not os.path.isfile(dump):
        out(["Il2CppDumper did not write dump.cs:"] + text[-25:] +
            ["(a protected game may encrypt global-metadata.dat; then the metadata must be dumped from memory while it runs)"])
        return
    with open(dump, encoding="utf-8", errors="replace") as f:
        body = f.read()
    classes = len(re.findall(r"^(?:public |internal |private )?(?:sealed |abstract |static )*(?:class|struct) ", body, re.M))
    methods = len(re.findall(r"// RVA: 0x", body))
    o = outdir.replace(os.sep, "/")
    out([f"wrote {o}/dump.cs (full path: {os.path.abspath(dump)}): {classes} classes and structs, {methods} methods with their addresses (RVA).",
         f"also: {o}/DummyDll/ (the types as DLLs: types / decompile on {o}/DummyDll/Assembly-CSharp.dll shows signatures, "
         f"not bodies), {o}/script.json and {o}/il2cpp.h (names and types for Ghidra)."] + text[-6:] +
        [f"next: GREP {o}/dump.cs for a class or method name, READ around it, then ghidra GameAssembly.dll 0xRVA "
         "(Ghidra shows the code; add the image base 0x180000000 when the RVA alone is not found)."])


# ---------------------------------------------------------------- Unity assets (UnityPy)

ASSET_KINDS = ("Texture2D", "Sprite", "Mesh", "AudioClip", "TextAsset", "MonoBehaviour", "Font", "VideoClip")
UNITY_SETTINGS = ("PhysicsManager", "Physics2DSettings", "TimeManager", "TagManager", "QualitySettings", "PlayerSettings",
                  "InputManager", "BuildSettings")


def unity_env(folder):
    try:
        import UnityPy
    except ImportError:
        print("UnityPy is not installed: RUN python -m pip install --user UnityPy (or neuro_re.py doctor --fix)")
        return None
    data = os.path.abspath(folder)
    if data.lower().endswith((".pak", ".utoc", ".ucas", ".uasset", ".uexp")):
        game = os.path.dirname(data)
        print(f"{os.path.basename(data)} is Unreal Engine content, not Unity: assets reads Unity files only. "
              f"Use: unreal \"{game}\" list, then unreal \"{game}\" unpack (an encrypted .pak needs the game's AES key).")
        return None
    if os.path.isdir(data) and not any(n.endswith(("_Data", ".assets")) or n in ("globalgamemanagers", "data.unity3d")
                                       for n in os.listdir(data)):
        print(f"{data} has no Unity data: give the game's <Game>_Data folder (or one .assets / .bundle file)")
        return None
    if os.path.isdir(data):
        inner = [os.path.join(data, n) for n in os.listdir(data) if n.endswith("_Data")]
        data = inner[0] if inner and not os.path.isfile(os.path.join(data, "globalgamemanagers")) else data
    return UnityPy.load(data), data


def cmd_assets(folder=".", what="list", outdir="assets_out"):
    """assets GAME_DATA [list|export|settings] [OUTDIR]: the game's own content, as Unity stores it.
    list      how many textures, sprites, meshes, sounds, texts and scripts' data there are, with examples
    export    writes them out: textures and sprites as PNG, meshes as OBJ, sounds as WAV, texts as files,
              MonoBehaviour data as JSON, into OUTDIR (assets_out) by kind
    settings  the project's settings: physics (gravity, layer collisions), time step, tags and layers, input"""
    loaded = unity_env(folder)
    if not loaded:
        return
    env, data = loaded
    objects = list(env.objects)
    if what == "settings":
        import json
        lines = [f"Unity settings in {data}:"]
        for obj in objects:
            name = obj.type.name
            if name not in UNITY_SETTINGS:
                continue
            try:
                tree = obj.read_typetree()
            except Exception as e:  # noqa: BLE001
                lines.append(f"{name}: could not read ({e})")
                continue
            keep = {k: v for k, v in tree.items() if not isinstance(v, (bytes, bytearray)) and len(json.dumps(v, default=str)) < 600}
            lines.append(f"{name}: " + json.dumps(keep, default=str, ensure_ascii=False)[:1500])
        if len(lines) == 1:
            lines.append("no settings objects found here (they are in globalgamemanagers, in the <Game>_Data folder)")
        out(lines)
        return
    counts, examples = {}, {}
    for obj in objects:
        name = obj.type.name
        if name in ASSET_KINDS:
            counts[name] = counts.get(name, 0) + 1
            if len(examples.setdefault(name, [])) < 6:
                try:
                    examples[name].append(getattr(obj.read(), "m_Name", "") or f"#{obj.path_id}")
                except Exception:  # noqa: BLE001
                    pass
    if what != "export":
        lines = [f"Unity data in {data}: {len(objects)} objects in {len(env.files)} files"]
        lines += [f"  {k}: {counts[k]} (e.g. {', '.join(examples.get(k, [])[:6])})" for k in ASSET_KINDS if k in counts]
        lines.append(f"next: assets {folder} export   (writes them to {os.path.abspath(outdir)}); assets {folder} settings for physics and the rest")
        out(lines)
        return
    import json
    root = os.path.abspath(outdir)
    done, failed = {}, 0
    used = set()

    def target(kind, name, ext):
        base = re.sub(r"[^\w.-]+", "_", name or kind)[:80] or kind
        path = os.path.join(root, kind, base + ext)
        n = 1
        while path.lower() in used:
            path = os.path.join(root, kind, f"{base}_{n}{ext}")
            n += 1
        used.add(path.lower())
        os.makedirs(os.path.dirname(path), exist_ok=True)
        return path

    for obj in objects:
        kind = obj.type.name
        if kind not in ASSET_KINDS:
            continue
        try:
            item = obj.read()
            name = getattr(item, "m_Name", "") or str(obj.path_id)
            if kind in ("Texture2D", "Sprite"):
                item.image.save(target(kind, name, ".png"))
            elif kind == "Mesh":
                with open(target(kind, name, ".obj"), "w", encoding="utf-8") as f:
                    f.write(item.export())
            elif kind == "AudioClip":
                for sample, raw in item.samples.items():
                    with open(target(kind, os.path.splitext(sample)[0], os.path.splitext(sample)[1] or ".wav"), "wb") as f:
                        f.write(raw)
            elif kind == "TextAsset":
                script = item.m_Script
                raw = script.encode("utf-8", "surrogateescape") if isinstance(script, str) else bytes(script)
                with open(target(kind, name, "" if "." in name else ".txt"), "wb") as f:
                    f.write(raw)
            elif kind == "MonoBehaviour":
                tree = obj.read_typetree()
                with open(target(kind, name, ".json"), "w", encoding="utf-8") as f:
                    json.dump(tree, f, ensure_ascii=False, indent=1, default=str)
            elif kind == "Font":
                raw = getattr(item, "m_FontData", b"")
                if raw:
                    with open(target(kind, name, ".ttf"), "wb") as f:
                        f.write(bytes(raw))
            else:
                continue
            done[kind] = done.get(kind, 0) + 1
        except Exception:  # noqa: BLE001  (an encrypted or unusual object: counted, the rest goes on)
            failed += 1
    meaning = {"Texture2D": "textures, 2D images (PNG)", "Sprite": "sprites, 2D images cut from textures (PNG), not 3D models",
               "Mesh": "3D models (OBJ)", "AudioClip": "sounds (WAV)", "TextAsset": "text and data files",
               "MonoBehaviour": "script data (JSON)", "Font": "fonts (TTF)"}
    lines = [f"exported to {root}:"] + [f"  {root}{os.sep}{k}{os.sep}: {n} files: {meaning.get(k, k)}" for k, n in done.items()]
    if "Mesh" not in done:
        lines.append("  no Mesh objects in these files: there are no 3D models here (the game may be 2D, or its models are in other asset files)")
    if failed:
        lines.append(f"  {failed} objects could not be exported (unusual formats or protected data)")
    lines.append("Meshes are .obj (Blender, Windows 3D Viewer); textures .png; give the user these full paths.")
    out(lines)


# ---------------------------------------------------------------- Unreal Engine (repak, retoc, UAssetGUI)

def unreal_containers(folder):
    paks, tocs = [], []
    for root, _, names in os.walk(folder):
        for n in names:
            if n.lower().endswith(".pak"):
                paks.append(os.path.join(root, n))
            elif n.lower().endswith(".utoc"):
                tocs.append(os.path.join(root, n))
    return paks, tocs


def cmd_unreal(folder=".", what="list", outdir="unreal_out", key=None):
    """unreal GAME_FOLDER [list|unpack|legacy] [OUTDIR] [AES_KEY]: an Unreal Engine game's content.
    list    the .pak (UE4) and .utoc/.ucas (UE5 IoStore) containers: version, encryption, how many files
    unpack  extracts every .pak into OUTDIR (repak); .utoc containers are converted to plain .uasset files (retoc)
    legacy  UE5 IoStore (.utoc) -> legacy .pak / .uasset files that other tools read (retoc to-legacy)
    The game code itself is native (the Shipping .exe): ghidra / decompile on it. .uasset files -> JSON with
    UAssetGUI tojson FILE OUT.json VER (VER like VER_UE4_27 or VER_UE5_1). An encrypted container needs the
    game's AES key (64 hex digits), given as the last argument."""
    paks, tocs = unreal_containers(folder)
    if not paks and not tocs:
        print(f"no .pak or .utoc files under {os.path.abspath(folder)}: an Unreal game keeps them in <Game>/Content/Paks/")
        return
    if outdir and (os.path.isfile(outdir) or outdir.lower().endswith((".pak", ".utoc", ".ucas"))):
        # "unpack Runtime C:\...\Runtime-WindowsClient.pak": one container, not a folder to write into.
        one = os.path.abspath(outdir)
        print(f"(the third argument is the output folder; {os.path.basename(one)} is a container, so only it is unpacked, into unreal_out)", flush=True)
        paks = [p for p in paks if os.path.abspath(p).lower() == one.lower()] or (paks if one.lower().endswith(".pak") else [])
        tocs = [t for t in tocs if os.path.abspath(t).lower() == one.lower()] or (tocs if one.lower().endswith((".utoc", ".ucas")) else [])
        outdir = "unreal_out"
    repak, retoc = shutil.which("repak"), shutil.which("retoc")
    keyargs = ["--aes-key", key] if key else []
    if what == "list":
        lines = [f"{len(paks)} .pak and {len(tocs)} .utoc containers under {os.path.abspath(folder)}:"]
        for p in paks[:20]:
            info = subprocess.run([repak, *keyargs, "info", p], capture_output=True, text=True, errors="replace", timeout=300) if repak else None
            text = (info.stdout + info.stderr).strip().replace("\n", "; ") if info else "repak missing"
            lines.append(f"  {os.path.relpath(p, folder)} ({os.path.getsize(p):,} bytes): {text[:300]}")
        for t in tocs[:20]:
            info = subprocess.run([retoc, *keyargs, "info", t], capture_output=True, text=True, errors="replace", timeout=300) if retoc else None
            text = (info.stdout + info.stderr).strip().replace("\n", "; ") if info else "retoc missing"
            lines.append(f"  {os.path.relpath(t, folder)}: {text[:300]}")
        lines.append(f"next: unreal {folder} unpack (into {os.path.abspath(outdir)}); encrypted ones need the AES key as the last argument")
        out(lines)
        return
    root = os.path.abspath(outdir)
    os.makedirs(root, exist_ok=True)
    lock = open(os.path.join(root, ".neuro-unpack.lock"), "a+b")
    try:
        if os.name == "nt":
            import msvcrt
            msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        print(f"another unpack into {root} is running right now (a background job started earlier). Do not start it again: "
              f"wait for that job (READ its .neuro/bg log, or LIST {outdir} to see the files arriving), then go on with its output.")
        return
    lines = []
    if what in ("unpack", "legacy"):
        total = sum(os.path.getsize(p) for p in paks) + sum(os.path.getsize(t) for t in tocs)
        print(f"unpacking {len(paks)} .pak and {len(tocs)} .utoc ({total // 1_000_000:,} MB) into {root}: this can take many minutes; "
              f"files appear there as it goes", flush=True)
    if what in ("unpack", "legacy") and tocs and retoc:
        paks_dir = os.path.dirname(tocs[0])
        run = subprocess.run([retoc, *keyargs, "to-legacy", paks_dir, os.path.join(root, "from_iostore")], capture_output=True,
                             text=True, errors="replace", timeout=7200)
        lines.append(f"retoc to-legacy: exit {run.returncode}; " + (run.stdout + run.stderr).strip()[-600:])
    if what == "unpack" and paks and repak:
        for p in paks:
            print(f"unpacking {os.path.basename(p)} ({os.path.getsize(p) // 1_000_000:,} MB) ...", flush=True)
            run = subprocess.run([repak, *keyargs, "unpack", "-q", "-f", "-o", os.path.join(root, os.path.splitext(os.path.basename(p))[0]), p],
                                 capture_output=True, text=True, errors="replace", timeout=7200)
            lines.append(f"{os.path.basename(p)}: exit {run.returncode} " + (run.stdout + run.stderr).strip()[-300:])
    count = sum(len(f) for _, _, f in os.walk(root))
    kinds = {}
    for _, _, names in os.walk(root):
        for n in names:
            ext = os.path.splitext(n)[1].lower() or "(none)"
            kinds[ext] = kinds.get(ext, 0) + 1
    lines.insert(0, f"wrote {count} files to {root}: " + ", ".join(f"{k} {v}" for k, v in sorted(kinds.items(), key=lambda x: -x[1])[:10]))
    lines.append("next: .uasset/.uexp are the assets (meshes, textures, blueprints): UAssetGUI tojson FILE OUT.json VER_UE4_27 for "
                 "their data; .ini files are the game's settings; the code is in the .exe (ghidra on it).")
    out(lines)


# ---------------------------------------------------------------- doctor: every tool, checked and repaired

def _ok_run(argv, env=None, timeout=60):
    try:
        run = subprocess.run(argv, capture_output=True, text=True, errors="replace", env=env, timeout=timeout,
                             stdin=subprocess.DEVNULL)
        return run.returncode == 0, (run.stdout + run.stderr).strip().splitlines()[:1]
    except (OSError, subprocess.TimeoutExpired) as e:
        return False, [str(e)]


def doctor_checks(fix):
    import importlib.util
    results = {}

    def note(name, ok, detail):
        results[name] = {"ok": bool(ok), "detail": detail}

    note("python", True, sys.version.split()[0] + " " + sys.executable)
    modules = {"capstone": "capstone", "lief": "lief", "pefile": "pefile", "UnityPy": "unitypy"}
    missing = [m for m in modules if importlib.util.find_spec(m) is None]
    if missing and fix:
        _ok_run([sys.executable, "-m", "pip", "install", "--user", "-q", *missing], timeout=900)
        importlib.invalidate_caches()
        missing = [m for m in missing if importlib.util.find_spec(m) is None]
    for m, key in modules.items():
        note(key, m not in missing, "installed" if m not in missing else f"missing: {sys.executable} -m pip install {m}")
    dotnet = shutil.which("dotnet")
    note("dotnet", bool(dotnet), dotnet or "missing: winget install Microsoft.DotNet.SDK.8")
    if not ilspy() and dotnet and fix:
        _ok_run([dotnet, "tool", "install", "-g", "ilspycmd", "--version", "8.2.0.7535"], timeout=900)
    exe = ilspy()
    if exe:
        ok, first = _ok_run([exe, "--version"], env=dict(os.environ, DOTNET_ROLL_FORWARD="Major"))
        note("ilspy", ok, (first[0] if first else exe) if ok else f"does not start: {first}")
    else:
        note("ilspy", False, "missing: " + ILSPY_INSTALL)
    home = ghidra_home()
    script_dir = os.path.dirname(os.path.abspath(__file__))
    if home:
        jdk = java_home(home)
        java = os.path.join(jdk, "bin", "java.exe" if os.name == "nt" else "java") if jdk else shutil.which("java")
        ok, first = _ok_run([java, "-version"]) if java and os.path.isfile(java) else (False, ["no JDK found"])
        script = os.path.isfile(os.path.join(script_dir, GHIDRA_SCRIPT))
        note("ghidra", ok and script, f"{os.path.basename(home)} with {os.path.basename(jdk or '?')}" if ok and script else
             f"{home}: " + ("JDK problem: " + " ".join(first) if not ok else f"{GHIDRA_SCRIPT} missing next to the toolkit"))
    else:
        note("ghidra", False, r"missing: unzip Ghidra (github.com/NationalSecurityAgency/ghidra/releases) to D:\liliai\tools with the JDK it needs")
    dumper = il2cpp_dumper()
    if dumper:
        config = os.path.join(os.path.dirname(dumper), "config.json")
        try:
            with open(config, encoding="utf-8") as f:
                text = f.read()
            if '"RequireAnyKey": true' in text and fix:
                with open(config, "w", encoding="utf-8") as f:
                    f.write(text.replace('"RequireAnyKey": true', '"RequireAnyKey": false'))
                text = text.replace('"RequireAnyKey": true', '"RequireAnyKey": false')
            note("il2cppdumper", '"RequireAnyKey": false' in text, dumper if '"RequireAnyKey": false' in text else
                 "RequireAnyKey is true in config.json (it would wait for a key)")
        except OSError as e:
            note("il2cppdumper", False, str(e))
    else:
        note("il2cppdumper", False, "missing: github.com/Perfare/Il2CppDumper/releases (net6-win) to D:\\liliai\\tools\\Il2CppDumper")
    for name, exe_name in (("gcc", "gcc"), ("objdump", "objdump"), ("upx", "upx"), ("7z", "7z"), ("repak", "repak"),
                           ("retoc", "retoc"), ("uassetgui", "UAssetGUI")):
        found = shutil.which(exe_name)
        note(name, bool(found), found or "not installed (optional)")
    return results


def cmd_doctor(*flags):
    """doctor [--fix] [--quiet]: checks every tool the toolkit uses (and with --fix installs what pip and dotnet can),
    writes status.json next to the toolkit, and prints what works."""
    import json
    import time
    results = doctor_checks("--fix" in flags)
    status = os.path.join(os.path.dirname(os.path.abspath(__file__)), "status.json")
    try:
        with open(status, "w", encoding="utf-8") as f:
            json.dump({"checked": int(time.time()), "tools": results}, f, indent=1)
    except OSError:
        pass
    if "--quiet" not in flags:
        out([f"{'ok  ' if r['ok'] else 'MISSING'}  {name}: {r['detail']}" for name, r in results.items()])


# ---------------------------------------------------------------- the command line

COMMANDS = {"functions": cmd_functions, "decompile": cmd_decompile, "xrefs": cmd_xrefs, "info": cmd_info, "imports": cmd_imports,
            "exports": cmd_exports, "sections": cmd_sections, "strings": cmd_strings, "hexdump": cmd_hexdump, "disasm": cmd_disasm,
            "find": cmd_find, "types": cmd_types, "project": cmd_project, "ghidra": cmd_ghidra, "il2cpp": cmd_il2cpp, "builderrors": cmd_builderrors, "doctor": cmd_doctor, "assets": cmd_assets, "unreal": cmd_unreal}
def placeholder(word):
    """A help-text placeholder copied as is: written in capitals ("FILE", "0xADDRESS"), never a real word ("export")."""
    return word.upper() in PLACEHOLDERS and word.replace("0x", "0X").isupper()


PLACEHOLDERS = {"FILE", "WORD", "MIN", "ADDRESS", "0XADDRESS", "EXPORT", "COUNT", "OFFSET", "LEN", "LENGTH", "OUTDIR", "TYPE", "METHOD", "HEXBYTES", "TYPE.METHOD"}
BINARY_EXTS = (".exe", ".dll", ".sys", ".so", ".dylib", ".elf", ".bin", ".o", ".obj", ".ko", ".efi", ".ocx", ".scr", ".drv", ".jar", ".apk", ".class", ".pyc", ".wasm")


def fix_args(cmd, args):
    """Placeholders copied from the help ("FILE", "entry|0xADDRESS|EXPORT") become the real
    values: the one binary in the folder, the first choice of an a|b|c list."""
    args = [a.split("|")[0] if "|" in a and not os.path.exists(a) else a for a in args]
    notes = []
    if args and placeholder(args[0]):
        here = [f for f in os.listdir(".") if f.lower().endswith(BINARY_EXTS) and os.path.isfile(f)]
        if len(here) == 1:
            notes.append(f"(FILE is a placeholder: used {here[0]}, the binary in this folder. Next time write the file name.)")
            args[0] = here[0]
        else:
            print(f"error: FILE is a placeholder: write the file's name, for example: {cmd} {here[0] if here else 'app.exe'}" +
                  (f" (binaries here: {', '.join(here[:10])})" if len(here) > 1 else ""))
            return None
    args = args[:1] + [a for a in args[1:] if not placeholder(a)]
    for n in notes:
        print(n)
    return args


def main(argv):
    if len(argv) >= 2 and argv[1].startswith("re_") and argv[1][3:] in COMMANDS:
        # The MCP server's tool names (re_info, re_functions) work here too, without option flags.
        argv = [argv[0], argv[1][3:]] + [a for a in argv[2:] if not (a.startswith("-") and len(a) <= 3)]
    if len(argv) >= 2 and argv[1] == "doctor":  # no file: it checks the tools themselves
        cmd_doctor(*argv[2:])
        return 0
    if len(argv) >= 3 and argv[1] not in COMMANDS and not os.path.exists(argv[1]):
        # "neuro_re.py then the command: decompile fsm.exe main": words copied from the explanation in front
        # of the command. The first known command in the next few words starts the real line.
        at = next((k for k in range(2, min(len(argv), 6)) if argv[k].rstrip(":") in COMMANDS), None)
        if at:
            argv = [argv[0], argv[at].rstrip(":")] + argv[at + 1:]
    if len(argv) >= 3 and argv[1] not in COMMANDS and argv[2] in COMMANDS and os.path.exists(argv[1]):
        argv = [argv[0], argv[2], argv[1]] + argv[3:]  # "neuro_re.py app.exe info": the file came first
    if len(argv) >= 2 and argv[1].lower() in ("read", "grep", "glob", "list", "cat", "type", "head", "findstr"):
        what = argv[1].upper() if argv[1].lower() in ("read", "grep", "glob", "list") else "READ"
        print(f"error: {argv[1]} is not a toolkit command. {what} is Neuro's own tool: send it on its own line, without python "
              f"and without neuro_re.py, for example:\nREAD {' '.join(argv[2:3]) or 'file.ghidra.c'}\nGREP gravity {' '.join(argv[2:3]) or 'file.ghidra.c'}  (with the word you look for)")
        return 2
    aliases = {"section": "sections", "string": "strings", "import": "imports", "export": "exports", "function": "functions",
               "decompiler": "decompile", "xref": "xrefs", "disassemble": "disasm", "type": "types"}
    if len(argv) >= 2 and argv[1].lower() in aliases:
        argv = [argv[0], aliases[argv[1].lower()]] + argv[2:]
    if len(argv) < 3 or argv[1] not in COMMANDS:
        if len(argv) >= 2 and argv[1] not in COMMANDS:
            print(f"error: no command {argv[1]}. Commands: {', '.join(COMMANDS)}\n")
        print(__doc__)
        return 2
    args = fix_args(argv[1], argv[2:])
    if args is None:
        return 1
    dll = apphost_dll(args[0]) if args and argv[1] in ("info", "functions", "decompile", "ghidra", "disasm", "xrefs", "imports", "strings", "types", "project") else None
    if dll:
        name, dname = os.path.basename(args[0]), os.path.basename(dll)
        if argv[1] in ("types", "project", "decompile"):
            print(f"({name} is only the .NET launcher; the program is {dname}, so this runs on {dname})", flush=True)
            args = [dll] + list(args[1:])
        else:
            print(f"{name} is only the .NET app launcher (apphost): it finds the .NET runtime and starts {dname}. The program's code, "
                  f"in C#, is in {dname}. Use: types {dname} (its classes) / decompile {dname} Namespace.Class (the C# of one class) / "
                  f"project {dname} src_out (all of it). Command-line options and hidden commands are in the C# of the class with Main.")
            return 0
    try:
        COMMANDS[argv[1]](*args)
    except (ValueError, struct.error, IndexError) as e:
        size = os.path.getsize(args[0]) if os.path.isfile(args[0]) else None
        there = f"{args[0]} is there ({size:,} bytes) but " if size is not None else ""
        print(f"error: {there}it could not be read as a program: {e}. Try: info {args[0]}, strings, hexdump")
        return 1
    except FileNotFoundError:
        here = [f for f in os.listdir(".") if f.lower().endswith(BINARY_EXTS)]
        print(f"error: {args[0]} is not there" + (f" (binaries in this folder: {', '.join(here[:10])})" if here else ""))
        return 1
    except TypeError as e:
        print(f"error: wrong arguments for {argv[1]} ({e}).\n")
        print(__doc__)
        return 2
    except subprocess.TimeoutExpired:
        print("error: the decompiler ran too long; narrow it to one TYPE or TYPE.METHOD")
        return 1
    return 0


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except AttributeError:
        pass
    sys.exit(main(sys.argv))
