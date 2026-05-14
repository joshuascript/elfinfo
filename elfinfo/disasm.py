"""
Disassembly-based function analysis: return register, return type inference,
instruction count, and raw return values.

Analysis always uses AT&T syntax (pattern matching is AT&T-specific).
Display instructions are stored in the requested syntax (second objdump pass
only when a non-default syntax is requested).

After analysis, a post-processing pass resolves the mangled C++ names that
objdump inlines as labels on call/jump targets, e.g.:
  call 25c900 <_ZN9mkvparser5Block5ParseE@plt>
  → call 25c900 <mkvparser::Block::Parse()@plt>
"""
import re
import subprocess
from collections import Counter
from pathlib import Path

_WINDOW = 12

# Maps --syntax names to objdump -M flags.
# att is the default and needs no -M flag.
SYNTAX_TO_M: dict[str, list[str]] = {
    "att":         [],
    "intel":       ["-M", "intel"],
    "no-aliases":  ["-M", "no-aliases"],
    "arm-apcs":    ["-M", "reg-names-apcs"],
    "arm-std":     ["-M", "reg-names-std"],
    "force-thumb": ["-M", "force-thumb"],
}
SYNTAX_CHOICES = list(SYNTAX_TO_M.keys())

# ---------------------------------------------------------------------------
# AT&T syntax patterns
# ---------------------------------------------------------------------------

_XORPS_XMM0  = re.compile(r"xorps\s+%xmm0,%xmm0")
_MOV_XMM0    = re.compile(r"movs[sd]\s+.+,%xmm0")
_IMM_MOV_EAX = re.compile(r"mov\w*\s+\$(?P<imm>0x[0-9a-f]+|-?[0-9]+),%(?:e|r)ax")
_XOR_EAX     = re.compile(r"xorl?\s+%(?:e|r)ax,%(?:e|r)ax")
_SETCC_AL    = re.compile(r"\bset\w{1,3}\s+%al\b")
_MOVZBL_EAX  = re.compile(r"movzbl?\s+%al,%(?:e|r)ax")
_MOVZBQ_RAX  = re.compile(r"movzbq?\s+%al,%(?:e|r)ax")
_MOVZWL_EAX  = re.compile(r"movzwl?\s+%ax,%eax")
_LEA_RAX     = re.compile(r"\blea\w*\b.+,%rax\b")
_WRITE_RAX   = re.compile(r"(?:,|^\s+\w+\s+\S+,)\s*%rax\b")
_WRITE_EAX   = re.compile(r"(?:,|^\s+\w+\s+\S+,)\s*%eax\b")
_WRITE_AL    = re.compile(r"(?:,|^\s+\w+\s+\S+,)\s*%al\b")
_STORE_MEM   = re.compile(r"\bmov\w*\s+%\w+,\s*\S*\(")
_FUNC_HDR    = re.compile(r"^([0-9a-f]+) <(.+?)(?:@@\w+)?>:\s*$")
_INSN_LINE   = re.compile(r"^\s+([0-9a-f]+):\s+(.+)$")

_RTTI_PREFIXES = ("typeinfo name for ", "typeinfo for ", "vtable for ")
_TYPE_PREFIXES = re.compile(
    r"^(?:(?:const|volatile|unsigned|signed|long|short|bool|void|int|"
    r"float|double|char|auto|__int\d+)\s+)+"
)


# ---------------------------------------------------------------------------
# Return classification
# ---------------------------------------------------------------------------

def _classify_return(insns: list[str]) -> tuple[str, str | None, str | None]:
    for insn in reversed(insns):
        insn = insn.strip()
        if _XORPS_XMM0.search(insn):                        return "xmm0",    "0.0", "float"
        if _MOV_XMM0.search(insn):                          return "xmm0",    None,  "float"
        if _MOVZBL_EAX.search(insn) or _MOVZBQ_RAX.search(insn): return "eax", None, "bool"
        if _MOVZWL_EAX.search(insn):                        return "eax",     None,  "short"
        if _SETCC_AL.search(insn):                          return "al",      None,  "bool"
        if _LEA_RAX.search(insn):                           return "rax",     None,  "pointer"
        m = _IMM_MOV_EAX.search(insn)
        if m:
            raw = m.group("imm")
            try:
                ival = int(raw, 16) if raw.startswith("0x") else int(raw)
                if ival == 0xFFFFFFFF:            raw = "0xFFFFFFFF (-1)"
                elif ival == 0xFFFFFFFFFFFFFFFF:  raw = "0xFFFFFFFFFFFFFFFF (-1)"
            except ValueError:
                pass
            return "eax/rax", raw, None
        if _XOR_EAX.search(insn):    return "eax/rax", "0",  None
        if _WRITE_AL.search(insn):   return "al",      None, "bool"
        if _WRITE_EAX.search(insn):  return "eax",     None, None
        if _WRITE_RAX.search(insn):  return "rax",     None, None
        if re.search(r"\bcallq?\b", insn) or _STORE_MEM.search(insn):
            break
    return "unknown", None, None


def _infer_return_type(reg: str, raw: str | None, hint: str | None, demangled: str) -> str:
    lo = demangled.lower()
    if re.search(r"\boperator new",    demangled): return "void*"
    if re.search(r"\boperator delete", demangled): return "void"
    if re.search(r"\b(\w+)::\1\s*\(",  demangled): return "void"
    if re.search(r"::~\w+\s*\(",       demangled): return "void"
    if hint == "float" or reg == "xmm0":           return "float / double"
    if hint == "bool":                             return "bool"
    if hint == "pointer":
        if any(k in lo for k in ("alloc","create","get","find","begin","end","data")):
            return "T* (pointer)"
        return "void* / T* (pointer)"
    if hint == "short":                            return "uint16 / short"
    if reg in ("eax/rax", "rax", "eax", "al"):
        if raw in ("0", "0.0"):
            if any(k in lo for k in ("is","has","can","should","check","equal","valid")):
                return "bool (false)"
            return "int / bool / pointer (0 / null)"
        if raw is not None:
            try:
                v = int(raw.split()[0], 16) if raw.startswith("0x") else int(raw.split()[0])
                return "bool / int" if v in (0, 1) else "int"
            except ValueError:
                return "int"
        if reg == "rax": return "void* / int64 (pointer or 64-bit int)"
        if reg == "al":  return "bool / uint8 (byte)"
        return "int / pointer (variable)"
    return "void / struct (return in memory)"


# ---------------------------------------------------------------------------
# Path parsing — template-aware :: splitting
# ---------------------------------------------------------------------------

def _split_qualified(name: str) -> list[str]:
    """Split a C++ qualified name on :: while respecting template angle brackets."""
    parts, current, depth = [], [], 0
    i = 0
    while i < len(name):
        c = name[i]
        if c == "<":
            depth += 1
            current.append(c)
        elif c == ">":
            depth -= 1
            current.append(c)
        elif c == ":" and i + 1 < len(name) and name[i + 1] == ":" and depth == 0:
            parts.append("".join(current))
            current = []
            i += 2
            continue
        else:
            current.append(c)
        i += 1
    if current:
        parts.append("".join(current))
    return [p for p in parts if p]


def _parse_path(demangled: str) -> tuple[list[str], str]:
    """
    Return (path_components, method_name) from a demangled C++ symbol.

    "mkvparser::Chapters::Display::GetCountry() const"
      → (["mkvparser", "Chapters", "Display"], "GetCountry")

    "SDL_SetModState"
      → ([], "SDL_SetModState")
    """
    name = demangled.strip()

    # Strip RTTI prefixes
    for p in _RTTI_PREFIXES:
        if name.startswith(p):
            name = name[len(p):]
            break

    # Strip trailing cv-qualifiers and params
    paren = name.find("(")
    if paren != -1:
        name = name[:paren]
    name = re.sub(r"\s+(const|volatile|override|final)\s*$", "", name).strip()

    # Strip leading return-type tokens
    name = _TYPE_PREFIXES.sub("", name).strip()

    parts = _split_qualified(name)
    if len(parts) <= 1:
        return [], parts[0] if parts else demangled
    return parts[:-1], parts[-1]


def _sanitize(name: str) -> str:
    """Make a name safe for use as a filesystem directory component."""
    return re.sub(r"[^a-zA-Z0-9_]", "_", name).strip("_")[:64] or "_"


# ---------------------------------------------------------------------------
# Main extraction
# ---------------------------------------------------------------------------

def _run_objdump(so_path: Path, extra_flags: list[str]) -> str:
    return subprocess.run(
        ["objdump", "-d", "--no-show-raw-insn"] + extra_flags + [str(so_path)],
        capture_output=True, text=True,
    ).stdout


def _parse_blocks(
    raw: str, func_addr_set: set[int]
) -> dict[int, list[tuple[str, str]] | None]:
    blocks: dict[int, list[tuple[str, str]] | None] = {}
    cur_addr: int | None = None
    for line in raw.splitlines():
        m = _FUNC_HDR.match(line)
        if m:
            cur_addr = int(m.group(1), 16)
            blocks[cur_addr] = [] if cur_addr in func_addr_set else None  # type: ignore
            continue
        if cur_addr is not None and blocks.get(cur_addr) is not None:
            mi = _INSN_LINE.match(line)
            if mi:
                blocks[cur_addr].append((mi.group(1), mi.group(2).rstrip()))  # type: ignore
    return blocks


def extract(so_path: str | Path, exports: list[dict], syntax: str = "att") -> list[dict]:
    """
    Run objdump, analyse return patterns for every exported function.
    Analysis always uses AT&T syntax; display instructions use `syntax`.
    Returns a list of dicts, one per function symbol.
    """
    so_path = Path(so_path)

    func_addr_set = {
        int(s["addr"], 16)
        for s in exports
        if s["type"] in ("STT_FUNC", "STT_NOTYPE") and int(s["addr"], 16)
    }

    # AT&T pass — always used for return-type analysis
    att_blocks = _parse_blocks(_run_objdump(so_path, []), func_addr_set)

    # Display pass — second objdump only when a different syntax is requested
    if syntax == "att":
        display_blocks = att_blocks
    else:
        m_flags = SYNTAX_TO_M.get(syntax, ["-M", syntax])
        display_blocks = _parse_blocks(_run_objdump(so_path, m_flags), func_addr_set)

    addr_analysis: dict[int, dict] = {}
    for addr, insns in att_blocks.items():
        if insns is None:
            continue
        raw_rets: list[str] = []
        reg_ctr:  Counter   = Counter()
        hint_ctr: Counter   = Counter()

        for i, (iaddr, insn) in enumerate(insns):
            if re.search(r"\bret\b", insn):
                window = [t for _, t in insns[max(0, i - _WINDOW): i]]
                reg, raw_val, hint = _classify_return(window)
                reg_ctr[reg] += 1
                if hint:
                    hint_ctr[hint] += 1
                if raw_val is not None:
                    raw_rets.append(raw_val)

        known    = {r: c for r, c in reg_ctr.items() if r != "unknown"}
        dom_reg  = max(known, key=known.__getitem__) if known else "unknown"
        dom_hint = hint_ctr.most_common(1)[0][0] if hint_ctr else None

        display_insns = display_blocks.get(addr) or []

        addr_analysis[addr] = {
            "return_reg":   dom_reg,
            "return_hint":  dom_hint,
            "raw_returns":  sorted(set(raw_rets)),
            "insn_count":   len(insns),
            "instructions": [{"addr": f"0x{a}", "insn": t} for a, t in display_insns],
        }

    results = []
    for sym in exports:
        addr = int(sym["addr"], 16)
        if not addr:
            continue
        a    = addr_analysis.get(addr, {})
        reg  = a.get("return_reg",  "unknown")
        hint = a.get("return_hint", None)
        raws = a.get("raw_returns", [])
        dem  = sym["demangled"]

        path, method = _parse_path(dem)

        results.append({
            "addr":              sym["addr"],
            "size":              sym["size"],
            "raw":               sym["raw"],
            "demangled":         dem,
            "path":              path,
            "method_name":       method,
            "instruction_count": a.get("insn_count", 0),
            "return_reg":        reg,
            "return_hint":       hint,
            "return_type":       _infer_return_type(reg, raws[0] if raws else None, hint, dem),
            "raw_returns":       raws,
            "instructions":      a.get("instructions", []),
        })

    _resolve_inline_labels(results)
    return results


# ---------------------------------------------------------------------------
# Inline label demangling
# ---------------------------------------------------------------------------

# Matches objdump's inline annotations: <mangled_name[@plt|@@Base][+offset]>
# Group 1 = mangled name, group 2 = optional suffix
_INLINE_LABEL = re.compile(r"<(_Z[^>@+]+)([@+][^>]*)?>")


def _resolve_inline_labels(results: list[dict]) -> None:
    """
    Demangle C++ names embedded in objdump's call/jump target annotations.
    Mutates the instructions list in each result dict in-place.
    One batch c++filt call covers all unique names across all functions.
    """
    # Collect unique mangled names
    names: set[str] = set()
    for fn in results:
        for entry in fn.get("instructions", []):
            for m in _INLINE_LABEL.finditer(entry["insn"]):
                names.add(m.group(1))

    if not names:
        return

    name_list = sorted(names)
    out = subprocess.run(["c++filt"] + name_list, capture_output=True, text=True)
    dem_map = dict(zip(name_list, out.stdout.splitlines()))

    def _sub(insn: str) -> str:
        def repl(m: re.Match) -> str:
            demangled = dem_map.get(m.group(1), m.group(1))
            suffix    = m.group(2) or ""
            return f"<{demangled}{suffix}>"
        return _INLINE_LABEL.sub(repl, insn)

    for fn in results:
        fn["instructions"] = [
            {"addr": e["addr"], "insn": _sub(e["insn"])}
            for e in fn.get("instructions", [])
        ]
