"""
Disassemble a single function by RVA and print to the terminal.

Uses objdump --start-address / --stop-address for fast targeted output
instead of disassembling the whole binary.
"""
import bisect
import re
import subprocess
import sys
from pathlib import Path

from elftools.elf.elffile import ELFFile
from elfinfo.resolve import _build_intervals, _build_sym_map, _name_at
from elfinfo.disasm  import SYNTAX_TO_M, _INLINE_LABEL


def show(
    so_path:   str | Path,
    rva:       int,
    load_base: int = 0,
    syntax:    str = "att",
) -> None:
    so_path = Path(so_path)
    rva     = rva - load_base

    with open(so_path, "rb") as f:
        elf       = ELFFile(f)
        intervals = _build_intervals(elf)
        sym_map   = _build_sym_map(elf)

    starts = [s for s, _ in intervals]
    idx    = bisect.bisect_right(starts, rva) - 1

    if idx >= 0 and intervals[idx][0] <= rva < intervals[idx][1]:
        fn_start = intervals[idx][0]
        fn_end   = intervals[idx][1]
        exact    = (rva == fn_start)
    else:
        # No interval found — show a 256-byte window from rva
        fn_start = rva
        fn_end   = rva + 256
        exact    = True

    name   = _name_at(fn_start, sym_map)
    offset = rva - fn_start

    m_flags = SYNTAX_TO_M.get(syntax, ["-M", syntax]) if syntax != "att" else []

    raw = subprocess.run(
        ["objdump", "-d", "--no-show-raw-insn",
         f"--start-address=0x{fn_start:x}",
         f"--stop-address=0x{fn_end:x}"] + m_flags + [str(so_path)],
        capture_output=True, text=True,
    ).stdout

    # Collect unique mangled names from labels and demangle in one batch
    mangled: set[str] = set()
    for line in raw.splitlines():
        for m in _INLINE_LABEL.finditer(line):
            mangled.add(m.group(1))
    dem_map: dict[str, str] = {}
    if mangled:
        name_list = sorted(mangled)
        out = subprocess.run(["c++filt"] + name_list, capture_output=True, text=True)
        dem_map = dict(zip(name_list, out.stdout.splitlines()))

    def _sub(line: str) -> str:
        def repl(m: re.Match) -> str:
            return f"<{dem_map.get(m.group(1), m.group(1))}{m.group(2) or ''}>"
        return _INLINE_LABEL.sub(repl, line)

    # Print header
    print(f"\n# {name}")
    if offset:
        print(f"  (showing from function start; requested offset +0x{offset:x})")
    print(f"\n  RVA    : 0x{fn_start:x}")
    print(f"  Size   : {fn_end - fn_start} bytes")
    print(f"  Syntax : {syntax}")
    print()

    # Print instruction lines only
    insn_re = re.compile(r"^\s+[0-9a-f]+:")
    func_re = re.compile(r"^[0-9a-f]+ <")
    for line in raw.splitlines():
        if func_re.match(line) or insn_re.match(line):
            print(_sub(line))
