"""
Resolve runtime addresses or RVAs to function names.

Builds an interval index from .eh_frame FDE entries (survives stripping),
augmented with .dynsym size fields, then bisects to find the enclosing
function for each address.

Supports piped GDB backtraces via --stdin:
  (gdb) bt | elfinfo resolve lib.so - --load-base 0x7f...
"""
import bisect
import json
import re
import sys
import subprocess
from pathlib import Path

from elftools.elf.elffile import ELFFile
from elftools.dwarf.callframe import FDE

# Extracts the first 0x... address from a line (handles GDB bt output)
_ADDR_RE = re.compile(r"0x[0-9a-fA-F]+")


def _build_intervals(elf: ELFFile) -> list[tuple[int, int]]:
    """Sorted (start, end) pairs for every known function boundary."""
    seen: set[tuple[int, int]] = set()

    if elf.has_dwarf_info():
        dwarf = elf.get_dwarf_info(relocate_dwarf_sections=False)
        if dwarf.has_EH_CFI():
            for entry in dwarf.EH_CFI_entries():
                if isinstance(entry, FDE):
                    start = entry.header.initial_location
                    size  = entry.header.address_range
                    if size > 0:
                        seen.add((start, start + size))

    dynsym = elf.get_section_by_name(".dynsym")
    if dynsym:
        for sym in dynsym.iter_symbols():
            v, s = sym["st_value"], sym["st_size"]
            if v and s and sym["st_shndx"] != "SHN_UNDEF":
                seen.add((v, v + s))

    return sorted(seen)


def _build_sym_map(elf: ELFFile) -> list[tuple[int, str]]:
    """Sorted (addr, demangled_name) from .dynsym for nearest-symbol lookup."""
    dynsym = elf.get_section_by_name(".dynsym")
    if not dynsym:
        return []
    syms = [
        (sym["st_value"], sym.name)
        for sym in dynsym.iter_symbols()
        if sym["st_value"] and sym["st_shndx"] != "SHN_UNDEF"
    ]
    if not syms:
        return []
    addrs, raws = zip(*syms)
    result = subprocess.run(["c++filt"] + list(raws), capture_output=True, text=True)
    demangled = result.stdout.splitlines()
    return sorted(zip(addrs, demangled))


def _name_at(rva: int, sym_map: list[tuple[int, str]]) -> str:
    """Return the demangled name of the symbol at or before rva."""
    if not sym_map:
        return f"0x{rva:x}"
    addrs = [a for a, _ in sym_map]
    idx = bisect.bisect_right(addrs, rva) - 1
    if idx >= 0:
        addr, name = sym_map[idx]
        offset = rva - addr
        return f"{name} + 0x{offset:x}" if offset else name
    return f"0x{rva:x}"


def _parse_stdin_addresses() -> list[str]:
    """
    Read hex addresses from stdin, one per line.
    Handles plain hex strings and GDB bt lines like:
      #0  0x00007f1a2146a790 in mkvparser::BlockGroup::Parse ()
    """
    addrs = []
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        m = _ADDR_RE.search(line)
        if m:
            addrs.append(m.group(0))
    return addrs


def _resolve_one(
    runtime: int,
    load_base: int,
    starts: list[int],
    intervals: list[tuple[int, int]],
    sym_map: list[tuple[int, str]],
) -> dict:
    rva = runtime - load_base
    idx = bisect.bisect_right(starts, rva) - 1

    if idx >= 0 and intervals[idx][0] <= rva < intervals[idx][1]:
        fn_start = intervals[idx][0]
        offset   = rva - fn_start
        name     = _name_at(fn_start, sym_map)
        return {"addr": f"0x{runtime:x}", "name": name, "offset": offset, "found": True}
    else:
        name = _name_at(rva, sym_map)
        return {"addr": f"0x{runtime:x}", "name": name, "offset": 0, "found": False}


def resolve(
    so_path:    str | Path,
    addresses:  list[str],
    load_base:  int = 0,
    from_stdin: bool = False,
    as_json:    bool = False,
) -> None:
    """
    Print a resolved name for each address.  Addresses may be runtime VAs
    (pass load_base) or RVAs (load_base=0).

    Args:
        addresses:  List of hex strings, or ["-"] to signal stdin.
        from_stdin: Read addresses from stdin (GDB bt format supported).
        as_json:    Emit a JSON array instead of human-readable text.
    """
    so_path = Path(so_path)

    if from_stdin or addresses == ["-"]:
        addresses = _parse_stdin_addresses()
        if not addresses:
            print("error: no addresses found on stdin", file=sys.stderr)
            sys.exit(1)

    with open(so_path, "rb") as f:
        elf       = ELFFile(f)
        intervals = _build_intervals(elf)
        sym_map   = _build_sym_map(elf)

    starts = [s for s, _ in intervals]

    results = []
    for raw in addresses:
        try:
            runtime = int(raw, 16)
        except ValueError:
            results.append({"addr": raw, "name": "error: invalid hex", "offset": 0, "found": False})
            continue
        results.append(_resolve_one(runtime, load_base, starts, intervals, sym_map))

    if as_json:
        print(json.dumps(results, indent=2))
        return

    print(f"# resolve: {so_path.name}  ({len(intervals)} function intervals)\n")
    if load_base:
        print(f"  load base : 0x{load_base:x}\n")

    for r in results:
        if not r["found"]:
            print(f"  {r['addr']:<20}  (no interval) nearest: {r['name']}")
        else:
            suffix = f" + 0x{r['offset']:x}" if r["offset"] else ""
            print(f"  {r['addr']:<20}  →  {r['name']}{suffix}")
