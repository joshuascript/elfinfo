"""
Vtable analysis: given an RVA, find every vtable that contains that function
pointer, identify the owning class via RTTI, and report the slot index with
surrounding context.
"""
import struct
import subprocess
from pathlib import Path

from elftools.elf.elffile import ELFFile


_ENDBR64 = b"\xf3\x0f\x1e\xfa"


# ---------------------------------------------------------------------------
# Section helpers (via pyelftools)
# ---------------------------------------------------------------------------

def _text_bounds(elf: ELFFile) -> tuple[int, int]:
    sec = elf.get_section_by_name(".text")
    if sec is None:
        return 0, 0
    vma = sec["sh_addr"]
    return vma, vma + sec["sh_size"]


def _symbol_map(elf: ELFFile) -> list[tuple[int, str]]:
    """Return [(addr, raw_name)] for all defined exported functions."""
    dynsym = elf.get_section_by_name(".dynsym")
    if dynsym is None:
        return []
    out = []
    for sym in dynsym.iter_symbols():
        if sym["st_shndx"] != "SHN_UNDEF" and sym["st_value"]:
            out.append((sym["st_value"], sym.name))
    return sorted(out)


# ---------------------------------------------------------------------------
# Binary scanning
# ---------------------------------------------------------------------------

def _find_vtable_refs(data: bytes, func_rva: int) -> list[int]:
    """Return all file offsets where func_rva appears as a 64-bit LE pointer."""
    needle = struct.pack("<Q", func_rva)
    offsets, pos = [], 0
    while True:
        idx = data.find(needle, pos)
        if idx == -1:
            break
        offsets.append(idx)
        pos = idx + 1
    return offsets


def _find_vtable_start(
    data: bytes, ref_offset: int, text_start: int, text_end: int
) -> int | None:
    """
    Walk backwards from ref_offset to find the vtable header:
      [offset_to_top][typeinfo_ptr][func_ptr_0][func_ptr_1]...
    Returns file offset of func_ptr_0, or None if not found within 2KB.
    """
    pos = ref_offset - 8
    while pos >= ref_offset - 2048 and pos >= 16:
        val = struct.unpack_from("<Q", data, pos)[0]
        if not (text_start <= val < text_end):
            is_offset_to_top = (val == 0 or val > 0xFFFF_FFFF_FFFF_0000 or val < 0x10000)
            if is_offset_to_top and pos + 8 < len(data):
                typeinfo_candidate = struct.unpack_from("<Q", data, pos + 8)[0]
                if typeinfo_candidate != 0 and not (text_start <= typeinfo_candidate < text_end):
                    return pos + 16
        pos -= 8
    return None


def _read_class_name(data: bytes, typeinfo_ptr_offset: int) -> str:
    """
    Read the mangled class name from the typeinfo object at the given file offset.
    Itanium ABI typeinfo layout:
      [0]  vtable ptr of std::type_info subclass  (8 bytes)
      [8]  pointer to null-terminated mangled name (8 bytes)
    """
    if typeinfo_ptr_offset + 8 > len(data):
        return "<unreadable typeinfo>"

    typeinfo_addr = struct.unpack_from("<Q", data, typeinfo_ptr_offset)[0]
    if typeinfo_addr == 0 or typeinfo_addr + 16 > len(data):
        return "<null typeinfo>"

    name_ptr = struct.unpack_from("<Q", data, typeinfo_addr + 8)[0]
    if name_ptr == 0 or name_ptr >= len(data):
        return "<unreadable name ptr>"

    try:
        end = data.index(b"\x00", name_ptr)
        mangled = data[name_ptr:end].decode("ascii", errors="replace")
    except (ValueError, UnicodeDecodeError):
        return "<unreadable mangled name>"

    to_demangle = ("_ZN" + mangled + "E") if mangled and mangled[0].isdigit() else mangled
    result = subprocess.run(["c++filt", to_demangle], capture_output=True, text=True)
    demangled = result.stdout.strip()
    return demangled if demangled and demangled != to_demangle else mangled


def _find_function_start(data: bytes, rva: int, max_walk: int = 256) -> int:
    """Walk back from rva looking for an endbr64 (CET function entry). Falls back to rva."""
    for delta in range(0, max_walk):
        candidate = rva - delta
        if candidate < 0:
            break
        if data[candidate:candidate + 4] == _ENDBR64:
            return candidate
    return rva


def _rva_to_symbol(rva: int, sym_map: list[tuple[int, str]]) -> str:
    """Find the closest exported symbol at or before rva."""
    best_addr, best_name = 0, ""
    for addr, name in sym_map:
        if addr <= rva and addr > best_addr:
            best_addr, best_name = addr, name
    if best_name:
        offset = rva - best_addr
        demangled = subprocess.run(
            ["c++filt", best_name], capture_output=True, text=True
        ).stdout.strip()
        label = demangled or best_name
        return f"{label}+0x{offset:x}" if offset else label
    return f"0x{rva:x}"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyse(so_path: str | Path, func_rva: int, context_slots: int = 8) -> None:
    """
    Given a binary and a function RVA, print every vtable that contains that
    pointer, the owning class name, slot index, and a context window of slots.
    """
    so_path = Path(so_path)
    data = so_path.read_bytes()

    with open(so_path, "rb") as f:
        elf = ELFFile(f)
        text_start, text_end = _text_bounds(elf)
        sym_map = _symbol_map(elf)

    refs = _find_vtable_refs(data, func_rva)

    if not refs:
        fn_start = _find_function_start(data, func_rva)
        if fn_start != func_rva:
            print(
                f"RVA 0x{func_rva:x} not in any vtable; "
                f"retrying with function start 0x{fn_start:x} "
                f"(endbr64 at -{func_rva - fn_start} bytes)\n"
            )
            func_rva = fn_start
            refs = _find_vtable_refs(data, func_rva)

    if not refs:
        print(f"No vtable references to RVA 0x{func_rva:x} found in {so_path.name}.")
        return

    print(f"# vtable: 0x{func_rva:x} in {so_path.name}\n")
    print(f"Found {len(refs)} reference(s).\n")

    for ref_idx, ref_off in enumerate(refs):
        vtable_fn_start = _find_vtable_start(data, ref_off, text_start, text_end)

        if vtable_fn_start is None:
            print(f"## Reference {ref_idx + 1} @ file offset 0x{ref_off:x}")
            print("  Could not locate vtable header.\n")
            continue

        typeinfo_ptr_offset = vtable_fn_start - 8
        class_name  = _read_class_name(data, typeinfo_ptr_offset)
        slot_index  = (ref_off - vtable_fn_start) // 8

        print(f"## Reference {ref_idx + 1}")
        print(f"  Class     : {class_name}")
        print(f"  Slot index: {slot_index}  (0-based, from first function pointer)")
        print(f"  File offset of slot : 0x{ref_off:x}")
        print(f"  Vtable fn-ptr start : 0x{vtable_fn_start:x}\n")

        ctx_start = max(vtable_fn_start, ref_off - context_slots * 8)
        ctx_end   = min(len(data) - 8, ref_off + context_slots * 8 + 8)

        print(f"  {'Slot':>4}  {'File offset':>14}  {'RVA':>18}  Symbol")
        print(f"  {'----':>4}  {'------------':>14}  {'------------------':>18}  ------")

        for slot_off in range(ctx_start, ctx_end, 8):
            val    = struct.unpack_from("<Q", data, slot_off)[0]
            slot_n = (slot_off - vtable_fn_start) // 8
            marker = "  <-- target" if slot_off == ref_off else ""
            sym    = _rva_to_symbol(val, sym_map) if (text_start <= val < text_end) else f"0x{val:x}"
            print(f"  {slot_n:>4}  0x{slot_off:014x}  0x{val:016x}  {sym}{marker}")

        print()
