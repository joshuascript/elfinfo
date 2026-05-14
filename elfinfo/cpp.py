import subprocess
from elftools.elf.elffile import ELFFile
from elftools.dwarf.callframe import FDE


def extract(elf: ELFFile) -> dict:
    """C++ specifics: vtables, RTTI typeinfo, .eh_frame function boundaries."""
    return {
        "vtables":    _vtables(elf),
        "typeinfo":   _typeinfo(elf),
        "eh_frame":   _eh_frame(elf),
    }


def _vtables(elf: ELFFile) -> list[dict]:
    dynsym = elf.get_section_by_name(".dynsym")
    if dynsym is None:
        return []

    syms = [s for s in dynsym.iter_symbols() if s.name.startswith("_ZTV")]
    demangled = _demangle([s.name for s in syms])

    out = []
    for sym, dem in zip(syms, demangled):
        out.append({
            "addr":      hex(sym["st_value"]),
            "size":      sym["st_size"],
            "defined":   sym["st_shndx"] != "SHN_UNDEF",
            "raw":       sym.name,
            "demangled": dem,
        })
    return out


def _typeinfo(elf: ELFFile) -> list[dict]:
    dynsym = elf.get_section_by_name(".dynsym")
    if dynsym is None:
        return []

    ti_syms = [s for s in dynsym.iter_symbols() if s.name.startswith("_ZTI")]
    ts_syms = [s for s in dynsym.iter_symbols() if s.name.startswith("_ZTS")]

    name_map = {s.name[4:]: s.name for s in ts_syms}  # strip _ZTS prefix for lookup

    all_syms = ti_syms
    demangled = _demangle([s.name for s in all_syms])

    out = []
    for sym, dem in zip(all_syms, demangled):
        out.append({
            "addr":      hex(sym["st_value"]),
            "defined":   sym["st_shndx"] != "SHN_UNDEF",
            "raw":       sym.name,
            "demangled": dem,
            "has_name_sym": sym.name[4:] in name_map,
        })
    return out


def _eh_frame(elf: ELFFile) -> list[dict]:
    if not elf.has_dwarf_info():
        return []

    dwarf = elf.get_dwarf_info(relocate_dwarf_sections=False)
    if not dwarf.has_EH_CFI():
        return []

    out = []
    for entry in dwarf.EH_CFI_entries():
        if not isinstance(entry, FDE):
            continue
        start = entry.header.initial_location
        size  = entry.header.address_range
        if size == 0:
            continue
        out.append({
            "addr": hex(start),
            "size": size,
        })
    return out


def _demangle(names: list[str]) -> list[str]:
    if not names:
        return []
    result = subprocess.run(["c++filt"] + names, capture_output=True, text=True)
    return result.stdout.splitlines()
