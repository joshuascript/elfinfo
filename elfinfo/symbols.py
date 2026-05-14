import subprocess
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection


def extract(elf: ELFFile) -> dict:
    """Dynamic symbol table (.dynsym) split into exports and imports, demangled."""
    dynsym = elf.get_section_by_name(".dynsym")
    symtab = elf.get_section_by_name(".symtab")

    exports, imports = _parse_table(dynsym)

    if symtab:
        local_exports, local_imports = _parse_table(symtab)
        exports += local_exports
        imports += local_imports

    return {
        "has_symtab": symtab is not None,
        "exports":    exports,
        "imports":    imports,
    }


def _parse_table(sec: SymbolTableSection) -> tuple[list[dict], list[dict]]:
    if sec is None:
        return [], []

    raw_names = [sym.name for sym in sec.iter_symbols()]
    demangled = _demangle(raw_names)

    exports = []
    imports = []

    for sym, dem in zip(sec.iter_symbols(), demangled):
        if not sym.name:
            continue

        entry = {
            "addr":      hex(sym["st_value"]),
            "size":      sym["st_size"],
            "type":      sym["st_info"]["type"],
            "bind":      sym["st_info"]["bind"],
            "visibility": sym["st_other"]["visibility"],
            "raw":       sym.name,
            "demangled": dem,
        }

        if sym["st_shndx"] == "SHN_UNDEF":
            imports.append(entry)
        else:
            entry["section_index"] = sym["st_shndx"]
            exports.append(entry)

    return exports, imports


def _demangle(names: list[str]) -> list[str]:
    if not names:
        return []
    result = subprocess.run(["c++filt"] + names, capture_output=True, text=True)
    return result.stdout.splitlines()
