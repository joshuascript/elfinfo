from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from elftools.elf.descriptions import describe_reloc_type


def extract(elf: ELFFile) -> dict:
    """Relocation entries from .rela.plt and .rela.dyn."""
    return {
        "rela_plt": _parse(elf, ".rela.plt"),
        "rela_dyn": _parse(elf, ".rela.dyn"),
    }


def _parse(elf: ELFFile, section_name: str) -> list[dict]:
    sec = elf.get_section_by_name(section_name)
    if sec is None or not isinstance(sec, RelocationSection):
        return []

    symtab = elf.get_section(sec["sh_link"])

    out = []
    for rel in sec.iter_relocations():
        sym_idx = rel["r_info_sym"]
        sym = symtab.get_symbol(sym_idx) if sym_idx else None
        out.append({
            "offset": hex(rel["r_offset"]),
            "type":   describe_reloc_type(rel["r_info_type"], elf),
            "addend": rel["r_addend"],
            "symbol": sym.name if sym else None,
        })
    return out
