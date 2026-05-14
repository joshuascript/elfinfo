from elftools.elf.elffile import ELFFile


def extract(elf: ELFFile) -> dict:
    """Program headers (segments) and section headers."""
    return {
        "segments": _segments(elf),
        "sections": _sections(elf),
    }


def _segments(elf: ELFFile) -> list[dict]:
    out = []
    for seg in elf.iter_segments():
        h = seg.header
        out.append({
            "type":     h["p_type"],
            "offset":   hex(h["p_offset"]),
            "vaddr":    hex(h["p_vaddr"]),
            "paddr":    hex(h["p_paddr"]),
            "filesz":   h["p_filesz"],
            "memsz":    h["p_memsz"],
            "flags":    _seg_flags(h["p_flags"]),
            "align":    h["p_align"],
        })
    return out


def _sections(elf: ELFFile) -> list[dict]:
    out = []
    for sec in elf.iter_sections():
        h = sec.header
        out.append({
            "name":     sec.name,
            "type":     h["sh_type"],
            "offset":   hex(h["sh_offset"]),
            "addr":     hex(h["sh_addr"]),
            "size":     h["sh_size"],
            "entsize":  h["sh_entsize"],
            "flags":    _sec_flags(h["sh_flags"]),
            "link":     h["sh_link"],
            "info":     h["sh_info"],
            "align":    h["sh_addralign"],
        })
    return out


def _seg_flags(flags: int) -> str:
    return "".join([
        "R" if flags & 4 else "-",
        "W" if flags & 2 else "-",
        "X" if flags & 1 else "-",
    ])


def _sec_flags(flags: int) -> list[str]:
    mapping = {
        0x1:        "SHF_WRITE",
        0x2:        "SHF_ALLOC",
        0x4:        "SHF_EXECINSTR",
        0x10:       "SHF_MERGE",
        0x20:       "SHF_STRINGS",
        0x40:       "SHF_INFO_LINK",
        0x80:       "SHF_LINK_ORDER",
        0x400:      "SHF_GROUP",
        0x800:      "SHF_TLS",
        0x8000000:  "SHF_EXCLUDE",
    }
    return [label for mask, label in mapping.items() if flags & mask]
