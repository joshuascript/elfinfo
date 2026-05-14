from elftools.elf.elffile import ELFFile


def extract(elf: ELFFile) -> dict:
    """ELF header fields: class, endianness, ABI, type, machine, build ID."""
    h = elf.header
    return {
        "class":      elf.elfclass,
        "endianness": "little" if elf.little_endian else "big",
        "abi":        h["e_ident"]["EI_OSABI"],
        "abi_version": h["e_ident"]["EI_ABIVERSION"],
        "type":       h["e_type"],
        "machine":    h["e_machine"],
        "entry":      hex(h["e_entry"]),
        "build_id":   _build_id(elf),
    }


def _build_id(elf: ELFFile) -> str | None:
    sec = elf.get_section_by_name(".note.gnu.build-id")
    if sec is None:
        return None
    for note in sec.iter_notes():
        if note.n_type == "NT_GNU_BUILD_ID":
            return note.n_desc
    return None
