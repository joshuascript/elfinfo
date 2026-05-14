"""
Quick terminal summary of an ELF binary.
No files written — output only.
"""
from pathlib import Path
from elftools.elf.elffile import ELFFile


def info(so_path: str | Path) -> None:
    so_path = Path(so_path)
    if not so_path.exists():
        import sys
        print(f"error: {so_path} not found", file=sys.stderr)
        sys.exit(1)

    size = so_path.stat().st_size

    with open(so_path, "rb") as f:
        elf = ELFFile(f)
        h   = elf.header

        build_id = _build_id(elf)

        exports, imports = 0, 0
        dynsym = elf.get_section_by_name(".dynsym")
        if dynsym:
            for sym in dynsym.iter_symbols():
                if not sym["st_value"] and sym["st_shndx"] == "SHN_UNDEF":
                    imports += 1
                elif sym["st_value"]:
                    exports += 1

        needed = []
        dynamic = elf.get_section_by_name(".dynamic")
        if dynamic:
            for tag in dynamic.iter_tags():
                if tag.entry.d_tag == "DT_NEEDED":
                    needed.append(tag.needed)

        sections  = elf.num_sections()
        segments  = elf.num_segments()
        has_debug = elf.has_dwarf_info()

        vtables  = 0
        typeinfo = 0
        if dynsym:
            for sym in dynsym.iter_symbols():
                if sym.name.startswith("_ZTV"):
                    vtables += 1
                elif sym.name.startswith("_ZTI"):
                    typeinfo += 1

    print(f"# {so_path.name}\n")
    _row("Path",       str(so_path))
    _row("Size",       f"{size:,} bytes  ({size / 1_048_576:.1f} MB)")
    _row("Class",      f"ELF{elf.elfclass}")
    _row("Endian",     "little" if elf.little_endian else "big")
    _row("Type",       h["e_type"])
    _row("Machine",    h["e_machine"])
    _row("Entry",      hex(h["e_entry"]))
    _row("Build ID",   build_id or "(none)")
    _row("Debug info", "yes" if has_debug else "no (stripped)")
    print()
    _row("Sections",   sections)
    _row("Segments",   segments)
    _row("Exports",    exports)
    _row("Imports",    imports)
    _row("Vtables",    vtables)
    _row("Typeinfo",   typeinfo)
    if needed:
        print()
        print("  Dependencies:")
        for lib in needed:
            print(f"    {lib}")


def _row(label: str, value) -> None:
    print(f"  {label:<14} {value}")


def _build_id(elf: ELFFile) -> str | None:
    sec = elf.get_section_by_name(".note.gnu.build-id")
    if sec is None:
        return None
    for note in sec.iter_notes():
        if note.n_type == "NT_GNU_BUILD_ID":
            return note.n_desc
    return None
