from elftools.elf.elffile import ELFFile


def extract(elf: ELFFile) -> dict:
    """Dynamic section tags: NEEDED, SONAME, RUNPATH, INIT/FINI, INIT_ARRAY/FINI_ARRAY."""
    sec = elf.get_section_by_name(".dynamic")
    if sec is None:
        return {}

    needed = []
    result = {}

    for tag in sec.iter_tags():
        t = tag.entry.d_tag
        if t == "DT_NEEDED":
            needed.append(tag.needed)
        elif t == "DT_SONAME":
            result["soname"] = tag.soname
        elif t == "DT_RUNPATH":
            result["runpath"] = tag.runpath
        elif t == "DT_RPATH":
            result["rpath"] = tag.rpath
        elif t == "DT_INIT":
            result["init"] = hex(tag.entry.d_val)
        elif t == "DT_FINI":
            result["fini"] = hex(tag.entry.d_val)
        elif t == "DT_INIT_ARRAY":
            result["init_array_addr"] = hex(tag.entry.d_val)
        elif t == "DT_INIT_ARRAYSZ":
            result["init_array_count"] = tag.entry.d_val // elf.elfclass // 8
        elif t == "DT_FINI_ARRAY":
            result["fini_array_addr"] = hex(tag.entry.d_val)
        elif t == "DT_FINI_ARRAYSZ":
            result["fini_array_count"] = tag.entry.d_val // elf.elfclass // 8
        elif t == "DT_FLAGS":
            result["flags"] = hex(tag.entry.d_val)
        elif t == "DT_FLAGS_1":
            result["flags_1"] = hex(tag.entry.d_val)

    result["needed"] = needed
    return result
