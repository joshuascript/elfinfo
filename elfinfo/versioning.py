from elftools.elf.elffile import ELFFile


def extract(elf: ELFFile) -> dict:
    """GNU symbol versioning: .gnu.version, .gnu.version_r, .gnu.version_d, .gnu.hash."""
    return {
        "version_needs": _version_needs(elf),
        "version_defs":  _version_defs(elf),
        "gnu_hash":      _gnu_hash(elf),
    }


def _version_needs(elf: ELFFile) -> list[dict]:
    sec = elf.get_section_by_name(".gnu.version_r")
    if sec is None:
        return []

    out = []
    for verneed, auxiliaries in sec.iter_versions():
        out.append({
            "library": verneed.name,
            "versions": [
                {
                    "name":  aux.name,
                    "flags": aux.entry.vna_flags,
                    "hash":  hex(aux.entry.vna_hash),
                    "index": aux.entry.vna_other,
                }
                for aux in auxiliaries
            ],
        })
    return out


def _version_defs(elf: ELFFile) -> list[dict]:
    sec = elf.get_section_by_name(".gnu.version_d")
    if sec is None:
        return []

    out = []
    for verdef, auxiliaries in sec.iter_versions():
        names = [aux.name for aux in auxiliaries]
        out.append({
            "index": verdef.entry.vd_ndx,
            "flags": verdef.entry.vd_flags,
            "names": names,
        })
    return out


def _gnu_hash(elf: ELFFile) -> dict | None:
    sec = elf.get_section_by_name(".gnu.hash")
    if sec is None:
        return None

    p = sec.params
    return {
        "num_symbols":  sec.get_number_of_symbols(),
        "num_buckets":  p.nbuckets,
        "sym_offset":   p.symoffset,
        "bloom_size":   p.bloom_size,
        "bloom_shift":  p.bloom_shift,
    }
