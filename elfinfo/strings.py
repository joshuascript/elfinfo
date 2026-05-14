from elftools.elf.elffile import ELFFile

_MIN_LEN = 5
_SECTIONS = (".rodata", ".data.rel.ro")


def extract(elf: ELFFile) -> dict:
    """Printable strings from .rodata and other allocated read-only sections."""
    out = {}
    for name in _SECTIONS:
        sec = elf.get_section_by_name(name)
        if sec is None:
            continue
        out[name] = _extract_strings(sec["sh_addr"], sec.data())
    return out


def _extract_strings(base_addr: int, data: bytes) -> list[dict]:
    results = []
    start = None

    for i, b in enumerate(data):
        if 0x20 <= b <= 0x7E:
            if start is None:
                start = i
        else:
            if start is not None:
                length = i - start
                if length >= _MIN_LEN:
                    s = data[start:i].decode("ascii", errors="replace")
                    results.append({
                        "addr":   hex(base_addr + start),
                        "length": length,
                        "value":  s,
                    })
                start = None

    return results
