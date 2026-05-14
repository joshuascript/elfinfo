from pathlib import Path
from elftools.elf.elffile import ELFFile

from . import identity, layout, symbols, dynamic, relocations, versioning, cpp, strings


class ELFParser:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._file = open(self.path, "rb")
        self.elf = ELFFile(self._file)

    def close(self):
        self._file.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def extract(self) -> dict:
        return {
            "meta":        self._meta(),
            "identity":    identity.extract(self.elf),
            "layout":      layout.extract(self.elf),
            "symbols":     symbols.extract(self.elf),
            "dynamic":     dynamic.extract(self.elf),
            "relocations": relocations.extract(self.elf),
            "versioning":  versioning.extract(self.elf),
            "cpp":         cpp.extract(self.elf),
            "strings":     strings.extract(self.elf),
        }

    def _meta(self) -> dict:
        import hashlib
        data = self.path.read_bytes()
        return {
            "file":         self.path.name,
            "size_bytes":   self.path.stat().st_size,
            "sha256":       hashlib.sha256(data).hexdigest(),
        }
