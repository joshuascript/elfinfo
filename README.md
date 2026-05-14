# elfinfo

ELF binary analysis tool. Extracts structured information from `.so` and ELF binaries into JSON and a navigable Markdown file tree mirroring the binary's class hierarchy.

## Features

- **Full metadata extraction** — ELF headers, sections, segments, symbols, relocations, versioning, C++ vtables/RTTI, strings
- **Disassembly tree** — class hierarchy as a filesystem: `namespace/Class/addr__method.md`, each with raw assembly and inferred return type
- **Address resolution** — resolve GDB runtime addresses back to function names via `.eh_frame` interval index (survives stripping)
- **Single-function view** — disassemble one function by RVA directly to terminal
- **Function search** — regex search over disasm output
- **Frida integration** — auto-generate hook scripts from disasm data; repair static return type inference with runtime observations
- **Multiple syntax modes** — AT&T, Intel, ARM variants

## Install

```bash
git clone https://github.com/joshuascript/elfinfo.git
cd elfinfo
./install.sh
```

Installs into a local `.venv` and symlinks `elfinfo` into `~/.local/bin`. To uninstall:

```bash
./install.sh uninstall
```

## Requirements

- Python 3.10+
- `objdump` (binutils)
- `c++filt` (binutils)
- [pyelftools](https://github.com/eliben/pyelftools) (installed automatically)
- [Frida](https://frida.re) CLI — optional, only needed to run generated hook scripts

## Usage

```
elfinfo <subcommand> [options]
```

### Quick start

```bash
# Binary summary
elfinfo info libengine2.so

# Full metadata → JSON + Markdown
elfinfo extract libengine2.so --outdir ./out

# Disassembly → class hierarchy tree
elfinfo disasm libengine2.so --outdir ./out --syntax intel

# Disassemble one function by RVA
elfinfo show libengine2.so 0x146a790 --syntax intel

# Search for functions
elfinfo search ./out/disasm/disasm.json "BlockGroup"

# Resolve a GDB runtime address
elfinfo resolve libengine2.so 0x7f1a2146a790 --load-base 0x7f1a20000000

# Pipe an entire GDB backtrace
elfinfo resolve libengine2.so - --load-base 0x7f1a20000000 < bt.txt

# Find vtables containing a function
elfinfo vtable libengine2.so 0x146a790

# Generate a Frida hook script
elfinfo frida ./out/disasm/disasm.json --filter "mkvparser" --out hooks.js

# Repair return types from Frida capture
elfinfo frida-repair ./out/disasm/disasm.json capture.log
```

### Subcommands

| Subcommand | Description |
|---|---|
| `info` | Quick terminal summary (arch, build ID, export counts, dependencies) |
| `extract` | Extract all metadata → JSON + Markdown |
| `disasm` | Disassemble → class hierarchy JSON + Markdown tree |
| `show` | Disassemble one function by RVA, print to terminal |
| `search` | Search disasm.json for functions matching a regex |
| `resolve` | Resolve runtime addresses or RVAs to function names |
| `vtable` | Find vtables containing a given function RVA |
| `frida` | Generate a Frida JS hook script from disasm.json |
| `frida-repair` | Patch return types in disasm.json from a Frida capture log |

### Disassembly output structure

```
<outdir>/disasm/
  disasm.json
  md/
    <namespace>/
      _namespace.md          # class list and method count
      <Class>/
        _class.md            # vtable addr, typeinfo addr, method index
        addr__method.md      # metadata table + full assembly block
    _global/
      <A-Z>/
        addr__func.md        # C functions bucketed by first letter
```

### Disassembly syntax

```bash
--syntax att          # AT&T (default)
--syntax intel        # Intel/NASM style
--syntax no-aliases   # ARM/AArch64 canonical instructions
--syntax arm-apcs     # ARM 32-bit APCS register names
--syntax arm-std      # ARM 32-bit standard register names
--syntax force-thumb  # ARM 32-bit force Thumb mode
```

Analysis (return type inference) always uses AT&T internally regardless of display syntax.

### Frida workflow

```bash
# 1. Generate hooks for a specific class
elfinfo frida ./out/disasm/disasm.json --filter "MyClass" --out hooks.js

# 2. Run against a live process
frida -n myprocess -l hooks.js > capture.log

# 3. Repair static inference with runtime observations
elfinfo frida-repair ./out/disasm/disasm.json capture.log
```

Each hook emits one JSON line per call:
```json
{"rva":"0x146a790","fn":"mkvparser::BlockGroup::Parse()","rtype":"void* / int64","ret":"0x7f1234abcd","this_ptr":"0x7f5678ef00"}
```

`frida-repair` requires a minimum of 5 observations (configurable with `--min-samples`) before overriding a static return type.

### GDB integration

```
(gdb) info sharedlibrary       # get load base
(gdb) bt                       # get backtrace

$ elfinfo resolve lib.so - --load-base 0x7f1a20000000 < bt.txt
```

## License

MIT
