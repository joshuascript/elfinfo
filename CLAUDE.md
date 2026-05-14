# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Install / Uninstall

```bash
./install.sh           # creates .venv and installs the package in editable mode
./install.sh uninstall # removes .venv and elfinfo.egg-info
```

After install, the CLI is available as `.venv/bin/elfinfo` or simply `elfinfo` if the venv is activated.

## Running the tool

```bash
# Extract all ELF metadata → JSON + Markdown
elfinfo extract <lib.so> [--outdir <dir>]

# Disassemble and build class hierarchy markdown
elfinfo disasm <lib.so> [--outdir <dir>]

# Find vtables containing a given function RVA
elfinfo vtable <lib.so> <rva_hex> [--load-base <hex>] [--context N]
```

If no subcommand is given, `extract` is assumed. `vtable --load-base` accepts the runtime base from GDB `info sharedlibrary` and subtracts it to produce an RVA.

## Architecture

### Two-phase design

**`extract` pipeline** — pure ELF metadata, no disassembly:

```
ELFParser (parser.py)
  └─ delegates to eight modules, each receiving the ELFFile handle:
       identity, layout, symbols, dynamic, relocations, versioning, cpp, strings
  └─ returns one nested dict
  └─ render.to_json()      → <name>/<name>.json
  └─ render.to_markdown()  → <name>/md/*.md
```

**`disasm` pipeline** — disassembly layered on top of `extract` data:

```
symbols.extract + cpp.extract  (reuse the same modules)
disasm.extract(binary, exports)
  └─ runs objdump -d once, splits into per-function blocks
  └─ walks backwards from each ret for return register/type inference (AT&T syntax)
  └─ template-aware :: splitting → (path[], method_name)
render.to_disasm_json()
render.to_disasm_markdown(cpp_data=cpp_data)
  └─ builds vtable_map + typeinfo_map from cpp_data
  └─ writes nested class hierarchy:
       <namespace>/<Class>/<Nested>/addr__method.md
       <namespace>/<Class>/_class.md
       <namespace>/_namespace.md
       _global/<A-Z|_|#>/addr__method.md
```

### Module responsibilities

| Module | What it reads | Key output keys |
|---|---|---|
| `identity.py` | ELF header, `.note.gnu.build-id` | `class`, `machine`, `build_id` |
| `layout.py` | segments, sections | `segments`, `sections` |
| `symbols.py` | `.dynsym` / `.symtab`, batch `c++filt` | `exports`, `imports` |
| `dynamic.py` | `.dynamic` tags | `needed`, `soname`, `flags` |
| `relocations.py` | `.rela.plt`, `.rela.dyn` | `rela_plt`, `rela_dyn` |
| `versioning.py` | `.gnu.version_r/d`, `.gnu.hash` | `requirements`, `definitions`, `gnu_hash` |
| `cpp.py` | `_ZTV*`/`_ZTI*` from `.dynsym`, `.eh_frame` FDEs | `vtables`, `typeinfo`, `eh_frame` |
| `strings.py` | `.rodata`, `.data.rel.ro` | per-section string lists |
| `disasm.py` | `objdump -d` output | per-function dicts with `path[]`, `method_name`, `return_type` |
| `vtable.py` | raw binary scan + Itanium ABI RTTI layout | printed vtable context |

### Key design decisions

- **`ELFParser` as context manager**: opens the file once and passes the single `ELFFile` handle to all modules. Always use `with ELFParser(path) as p:`.
- **`c++filt` batching**: all demangling is done in one subprocess call per module invocation to avoid per-symbol overhead.
- **`objdump` for disassembly**: pyelftools has no disassembler; `objdump -d --no-show-raw-insn` (AT&T syntax) is run once and split into per-function blocks by parsing `addr <name>:` headers.
- **`.eh_frame` for function boundaries**: survives stripping; accessed via `dwarf.EH_CFI_entries()` (not `CFI_entries()` — that needs `.debug_frame` which is absent in stripped binaries).
- **`_sanitize` in render.py**: converts names to filesystem-safe strings with `rstrip("_")` only — leading underscores (e.g., `_global`) are preserved intentionally.
- **Template-aware `::` splitting** (`disasm._split_qualified`): tracks angle-bracket depth to avoid splitting inside template parameters like `std::vector<A::B>`.
- **cpp_data cross-reference**: `cmd_disasm` passes the `cpp.extract()` result into `render.to_disasm_markdown()` so `_class.md` files can display vtable and typeinfo addresses alongside methods.

### External dependencies

- `pyelftools` — all ELF/DWARF parsing
- `objdump` — disassembly (system binary, must be on PATH)
- `c++filt` — C++ name demangling (system binary, must be on PATH)
