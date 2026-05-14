# elfinfo — Agent Reference

This document gives a Claude agent full context to work on the elfinfo codebase without prior conversation history.

---

## What this tool does

`elfinfo` is a generic ELF binary analysis tool. It extracts everything knowable from a `.so` or ELF binary without a running process — headers, symbols, relocations, C++ vtables/RTTI, disassembly — and writes structured JSON and a navigable Markdown file tree. It also supports runtime cross-referencing via GDB address resolution and Frida dynamic instrumentation hooks.

**Primary use case**: given a stripped `.so`, reconstruct its codebase structure as a filesystem tree of Markdown files, then cross-reference GDB runtime addresses back to function identities.

---

## Install / run

```bash
./install.sh           # creates .venv, pip install -e .
./install.sh uninstall # removes .venv and egg-info
.venv/bin/elfinfo --help
```

---

## All subcommands

### `elfinfo info <lib.so>`
Quick terminal summary: arch, type, build ID, export/import counts, vtable count, dependencies. No files written.

### `elfinfo extract <lib.so> [--outdir DIR]`
Full metadata extraction → JSON + Markdown. Output layout:
```
<outdir>/
  <name>.json          # all extracted data
  md/
    index.md           # identity, sections, segments, summary
    symbols_exports.md
    symbols_imports.md
    relocations.md
    cpp.md             # vtables, typeinfo, eh_frame boundaries
    strings.md
```
Default `--outdir`: `./<binary stem>`.

### `elfinfo disasm <lib.so> [--outdir DIR] [--syntax STYLE]`
Full disassembly → class hierarchy Markdown tree + JSON. Output layout:
```
<outdir>/disasm/
  disasm.json          # all function data including instructions
  md/
    <namespace>/
      _namespace.md    # class list, total method count
      <Class>/
        _class.md      # vtable addr, typeinfo addr, method index table
        <nested>/
          _class.md
          addr__method.md   # full metadata + assembly block per function
    _global/
      <A-Z|_|#>/
        addr__func.md  # C functions bucketed by first letter
```

`--syntax` choices: `att` (default), `intel`, `no-aliases`, `arm-apcs`, `arm-std`, `force-thumb`.
Analysis (return type inference) always uses AT&T internally; display syntax is a separate objdump pass.

### `elfinfo show <lib.so> <rva_hex> [--load-base HEX] [--syntax STYLE]`
Disassemble one function by RVA, print to terminal. Fast — uses `objdump --start-address/--stop-address`. Finds function bounds from `.eh_frame` intervals. Inline labels are demangled.

```bash
elfinfo show libengine2.so 0x146a790 --syntax intel
elfinfo show libengine2.so 0x7f1a2146a790 --load-base 0x7f1a20000000
```

### `elfinfo search <disasm.json> <pattern> [--limit N] [--json]`
Regex search over disasm.json, prints a table of matching functions. Case-insensitive. `--json` emits a JSON array for scripting.

```bash
elfinfo search ./out/disasm/disasm.json "BlockGroup::Get"
elfinfo search ./out/disasm/disasm.json "^mkvparser" --limit 100
```

### `elfinfo resolve <lib.so> <addr> [<addr> ...] [--load-base HEX] [--json]`
Resolve one or more addresses to function names using `.eh_frame` interval index (45k+ intervals even on stripped binaries, vs ~16k exported symbols). Pass `-` as address to read from stdin.

```bash
# Direct RVAs
elfinfo resolve libengine2.so 0x146a790 0x146a7ab

# Runtime addresses from GDB
elfinfo resolve libengine2.so 0x7f1a2146a790 --load-base 0x7f1a20000000

# Pipe a GDB backtrace
(gdb) bt | elfinfo resolve libengine2.so - --load-base 0x7f1a20000000

# Machine-readable
elfinfo resolve libengine2.so 0x146a790 --json
```

Output distinguishes "found in interval" (exact function + offset) vs "nearest symbol" (outside all known intervals).

### `elfinfo vtable <lib.so> <rva_hex> [--load-base HEX] [--context N]`
Given a function RVA, find all vtables containing that pointer. Identifies owning class via Itanium RTTI, shows slot index and context window.

### `elfinfo frida <disasm.json> [--out FILE] [--filter PATTERN] [--include-void]`
Generate a Frida JS hook script from disasm.json. No frida Python package required — output is a `.js` for the `frida` CLI.

```bash
# Hook everything (use --filter for large binaries)
elfinfo frida ./out/disasm/disasm.json

# Hook one class only
elfinfo frida ./out/disasm/disasm.json --filter "mkvparser::BlockGroup" --out hooks.js

# Include void-return functions (call tracing)
elfinfo frida ./out/disasm/disasm.json --filter "mkvparser" --include-void

# Run against live process
frida -n <process_name> -l hooks.js
frida -p <pid>          -l hooks.js
```

Each hook emits one JSON line per call:
```json
{"rva":"0x146a790","fn":"mkvparser::BlockGroup::Parse()","rtype":"void* / int64 (pointer or 64-bit int)","ret":"0x7f1234abcd","this_ptr":"0x7f5678ef00"}
```

### `elfinfo frida-repair <disasm.json> <capture.log> [--min-samples N] [--no-regen] [--outdir DIR]`
Read a Frida capture log and patch `return_type` fields in disasm.json where runtime observations contradict the static inference. Requires `--min-samples` (default 5) observations before overriding.

Confidence rules applied to observed return values:
- All 0 or 1 → `bool`
- All in pointer range (> 0x10000) or 0 → `void* / T* (pointer)`
- All fit int32 → `int`
- Mix → `int / pointer (variable)`

After patching JSON, regenerates the markdown tree unless `--no-regen` is passed.

---

## Module map

| File | Role |
|---|---|
| `parser.py` | `ELFParser` context manager — opens binary once, delegates to all modules |
| `identity.py` | ELF header fields, build ID from `.note.gnu.build-id` |
| `layout.py` | Sections and segments |
| `symbols.py` | `.dynsym` / `.symtab` exports + imports, batch `c++filt` demangling |
| `dynamic.py` | `.dynamic` section tags (NEEDED, SONAME, RUNPATH, FLAGS) |
| `relocations.py` | `.rela.plt` and `.rela.dyn` with named relocation types |
| `versioning.py` | `.gnu.version_r/d` and `.gnu.hash` metadata |
| `cpp.py` | `_ZTV*`/`_ZTI*` vtables + typeinfo, `.eh_frame` FDE boundaries |
| `strings.py` | Printable ASCII strings from `.rodata` and `.data.rel.ro` |
| `disasm.py` | `objdump -d` parse + return type inference + inline label demangling |
| `render.py` | JSON and Markdown writers for both extract and disasm pipelines |
| `resolve.py` | `.eh_frame` interval index + bisect lookup, stdin GDB bt parsing |
| `vtable.py` | Raw binary scan for vtable references, RTTI class name reading |
| `show.py` | Single-function targeted objdump + terminal print |
| `search.py` | Regex search over disasm.json, formatted table output |
| `info.py` | Quick ELF summary without writing files |
| `frida_gen.py` | Frida JS hook script generator from disasm.json |
| `frida_repair.py` | Patches disasm.json return types from Frida capture log |
| `__main__.py` | CLI entry point — all subcommand wiring |

---

## Key design decisions

**Two objdump passes for non-AT&T syntax**: Return type inference regexes are AT&T-specific. When `--syntax intel` (or other) is requested, `disasm.py` runs two `objdump` passes — AT&T for analysis, requested syntax for display storage.

**`.eh_frame` over `.dynsym` for intervals**: `.eh_frame` FDEs survive stripping and cover ~3× more functions than `.dynsym` size fields. `resolve.py` and `show.py` both use the FDE interval index as their primary source.

**`c++filt` batching**: All demangling is done in one subprocess call per module invocation — never per-symbol — to avoid fork overhead on large binaries.

**Inline label demangling**: After `objdump` output is parsed, `_resolve_inline_labels()` in `disasm.py` collects all `_Z...` names embedded in call/jump annotations, demangles them in one batch, and substitutes back. Applied to all 16k functions at once with a single `c++filt` call.

**`_sanitize` strips trailing underscores only**: `rstrip("_")` not `strip("_")` — preserves leading underscores so `_global/` stays as `_global/` in the output tree.

**Deduplication by address**: Itanium ABI generates D1/D2 destructor and C1/C2 constructor variants as separate symbols at the same address. Both `_write_tree` (file writing) and `_render_class` (method index table) deduplicate by address to avoid duplicate entries.

**frida-repair confidence threshold**: A single Frida observation is not enough to override static inference (could be a cold-path or edge case). Default of 5 samples before overriding balances noise with correctness.

---

## Data flow

```
ELF binary
  │
  ├─ elfinfo extract ──→ parser.py ──→ {identity, layout, symbols,
  │                                     dynamic, relocations,
  │                                     versioning, cpp, strings}
  │                                  ──→ <name>.json
  │                                  ──→ md/*.md
  │
  ├─ elfinfo disasm  ──→ symbols + cpp (reuse parser.py modules)
  │                  ──→ disasm.py (objdump ×1 or ×2)
  │                  ──→ disasm.json  {"file", "syntax", "functions": [...]}
  │                  ──→ md/<namespace>/<Class>/<addr>__<method>.md
  │
  ├─ elfinfo show    ──→ resolve.py (interval index)
  │                  ──→ objdump --start-address --stop-address
  │                  ──→ terminal output
  │
  ├─ elfinfo resolve ──→ resolve.py (interval bisect)
  │                  ──→ terminal or JSON output
  │
  ├─ elfinfo frida   ──→ frida_gen.py ──→ frida_hooks.js
  │
  └─ elfinfo frida-repair ──→ frida_repair.py
                            ──→ patches disasm.json in-place
                            ──→ re-renders md/ tree
```

---

## disasm.json schema (per function entry)

```json
{
  "addr":              "0x146a790",
  "size":              "71",
  "raw":               "_ZN9mkvparser10BlockGroup5ParseEv",
  "demangled":         "mkvparser::BlockGroup::Parse()",
  "path":              ["mkvparser", "BlockGroup"],
  "method_name":       "Parse",
  "instruction_count": 27,
  "return_reg":        "rax",
  "return_hint":       null,
  "return_type":       "void* / int64 (pointer or 64-bit int)",
  "return_type_source": "frida",
  "return_type_samples": 12,
  "raw_returns":       [],
  "instructions": [
    {"addr": "0x146a790", "insn": "endbr64"},
    {"addr": "0x146a794", "insn": "push   r12"},
    ...
  ]
}
```

`return_type_source` and `return_type_samples` are added by `frida-repair` when a type is overridden at runtime.

---

## Common workflows

**Full analysis of a new binary:**
```bash
elfinfo info        mylib.so
elfinfo extract     mylib.so --outdir ./out
elfinfo disasm      mylib.so --outdir ./out --syntax intel
```

**GDB trace → function identity:**
```bash
# In GDB:
#   info sharedlibrary  → get load base (e.g. 0x7f1a20000000)
#   bt                  → get backtrace with runtime addresses

elfinfo resolve mylib.so 0x7f1a2146a790 --load-base 0x7f1a20000000

# Or pipe the whole backtrace:
elfinfo resolve mylib.so - --load-base 0x7f1a20000000 < bt.txt
```

**Find a class and inspect it:**
```bash
elfinfo search ./out/disasm/disasm.json "MyClass"
elfinfo show   mylib.so 0x<addr_from_search> --syntax intel
cat ./out/disasm/md/MyNamespace/MyClass/_class.md
```

**Runtime return type correction:**
```bash
elfinfo frida ./out/disasm/disasm.json --filter "MyClass" --out hooks.js
frida -n myprocess -l hooks.js > capture.log
elfinfo frida-repair ./out/disasm/disasm.json capture.log
```
