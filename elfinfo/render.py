import json
import re
from pathlib import Path


# ---------------------------------------------------------------------------
# Disasm output
# ---------------------------------------------------------------------------

def to_disasm_json(
    file_name: str, functions: list[dict], path: str | Path, syntax: str = "att"
) -> None:
    """Write disasm data to a JSON file."""
    path = Path(path)
    with open(path, "w") as f:
        json.dump({"file": file_name, "syntax": syntax, "functions": functions}, f, indent=2)


def to_disasm_markdown(
    file_name: str,
    functions: list[dict],
    out_dir: str | Path,
    cpp_data: dict | None = None,
    syntax: str = "att",
) -> None:
    """
    Write the full disasm hierarchy:
      <namespace>/<Class>/<Nested>/addr__method.md
      <namespace>/<Class>/_class.md
      <namespace>/_namespace.md
      _global/<A-Z#_>/addr__func.md
    """
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    asm_lang = "nasm" if syntax == "intel" else "asm"
    vtable_map, typeinfo_map = _build_cpp_maps(cpp_data)
    tree = _build_tree(functions)
    _write_tree(out_dir, tree, file_name, vtable_map, typeinfo_map, asm_lang=asm_lang)


# ---------------------------------------------------------------------------
# CPP lookup maps
# ---------------------------------------------------------------------------

def _build_cpp_maps(cpp_data: dict | None) -> tuple[dict, dict]:
    """
    Build {qualified_class_name: entry} dicts from cpp extraction data.
    e.g. "mkvparser::BlockGroup" → {"addr": "0x...", "size": 48}
    """
    vtable_map:   dict[str, dict] = {}
    typeinfo_map: dict[str, dict] = {}

    if not cpp_data:
        return vtable_map, typeinfo_map

    for v in cpp_data.get("vtables", []):
        dem = v.get("demangled", "")
        if dem.startswith("vtable for "):
            key = dem[len("vtable for "):]
            vtable_map[key] = {"addr": v["addr"], "size": v["size"], "defined": v["defined"]}

    for t in cpp_data.get("typeinfo", []):
        dem = t.get("demangled", "")
        if dem.startswith("typeinfo for "):
            key = dem[len("typeinfo for "):]
            typeinfo_map[key] = {"addr": t["addr"], "defined": t["defined"]}

    return vtable_map, typeinfo_map


# ---------------------------------------------------------------------------
# Tree building
# ---------------------------------------------------------------------------

def _build_tree(functions: list[dict]) -> dict:
    """
    Build a nested dict tree from function path components.
    Each node is a dict with special keys:
      "_functions" → list of function dicts at this level
      other keys   → child nodes (class/namespace names)
    """
    root: dict = {"_functions": []}

    for fn in functions:
        path = fn.get("path", [])

        if not path:
            # _global — bucket by first letter of method name
            method = fn.get("method_name", fn.get("demangled", "?"))
            bucket = _global_bucket(method)
            node = root.setdefault("_global", {"_functions": []})
            node = node.setdefault(bucket, {"_functions": []})
            node["_functions"].append(fn)
        else:
            node = root
            for part in path:
                node = node.setdefault(part, {"_functions": []})
            node["_functions"].append(fn)

    return root


def _global_bucket(name: str) -> str:
    if not name:
        return "#"
    c = name.lstrip("_")[0].upper() if name.lstrip("_") else "_"
    return c if c.isalpha() else ("#" if c.isdigit() else "_")


# ---------------------------------------------------------------------------
# Tree writing
# ---------------------------------------------------------------------------

def _write_tree(
    directory: Path,
    node: dict,
    file_name: str,
    vtable_map: dict,
    typeinfo_map: dict,
    qualified_path: list[str] | None = None,
    asm_lang: str = "asm",
) -> None:
    if qualified_path is None:
        qualified_path = []

    directory.mkdir(parents=True, exist_ok=True)

    # Write function files at this level — deduplicate by address
    fns  = node.get("_functions", [])
    seen: set[int] = set()
    for fn in sorted(fns, key=lambda f: int(f["addr"], 16)):
        addr_int = int(fn["addr"], 16)
        if addr_int in seen:
            continue
        seen.add(addr_int)
        addr_short = hex(addr_int)[2:]
        method     = _sanitize(fn.get("method_name", "unknown"))
        filename   = f"{addr_short}__{method}.md"
        _write(directory / filename, _render_function(file_name, fn, asm_lang=asm_lang))

    # Recurse into children
    children = {k: v for k, v in node.items() if k != "_functions"}

    for child_name, child_node in sorted(children.items()):
        child_dir  = directory / _sanitize(child_name)
        child_path = qualified_path + [child_name]

        _write_tree(child_dir, child_node, file_name, vtable_map, typeinfo_map, child_path, asm_lang=asm_lang)

        # Write _class.md for any non-global non-bucket node that has methods
        is_global_bucket = (
            len(qualified_path) == 1 and qualified_path[0] == "_global"
        )
        is_global_root = child_name == "_global"

        if not is_global_root and not is_global_bucket:
            qualified_name = "::".join(child_path)
            all_fns        = _collect_functions(child_node)

            if qualified_path:
                # This is a class or nested class — write _class.md
                vtable   = vtable_map.get(qualified_name)
                typeinfo = typeinfo_map.get(qualified_name)
                _write(
                    child_dir / "_class.md",
                    _render_class(qualified_name, all_fns, vtable, typeinfo)
                )
            else:
                # Top-level namespace — write _namespace.md
                classes = [k for k in child_node if k != "_functions"]
                _write(
                    child_dir / "_namespace.md",
                    _render_namespace(child_name, all_fns, classes)
                )


def _collect_functions(node: dict) -> list[dict]:
    """Recursively collect all functions in a subtree."""
    out = list(node.get("_functions", []))
    for k, v in node.items():
        if k != "_functions" and isinstance(v, dict):
            out.extend(_collect_functions(v))
    return out


def _sanitize(name: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_]", "_", name).rstrip("_")[:64] or "_"


def to_json(data: dict, path: str | Path) -> None:
    """Write extracted data to a JSON file."""
    path = Path(path)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


def to_markdown(data: dict, out_dir: str | Path) -> None:
    """Render extracted data into a set of markdown files under out_dir."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    _write(out_dir / "index.md",           _render_index(data))
    _write(out_dir / "symbols_exports.md", _render_exports(data))
    _write(out_dir / "symbols_imports.md", _render_imports(data))
    _write(out_dir / "relocations.md",     _render_relocations(data))
    _write(out_dir / "cpp.md",             _render_cpp(data))
    _write(out_dir / "strings.md",         _render_strings(data))


def _write(path: Path, content: str) -> None:
    with open(path, "w") as f:
        f.write(content)


# ---------------------------------------------------------------------------
# index.md
# ---------------------------------------------------------------------------

def _render_index(data: dict) -> str:
    meta     = data.get("meta", {})
    identity = data.get("identity", {})
    layout   = data.get("layout", {})
    symbols  = data.get("symbols", {})
    dyn      = data.get("dynamic", {})
    relocs   = data.get("relocations", {})
    cpp      = data.get("cpp", {})

    lines = [f"# {meta.get('file', 'unknown')}\n"]

    lines += [
        "## Identity\n",
        "| Field | Value |",
        "|---|---|",
        f"| Class | `{identity.get('class')}-bit` |",
        f"| Endianness | `{identity.get('endianness')}` |",
        f"| ABI | `{identity.get('abi')}` |",
        f"| Type | `{identity.get('type')}` |",
        f"| Machine | `{identity.get('machine')}` |",
        f"| Entry | `{identity.get('entry')}` |",
        f"| Build ID | `{identity.get('build_id')}` |",
        f"| Size | `{meta.get('size_bytes', 0):,} bytes` |",
        f"| SHA-256 | `{meta.get('sha256')}` |",
        "",
    ]

    lines += [
        "## Sections\n",
        "| Name | Type | Address | Size | Flags |",
        "|---|---|---|---|---|",
    ]
    for sec in layout.get("sections", []):
        if not sec["name"]:
            continue
        flags = ", ".join(sec.get("flags", []))
        lines.append(
            f"| `{sec['name']}` | `{sec['type']}` | `{sec['addr']}` "
            f"| `{sec['size']:,}` | {flags} |"
        )
    lines.append("")

    lines += [
        "## Segments\n",
        "| Type | VAddr | FileSize | MemSize | Flags |",
        "|---|---|---|---|---|",
    ]
    for seg in layout.get("segments", []):
        lines.append(
            f"| `{seg['type']}` | `{seg['vaddr']}` | `{seg['filesz']:,}` "
            f"| `{seg['memsz']:,}` | `{seg['flags']}` |"
        )
    lines.append("")

    lines += [
        "## Summary\n",
        "| Category | Count |",
        "|---|---|",
        f"| Exported symbols | `{len(symbols.get('exports', []))}` |",
        f"| Imported symbols | `{len(symbols.get('imports', []))}` |",
        f"| PLT relocations | `{len(relocs.get('rela_plt', []))}` |",
        f"| Dynamic relocations | `{len(relocs.get('rela_dyn', []))}` |",
        f"| Vtables | `{len(cpp.get('vtables', []))}` |",
        f"| Typeinfo | `{len(cpp.get('typeinfo', []))}` |",
        f"| eh_frame entries | `{len(cpp.get('eh_frame', []))}` |",
        f"| Dependencies | `{len(dyn.get('needed', []))}` |",
        "",
        "## Dependencies\n",
    ]
    for lib in dyn.get("needed", []):
        lines.append(f"- `{lib}`")
    lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# symbols_exports.md
# ---------------------------------------------------------------------------

def _render_exports(data: dict) -> str:
    exports = data.get("symbols", {}).get("exports", [])
    name    = data.get("meta", {}).get("file", "")

    lines = [
        f"# {name} — Exported Symbols ({len(exports)})\n",
        "| Address | Size | Type | Bind | Name |",
        "|---|---|---|---|---|",
    ]
    for s in exports:
        lines.append(
            f"| `{s['addr']}` | `{s['size']}` | `{s['type']}` "
            f"| `{s['bind']}` | `{s['demangled']}` |"
        )
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# symbols_imports.md
# ---------------------------------------------------------------------------

def _render_imports(data: dict) -> str:
    imports = data.get("symbols", {}).get("imports", [])
    name    = data.get("meta", {}).get("file", "")

    lines = [
        f"# {name} — Imported Symbols ({len(imports)})\n",
        "| Type | Bind | Name |",
        "|---|---|---|",
    ]
    for s in imports:
        lines.append(
            f"| `{s['type']}` | `{s['bind']}` | `{s['demangled']}` |"
        )
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# relocations.md
# ---------------------------------------------------------------------------

def _render_relocations(data: dict) -> str:
    plt = data.get("relocations", {}).get("rela_plt", [])
    dyn = data.get("relocations", {}).get("rela_dyn", [])
    name = data.get("meta", {}).get("file", "")

    lines = [f"# {name} — Relocations\n"]

    lines += [
        f"## .rela.plt ({len(plt)} entries)\n",
        "| Offset | Type | Symbol |",
        "|---|---|---|",
    ]
    for r in plt:
        lines.append(f"| `{r['offset']}` | `{r['type']}` | `{r['symbol']}` |")
    lines.append("")

    lines += [
        f"## .rela.dyn ({len(dyn)} entries)\n",
        "| Offset | Type | Addend | Symbol |",
        "|---|---|---|---|",
    ]
    for r in dyn:
        sym = r["symbol"] or ""
        lines.append(
            f"| `{r['offset']}` | `{r['type']}` | `{r['addend']}` | `{sym}` |"
        )
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# cpp.md
# ---------------------------------------------------------------------------

def _render_cpp(data: dict) -> str:
    cpp  = data.get("cpp", {})
    name = data.get("meta", {}).get("file", "")

    lines = [f"# {name} — C++ Specifics\n"]

    vtables = cpp.get("vtables", [])
    lines += [
        f"## Vtables ({len(vtables)})\n",
        "| Address | Size | Defined | Name |",
        "|---|---|---|---|",
    ]
    for v in vtables:
        lines.append(
            f"| `{v['addr']}` | `{v['size']}` "
            f"| {'yes' if v['defined'] else 'no'} | `{v['demangled']}` |"
        )
    lines.append("")

    typeinfo = cpp.get("typeinfo", [])
    lines += [
        f"## Typeinfo ({len(typeinfo)})\n",
        "| Address | Defined | Name |",
        "|---|---|---|",
    ]
    for t in typeinfo:
        lines.append(
            f"| `{t['addr']}` | {'yes' if t['defined'] else 'no'} | `{t['demangled']}` |"
        )
    lines.append("")

    eh = cpp.get("eh_frame", [])
    lines += [
        f"## eh_frame Function Boundaries ({len(eh)})\n",
        "| Address | Size (bytes) |",
        "|---|---|",
    ]
    for e in eh:
        lines.append(f"| `{e['addr']}` | `{e['size']}` |")
    lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# strings.md
# ---------------------------------------------------------------------------

def _render_strings(data: dict) -> str:
    strings = data.get("strings", {})
    name    = data.get("meta", {}).get("file", "")

    lines = [f"# {name} — Strings\n"]

    for sec_name, entries in strings.items():
        lines += [
            f"## {sec_name} ({len(entries)} strings)\n",
            "| Address | Length | Value |",
            "|---|---|---|",
        ]
        for e in entries:
            escaped = e["value"].replace("|", "\\|")
            lines.append(f"| `{e['addr']}` | `{e['length']}` | {escaped} |")
        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Per-function disasm markdown
# ---------------------------------------------------------------------------

def _render_function(file_name: str, fn: dict, asm_lang: str = "asm") -> str:
    dem    = fn.get("demangled", fn.get("raw", "unknown"))
    raw    = fn.get("raw", "")
    rtype  = fn.get("return_type", "unknown")
    rreg   = fn.get("return_reg",  "unknown")
    rhint  = fn.get("return_hint")
    raws   = fn.get("raw_returns", [])
    icount = fn.get("instruction_count", 0)
    path   = fn.get("path", [])
    method = fn.get("method_name", "")
    insns  = fn.get("instructions", [])

    lines = [f"# `{dem}`\n"]
    lines += [
        "## Info\n",
        "| Field | Value |",
        "|---|---|",
        f"| File | `{file_name}` |",
        f"| Address | `{fn.get('addr')}` |",
        f"| Size | `{fn.get('size')} bytes` |",
        f"| Path | `{'::'.join(path) if path else '_global'}` |",
        f"| Method | `{method}` |",
        f"| Instructions | `{icount}` |",
        f"| Return type | `{rtype}` |",
        f"| Return register | `{rreg}` |",
    ]
    if rhint:
        lines.append(f"| Return hint | `{rhint}` |")
    if raws:
        lines.append(f"| Raw return value(s) | {', '.join(f'`{v}`' for v in raws)} |")
    else:
        lines.append("| Raw return value(s) | *(variable)* |")
    if raw and raw != dem:
        lines.append(f"| Mangled name | `{raw}` |")
    lines.append("")

    if insns:
        lines += [f"## Assembly\n", f"```{asm_lang}"]
        for entry in insns:
            lines.append(f"  {entry['addr']}  {entry['insn']}")
        lines += ["```", ""]

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# _class.md
# ---------------------------------------------------------------------------

def _render_class(
    qualified_name: str,
    functions: list[dict],
    vtable: dict | None,
    typeinfo: dict | None,
) -> str:
    lines = [f"# `{qualified_name}`\n"]
    lines += ["## Class Info\n", "| Field | Value |", "|---|---|"]

    if vtable:
        defined = "yes" if vtable.get("defined") else "no (imported)"
        lines.append(f"| Vtable address | `{vtable['addr']}` |")
        lines.append(f"| Vtable size | `{vtable['size']} bytes` |")
        lines.append(f"| Vtable defined | {defined} |")
    else:
        lines.append("| Vtable | *(not found)* |")

    if typeinfo:
        defined = "yes" if typeinfo.get("defined") else "no (imported)"
        lines.append(f"| Typeinfo address | `{typeinfo['addr']}` |")
        lines.append(f"| Typeinfo defined | {defined} |")
    else:
        lines.append("| Typeinfo | *(not found)* |")

    lines.append(f"| Method count | `{len(functions)}` |")
    lines.append("")

    lines += ["## Methods\n", "| Address | Method | Return Type | Instructions |", "|---|---|---|---|"]
    seen: set[int] = set()
    for fn in sorted(functions, key=lambda f: int(f["addr"], 16)):
        addr_int = int(fn.get("addr", "0x0"), 16)
        if addr_int in seen:
            continue
        seen.add(addr_int)
        addr   = fn.get("addr", "0x0")
        method = fn.get("method_name", "?")
        rtype  = fn.get("return_type", "unknown")
        icount = fn.get("instruction_count", 0)
        lines.append(f"| `{addr}` | `{method}` | `{rtype}` | `{icount}` |")
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# _namespace.md
# ---------------------------------------------------------------------------

def _render_namespace(
    namespace: str,
    functions: list[dict],
    classes: list[str],
) -> str:
    lines = [f"# `{namespace}`\n"]
    lines += ["## Summary\n", "| Field | Value |", "|---|---|"]
    lines.append(f"| Classes | `{len(classes)}` |")
    lines.append(f"| Total methods | `{len(functions)}` |")
    lines.append("")

    if classes:
        lines += ["## Classes\n"]
        for cls in sorted(classes):
            lines.append(f"- `{cls}`")
        lines.append("")

    return "\n".join(lines)
