#!/usr/bin/env python3
"""
elfinfo — ELF binary analysis tool.

Subcommands:
  info          Quick binary summary (arch, type, exports, build ID)
  extract       Extract all metadata → JSON + Markdown
  disasm        Disassemble → class hierarchy JSON + Markdown tree
  show          Disassemble one function by RVA, print to terminal
  search        Search disasm.json for functions matching a pattern
  resolve       Resolve runtime addresses / RVAs to function names
  vtable        Find vtables containing a function RVA
  frida         Generate a Frida hook script from disasm.json
  frida-repair  Patch return types in disasm.json from a Frida capture log

Quick start:
  elfinfo info       libengine2.so
  elfinfo extract    libengine2.so --outdir ./out
  elfinfo disasm     libengine2.so --outdir ./out --syntax intel
  elfinfo show       libengine2.so 0x146a790 --syntax intel
  elfinfo search     ./out/disasm/disasm.json "BlockGroup"
  elfinfo resolve    libengine2.so 0x7f1a2146a790 --load-base 0x7f1a20000000
  elfinfo vtable     libengine2.so 0x146a790
  elfinfo frida      ./out/disasm/disasm.json --filter "mkvparser"
  elfinfo frida-repair ./out/disasm/disasm.json capture.log
"""
import argparse
import sys
from pathlib import Path

from elfinfo import ELFParser
from elfinfo.render import to_json, to_markdown, to_disasm_json, to_disasm_markdown
from elfinfo import vtable       as vtable_mod
from elfinfo import disasm       as disasm_mod
from elfinfo import resolve      as resolve_mod
from elfinfo import frida_gen    as frida_mod
from elfinfo import frida_repair as frida_repair_mod
from elfinfo import search       as search_mod
from elfinfo import info         as info_mod
from elfinfo import show         as show_mod
from elfinfo.disasm import SYNTAX_CHOICES


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_info(args):
    info_mod.info(args.binary)


def cmd_extract(args):
    binary = Path(args.binary)
    if not binary.exists():
        print(f"error: {binary} not found", file=sys.stderr)
        sys.exit(1)

    name     = binary.stem
    root     = Path(args.outdir) if args.outdir else Path(name)
    out_json = root / f"{name}.json"
    out_md   = root / "md"

    root.mkdir(parents=True, exist_ok=True)

    print(f"extracting {binary.name} ...")
    with ELFParser(binary) as p:
        data = p.extract()

    to_json(data, out_json)
    print(f"  wrote {out_json}")

    to_markdown(data, out_md)
    print(f"  wrote {out_md}/")


def cmd_disasm(args):
    binary = Path(args.binary)
    if not binary.exists():
        print(f"error: {binary} not found", file=sys.stderr)
        sys.exit(1)

    name     = binary.stem
    outdir   = Path(args.outdir) if args.outdir else Path(name)
    root     = outdir / "disasm"
    out_json = root / "disasm.json"
    out_md   = root / "md"

    root.mkdir(parents=True, exist_ok=True)

    print(f"loading symbols and C++ data from {binary.name} ...")
    from elfinfo.symbols import extract as sym_extract
    from elfinfo.cpp     import extract as cpp_extract
    with ELFParser(binary) as p:
        sym_data = sym_extract(p.elf)
        cpp_data = cpp_extract(p.elf)

    syntax = args.syntax
    print(f"disassembling {binary.name} (syntax: {syntax}) ...")
    functions = disasm_mod.extract(binary, sym_data["exports"], syntax=syntax)

    to_disasm_json(binary.name, functions, out_json, syntax=syntax)
    print(f"  wrote {out_json}  ({len(functions)} functions)")

    print(f"  writing markdown ...")
    to_disasm_markdown(binary.name, functions, out_md, cpp_data=cpp_data, syntax=syntax)
    print(f"  wrote {out_md}/")


def cmd_show(args):
    binary = Path(args.binary)
    if not binary.exists():
        print(f"error: {binary} not found", file=sys.stderr)
        sys.exit(1)

    try:
        load_base = int(args.load_base, 16) if args.load_base else 0
        rva       = int(args.rva, 16)
    except ValueError:
        print("error: rva and load-base must be hex values (e.g. 0x146a790)", file=sys.stderr)
        sys.exit(1)

    show_mod.show(binary, rva, load_base=load_base, syntax=args.syntax)


def cmd_search(args):
    search_mod.search(
        args.disasm_json,
        args.pattern,
        limit=args.limit,
        as_json=args.json,
    )


def cmd_resolve(args):
    binary = Path(args.binary)
    if not binary.exists():
        print(f"error: {binary} not found", file=sys.stderr)
        sys.exit(1)

    try:
        load_base = int(args.load_base, 16) if args.load_base else 0
    except ValueError:
        print("error: load-base must be a hex value (e.g. 0x7f1234560000)", file=sys.stderr)
        sys.exit(1)

    from_stdin = args.addresses == ["-"]
    resolve_mod.resolve(
        binary,
        args.addresses,
        load_base=load_base,
        from_stdin=from_stdin,
        as_json=args.json,
    )


def cmd_vtable(args):
    binary = Path(args.binary)
    if not binary.exists():
        print(f"error: {binary} not found", file=sys.stderr)
        sys.exit(1)

    try:
        load_base = int(args.load_base, 16) if args.load_base else 0
        rva       = int(args.rva, 16) - load_base
    except ValueError:
        print("error: rva and load-base must be hex values (e.g. 0x1234abc)", file=sys.stderr)
        sys.exit(1)

    if load_base:
        print(f"runtime 0x{int(args.rva, 16):x} - load base 0x{load_base:x} = RVA 0x{rva:x}\n")

    vtable_mod.analyse(binary, rva, context_slots=args.context)


def cmd_frida(args):
    disasm_json = Path(args.disasm_json)
    if not disasm_json.exists():
        print(f"error: {disasm_json} not found", file=sys.stderr)
        sys.exit(1)

    frida_mod.generate(
        disasm_json,
        out_path=Path(args.out) if args.out else None,
        filter_pat=args.filter,
        include_void=args.include_void,
    )


def cmd_frida_repair(args):
    frida_repair_mod.repair(
        args.disasm_json,
        args.capture_log,
        min_samples=args.min_samples,
        no_regen=args.no_regen,
        outdir=args.outdir,
    )


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        prog="elfinfo",
        description="ELF binary analysis tool.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = parser.add_subparsers(dest="cmd")

    # info
    p_info = sub.add_parser("info", help="Quick binary summary")
    p_info.add_argument("binary", help="Path to the .so or ELF binary")

    # extract
    p_extract = sub.add_parser("extract", help="Extract metadata → JSON + Markdown")
    p_extract.add_argument("binary", help="Path to the .so or ELF binary")
    p_extract.add_argument("--outdir", default=None,
                           help="Output directory (default: ./<binary stem>)")

    # disasm
    p_disasm = sub.add_parser("disasm", help="Disassemble → class hierarchy Markdown tree")
    p_disasm.add_argument("binary", help="Path to the .so or ELF binary")
    p_disasm.add_argument("--outdir", default=None,
                          help="Output directory (default: ./<binary stem>)")
    p_disasm.add_argument("--syntax", default="att", choices=SYNTAX_CHOICES,
                          help="Disassembly display syntax (default: att)")

    # show
    p_show = sub.add_parser("show", help="Disassemble one function by RVA, print to terminal")
    p_show.add_argument("binary", help="Path to the .so or ELF binary")
    p_show.add_argument("rva",    help="Function RVA or runtime address (hex)")
    p_show.add_argument("--load-base", default=None, metavar="HEX",
                        help="Runtime load base (subtracts to get RVA)")
    p_show.add_argument("--syntax", default="att", choices=SYNTAX_CHOICES,
                        help="Disassembly display syntax (default: att)")

    # search
    p_search = sub.add_parser("search", help="Search disasm.json for functions by name pattern")
    p_search.add_argument("disasm_json", help="Path to disasm.json")
    p_search.add_argument("pattern",     help="Regex pattern to match against demangled names")
    p_search.add_argument("--limit", type=int, default=50, metavar="N",
                          help="Maximum results to show (default: 50)")
    p_search.add_argument("--json", action="store_true",
                          help="Emit JSON array instead of formatted table")

    # resolve
    p_resolve = sub.add_parser("resolve", help="Resolve addresses to function names")
    p_resolve.add_argument("binary",    help="Path to the .so or ELF binary")
    p_resolve.add_argument("addresses", nargs="+", metavar="ADDR",
                           help="Hex addresses, or '-' to read from stdin (GDB bt format)")
    p_resolve.add_argument("--load-base", default=None, metavar="HEX",
                           help="Runtime load base (subtracts to get RVA)")
    p_resolve.add_argument("--json", action="store_true",
                           help="Emit JSON array instead of formatted text")

    # vtable
    p_vtable = sub.add_parser("vtable", help="Find vtables containing a function RVA")
    p_vtable.add_argument("binary", help="Path to the .so or ELF binary")
    p_vtable.add_argument("rva",    help="Function RVA or runtime address (hex)")
    p_vtable.add_argument("--load-base", default=None, metavar="HEX",
                          help="Runtime load base (subtracts to get RVA)")
    p_vtable.add_argument("--context", type=int, default=8, metavar="N",
                          help="Vtable slots to show before/after match (default: 8)")

    # frida
    p_frida = sub.add_parser("frida", help="Generate a Frida hook script from disasm.json")
    p_frida.add_argument("disasm_json", help="Path to disasm.json from elfinfo disasm")
    p_frida.add_argument("--out", default=None,
                         help="Output .js file (default: frida_hooks.js alongside disasm.json)")
    p_frida.add_argument("--filter", default=None, metavar="PATTERN",
                         help="Only hook functions whose name matches this regex")
    p_frida.add_argument("--include-void", action="store_true",
                         help="Also hook void-return functions (excluded by default)")

    # frida-repair
    p_repair = sub.add_parser("frida-repair",
                               help="Patch disasm.json return types from a Frida capture log")
    p_repair.add_argument("disasm_json",  help="Path to disasm.json")
    p_repair.add_argument("capture_log",  help="Frida console output (JSON lines)")
    p_repair.add_argument("--min-samples", type=int, default=5, metavar="N",
                          help="Minimum observations before overriding a return type (default: 5)")
    p_repair.add_argument("--no-regen", action="store_true",
                          help="Patch JSON only, skip markdown regeneration")
    p_repair.add_argument("--outdir", default=None,
                          help="Markdown directory to regenerate (default: auto-detect)")

    # default to extract if no subcommand given
    _CMDS = {"info", "extract", "disasm", "show", "search",
             "resolve", "vtable", "frida", "frida-repair", "-h", "--help"}
    if len(sys.argv) > 1 and sys.argv[1] not in _CMDS:
        sys.argv.insert(1, "extract")

    args = parser.parse_args()

    dispatch = {
        "info":         cmd_info,
        "extract":      cmd_extract,
        "disasm":       cmd_disasm,
        "show":         cmd_show,
        "search":       cmd_search,
        "resolve":      cmd_resolve,
        "vtable":       cmd_vtable,
        "frida":        cmd_frida,
        "frida-repair": cmd_frida_repair,
    }

    fn = dispatch.get(args.cmd)
    if fn:
        fn(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
