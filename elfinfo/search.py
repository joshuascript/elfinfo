"""
Search disasm.json for functions matching a regex pattern.
Prints a table to the terminal.
"""
import json
import re
import sys
from pathlib import Path


def search(
    disasm_json: str | Path,
    pattern:     str,
    limit:       int = 50,
    as_json:     bool = False,
) -> None:
    disasm_json = Path(disasm_json)
    if not disasm_json.exists():
        print(f"error: {disasm_json} not found", file=sys.stderr)
        sys.exit(1)

    with open(disasm_json) as f:
        data = json.load(f)

    functions = data.get("functions", [])
    lib       = data.get("file", disasm_json.stem)

    try:
        pat = re.compile(pattern, re.IGNORECASE)
    except re.error as e:
        print(f"error: invalid pattern: {e}", file=sys.stderr)
        sys.exit(1)

    matches = [fn for fn in functions if pat.search(fn.get("demangled", ""))]

    if as_json:
        print(json.dumps(matches[:limit], indent=2))
        return

    print(f"# search: {lib}  —  pattern: {pattern!r}  ({len(matches)} match{'es' if len(matches) != 1 else ''})\n")

    if not matches:
        print("  (no results)")
        return

    shown = matches[:limit]

    # column widths
    w_addr   = max(len(fn["addr"]) for fn in shown) + 2
    w_method = min(max(len(fn.get("method_name", "?")) for fn in shown), 40) + 2
    w_rtype  = min(max(len(fn.get("return_type",  "?")) for fn in shown), 36) + 2

    header = f"  {'Address':<{w_addr}}  {'Method':<{w_method}}  {'Return Type':<{w_rtype}}  {'Insns':>5}  Qualified Name"
    print(header)
    print("  " + "-" * (len(header) - 2))

    for fn in shown:
        addr   = fn.get("addr",        "?")
        method = fn.get("method_name", "?")[:40]
        rtype  = fn.get("return_type", "?")[:36]
        icount = fn.get("instruction_count", 0)
        path   = fn.get("path", [])
        qname  = "::".join(path + [method]) if path else method
        print(f"  {addr:<{w_addr}}  {method:<{w_method}}  {rtype:<{w_rtype}}  {icount:>5}  {qname}")

    if len(matches) > limit:
        print(f"\n  ... {len(matches) - limit} more results (use --limit to show more)")
