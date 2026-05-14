"""
Repair return type inference in disasm.json using a Frida capture log.

Workflow:
  1. elfinfo frida disasm.json --out hooks.js
  2. frida -n <process> -l hooks.js > capture.log
  3. elfinfo frida-repair disasm.json capture.log

The capture log is the stdout of the Frida script — one JSON object per line.
Lines that are not valid JSON are skipped (covers Frida console messages).

Confidence rules (MIN_SAMPLES observations required before overriding):
  - All values 0 or 1              → bool
  - All values in pointer range    → void* / T* (pointer)
  - All values fit in int32        → int
  - Mix of 0 and pointer-range     → int / pointer (variable)
  - Consistent with current type   → no change
"""
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

MIN_SAMPLES    = 5
POINTER_THRESH = 0x10000  # values above this treated as pointers


def _classify_samples(raws: list) -> str | None:
    """
    Given a list of observed return values (int, bool, or hex string),
    return a corrected return type string, or None to leave unchanged.
    """
    ints: list[int] = []
    for v in raws:
        try:
            if isinstance(v, bool):
                ints.append(int(v))
            elif isinstance(v, int):
                ints.append(v)
            elif isinstance(v, str) and v.startswith("0x"):
                ints.append(int(v, 16))
            elif isinstance(v, str):
                ints.append(int(v))
            elif isinstance(v, float):
                # float return — trust existing inference
                return None
        except (ValueError, TypeError):
            return None

    if not ints:
        return None

    all_bool    = all(v in (0, 1) for v in ints)
    all_ptr     = all(v >= POINTER_THRESH or v == 0 for v in ints)
    all_int32   = all(-(2**31) <= v <= 2**31 - 1 for v in ints)
    has_nonzero = any(v != 0 for v in ints)

    if all_bool and has_nonzero:
        return "bool"
    if all_ptr:
        return "void* / T* (pointer)"
    if all_int32:
        return "int"
    return "int / pointer (variable)"


def repair(
    disasm_json: str | Path,
    capture_log: str | Path,
    min_samples: int = MIN_SAMPLES,
    no_regen:    bool = False,
    outdir:      str | Path | None = None,
) -> None:
    disasm_json = Path(disasm_json)
    capture_log = Path(capture_log)

    if not disasm_json.exists():
        print(f"error: {disasm_json} not found", file=sys.stderr)
        sys.exit(1)
    if not capture_log.exists():
        print(f"error: {capture_log} not found", file=sys.stderr)
        sys.exit(1)

    with open(disasm_json) as f:
        data = json.load(f)

    # Parse capture log — group samples by RVA (fall back to name)
    samples: dict[str, list] = defaultdict(list)  # rva_hex → [ret_values]
    name_to_rva: dict[str, str] = {}
    skipped = 0

    with open(capture_log) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("[elfinfo]"):
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                skipped += 1
                continue
            rva = rec.get("rva")
            if not rva:
                # fall back to name matching
                name = rec.get("fn", "")
                rva  = name_to_rva.get(name)
                if not rva:
                    continue
            ret = rec.get("ret")
            if ret is not None:
                samples[str(rva)].append(ret)

    if skipped:
        print(f"  skipped {skipped} non-JSON lines in capture log")

    # Build rva → function index map from disasm.json
    rva_map: dict[str, int] = {}
    for i, fn in enumerate(data["functions"]):
        rva_hex = fn.get("addr", "")
        rva_map[rva_hex] = i
        # also index by normalised hex (strip leading zeros)
        try:
            rva_map[hex(int(rva_hex, 16))] = i
        except (ValueError, TypeError):
            pass

    # Apply corrections
    patched    = 0
    unchanged  = 0
    low_sample = 0

    for rva_key, obs in samples.items():
        if len(obs) < min_samples:
            low_sample += 1
            continue

        idx = rva_map.get(rva_key)
        if idx is None:
            # try normalising
            try:
                idx = rva_map.get(hex(int(rva_key, 16)))
            except (ValueError, TypeError):
                pass
        if idx is None:
            continue

        fn      = data["functions"][idx]
        current = fn.get("return_type", "unknown")
        inferred = _classify_samples(obs)

        if inferred and inferred != current:
            fn["return_type"]       = inferred
            fn["return_type_source"] = "frida"
            fn["return_type_samples"] = len(obs)
            patched += 1
        else:
            unchanged += 1

    print(f"  capture log : {capture_log.name}  ({sum(len(v) for v in samples.values())} observations, {len(samples)} functions)")
    print(f"  patched     : {patched}")
    print(f"  unchanged   : {unchanged}")
    print(f"  low samples : {low_sample}  (< {min_samples} observations, skipped)")

    # Write patched JSON
    with open(disasm_json, "w") as f:
        json.dump(data, f, indent=2)
    print(f"  wrote       : {disasm_json}")

    if no_regen or patched == 0:
        return

    # Regenerate markdown for patched functions only
    print(f"  regenerating {patched} markdown file(s) ...")
    _regen_changed(data, disasm_json, outdir)


def _regen_changed(data: dict, disasm_json: Path, outdir: str | Path | None) -> None:
    from elfinfo.render import to_disasm_markdown

    syntax = data.get("syntax", "att")

    if outdir:
        md_root = Path(outdir)
    else:
        # Guess: disasm.json lives in <root>/disasm/disasm.json
        md_root = disasm_json.parent / "md"

    if not md_root.exists():
        print(f"  warning: markdown dir {md_root} not found, skipping regen")
        return

    # Full regen is simplest — selective would require threading outdir through
    # the whole render tree which adds complexity for little gain on disk.
    to_disasm_markdown(
        data.get("file", "unknown"),
        data["functions"],
        md_root,
        syntax=syntax,
    )
    print(f"  wrote       : {md_root}/")
