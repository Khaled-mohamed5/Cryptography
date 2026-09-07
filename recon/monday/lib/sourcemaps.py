#!/usr/bin/env python3
"""Locate and unpack JavaScript source maps.

Two discovery modes:
  declared - honour the //# sourceMappingURL= comment in each bundle
  blind    - probe <bundle>.map even when no comment survives minification

An exposed .map on a production bundle hands you original, unminified,
commented source -- comments, dead code, internal endpoints and all. That is
worth reporting on its own, and it makes every other check far more accurate.
"""

import argparse
import json
import os
import re
import sys
from urllib.parse import urljoin

SOURCE_MAP_COMMENT = re.compile(r"//[#@]\s*sourceMappingURL=([^\s*'\"]+)")


def declared_map_urls(js_dir, url_index):
    """Yield (bundle_rel_path, absolute_map_url) for every declared map."""
    for root, _dirs, files in os.walk(js_dir):
        for fn in sorted(files):
            if not fn.endswith(".js"):
                continue
            full = os.path.join(root, fn)
            rel = os.path.relpath(full, js_dir)
            try:
                tail = open(full, "r", encoding="utf-8", errors="replace").read()[-4096:]
            except OSError:
                continue
            m = SOURCE_MAP_COMMENT.search(tail)
            if not m:
                continue
            ref = m.group(1)
            if ref.startswith("data:"):
                yield rel, "data:(inline)"
                continue
            origin = url_index.get(rel)
            yield rel, urljoin(origin, ref) if origin else ref


def unpack(map_path, outdir):
    """Write sourcesContent out as a browsable tree. Returns file count."""
    try:
        data = json.load(open(map_path, "r", encoding="utf-8", errors="replace"))
    except (OSError, ValueError) as exc:
        print(f"[!] {os.path.basename(map_path)}: not valid JSON ({exc})", file=sys.stderr)
        return 0

    sources = data.get("sources") or []
    contents = data.get("sourcesContent") or []
    if not contents:
        print(f"[!] {os.path.basename(map_path)}: no sourcesContent "
              f"({len(sources)} source paths only)", file=sys.stderr)
        return 0

    written = 0
    for name, body in zip(sources, contents):
        if body is None:
            continue
        # Normalise webpack:// style names into a safe relative path.
        clean = re.sub(r"^\w+://", "", name)
        clean = clean.replace("\\", "/").lstrip("/")
        parts = [p for p in clean.split("/") if p not in ("", ".", "..")]
        if not parts:
            continue
        dest = os.path.join(outdir, *parts)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        with open(dest, "w", encoding="utf-8") as fh:
            fh.write(body)
        written += 1
    return written


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("discover", help="list source map URLs to try")
    d.add_argument("js_dir")
    d.add_argument("--url-index", help="TSV of 'relpath<TAB>url' for resolving relative refs")
    d.add_argument("--blind", action="store_true",
                   help="also emit <bundle>.map for every bundle")

    u = sub.add_parser("unpack", help="expand downloaded .map files to source")
    u.add_argument("map_dir")
    u.add_argument("outdir")

    opts = ap.parse_args()

    if opts.cmd == "discover":
        index = {}
        if opts.url_index and os.path.isfile(opts.url_index):
            for line in open(opts.url_index):
                if "\t" in line:
                    rel, url = line.rstrip("\n").split("\t", 1)
                    index[rel] = url
        seen = set()
        for rel, map_url in declared_map_urls(opts.js_dir, index):
            if map_url.startswith("data:"):
                print(f"[*] {rel}: inline source map embedded in bundle", file=sys.stderr)
                continue
            if map_url not in seen:
                seen.add(map_url)
                print(map_url)
        if opts.blind:
            for rel, url in sorted(index.items()):
                cand = url.split("?")[0] + ".map"
                if cand not in seen:
                    seen.add(cand)
                    print(cand)
        print(f"[*] {len(seen)} candidate source map URLs", file=sys.stderr)
        return

    total_maps = total_files = 0
    for root, _dirs, files in os.walk(opts.map_dir):
        for fn in sorted(files):
            if not fn.endswith(".map"):
                continue
            n = unpack(os.path.join(root, fn), opts.outdir)
            if n:
                total_maps += 1
                total_files += n
                print(f"[+] {fn}: {n} original sources recovered")
    print(f"[*] {total_files} source files from {total_maps} maps -> {opts.outdir}/")


if __name__ == "__main__":
    main()
