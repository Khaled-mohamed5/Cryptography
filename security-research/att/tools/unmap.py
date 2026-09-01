#!/usr/bin/env python3
"""Reconstruct original sources from an exposed JavaScript source map.

    curl -s <bundle>.js.map -o main.js.map
    python3 unmap.py main.js.map ./src

Writes every embedded source file to <outdir>, preserving structure, then
prints a summary. Paths are sanitised so a crafted map cannot write outside
the output directory.
"""
import json, sys, pathlib

def main(map_path, out_dir):
    m = json.load(open(map_path, encoding="utf-8"))
    sources = m.get("sources") or []
    contents = m.get("sourcesContent") or []

    if not contents:
        print("No sourcesContent — map has references only, not the source itself.")
        print(f"{len(sources)} source paths listed:")
        for s in sources[:60]:
            print("  ", s)
        return

    out = pathlib.Path(out_dir).resolve()
    written = skipped = 0
    for name, content in zip(sources, contents):
        if content is None:
            skipped += 1
            continue
        # strip webpack:// style prefixes and any traversal
        rel = name.split("://", 1)[-1].replace("..", "").lstrip("/")
        if not rel:
            rel = f"unnamed_{written}.js"
        dest = (out / rel).resolve()
        if not str(dest).startswith(str(out)):   # path traversal guard
            skipped += 1
            continue
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(content, encoding="utf-8")
        written += 1

    print(f"wrote {written} files to {out}  ({skipped} skipped)")
    app = [s for s in sources if "node_modules" not in s]
    print(f"\n{len(app)} application files (excluding node_modules):")
    for s in sorted(app)[:80]:
        print("  ", s)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2])
