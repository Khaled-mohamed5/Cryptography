#!/usr/bin/env python3
"""Enumerate every webpack chunk from a Next.js runtime + build manifest.

A crawler only sees the chunks a page happened to load. The webpack runtime
carries the full id->contenthash map for *all* lazily-loaded chunks, so
parsing it recovers the chunks the crawl never touched -- which is usually
where the interesting, rarely-shipped code lives (admin panels, feature-
flagged surfaces, internal tooling).

Emits one absolute URL per line on stdout.
"""

import argparse
import os
import re
import sys

# {123:"a1b2c3",456:"d4e5f6"} / {"123":"a1b2c3"} -- webpack's chunk hash map.
HASH_MAP = re.compile(r"\{((?:\s*[\"']?[\w\-]+[\"']?\s*:\s*[\"'][0-9a-f]{8,32}[\"']\s*,?){4,})\}")
PAIR = re.compile(r"[\"']?([\w\-]+)[\"']?\s*:\s*[\"']([0-9a-f]{8,32})[\"']")

# Template of the chunk URL, e.g. "static/chunks/" + e + "." + {..}[e] + ".js"
URL_TEMPLATE = re.compile(r"[\"']((?:static/)?chunks/[^\"']*?)[\"']\s*\+")

# Paths quoted inside _buildManifest.js / _ssgManifest.js
MANIFEST_PATH = re.compile(r"[\"']([\w\-./]+\.js)[\"']")


def enumerate_from_runtime(text, base):
    urls = set()
    prefixes = {m.group(1) for m in URL_TEMPLATE.finditer(text)}
    # Next.js default when the template is inlined/mangled beyond recognition.
    prefixes.add("static/chunks/")
    prefixes = {p if p.endswith("/") else p.rsplit("/", 1)[0] + "/" for p in prefixes}

    for m in HASH_MAP.finditer(text):
        pairs = PAIR.findall(m.group(1))
        if len(pairs) < 4:
            continue
        for cid, chash in pairs:
            for prefix in prefixes:
                urls.add(f"{base.rstrip('/')}/{prefix}{cid}.{chash}.js")
    return urls


def enumerate_from_manifest(text, base):
    urls = set()
    for m in MANIFEST_PATH.finditer(text):
        path = m.group(1).lstrip("/")
        if not path.startswith("static/"):
            path = "static/" + path if path.startswith("chunks/") else path
        urls.add(f"{base.rstrip('/')}/{path}")
    return urls


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("files", nargs="+",
                    help="webpack runtime and/or *Manifest.js files on disk")
    ap.add_argument("--base", default="https://monday.com/nhp/_next",
                    help="base URL that 'static/chunks/...' is resolved against")
    opts = ap.parse_args()

    out = set()
    for path in opts.files:
        if not os.path.isfile(path):
            print(f"[!] missing: {path}", file=sys.stderr)
            continue
        text = open(path, "r", encoding="utf-8", errors="replace").read()
        name = os.path.basename(path)
        before = len(out)
        if "Manifest" in name:
            out |= enumerate_from_manifest(text, opts.base)
        else:
            out |= enumerate_from_runtime(text, opts.base)
        print(f"[*] {name}: +{len(out) - before} chunk URLs", file=sys.stderr)

    for url in sorted(out):
        print(url)
    print(f"[*] {len(out)} unique chunk URLs total", file=sys.stderr)


if __name__ == "__main__":
    main()
