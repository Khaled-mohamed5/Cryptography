#!/usr/bin/env python3
"""
Find + pull + unpack source maps for every fetched JS file.

Two discovery paths:
  1. declared:  //# sourceMappingURL=...  (also the older //@ form)
  2. blind:     <js-url>.map  and  <dir>/<basename>.map

A recovered .map with sourcesContent gives you the ORIGINAL, unminified source
of the app - by far the highest-value artefact in JS recon. Unpacked trees land
in out/sourcemaps/<host>/<bundle>/.
"""
import base64, json, os, re, sys, time, urllib.parse, urllib.request, ssl, gzip, io

ROOT = os.path.dirname(os.path.abspath(__file__))
RAW = os.path.join(ROOT, "out", "raw")
DEST = os.path.join(ROOT, "out", "sourcemaps")
INDEX = os.path.join(ROOT, "out", "meta", "fetch-index.tsv")
UA = os.environ.get("RECON_UA",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0 Safari/537.36 (bugbounty)")
DELAY = float(os.environ.get("RECON_DELAY", "0.25"))

SM_RE = re.compile(rb"(?://|/\*)[#@]\s*sourceMappingURL\s*=\s*([^\s'\"*]+)")

def get(url, timeout=45):
    req = urllib.request.Request(url, headers={
        "User-Agent": UA, "Accept": "*/*", "Accept-Encoding": "gzip, deflate"})
    ctx = ssl.create_default_context()
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
        data = r.read()
        if r.headers.get("Content-Encoding") == "gzip":
            data = gzip.decompress(data)
        return r.status, data

def safe(name):
    return re.sub(r"[^A-Za-z0-9._-]", "_", name)[:150]

def unpack(mapping_bytes, outdir, origin):
    try:
        sm = json.loads(mapping_bytes.decode("utf-8", "replace"))
    except Exception as e:
        print(f"    [!] not valid JSON ({e})")
        return 0
    sources = sm.get("sources") or []
    contents = sm.get("sourcesContent") or []
    if not contents:
        print(f"    [!] map has no sourcesContent (names only: {len(sources)} sources)")
        os.makedirs(outdir, exist_ok=True)
        with open(os.path.join(outdir, "_sources.txt"), "w") as f:
            f.write("\n".join(sources))
        return 0
    n = 0
    for i, src in enumerate(sources):
        if i >= len(contents) or contents[i] is None:
            continue
        rel = src
        for pfx in ("webpack://", "webpack:///", "rollup://", "vite://"):
            if rel.startswith(pfx):
                rel = rel[len(pfx):]
        rel = rel.replace("://", "/").lstrip("/")
        rel = re.sub(r"\.\.[\\/]", "", rel)          # no traversal out of outdir
        rel = re.sub(r"[^A-Za-z0-9._/\\-]", "_", rel) or f"source_{i}.js"
        dst = os.path.normpath(os.path.join(outdir, rel))
        if not dst.startswith(os.path.abspath(outdir)):
            dst = os.path.join(outdir, f"source_{i}.js")
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        with open(dst, "w", encoding="utf-8", errors="replace") as f:
            f.write(contents[i])
        n += 1
    print(f"    [+] unpacked {n} original source files -> {os.path.relpath(outdir, ROOT)}")
    with open(os.path.join(outdir, "_origin.txt"), "w") as f:
        f.write(origin + "\n")
    return n

def main():
    if not os.path.isfile(INDEX):
        print("run ./01-fetch.sh first"); sys.exit(1)
    rows = [l.rstrip("\n").split("\t") for l in open(INDEX) if l.strip()]
    total_files = 0
    hits = []
    for code, size, url, path in rows:
        if code != "200" or not os.path.isfile(path):
            continue
        blob = open(path, "rb").read()

        candidates = []
        m = SM_RE.search(blob)
        if m:
            candidates.append(("declared", m.group(1).decode("utf-8", "replace")))
        base = url.split("?")[0]
        candidates.append(("blind", base + ".map"))

        for kind, cand in candidates:
            if cand.startswith("data:"):
                print(f"[*] {url}\n    inline data: sourcemap")
                try:
                    b64 = cand.split(",", 1)[1]
                    raw = base64.b64decode(b64)
                except Exception:
                    continue
                out = os.path.join(DEST, safe(urllib.parse.urlparse(url).netloc), safe(os.path.basename(base)))
                n = unpack(raw, out, url)
                if n: hits.append((url, "inline", n)); total_files += n
                break

            mapurl = urllib.parse.urljoin(base, cand)
            try:
                st, raw = get(mapurl)
            except Exception as e:
                if kind == "declared":
                    print(f"[*] {url}\n    [!] declared map {mapurl} -> {e}")
                time.sleep(DELAY)
                continue
            time.sleep(DELAY)
            if st == 200 and raw[:1] in (b"{", b"\xef"):
                print(f"[*] {url}\n    [+] {kind} sourcemap: {mapurl} ({len(raw)}B)")
                out = os.path.join(DEST, safe(urllib.parse.urlparse(url).netloc), safe(os.path.basename(base)))
                n = unpack(raw, out, mapurl)
                if n: hits.append((mapurl, kind, n)); total_files += n
                break

    print("\n=== SOURCEMAP SUMMARY ===")
    if not hits:
        print("no usable source maps recovered")
    for u, k, n in hits:
        print(f"  {n:5d} files  [{k}]  {u}")
    print(f"  total original source files recovered: {total_files}")

if __name__ == "__main__":
    main()
