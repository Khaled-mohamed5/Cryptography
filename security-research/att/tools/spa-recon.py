#!/usr/bin/env python3
"""Quiet reconnaissance of a JavaScript single-page application.

    python3 spa-recon.py https://host/

Makes a small, bounded number of requests: one for the page, one per JS
bundle, and one HEAD per candidate source map. No wordlists, no brute
forcing, one request at a time with a delay. Designed to stay under bot
management thresholds.

Findings are printed, not acted on. Nothing is exploited.
"""
import re, sys, time, json, gzip, io
import urllib.request, urllib.error
from urllib.parse import urljoin, urlparse

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
DELAY = 1.5
TIMEOUT = 30

def get(url, method="GET"):
    req = urllib.request.Request(url, method=method, headers={
        "User-Agent": UA, "Accept": "*/*", "Accept-Encoding": "gzip, identity"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            raw = r.read() if method == "GET" else b""
            if r.headers.get("Content-Encoding") == "gzip" and raw:
                raw = gzip.GzipFile(fileobj=io.BytesIO(raw)).read()
            return r.status, raw.decode("utf-8", "replace"), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, "", dict(e.headers or {})
    except Exception as e:
        return 0, f"{type(e).__name__}: {e}", {}

def uniq(xs):
    return sorted(set(xs))

def show(title, items, limit=40):
    if not items:
        return
    print(f"\n=== {title} ({len(items)}) ===")
    for i in items[:limit]:
        print("  ", i)
    if len(items) > limit:
        print(f"   ... {len(items)-limit} more")

def main(base):
    print(f"[*] {base}")
    status, html, hdrs = get(base)
    print(f"[*] page: HTTP {status}, {len(html)} bytes")
    if hdrs.get("Server"):
        print(f"[*] server: {hdrs['Server']}")
    if status != 200 or not html:
        print("[!] no page content; stopping")
        return

    title = re.search(r"<title[^>]*>(.*?)</title>", html, re.S | re.I)
    if title:
        print(f"[*] title: {title.group(1).strip()[:120]}")

    # scripts and stylesheets referenced by the page
    assets = uniq(re.findall(r'(?:src|href)=["\']([^"\']+\.js)["\']', html))
    scripts = [urljoin(base, a) for a in assets if not a.startswith("data:")]
    show("JS bundles referenced", scripts)

    api, hosts, routes, secrets, maps = [], [], [], [], []
    for s in scripts:
        time.sleep(DELAY)
        st, body, _ = get(s)
        print(f"\n[*] {s} -> HTTP {st}, {len(body)} bytes")
        if st != 200 or not body:
            continue

        api += re.findall(r'["\'`](/(?:api|v\d|rest|graphql|services?|gateway)[A-Za-z0-9._/{}$-]*)', body)
        hosts += re.findall(r'https?://[A-Za-z0-9.-]+\.[a-z]{2,}[A-Za-z0-9._/-]*', body)
        routes += re.findall(r'path\s*:\s*["\']([^"\']+)', body)
        secrets += re.findall(
            r'["\']?([A-Za-z_]*(?:api[_-]?key|secret|token|password|bearer)[A-Za-z_]*)["\']?\s*[:=]\s*["\']([^"\']{8,80})["\']',
            body, re.I)

        # source map: declared, then conventional
        m = re.search(r'sourceMappingURL=([^\s*]+)', body)
        cands = [urljoin(s, m.group(1))] if m else []
        cands.append(s + ".map")
        for c in uniq(cands):
            time.sleep(DELAY)
            ms, _, _ = get(c, "HEAD")
            print(f"    source map {c} -> HTTP {ms}")
            if ms == 200:
                maps.append(c)

    show("API paths", uniq(api))
    show("client-side routes", uniq(routes))
    show("external hosts", [h for h in uniq(hosts)
                            if not re.search(r"(w3\.org|schema\.org|reactjs|redux|nextjs|github\.com|npmjs|jquery|mozilla)", h)])
    if secrets:
        print(f"\n=== candidate secrets ({len(secrets)}) — VERIFY, most are public identifiers ===")
        for k, v in uniq(secrets)[:25]:
            print(f"   {k} = {v[:60]}")
    if maps:
        print(f"\n=== SOURCE MAPS EXPOSED ({len(maps)}) ===")
        for m_ in maps:
            print("  ", m_)
        print("\n   Retrieve and expand with unmap.py — that is the real prize.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(sys.argv[1])
