#!/usr/bin/env python3
"""
jsrecon - fetch and statically analyse JavaScript assets discovered by a crawler.

Two stages, usable independently:

    python3 jsrecon.py fetch   -i js-urls.txt -o out
    python3 jsrecon.py analyze -i out        -o reports --target-domain monday.com

Stdlib only. Honours HTTP(S)_PROXY from the environment.
Passive analysis of publicly served assets: it issues plain GETs, nothing else.
"""

import argparse
import base64
import binascii
import gzip
import hashlib
import io
import json
import math
import os
import re
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

DEFAULT_UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")

# --------------------------------------------------------------------------- #
# fetch
# --------------------------------------------------------------------------- #

_print_lock = threading.Lock()


def log(*a):
    with _print_lock:
        print(*a, file=sys.stderr, flush=True)


def safe_name(url):
    """Deterministic on-disk name: <sha1[:10]>__<basename>."""
    h = hashlib.sha1(url.encode()).hexdigest()[:10]
    base = urllib.parse.urlsplit(url).path.rsplit("/", 1)[-1] or "index.js"
    base = re.sub(r"[^A-Za-z0-9._-]", "_", base)[:80]
    return f"{h}__{base}"


def http_get(url, ua, timeout, retries=3):
    req = urllib.request.Request(url, headers={
        "User-Agent": ua,
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "close",
    })
    last = None
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                raw = r.read()
                if r.headers.get("Content-Encoding", "").lower() == "gzip":
                    try:
                        raw = gzip.GzipFile(fileobj=io.BytesIO(raw)).read()
                    except OSError:
                        pass
                return r.status, dict(r.headers), raw
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers or {}), e.read()
        except Exception as e:                                    # noqa: BLE001
            last = e
            time.sleep(2 ** attempt)
    return 0, {}, str(last).encode()


SOURCEMAP_RE = re.compile(rb"//[#@]\s*sourceMappingURL=([^\s*'\"]+)")


def cmd_fetch(args):
    urls = []
    seen = set()
    with open(args.input) as fh:
        for line in fh:
            u = line.strip()
            if u and not u.startswith("#") and u not in seen:
                seen.add(u)
                urls.append(u)

    files_dir = os.path.join(args.output, "files")
    os.makedirs(files_dir, exist_ok=True)
    manifest_path = os.path.join(args.output, "manifest.jsonl")

    done = set()
    if args.resume and os.path.exists(manifest_path):
        with open(manifest_path) as fh:
            for line in fh:
                try:
                    done.add(json.loads(line)["url"])
                except Exception:                                 # noqa: BLE001
                    pass
        log(f"[*] resume: {len(done)} already fetched")

    todo = [u for u in urls if u not in done]
    log(f"[*] {len(todo)} to fetch (of {len(urls)} unique), "
        f"concurrency={args.concurrency}, delay={args.delay}s")

    mf = open(manifest_path, "a")
    counter = {"ok": 0, "fail": 0}

    def work(url):
        time.sleep(args.delay)
        status, headers, body = http_get(url, args.user_agent, args.timeout)
        rec = {
            "url": url,
            "status": status,
            "bytes": len(body),
            "sha256": hashlib.sha256(body).hexdigest(),
            "content_type": headers.get("Content-Type", ""),
            "server": headers.get("Server", ""),
            "cache_control": headers.get("Cache-Control", ""),
            "last_modified": headers.get("Last-Modified", ""),
            "sourcemap": None,
            "file": None,
        }
        if status == 200 and body:
            name = safe_name(url)
            with open(os.path.join(files_dir, name), "wb") as fh:
                fh.write(body)
            rec["file"] = name
            m = SOURCEMAP_RE.search(body[-4096:]) or SOURCEMAP_RE.search(body)
            if m:
                rec["sourcemap"] = m.group(1).decode("utf-8", "replace")
            counter["ok"] += 1
        else:
            counter["fail"] += 1
        with _print_lock:
            mf.write(json.dumps(rec) + "\n")
            mf.flush()
        log(f"    {status:>3} {rec['bytes']:>9} {url}")

        # Optional: chase the source map -- a hit reconstructs original sources.
        if args.maps and rec["file"]:
            cands = []
            if rec["sourcemap"] and not rec["sourcemap"].startswith("data:"):
                cands.append(urllib.parse.urljoin(url, rec["sourcemap"]))
            cands.append(url.split("?")[0] + ".map")
            for c in dict.fromkeys(cands):
                st, _, b = http_get(c, args.user_agent, args.timeout, retries=1)
                if st == 200 and b.lstrip()[:1] == b"{":
                    mp = os.path.join(files_dir, safe_name(c) + ".map")
                    with open(mp, "wb") as fh:
                        fh.write(b)
                    log(f"    MAP {len(b):>9} {c}")
                    break

    with ThreadPoolExecutor(max_workers=args.concurrency) as ex:
        list(ex.map(work, todo))
    mf.close()
    log(f"[*] done: {counter['ok']} ok, {counter['fail']} failed -> {args.output}")


# --------------------------------------------------------------------------- #
# analyze
# --------------------------------------------------------------------------- #

def shannon(s):
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in freq.values())


# (name, regex, high_confidence)
SECRET_RULES = [
    ("aws_access_key_id",      r"\b((?:A3T[A-Z0-9]|AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16})\b", True),
    ("aws_secret_hint",        r"(?i)aws[_-]?(?:secret|sk)[_-]?(?:access)?[_-]?key\W{1,4}([A-Za-z0-9/+=]{40})", True),
    ("google_api_key",         r"\b(AIza[0-9A-Za-z_\-]{35})\b", True),
    ("gcp_oauth_client",       r"\b([0-9]+-[0-9a-z_]{32}\.apps\.googleusercontent\.com)\b", True),
    ("firebase_db",            r"\b([a-z0-9-]+\.firebaseio\.com)\b", True),
    ("stripe_key",             r"\b((?:sk|rk|pk)_(?:live|test)_[0-9A-Za-z]{16,})\b", True),
    ("slack_token",            r"\b(xox[baprs]-[0-9A-Za-z-]{10,})\b", True),
    ("slack_webhook",          r"(https://hooks\.slack\.com/services/[A-Za-z0-9/+_-]+)", True),
    ("github_token",           r"\b((?:ghp|gho|ghu|ghs|ghr|github_pat)_[0-9A-Za-z_]{20,})\b", True),
    ("gitlab_token",           r"\b(glpat-[0-9A-Za-z_-]{20,})\b", True),
    ("npm_token",              r"\b(npm_[0-9A-Za-z]{36})\b", True),
    ("sendgrid_key",           r"\b(SG\.[0-9A-Za-z_-]{16,}\.[0-9A-Za-z_-]{16,})\b", True),
    ("twilio_sid",             r"\b(AC[0-9a-f]{32})\b", True),
    ("mailgun_key",            r"\b(key-[0-9a-f]{32})\b", True),
    ("mailchimp_key",          r"\b([0-9a-f]{32}-us[0-9]{1,2})\b", True),
    ("openai_key",             r"\b(sk-[A-Za-z0-9_-]{20,})\b", True),
    ("anthropic_key",          r"\b(sk-ant-[A-Za-z0-9_-]{20,})\b", True),
    ("private_key_block",      r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----)", True),
    ("jwt",                    r"\b(eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})\b", True),
    ("basic_auth_url",         r"\b(https?://[^/\s:@\"']+:[^/\s:@\"']+@[A-Za-z0-9.-]+)", True),
    # Third-party client-side identifiers: usually public by design, but they
    # map the vendor stack and occasionally carry write scope.
    ("sentry_dsn",             r"(https://[0-9a-f]{16,}@[a-z0-9.-]*sentry[a-z0-9.-]*/[0-9]+)", False),
    ("segment_write_key",      r"(?i)\bwriteKey\W{1,6}[\"']([A-Za-z0-9]{20,})[\"']", False),
    ("launchdarkly_id",        r"(?i)launchdarkly[^\n]{0,40}?[\"']([0-9a-f]{24})[\"']", False),
    ("mixpanel_token",         r"(?i)mixpanel[^\n]{0,60}?[\"']([0-9a-f]{32})[\"']", False),
    ("amplitude_key",          r"(?i)amplitude[^\n]{0,60}?[\"']([0-9a-f]{32})[\"']", False),
    ("algolia_key",            r"(?i)algolia[^\n]{0,60}?[\"']([0-9a-f]{32})[\"']", False),
    ("mapbox_token",           r"\b(pk\.eyJ[A-Za-z0-9_.-]{20,})\b", False),
    ("recaptcha_site_key",     r"\b(6L[0-9A-Za-z_-]{38})\b", False),
    ("google_analytics",       r"\b((?:UA-[0-9]{4,}-[0-9]{1,4}|G-[A-Z0-9]{8,12}|GTM-[A-Z0-9]{5,8}))\b", False),
    # Generic assignment - noisy, entropy-filtered below.
    ("generic_secret_assign",
     r"(?i)[\"']?\b(?:api[_-]?key|apikey|secret|client[_-]?secret|auth[_-]?token|access[_-]?token|"
     r"private[_-]?key|passwd|password)\b[\"']?\s*[:=]\s*[\"']([^\"'\s]{12,80})[\"']", False),
]

CONTEXT_RULES = [
    ("endpoint_path",    r"[\"'`](/(?:api|v[0-9]|graphql|internal|admin|_next/data|rest|rpc|auth|oauth|"
                         r"webhook|callback|upload|download|export|import|debug|health|status|config|"
                         r"settings|account|user|users|billing|payment|subscription)[A-Za-z0-9_\-./{}$:]*)[\"'`]"),
    ("graphql_op",       r"\b(?:query|mutation|subscription)\s+([A-Za-z][A-Za-z0-9_]{2,})\s*[({]"),
    ("absolute_url",     r"https?://[A-Za-z0-9.\-]+\.[A-Za-z]{2,}(?:/[^\s\"'`<>\\)]{0,120})?"),
    ("s3_bucket",        r"\b([A-Za-z0-9.\-]+\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com|s3://[A-Za-z0-9.\-/]+)\b"),
    ("gcs_bucket",       r"\b(storage\.googleapis\.com/[A-Za-z0-9._\-/]+|gs://[A-Za-z0-9._\-/]+)\b"),
    ("azure_blob",       r"\b([a-z0-9]+\.blob\.core\.windows\.net[A-Za-z0-9._\-/]*)\b"),
    ("internal_host",    r"(?<![\w.-])((?:[a-z0-9][a-z0-9-]+\.)+(?:internal|local|corp|intranet)\b"
                         r"|(?<![\w.-])(?:[a-z0-9][a-z0-9-]+\.)*(?:staging|stage|qa|uat|preprod|dev|test|"
                         r"sandbox|internal|admin)\.[a-z0-9-]{2,}\.[a-z]{2,6})\b"),
    ("ip_address",       r"\b((?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}"
                         r"(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9]))\b"),
    ("email",            r"\b([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})\b"),
    ("feature_flag",     r"[\"'{,]\s*[\"']?((?:ff|flag|feature|enable|is|has|show|use)[_-][A-Za-z0-9_-]{4,60})[\"']?\s*[:,}]"),
    ("env_var",          r"\b(?:process\.env|NEXT_PUBLIC_|REACT_APP_|VUE_APP_|import\.meta\.env)"
                         r"[.\[]?[\"']?([A-Za-z_][A-Za-z0-9_]{2,60})"),
    ("storage_key",      r"(?:localStorage|sessionStorage)\.(?:get|set|remove)Item\(\s*[\"'`]([^\"'`]{1,60})"),
    ("cookie_name",      r"(?:Cookies|cookie)\.(?:set|get|remove)\(\s*[\"'`]([^\"'`]{1,60})"),
    # DOM-sink / message-handler leads for manual XSS review.
    ("dom_sink",         r"\b(innerHTML|outerHTML|insertAdjacentHTML|document\.write(?:ln)?|"
                         r"dangerouslySetInnerHTML|eval\(|new Function\(|srcdoc)\b"),
    ("postmessage",      r"\b(postMessage\(|addEventListener\(\s*[\"']message[\"'])"),
    ("url_param_read",   r"\b(?:URLSearchParams|searchParams\.get|getParameterByName)\s*\(?\s*[\"']?"
                         r"([A-Za-z0-9_\-]{2,40})?"),
]

BIN_EXT = (".map",)


def iter_files(indir):
    files_dir = os.path.join(indir, "files")
    root = files_dir if os.path.isdir(files_dir) else indir
    for dirpath, _, names in os.walk(root):
        for n in sorted(names):
            yield os.path.join(dirpath, n)


def load_url_map(indir):
    """file basename -> source url, from the fetch manifest."""
    m = {}
    mp = os.path.join(indir, "manifest.jsonl")
    if os.path.exists(mp):
        with open(mp) as fh:
            for line in fh:
                try:
                    r = json.loads(line)
                except Exception:                                 # noqa: BLE001
                    continue
                if r.get("file"):
                    m[r["file"]] = r["url"]
    return m


def cmd_analyze(args):
    os.makedirs(args.output, exist_ok=True)
    url_map = load_url_map(args.input)
    target = args.target_domain
    sub_re = re.compile(r"\b((?:[A-Za-z0-9_-]+\.)+" + re.escape(target) + r")\b") if target else None

    secret_rx = [(n, re.compile(p), hc) for n, p, hc in SECRET_RULES]
    ctx_rx = [(n, re.compile(p)) for n, p in CONTEXT_RULES]

    findings = []          # secrets, with file+context
    buckets = {n: {} for n, _ in CONTEXT_RULES}
    subdomains = {}
    per_file = []

    for path in iter_files(args.input):
        name = os.path.basename(path)
        try:
            with open(path, "rb") as fh:
                blob = fh.read()
        except OSError:
            continue
        text = blob.decode("utf-8", "replace")
        src = url_map.get(name, name)
        hits_here = 0

        for rname, rx, high in secret_rx:
            for m in rx.finditer(text):
                val = m.group(1) if m.groups() else m.group(0)
                if not high:
                    if rname == "generic_secret_assign":
                        # kill obvious template/placeholder noise
                        if re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]*", val):
                            continue
                        if any(k in val.lower() for k in
                               ("undefined", "null", "example", "your", "xxx", "placeholder",
                                "changeme", "dummy", "test", "%s", "${", "{{")):
                            continue
                        if shannon(val) < args.min_entropy:
                            continue
                s = max(0, m.start() - 60)
                ctx = re.sub(r"\s+", " ", text[s:m.end() + 60])
                findings.append({
                    "rule": rname, "confidence": "high" if high else "review",
                    "value": val, "file": name, "url": src, "offset": m.start(),
                    "context": ctx,
                })
                hits_here += 1

        for rname, rx in ctx_rx:
            for m in rx.finditer(text):
                val = (m.group(1) if m.groups() and m.group(1) else m.group(0)).strip()
                if not val or len(val) > 200:
                    continue
                b = buckets[rname]
                if val not in b:
                    b[val] = set()
                if len(b[val]) < 8:
                    b[val].add(src)

        if sub_re:
            for m in sub_re.finditer(text):
                subdomains.setdefault(m.group(1).lower(), set()).add(src)

        per_file.append({"file": name, "url": src, "bytes": len(blob),
                         "secret_hits": hits_here})

    # ---- write outputs ---------------------------------------------------- #
    def dump(fname, mapping):
        p = os.path.join(args.output, fname)
        with open(p, "w") as fh:
            for k in sorted(mapping):
                fh.write(f"{k}\n")
        return p

    with open(os.path.join(args.output, "findings.jsonl"), "w") as fh:
        for f in findings:
            fh.write(json.dumps(f) + "\n")

    for rname in buckets:
        if buckets[rname]:
            dump(f"{rname}.txt", buckets[rname])
    if subdomains:
        dump("subdomains.txt", subdomains)

    high = [f for f in findings if f["confidence"] == "high"]
    review = [f for f in findings if f["confidence"] != "high"]

    rp = os.path.join(args.output, "report.md")
    with open(rp, "w") as fh:
        fh.write("# JS static analysis\n\n")
        fh.write(f"- files analysed: **{len(per_file)}**\n")
        fh.write(f"- bytes analysed: **{sum(p['bytes'] for p in per_file):,}**\n")
        fh.write(f"- high-confidence secret matches: **{len(high)}**\n")
        fh.write(f"- matches needing review: **{len(review)}**\n\n")

        fh.write("## Extracted inventory\n\n| category | unique |\n|---|---|\n")
        for rname in buckets:
            if buckets[rname]:
                fh.write(f"| {rname} | {len(buckets[rname])} |\n")
        if subdomains:
            fh.write(f"| subdomains ({target}) | {len(subdomains)} |\n")

        if high:
            fh.write("\n## High-confidence matches\n\n")
            for f in high:
                fh.write(f"- **{f['rule']}** `{f['value'][:60]}`\n"
                         f"  - {f['url']} @ {f['offset']}\n"
                         f"  - `{f['context'][:200]}`\n")
        if review:
            fh.write("\n## Needs review (entropy-filtered, expect false positives)\n\n")
            for f in review[:args.max_review]:
                fh.write(f"- **{f['rule']}** `{f['value'][:60]}` — {f['url']}\n")
            if len(review) > args.max_review:
                fh.write(f"\n_({len(review) - args.max_review} more in findings.jsonl)_\n")

        if subdomains:
            fh.write("\n## Subdomains\n\n")
            for s in sorted(subdomains):
                fh.write(f"- `{s}`\n")

        fh.write("\n## Largest files\n\n")
        for p in sorted(per_file, key=lambda x: -x["bytes"])[:25]:
            fh.write(f"- {p['bytes']:>9,}  {p['url']}\n")

    log(f"[*] analysed {len(per_file)} files -> {args.output}")
    log(f"[*] high={len(high)} review={len(review)}  report: {rp}")


# --------------------------------------------------------------------------- #

def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    f = sub.add_parser("fetch", help="download JS assets from a URL list")
    f.add_argument("-i", "--input", required=True, help="file with one URL per line")
    f.add_argument("-o", "--output", required=True, help="output directory")
    f.add_argument("-c", "--concurrency", type=int, default=4)
    f.add_argument("-d", "--delay", type=float, default=0.25, help="per-request delay (politeness)")
    f.add_argument("-t", "--timeout", type=float, default=30)
    f.add_argument("-A", "--user-agent", default=DEFAULT_UA)
    f.add_argument("--maps", action="store_true", help="also try to pull .map source maps")
    f.add_argument("--resume", action="store_true", default=True)
    f.set_defaults(func=cmd_fetch)

    a = sub.add_parser("analyze", help="regex-analyse downloaded JS")
    a.add_argument("-i", "--input", required=True, help="fetch output directory (or a dir of .js)")
    a.add_argument("-o", "--output", required=True, help="report directory")
    a.add_argument("--target-domain", default=None, help="e.g. monday.com, for subdomain extraction")
    a.add_argument("--min-entropy", type=float, default=3.2)
    a.add_argument("--max-review", type=int, default=300)
    a.set_defaults(func=cmd_analyze)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
