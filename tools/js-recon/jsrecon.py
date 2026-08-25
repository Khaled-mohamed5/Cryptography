#!/usr/bin/env python3
"""
jsrecon - static analysis for JavaScript bundles collected during authorized
web application security testing.

Stdlib only. Two modes:

    python3 jsrecon.py fetch   -t targets.txt -o ./js        # download assets
    python3 jsrecon.py analyze -d ./js -o report.md          # analyze a directory

Design notes
------------
Modern bundles (Turbo/Stimulus/Trix/vendor libs) are full of `innerHTML` and
friends. A flat grep produces hundreds of hits and buries the real ones. So
sink matches are scored by *proximity to a controllable source*: a sink whose
surrounding window mentions `location.hash`, `event.data`, `dataset`, etc. is
ranked HIGH; an isolated sink in vendor code is ranked INFO.
"""

import argparse
import base64
import concurrent.futures as futures
import hashlib
import json
import math
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter, defaultdict

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0 Safari/537.36"

# --------------------------------------------------------------------------
# Pattern catalog
# --------------------------------------------------------------------------

# (name, regex, severity, note)
SECRET_PATTERNS = [
    ("aws_access_key_id",      r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b", "CRITICAL", "AWS access key ID"),
    ("aws_secret_guess",       r"(?i)aws.{0,24}?(?:secret|private).{0,24}?['\"][A-Za-z0-9/+=]{40}['\"]", "CRITICAL", "AWS secret access key"),
    ("private_key_block",      r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY", "CRITICAL", "Embedded private key"),
    ("stripe_secret",          r"\b(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{16,}\b", "CRITICAL", "Stripe secret/restricted key"),
    ("slack_token",            r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b", "CRITICAL", "Slack token"),
    ("github_token",           r"\bgh[pousr]_[A-Za-z0-9]{36,}\b", "CRITICAL", "GitHub token"),
    ("google_api_key",         r"\bAIza[0-9A-Za-z_\-]{35}\b", "HIGH", "Google API key - check referrer restrictions"),
    ("gcp_service_account",    r"\"type\"\s*:\s*\"service_account\"", "CRITICAL", "GCP service account JSON"),
    ("stripe_publishable",     r"\bpk_(?:live|test)_[0-9a-zA-Z]{16,}\b", "INFO", "Stripe publishable key (public by design)"),
    ("sentry_dsn",             r"https://[0-9a-f]{32}@[A-Za-z0-9.\-]+/[0-9]+", "MEDIUM", "Sentry DSN"),
    ("appsignal_key",          r"(?i)(?:appsignal[_\-]?)?(?:push[_\-]?api[_\-]?key|frontend[_\-]?key)\s*[:=]\s*['\"][A-Za-z0-9\-]{8,}['\"]", "MEDIUM", "AppSignal key - frontend keys are semi-public, verify it is not the backend push key"),
    ("twilio_sid",             r"\bAC[0-9a-fA-F]{32}\b", "HIGH", "Twilio Account SID"),
    ("twilio_key",             r"\bSK[0-9a-fA-F]{32}\b", "CRITICAL", "Twilio API key SID"),
    ("mapbox_token",           r"\bpk\.eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}", "MEDIUM", "Mapbox token"),
    ("jwt",                    r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}", "HIGH", "JWT - decode it, check for embedded claims/roles"),
    ("pusher_key",             r"(?i)pusher.{0,20}?key\s*[:=]\s*['\"][0-9a-f]{20,}['\"]", "HIGH", "Pusher app key"),
    ("agora_appid",            r"(?i)agora.{0,20}?app[_\-]?id\s*[:=]\s*['\"][0-9a-f]{32}['\"]", "MEDIUM", "Agora App ID"),
    ("livekit_key",            r"\bAPI[A-Za-z0-9]{12,}\b(?=.{0,80}livekit)", "HIGH", "Possible LiveKit API key"),
    ("openai_key",             r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}\b", "CRITICAL", "OpenAI-style API key"),
    ("anthropic_key",          r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b", "CRITICAL", "Anthropic API key"),
    ("basic_auth_url",         r"https?://[A-Za-z0-9._%\-]+:[^/@\s'\"]{3,}@[A-Za-z0-9.\-]+", "CRITICAL", "Credentials embedded in URL"),
    ("generic_secret_assign",  r"(?i)\b(?:api[_\-]?key|apikey|secret|passwd|password|auth[_\-]?token|access[_\-]?token|client[_\-]?secret|private[_\-]?key)\s*[:=]\s*['\"][^'\"\s]{12,}['\"]", "MEDIUM", "Generic secret-shaped assignment - triage for entropy/placeholder"),
]

# Sinks that can lead to XSS / code execution / open redirect.
SINK_PATTERNS = [
    ("html_innerHTML",         r"\.innerHTML\s*=", "xss"),
    ("html_outerHTML",         r"\.outerHTML\s*=", "xss"),
    ("html_insertAdjacent",    r"\.insertAdjacentHTML\s*\(", "xss"),
    ("html_documentWrite",     r"\bdocument\.write(?:ln)?\s*\(", "xss"),
    ("html_setHTMLUnsafe",     r"\.setHTMLUnsafe\s*\(", "xss"),
    ("html_createContextual",  r"\.createContextualFragment\s*\(", "xss"),
    ("html_domparser",         r"\.parseFromString\s*\(", "xss"),
    ("html_srcdoc",            r"\.srcdoc\s*=", "xss"),
    ("html_jquery",            r"\$\([^)]{0,80}\)\s*\.(?:html|append|prepend|after|before|replaceWith|wrap)\s*\(", "xss"),
    ("exec_eval",              r"\beval\s*\(", "code-exec"),
    ("exec_newFunction",       r"\bnew\s+Function\s*\(", "code-exec"),
    ("exec_timerString",       r"\bset(?:Timeout|Interval)\s*\(\s*['\"]", "code-exec"),
    ("exec_dynamicImport",     r"\bimport\s*\(\s*(?!['\"])", "code-exec"),
    ("nav_locationAssign",     r"\blocation\s*(?:\.href)?\s*=(?!=)", "open-redirect"),
    ("nav_locationMethod",     r"\blocation\.(?:assign|replace)\s*\(", "open-redirect"),
    ("nav_windowOpen",         r"\bwindow\.open\s*\(", "open-redirect"),
    ("nav_srcAssign",          r"\.src\s*=(?!=)", "open-redirect"),
    ("nav_formAction",         r"\.(?:action|formAction)\s*=(?!=)", "open-redirect"),
    ("attr_setAttribute",      r"\.setAttribute\s*\(\s*['\"](?:src|href|action|formaction|data|srcdoc|on\w+)['\"]", "xss"),
    ("proto_pollution",        r"__proto__|\bconstructor\s*\[\s*['\"]prototype|\.prototype\s*\[", "proto-pollution"),
]

# Attacker-influenceable sources. Presence near a sink escalates severity.
SOURCE_TOKENS = [
    r"location\.(?:href|hash|search|pathname|host|hostname)", r"\bdocument\.URL\b",
    r"\bdocument\.documentURI\b", r"\bdocument\.referrer\b", r"\bwindow\.name\b",
    r"\bURLSearchParams\b", r"searchParams\.get", r"\.getAttribute\s*\(",
    r"\bdataset\b", r"\b(?:event|evt|e|msg|message)\.data\b", r"\bdocument\.cookie\b",
    r"localStorage\.getItem", r"sessionStorage\.getItem", r"\bdecodeURI(?:Component)?\s*\(",
    r"\batob\s*\(", r"\blocation\b", r"\.value\b", r"\bJSON\.parse\s*\(",
]
SOURCE_RE = re.compile("|".join(SOURCE_TOKENS))

# Bundles that are third-party vendor code; sinks there are demoted unless a
# source is adjacent. Substring match against the filename.
VENDOR_HINTS = [
    "trix", "actiontext", "stimulus-loading", "turbo", "appsignal",
    "lunr", "jquery", "lodash", "moment", "chunk-vendors", "polyfill",
]

INTERESTING_COMMENT = re.compile(
    r"(?://|/\*)\s*(?:TODO|FIXME|HACK|XXX|BUG|NOTE|WARNING|DEPRECATED|REMOVE|TEMP|"
    r"SECURITY|INSECURE|DISABLE[D]?|BYPASS|WORKAROUND)\b[^\n\r*]{0,160}", re.I)

SOURCEMAP_RE = re.compile(r"//[#@]\s*sourceMappingURL=([^\s'\"]+)")

# Endpoint / route extraction.
PATH_RE = re.compile(r"""['"`](/(?!/)[A-Za-z0-9_\-./{}:%]{2,120})['"`]""")
FULLURL_RE = re.compile(r"""['"`](https?://[A-Za-z0-9._\-]+(?::\d+)?[/A-Za-z0-9._\-~%?=&{}:+]*)['"`]""")
WS_RE = re.compile(r"""['"`](wss?://[^'"`\s]{4,200})['"`]""")
FETCHY_RE = re.compile(r"\b(?:fetch|axios(?:\.\w+)?|XMLHttpRequest|\.open)\s*\(")

# Rails / Hotwire / app-specific things worth surfacing.
APP_PATTERNS = [
    ("actioncable",   r"ActionCable|createConsumer|/cable\b|subscriptions\.create", "ActionCable / WebSocket wiring"),
    ("turbo_stream",  r"turbo[_-]?stream|TurboStream|StreamActions", "Turbo Stream action handlers - check for DOM injection of server content"),
    ("csrf",          r"csrf[_-]?token|X-CSRF-Token|authenticity_token", "CSRF token handling"),
    ("role_perm",     r"(?i)\b(?:is[_A-Z]?admin|isAdmin|can[_A-Z]\w+|permission|role[_s]?\b|privilege|owner|moderator|superuser)\s*[:=(]", "Client-side role/permission logic - verify server enforces it"),
    ("feature_flag",  r"(?i)\b(?:feature[_\-]?flag|featureFlag|flipper|launchDarkly|isEnabled|enableFeature)\b", "Feature flags - may reveal unreleased functionality"),
    ("debug_mode",    r"(?i)\b(?:debug\s*[:=]\s*(?:!0|true|1)|verbose\s*[:=]\s*(?:!0|true)|NODE_ENV\s*[!=]==?\s*['\"]development)", "Debug/development toggles"),
    ("internal_host", r"(?i)\b[a-z0-9\-]+\.(?:internal|local|localdomain|corp|intranet|test)\b|\b(?:staging|dev|qa|uat|preprod|sandbox)[.\-][a-z0-9\-]+\.[a-z]{2,}", "Internal / non-production hostname"),
    ("s3_bucket",     r"[a-z0-9.\-]+\.s3(?:[.\-][a-z0-9\-]+)?\.amazonaws\.com|s3://[a-z0-9.\-]+", "S3 bucket reference - check for public listing"),
    ("upload_direct", r"(?i)direct[_\-]?upload|presigned|signed[_\-]?url|blob[_\-]?signed", "Direct-upload / presigned URL flow - classic IDOR + content-type bypass surface"),
    ("saml_sso",      r"(?i)\bsaml\b|idp_entity_id|SAMLResponse|/users/saml", "SAML SSO wiring"),
]


def severity_rank(s):
    return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(s, 5)


def shannon_entropy(s):
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


# --------------------------------------------------------------------------
# Fetching
# --------------------------------------------------------------------------

def http_get(url, timeout=30):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status, r.read(), dict(r.headers)


def safe_name(url):
    p = urllib.parse.urlparse(url)
    base = os.path.basename(p.path) or "index"
    if not base.endswith((".js", ".map", ".mjs")):
        base += ".js"
    digest = hashlib.sha1(url.encode()).hexdigest()[:8]
    return f"{p.netloc.replace(':', '_')}__{digest}__{base}"


def cmd_fetch(args):
    os.makedirs(args.outdir, exist_ok=True)
    with open(args.targets) as f:
        urls = [l.strip() for l in f if l.strip() and not l.startswith("#")]

    if args.allow_host:
        allowed = set(args.allow_host)
        kept = [u for u in urls if urllib.parse.urlparse(u).netloc in allowed]
        skipped = len(urls) - len(kept)
        if skipped:
            print(f"[scope] dropped {skipped} URL(s) outside --allow-host {sorted(allowed)}")
        urls = kept

    print(f"[fetch] {len(urls)} target(s) -> {args.outdir}")
    manifest = {}

    def one(url):
        try:
            status, body, hdrs = http_get(url)
            path = os.path.join(args.outdir, safe_name(url))
            with open(path, "wb") as fh:
                fh.write(body)
            return url, status, len(body), path, hdrs.get("Content-Type", ""), None
        except urllib.error.HTTPError as e:
            return url, e.code, 0, None, "", f"HTTP {e.code}"
        except Exception as e:
            return url, 0, 0, None, "", str(e)

    with futures.ThreadPoolExecutor(max_workers=args.concurrency) as ex:
        for url, status, size, path, ctype, err in ex.map(one, urls):
            flag = "ok " if not err else "ERR"
            print(f"  [{flag}] {status:>3} {size:>9,}b  {url}{'  ' + err if err else ''}")
            manifest[url] = {"status": status, "bytes": size, "path": path,
                             "content_type": ctype, "error": err}

    # Second pass: source maps referenced by what we just downloaded.
    if args.sourcemaps:
        extra = []
        for url, meta in list(manifest.items()):
            if not meta["path"]:
                continue
            try:
                txt = open(meta["path"], "r", errors="replace").read()
            except OSError:
                continue
            for m in SOURCEMAP_RE.finditer(txt):
                ref = m.group(1)
                if ref.startswith("data:"):
                    continue
                extra.append(urllib.parse.urljoin(url, ref))
        extra = sorted(set(extra) - set(manifest))
        if extra:
            print(f"[fetch] {len(extra)} source map(s) referenced")
            with futures.ThreadPoolExecutor(max_workers=args.concurrency) as ex:
                for url, status, size, path, ctype, err in ex.map(one, extra):
                    flag = "ok " if not err else "ERR"
                    print(f"  [{flag}] {status:>3} {size:>9,}b  {url}")
                    manifest[url] = {"status": status, "bytes": size, "path": path,
                                     "content_type": ctype, "error": err}
        else:
            print("[fetch] no external source maps referenced")

    with open(os.path.join(args.outdir, "_manifest.json"), "w") as fh:
        json.dump(manifest, fh, indent=2)
    ok = sum(1 for m in manifest.values() if not m["error"])
    print(f"[fetch] done: {ok}/{len(manifest)} retrieved")
    return 0


# --------------------------------------------------------------------------
# Analysis
# --------------------------------------------------------------------------

def offset_to_linecol(text, off):
    line = text.count("\n", 0, off) + 1
    last_nl = text.rfind("\n", 0, off)
    col = off - last_nl
    return line, col


def snippet(text, start, end, pad=110):
    a, b = max(0, start - pad), min(len(text), end + pad)
    s = text[a:b].replace("\n", "\\n").replace("\r", "")
    s = re.sub(r"\s{2,}", " ", s)
    return ("..." if a > 0 else "") + s + ("..." if b < len(text) else "")


def is_vendor(fname):
    low = fname.lower()
    return any(h in low for h in VENDOR_HINTS)


def analyze_file(path, text):
    fname = os.path.basename(path)
    vendor = is_vendor(fname)
    minified = (len(text) / max(1, text.count("\n") + 1)) > 400
    out = []

    def add(kind, name, sev, off, end, note=""):
        line, col = offset_to_linecol(text, off)
        out.append({
            "file": fname, "kind": kind, "name": name, "severity": sev,
            "offset": off, "line": line, "col": col, "note": note,
            "match": text[off:end][:200], "context": snippet(text, off, end),
        })

    # --- secrets
    for name, pat, sev, note in SECRET_PATTERNS:
        for m in re.finditer(pat, text):
            val = m.group(0)
            # entropy gate for the noisy generic rule
            if name == "generic_secret_assign":
                lit = re.search(r"['\"]([^'\"]{12,})['\"]", val)
                if lit:
                    v = lit.group(1)
                    if shannon_entropy(v) < 3.0:
                        continue
                    if re.fullmatch(r"[a-z0-9_\-./]+", v) and "/" in v:
                        continue  # looks like a path
            add("secret", name, sev, m.start(), m.end(), note)

    # --- sinks, scored by nearby sources
    for name, pat, cat in SINK_PATTERNS:
        for m in re.finditer(pat, text):
            a, b = max(0, m.start() - 260), min(len(text), m.end() + 260)
            window = text[a:b]
            tainted = bool(SOURCE_RE.search(window))
            if tainted:
                sev = "HIGH" if cat in ("xss", "code-exec") else "MEDIUM"
            elif vendor:
                sev = "INFO"
            else:
                sev = "LOW"
            note = cat + (" | controllable source in window" if tainted else "")
            add("sink", name, sev, m.start(), m.end(), note)

    # --- postMessage handling
    # The scan window must stop at the *next* listener, otherwise a neighbouring
    # handler's origin check is credited to this one (false negative).
    listener_re = re.compile(r"addEventListener\s*\(\s*['\"]message['\"]|\bonmessage\s*=")
    listeners = [m for m in listener_re.finditer(text)]
    for i, m in enumerate(listeners):
        hard_stop = listeners[i + 1].start() if i + 1 < len(listeners) else len(text)
        b = min(len(text), m.end() + 700, hard_stop)
        window = text[m.start():b]
        has_origin = re.search(r"\.origin\b|\borigin\s*[!=]==?", window)
        sev = "LOW" if has_origin else "HIGH"
        note = ("message listener (origin check present in handler)" if has_origin
                else "message listener with NO origin check before next handler/EOF - "
                     "verify whether handler data reaches a DOM or navigation sink")
        add("postmessage", "message_listener", sev, m.start(), m.end(), note)

    for m in re.finditer(r"\.postMessage\s*\([^)]{0,300}?['\"]\*['\"]\s*\)", text, re.S):
        add("postmessage", "wildcard_target_origin", "MEDIUM", m.start(),
            min(m.end(), m.start() + 200), "postMessage to '*' - data may leak to any origin")

    # --- source maps
    for m in SOURCEMAP_RE.finditer(text):
        add("sourcemap", "sourceMappingURL", "MEDIUM", m.start(), m.end(),
            f"source map reference: {m.group(1)[:120]} - retrieve for original sources")

    # --- comments
    for m in INTERESTING_COMMENT.finditer(text):
        add("comment", "developer_comment", "INFO", m.start(), m.end(), m.group(0)[:160])

    # --- app-specific
    for name, pat, note in APP_PATTERNS:
        seen = 0
        for m in re.finditer(pat, text):
            seen += 1
            if seen > 12:  # cap noise per file
                break
            add("app", name, "INFO", m.start(), m.end(), note)

    return out, {"file": fname, "bytes": len(text), "vendor": vendor, "minified": minified}


def extract_endpoints(text):
    paths, urls, sockets = set(), set(), set()
    for m in PATH_RE.finditer(text):
        p = m.group(1)
        if re.search(r"\.(?:png|jpe?g|gif|svg|woff2?|ttf|eot|ico|css|map)$", p, re.I):
            continue
        if len(p) < 3 or p.count("/") > 8:
            continue
        paths.add(p)
    for m in FULLURL_RE.finditer(text):
        urls.add(m.group(1))
    for m in WS_RE.finditer(text):
        sockets.add(m.group(1))
    return paths, urls, sockets


def cmd_analyze(args):
    files = []
    for root, _, names in os.walk(args.dir):
        for n in sorted(names):
            if n.endswith((".js", ".mjs", ".map")) and not n.startswith("_"):
                files.append(os.path.join(root, n))
    if not files:
        print(f"[!] no .js/.map files under {args.dir}", file=sys.stderr)
        return 1

    print(f"[analyze] {len(files)} file(s)")
    all_findings, stats = [], []
    ep_paths, ep_urls, ep_ws = set(), set(), set()
    per_file_paths = defaultdict(set)

    for path in files:
        try:
            text = open(path, "r", errors="replace").read()
        except OSError as e:
            print(f"  [!] {path}: {e}", file=sys.stderr)
            continue

        if path.endswith(".map"):
            # Source maps: pull original sources out and note them.
            try:
                sm = json.loads(text)
                srcs = sm.get("sources", [])
                print(f"  [map] {os.path.basename(path)}: {len(srcs)} original source(s)")
                if args.unpack_maps and sm.get("sourcesContent"):
                    outd = os.path.join(args.dir, "_unpacked",
                                        os.path.basename(path).replace(".map", ""))
                    for s, c in zip(srcs, sm["sourcesContent"]):
                        if not c:
                            continue
                        rel = re.sub(r"^(?:\.\./)+|^webpack://[^/]*/", "", s).lstrip("/")
                        dest = os.path.join(outd, rel)
                        os.makedirs(os.path.dirname(dest), exist_ok=True)
                        with open(dest, "w") as fh:
                            fh.write(c)
                    print(f"        unpacked -> {outd}")
            except (ValueError, KeyError):
                print(f"  [map] {os.path.basename(path)}: not valid JSON")
            continue

        findings, st = analyze_file(path, text)
        all_findings.extend(findings)
        stats.append(st)
        p, u, w = extract_endpoints(text)
        ep_paths |= p
        ep_urls |= u
        ep_ws |= w
        per_file_paths[os.path.basename(path)] = p
        hi = sum(1 for f in findings if f["severity"] in ("CRITICAL", "HIGH"))
        print(f"  [ok] {st['file'][:70]:<70} {st['bytes']:>9,}b  "
              f"{len(findings):>4} finding(s){'  <-- ' + str(hi) + ' high+' if hi else ''}")

    all_findings.sort(key=lambda f: (severity_rank(f["severity"]), f["file"], f["offset"]))
    write_report(args.out, all_findings, stats, ep_paths, ep_urls, ep_ws, per_file_paths)
    if args.json:
        with open(args.json, "w") as fh:
            json.dump({"findings": all_findings, "files": stats,
                       "endpoints": {"paths": sorted(ep_paths),
                                     "urls": sorted(ep_urls),
                                     "websockets": sorted(ep_ws)}}, fh, indent=2)
        print(f"[analyze] json -> {args.json}")
    print(f"[analyze] report -> {args.out}")

    counts = Counter(f["severity"] for f in all_findings)
    print("[analyze] " + "  ".join(f"{k}={counts.get(k,0)}"
                                   for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")))
    return 0


def write_report(out, findings, stats, paths, urls, sockets, per_file_paths):
    L = []
    A = L.append
    A("# JavaScript recon report\n")
    A(f"Files analyzed: **{len(stats)}** | Findings: **{len(findings)}**\n")

    counts = Counter(f["severity"] for f in findings)
    A("| Severity | Count |")
    A("|---|---|")
    for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        A(f"| {s} | {counts.get(s, 0)} |")
    A("")

    A("## Files\n")
    A("| File | Bytes | Vendor | Minified |")
    A("|---|---|---|---|")
    for s in sorted(stats, key=lambda x: -x["bytes"]):
        A(f"| `{s['file']}` | {s['bytes']:,} | {'yes' if s['vendor'] else 'no'} "
          f"| {'yes' if s['minified'] else 'no'} |")
    A("")

    A("## Findings\n")
    A("_Minified files: use the byte offset, not the line number._\n")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        group = [f for f in findings if f["severity"] == sev]
        if not group:
            continue
        A(f"### {sev} ({len(group)})\n")
        if sev in ("LOW", "INFO"):
            by = Counter((f["kind"], f["name"], f["file"]) for f in group)
            A("| Kind | Rule | File | Count |")
            A("|---|---|---|---|")
            for (kind, name, fl), n in by.most_common(80):
                A(f"| {kind} | `{name}` | `{fl}` | {n} |")
            A("")
            continue
        for f in group:
            A(f"- **`{f['name']}`** in `{f['file']}` @ offset `{f['offset']}` "
              f"(line {f['line']}, col {f['col']})")
            if f["note"]:
                A(f"  - {f['note']}")
            A(f"  - match: `{f['match'][:160]}`")
            A(f"  - context: `{f['context'][:340]}`")
        A("")

    A("## Extracted endpoints\n")
    A(f"### Absolute paths ({len(paths)})\n")
    A("```")
    for p in sorted(paths):
        A(p)
    A("```\n")
    if urls:
        A(f"### Absolute URLs ({len(urls)})\n")
        A("```")
        for u in sorted(urls):
            A(u)
        A("```\n")
    if sockets:
        A(f"### WebSocket URLs ({len(sockets)})\n")
        A("```")
        for w in sorted(sockets):
            A(w)
        A("```\n")

    with open(out, "w") as fh:
        fh.write("\n".join(L))


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    f = sub.add_parser("fetch", help="download JS assets listed in a targets file")
    f.add_argument("-t", "--targets", required=True)
    f.add_argument("-o", "--outdir", default="./js")
    f.add_argument("-c", "--concurrency", type=int, default=6)
    f.add_argument("--allow-host", action="append",
                   help="only fetch these hosts (repeatable) - enforce your scope")
    f.add_argument("--no-sourcemaps", dest="sourcemaps", action="store_false")
    f.set_defaults(func=cmd_fetch, sourcemaps=True)

    a = sub.add_parser("analyze", help="analyze a directory of JS files")
    a.add_argument("-d", "--dir", required=True)
    a.add_argument("-o", "--out", default="js-recon-report.md")
    a.add_argument("--json", help="also write raw findings as JSON")
    a.add_argument("--unpack-maps", action="store_true",
                   help="write sourcesContent from .map files to _unpacked/")
    a.set_defaults(func=cmd_analyze)

    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
