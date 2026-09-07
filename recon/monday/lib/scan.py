#!/usr/bin/env python3
"""Static analysis of downloaded JavaScript for bug-bounty recon.

Reads every file under a directory and reports four classes of finding:
  secrets   - credential-shaped strings (API keys, tokens, private keys)
  endpoints - URLs, API paths and GraphQL operations worth probing
  sinks     - DOM-XSS sinks and unvalidated postMessage handlers
  hosts     - hostnames referenced by the code, for scope expansion

Everything is reported with file + byte offset + surrounding context so a
human can confirm it before it goes anywhere near a report.
"""

import argparse
import json
import math
import os
import re
import sys
from collections import defaultdict

# ---------------------------------------------------------------- secrets

# (name, severity, pattern, precise). `precise` marks structurally-anchored
# patterns -- a string starting AKIA/xoxb-/sk_live_ is a credential by
# construction, so the noise and entropy filters below are skipped for them.
# Only the loose, name-based rules get filtered.
SECRET_RULES = [
    ("aws_access_key_id",      "high",   r"\b((?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16})\b", True),
    ("aws_secret_access_key",  "high",   r"""(?i)aws[_-]?(?:secret|sk)[_-]?(?:access)?[_-]?key\W{0,3}["']([A-Za-z0-9/+=]{40})["']""", False),
    ("google_api_key",         "medium", r"\b(AIza[0-9A-Za-z_\-]{35})\b", True),
    ("google_oauth_id",        "low",    r"\b([0-9]+-[0-9a-z_]{32}\.apps\.googleusercontent\.com)\b", True),
    ("slack_token",            "high",   r"\b(xox[baprs]-[0-9A-Za-z-]{10,72})\b", True),
    ("slack_webhook",          "high",   r"(https://hooks\.slack\.com/services/T[0-9A-Za-z_/]{20,})", True),
    ("stripe_secret_key",      "high",   r"\b((?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,})\b", True),
    ("stripe_publishable",     "info",   r"\b(pk_(?:live|test)_[0-9A-Za-z]{16,})\b", True),
    ("github_token",           "high",   r"\b((?:ghp|gho|ghu|ghs|ghr|github_pat)_[0-9A-Za-z_]{20,})\b", True),
    ("gitlab_token",           "high",   r"\b(glpat-[0-9A-Za-z_\-]{20,})\b", True),
    ("npm_token",              "high",   r"\b(npm_[0-9A-Za-z]{36})\b", True),
    ("sendgrid_key",           "high",   r"\b(SG\.[0-9A-Za-z_\-]{22}\.[0-9A-Za-z_\-]{43})\b", True),
    ("twilio_sid",             "medium", r"\b(AC[0-9a-f]{32})\b", True),
    ("mailgun_key",            "high",   r"\b(key-[0-9a-f]{32})\b", True),
    ("algolia_admin_key",      "medium", r"(?i)algolia\w*(?:admin|api)?\w*key\W{0,3}[\"']([0-9a-f]{32})[\"']", False),
    ("segment_write_key",      "medium", r"(?i)(?:segment|analytics)\w*(?:write)?key\W{0,3}[\"']([0-9A-Za-z]{20,40})[\"']", False),
    ("sentry_dsn",             "low",    r"(https://[0-9a-f]{32}@[0-9a-z.\-]+/\d+)", True),
    ("firebase_db",            "low",    r"(https://[0-9a-z\-]+\.firebaseio\.com)", True),
    ("private_key_block",      "high",   r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----)", True),
    ("jwt",                    "medium", r"\b(eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{10,})\b", True),
    ("basic_auth_in_url",      "high",   r"([a-z]{2,10}://[^/\s:@\"']{2,40}:[^/\s:@\"']{2,60}@[a-z0-9.\-]+)", True),
    ("generic_assigned_secret","medium", r"""(?i)\b(?:api[_-]?key|apikey|secret|passwd|password|auth[_-]?token|access[_-]?token|client[_-]?secret|private[_-]?key|[a-z]{2,20}[_-]token)\b\s*[:=]\s*["']([^"'\s]{12,120})["']""", False),
]
SECRET_RULES = [(n, s, re.compile(p), x) for n, s, p, x in SECRET_RULES]

# Values that match a rule but are structurally never credentials.
SECRET_NOISE = re.compile(
    r"^(?:"
    r"(?i:true|false|null|undefined|none|nil|empty|test|example|sample|dummy"
    r"|change[_-]?me|your[_-]?\w+|xxx+)|"
    r"\.{3,}|<[^>]+>|\$\{[^}]*\}|%[sd]|\[object\s|function\b|"
    r"[a-z]+(?:[_-][a-z]+)+|"                       # snake_case / kebab-case identifiers
    r"(?:[A-Za-z]+\.)+[A-Za-z]+|"                   # dotted paths
    r"/[\w/.\-]*|"                                  # URL paths
    r"#[0-9a-f]{3,8}|"                              # colours
    r"\d+(?:\.\d+)*"                                # versions / numbers
    r")$"
)


def shannon(s: str) -> float:
    if not s:
        return 0.0
    freq = defaultdict(int)
    for ch in s:
        freq[ch] += 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


# -------------------------------------------------------------- endpoints

ABS_URL = re.compile(r"""https?://[A-Za-z0-9._\-]+(?::\d+)?(?:/[^\s"'`<>\\)]{0,300})?""")
API_PATH = re.compile(r"""["'`](/(?:api|v\d|graphql|gql|internal|admin|auth|oauth|rpc|_next/data|export|import|upload|download|webhook|callback|sso|saml|debug|health|metrics|actuator)[A-Za-z0-9/_.\-{}$:%]{0,200})["'`]""")
GQL_OP = re.compile(r"\b(?:query|mutation|subscription)\s+([A-Za-z_][A-Za-z0-9_]{2,60})\s*[({]")

# ------------------------------------------------------------------ sinks

SINK_RULES = [
    ("innerHTML_assignment",     "medium", r"\.(?:innerHTML|outerHTML)\s*="),
    ("insertAdjacentHTML",       "medium", r"\.insertAdjacentHTML\s*\("),
    ("document_write",           "medium", r"\bdocument\s*\.\s*write(?:ln)?\s*\("),
    ("eval_call",                "high",   r"(?<![\w.$])eval\s*\("),
    ("function_constructor",     "medium", r"\bnew\s+Function\s*\("),
    ("settimeout_string",        "medium", r"\bset(?:Timeout|Interval)\s*\(\s*[\"'`]"),
    ("jquery_html_sink",         "medium", r"\$\([^)]{0,80}\)\s*\.\s*(?:html|append|prepend|after|before|replaceWith)\s*\("),
    ("react_dangerous_html",     "medium", r"dangerouslySetInnerHTML"),
    ("iframe_srcdoc",            "medium", r"\.srcdoc\s*="),
    ("location_assignment",      "medium", r"(?:location\s*\.\s*(?:href|replace|assign)\s*[=(]|window\s*\.\s*location\s*=)"),
    ("postmessage_send_wildcard","high",   r"\.postMessage\s*\([^;]{0,200}?[\"'`]\*[\"'`]\s*\)"),
]
SINK_RULES = [(n, s, re.compile(p)) for n, s, p in SINK_RULES]

MSG_LISTENER = re.compile(r"""addEventListener\s*\(\s*["'`]message["'`]""")
ORIGIN_CHECK = re.compile(r"\b(?:origin|\.origin\b|isTrustedOrigin|allowedOrigins?|ALLOWED_ORIGINS)\b")

TAINT_SOURCE = re.compile(
    r"\b(?:location\s*\.\s*(?:hash|search|href|pathname)|document\s*\.\s*(?:URL|documentURI|referrer)|"
    r"URLSearchParams|window\s*\.\s*name|event\s*\.\s*data|e\s*\.\s*data)\b"
)

HOSTNAME = re.compile(r"\b((?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|dev|ai|co|cloud|app|sh|xyz|internal|local))\b", re.I)


def context(blob: str, start: int, end: int, width: int = 90) -> str:
    lo = max(0, start - width)
    hi = min(len(blob), end + width)
    snippet = blob[lo:hi].replace("\n", "\\n").replace("\r", "")
    return re.sub(r"\s+", " ", snippet).strip()


def scan_file(path: str, rel: str, findings: dict, opts) -> None:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            blob = fh.read()
    except OSError as exc:
        print(f"[!] cannot read {rel}: {exc}", file=sys.stderr)
        return

    for name, sev, rx, precise in SECRET_RULES:
        for m in rx.finditer(blob):
            value = m.group(m.lastindex or 0)
            if not precise:
                if SECRET_NOISE.match(value):
                    continue
                # Random-looking strings only; kills minified identifiers.
                if shannon(value) < 3.2:
                    continue
            findings["secrets"].append({
                "rule": name, "severity": sev, "file": rel,
                "offset": m.start(), "value": value,
                "context": context(blob, m.start(), m.end()),
            })

    for m in ABS_URL.finditer(blob):
        findings["urls"].add(m.group(0).rstrip(".,;)'\"`"))
    for m in API_PATH.finditer(blob):
        findings["paths"].add(m.group(1))
    for m in GQL_OP.finditer(blob):
        findings["graphql"].add(m.group(1))
    for m in HOSTNAME.finditer(blob):
        findings["hosts"].add(m.group(1).lower())

    for name, sev, rx in SINK_RULES:
        for m in rx.finditer(blob):
            ctx = context(blob, m.start(), m.end(), 130)
            tainted = bool(TAINT_SOURCE.search(ctx))
            if opts.sinks_tainted_only and not tainted:
                continue
            findings["sinks"].append({
                "rule": name,
                "severity": "high" if tainted else sev,
                "file": rel, "offset": m.start(),
                "tainted_context": tainted, "context": ctx,
            })

    for m in MSG_LISTENER.finditer(blob):
        window = blob[m.start(): m.start() + opts.postmessage_window]
        if not ORIGIN_CHECK.search(window):
            findings["sinks"].append({
                "rule": "postmessage_listener_no_origin_check",
                "severity": "high", "file": rel, "offset": m.start(),
                "tainted_context": True,
                "context": context(blob, m.start(), m.end(), 200),
            })


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("directory", help="directory of downloaded .js files")
    ap.add_argument("-o", "--outdir", default="out/analysis")
    ap.add_argument("--in-scope", default="monday.com",
                    help="comma-separated domain suffixes considered in scope")
    ap.add_argument("--postmessage-window", type=int, default=1200,
                    help="chars after a message listener searched for an origin check")
    ap.add_argument("--sinks-tainted-only", action="store_true",
                    help="only report sinks whose context also shows a taint source")
    opts = ap.parse_args()

    scope = tuple(s.strip().lower() for s in opts.in_scope.split(",") if s.strip())

    findings = {"secrets": [], "sinks": [],
                "urls": set(), "paths": set(), "graphql": set(), "hosts": set()}

    count = 0
    for root, _dirs, files in os.walk(opts.directory):
        for fn in sorted(files):
            if not fn.endswith((".js", ".mjs", ".ts", ".jsx", ".tsx", ".json", ".map")):
                continue
            full = os.path.join(root, fn)
            scan_file(full, os.path.relpath(full, opts.directory), findings, opts)
            count += 1

    os.makedirs(opts.outdir, exist_ok=True)

    def dump_list(name, rows):
        with open(os.path.join(opts.outdir, name), "w") as fh:
            fh.write("\n".join(rows) + ("\n" if rows else ""))

    in_scope_hosts = sorted(h for h in findings["hosts"] if h.endswith(scope))
    third_party = sorted(h for h in findings["hosts"] if not h.endswith(scope))

    dump_list("urls.txt", sorted(findings["urls"]))
    dump_list("api-paths.txt", sorted(findings["paths"]))
    dump_list("graphql-operations.txt", sorted(findings["graphql"]))
    dump_list("hosts-in-scope.txt", in_scope_hosts)
    dump_list("hosts-third-party.txt", third_party)

    sev_rank = {"high": 0, "medium": 1, "low": 2, "info": 3}
    findings["secrets"].sort(key=lambda f: (sev_rank.get(f["severity"], 9), f["rule"]))
    findings["sinks"].sort(key=lambda f: (sev_rank.get(f["severity"], 9), f["rule"]))

    with open(os.path.join(opts.outdir, "findings.json"), "w") as fh:
        json.dump({"secrets": findings["secrets"], "sinks": findings["sinks"]}, fh, indent=2)

    print(f"[*] scanned {count} files")
    print(f"[*] secrets (candidates) : {len(findings['secrets'])}")
    print(f"[*] sinks                : {len(findings['sinks'])}")
    print(f"[*] absolute URLs        : {len(findings['urls'])}")
    print(f"[*] api paths            : {len(findings['paths'])}")
    print(f"[*] graphql operations   : {len(findings['graphql'])}")
    print(f"[*] in-scope hosts       : {len(in_scope_hosts)}")
    print(f"[*] third-party hosts    : {len(third_party)}")
    print(f"[*] written to {opts.outdir}/")

    high = [f for f in findings["secrets"] + findings["sinks"] if f["severity"] == "high"]
    if high:
        print(f"\n[!] {len(high)} high-severity candidates — verify each by hand:")
        for f in high[:25]:
            print(f"    {f['rule']:38s} {f['file']}@{f['offset']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
