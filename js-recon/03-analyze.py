#!/usr/bin/env python3
"""
Static analysis over every fetched / unpacked JS file.

Passes:
  1. SECRETS        - high-signal key formats + generic assignment heuristics
  2. ENDPOINTS      - LinkFinder-style path/URL extraction, deduped per host
  3. DOM-XSS        - taint SOURCES and SINKS, correlated by byte proximity
  4. POSTMESSAGE    - message listeners + missing origin checks
  5. DYN-LOAD       - runtime script/iframe injection (script.src = var)
  6. LIBS           - dependency fingerprints with known-vulnerable ranges
  7. INTERNALS      - internal hostnames, IPs, buckets, emails, debug flags

Minified-safe: all context windows are byte-offset based, not line based.
Writes out/report.md and out/findings.json
"""
import json, os, re, sys, collections, html

ROOT = os.path.dirname(os.path.abspath(__file__))
SCAN_DIRS = [os.path.join(ROOT, "out", "raw"), os.path.join(ROOT, "out", "sourcemaps")]
OUT_MD = os.path.join(ROOT, "out", "report.md")
OUT_JSON = os.path.join(ROOT, "out", "findings.json")
CTX = 90  # chars either side of a match

# --------------------------------------------------------------------------- 1
SECRETS = [
    ("AWS access key id",      r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b",                 "critical"),
    ("AWS secret (heuristic)", r"(?i)aws.{0,20}(?:secret|sk).{0,10}['\"][0-9a-zA-Z/+]{40}['\"]", "critical"),
    ("Google API key",         r"\bAIza[0-9A-Za-z_\-]{35}\b",                              "high"),
    ("Google OAuth client",    r"\b[0-9]+-[0-9a-z_]{32}\.apps\.googleusercontent\.com\b",  "medium"),
    ("Firebase URL",           r"https://[a-z0-9-]+\.firebaseio\.com",                     "high"),
    ("Slack token",            r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b",                        "critical"),
    ("Slack webhook",          r"https://hooks\.slack\.com/services/[A-Za-z0-9/+]{40,}",   "critical"),
    ("Stripe live key",        r"\b(?:sk|rk)_live_[0-9a-zA-Z]{20,}\b",                     "critical"),
    ("Stripe publishable",     r"\bpk_live_[0-9a-zA-Z]{20,}\b",                            "low"),
    ("Mapbox token",           r"\bpk\.eyJ[0-9A-Za-z_\-]{20,}\.[0-9A-Za-z_\-]{20,}\b",     "medium"),
    ("Sentry DSN",             r"https://[0-9a-f]{32}(?::[0-9a-f]{32})?@[a-z0-9.\-]+/\d+", "medium"),
    ("JWT",                    r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b", "high"),
    ("Private key block",      r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----", "critical"),
    ("Basic auth in URL",      r"https?://[A-Za-z0-9._%+-]+:[^/@\s\"']{3,}@[A-Za-z0-9.\-]+", "critical"),
    ("Azure storage key",      r"(?i)(?:AccountKey|SharedAccessSignature)=[A-Za-z0-9+/=]{30,}", "critical"),
    ("SendGrid key",           r"\bSG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}\b",        "critical"),
    ("Twilio SID",             r"\bAC[0-9a-fA-F]{32}\b",                                   "medium"),
    ("Algolia admin key",      r"(?i)algolia.{0,30}(?:admin|api)[_-]?key.{0,10}['\"][0-9a-f]{32}['\"]", "high"),
    ("Adobe IMS org",          r"\b[0-9A-F]{24}@AdobeOrg\b",                               "low"),
    ("reCAPTCHA site key",     r"\b6L[0-9A-Za-z_\-]{38}\b",                                "info"),
    ("GTM container",          r"\bGTM-[A-Z0-9]{6,8}\b",                                   "info"),
    ("GA measurement id",      r"\b(?:UA-\d{4,10}-\d{1,4}|G-[A-Z0-9]{8,12})\b",            "info"),
    ("Salesforce session",     r"\b00D[A-Za-z0-9]{12,18}![A-Za-z0-9._\-]{50,}",            "critical"),
    ("Generic secret assign",  r"(?i)\b(?:api[_-]?key|apikey|client[_-]?secret|auth[_-]?token|"
                               r"access[_-]?token|secret[_-]?key|private[_-]?key|passwd|password|pwd|"
                               r"bearer|x-api-key)\b\s*[:=]\s*['\"]([^'\"\s]{8,})['\"]",   "medium"),
]

# --------------------------------------------------------------------------- 3
SOURCES = [
    ("location.hash",     r"location\s*\.\s*hash"),
    ("location.search",   r"location\s*\.\s*search"),
    ("location.href",     r"location\s*\.\s*href"),
    ("location.pathname", r"location\s*\.\s*pathname"),
    ("document.URL",      r"document\s*\.\s*(?:URL|documentURI|baseURI)"),
    ("document.referrer", r"document\s*\.\s*referrer"),
    ("window.name",       r"window\s*\.\s*name\b"),
    ("URLSearchParams",   r"\bURLSearchParams\b"),
    ("getParameter fn",   r"(?i)\b(?:get(?:Url|Query)?Param(?:eter)?s?|getQueryString|parseQuery|qs\.parse)\s*\("),
    ("document.cookie",   r"document\s*\.\s*cookie"),
    ("web storage",       r"\b(?:local|session)Storage\s*\.\s*getItem"),
    ("postMessage data",  r"\.\s*data\b(?=[^\w])"),
    ("AEM suffix/selector", r"(?i)\b(?:requestPathInfo|getSuffix|getSelectors?)\b"),
]
SINKS = [
    ("innerHTML",             r"\.\s*(?:inner|outer)HTML\s*(?:\+)?=",                 "high"),
    ("insertAdjacentHTML",    r"\.\s*insertAdjacentHTML\s*\(",                        "high"),
    ("document.write",        r"document\s*\.\s*write(?:ln)?\s*\(",                   "high"),
    ("eval",                  r"(?<![.\w])eval\s*\(",                                 "critical"),
    ("new Function",          r"\bnew\s+Function\s*\(",                               "critical"),
    ("setTimeout/Interval str", r"\bset(?:Timeout|Interval)\s*\(\s*['\"]",            "high"),
    ("jQuery .html()",        r"\.\s*html\s*\(\s*[^)'\"]",                            "high"),
    ("jQuery insert",         r"\.\s*(?:append|prepend|after|before|replaceWith|wrap)\s*\(\s*[^)'\"]", "medium"),
    ("jQuery $(var)",         r"\$\s*\(\s*(?![\"'#.])[A-Za-z_$][\w$]*\s*\)",          "medium"),
    ("assign to .src",        r"\.\s*src\s*=\s*(?!['\"])",                            "medium"),
    ("srcdoc",                r"\.\s*srcdoc\s*=",                                     "high"),
    ("location assign",       r"(?:location\s*(?:\.\s*href)?\s*=\s*(?!['\"])|location\s*\.\s*(?:assign|replace)\s*\()", "medium"),
    ("window.open",           r"window\s*\.\s*open\s*\(",                             "low"),
    ("setAttribute on*/href", r"\.\s*setAttribute\s*\(\s*['\"](?:on\w+|href|src|formaction)['\"]", "high"),
    ("angular $sce.trustAsHtml", r"trustAs(?:Html|Js|ResourceUrl)?\s*\(",             "high"),
    ("angular $compile",      r"\$compile\s*\(",                                      "critical"),
    ("ng-bind-html / v-html", r"(?:ng-bind-html|v-html|dangerouslySetInnerHTML)",      "high"),
    ("template literal HTML", r"`[^`]{0,200}<[a-zA-Z][^`]{0,200}\$\{[^}]{1,80}\}",    "high"),
    ("Element.outerHTML tpl", r"createContextualFragment\s*\(",                       "high"),
]

# --------------------------------------------------------------------------- 6
LIBS = [
    ("jQuery",       r"jQuery\s*(?:JavaScript Library\s*)?v?([0-9]+\.[0-9]+\.[0-9]+)",
     "<3.5.0 -> CVE-2020-11022/11023 htmlPrefilter XSS; <3.4.0 -> CVE-2019-11358 proto pollution; <1.9 -> $() selector XSS"),
    ("jQuery Migrate", r"jquery[.-]migrate[.-]?v?([0-9.]+)", "1.x implies jQuery <3 codepaths kept alive"),
    ("jQuery UI",    r"jQuery UI[^0-9]{0,20}([0-9]+\.[0-9]+\.[0-9]+)", "<1.13.0 -> CVE-2021-41182/41183/41184 XSS"),
    ("AngularJS",    r"angular(?:js)?[^0-9]{0,20}v?([1-9]\.[0-9]+\.[0-9]+)",
     "AngularJS 1.x is END-OF-LIFE. Any {{ }} interpolation of user input = client-side template injection -> sandbox escape XSS"),
    ("Bootstrap",    r"[Bb]ootstrap[^0-9]{0,20}v?([0-9]+\.[0-9]+\.[0-9]+)",
     "3.x <3.4.1 -> CVE-2019-8331 data-template XSS; 4.x <4.3.1 same family"),
    ("DOMPurify",    r"(?:DOMPurify|purify)[^0-9]{0,20}([0-9]+\.[0-9]+\.[0-9]+)",
     "<2.4.2 / <3.0.x -> multiple mXSS sanitiser bypasses; check exact version"),
    ("Lodash",       r"lodash[^0-9]{0,20}([0-9]+\.[0-9]+\.[0-9]+)", "<4.17.21 -> proto pollution / ReDoS"),
    ("Moment.js",    r"moment[^0-9]{0,20}([0-9]+\.[0-9]+\.[0-9]+)", "<2.29.4 -> CVE-2022-31129 ReDoS"),
    ("Handlebars",   r"[Hh]andlebars[^0-9]{0,20}([0-9]+\.[0-9]+\.[0-9]+)", "<4.7.7 -> template injection RCE/XSS"),
    ("Underscore",   r"underscore[^0-9]{0,20}([0-9]+\.[0-9]+\.[0-9]+)", "<1.13.0-2 -> CVE-2021-23358 template code injection"),
    ("Slick carousel", r"slick[^0-9]{0,20}([0-9]+\.[0-9]+\.[0-9]+)", "old slick builds have HTML-injection in responsive config"),
    ("js-cookie",    r"js\.?cookie[^0-9]{0,20}([0-9]+\.[0-9]+\.[0-9]+)", "informational"),
]

INTERNALS = [
    ("Internal hostname", r"(?i)\b(?:[a-z0-9\-]+\.)*(?:"
                          r"(?:dev|stg|stage|staging|uat|qa|test|tst|preprod|pre-prod|nonprod|sandbox|sbx|int|intg)"
                          r"(?:[0-9]{1,2})?(?:-[a-z0-9]+)?"
                          r"|[a-z0-9\-]+-(?:dev|stg|staging|uat|qa|test|preprod|sandbox|int)"
                          r")\.(?:[a-z0-9\-]+\.)+[a-z]{2,}\b"
                          r"|\b[a-z0-9\-.]+\.(?:internal|corp|intra|local|lan|intranet)(?:\.[a-z]{2,})?\b"),
    ("RFC1918 / loopback", r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|"
                           r"172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|127\.0\.0\.1:\d+)\b"),
    ("S3 / blob bucket",   r"(?i)\b[a-z0-9.\-]{3,63}\.s3[.\-][a-z0-9\-]*\.amazonaws\.com|"
                           r"\b[a-z0-9\-]{3,24}\.blob\.core\.windows\.net"),
    ("AEM internal path",  r"/(?:crx|system/console|bin/querybuilder|libs/granite|apps/|conf/|var/)[A-Za-z0-9/_.\-]*"),
    ("Email address",      r"\b[A-Za-z0-9._%+\-]+@(?:bentleymotors\.com|vw\.com|volkswagen\.[a-z]{2,3}|skoda-auto\.[a-z]{2,3})\b"),
    ("Debug flag",         r"(?i)\b(?:isDebug|debugMode|DEBUG\s*[:=]\s*(?:true|1)|verbose\s*[:=]\s*true)\b"),
    ("TODO/FIXME/HACK",    r"(?i)\b(?:TODO|FIXME|XXX|HACK)\b\s*[:\-]"),
]

ENDPOINT_RE = re.compile(r"""
  (?:"|')(
     (?:https?:)?//[A-Za-z0-9_\-.]{2,}\.[A-Za-z]{2,}[^"'\s]{0,180}
   | /(?!/)[A-Za-z0-9_\-/.%]{2,180}\.(?:json|xml|do|action|php|aspx?|jsp|api|graphql|txt|csv|xlsx?|pdf|html?)(?:\?[^"'\s]{0,100})?
   | /(?:api|rest|graphql|services?|bin|content|apps|conf|var|libs|etc|system|admin|internal|v[0-9]{1,2})/[A-Za-z0-9_\-/.%{}$]{1,180}
  )(?:"|')
""", re.X)

def sev_rank(s):
    return {"critical":0,"high":1,"medium":2,"low":3,"info":4}.get(s, 5)

def walk():
    for base in SCAN_DIRS:
        for dp, _, fns in os.walk(base):
            for fn in fns:
                if fn.endswith((".headers", ".txt")):
                    continue
                p = os.path.join(dp, fn)
                try:
                    if os.path.getsize(p) > 20 * 1024 * 1024:
                        continue
                    yield p, open(p, "r", encoding="utf-8", errors="replace").read()
                except Exception:
                    continue

def ctx(text, s, e):
    a, b = max(0, s - CTX), min(len(text), e + CTX)
    return re.sub(r"\s+", " ", text[a:b]).strip()

def main():
    if not any(os.path.isdir(d) for d in SCAN_DIRS):
        print("nothing to analyse - run ./01-fetch.sh first"); sys.exit(1)

    F = {k: [] for k in
         ("secrets", "endpoints", "sinks", "sources", "postmessage", "dynload", "libs", "internals")}
    endpoints = collections.defaultdict(set)
    nfiles = 0

    for path, text in walk():
        nfiles += 1
        rel = os.path.relpath(path, ROOT)

        for name, pat, sev in SECRETS:
            for m in re.finditer(pat, text):
                val = m.group(0)
                if len(val) > 200: continue
                # cheap FP filters
                low = val.lower()
                if name == "Generic secret assign":
                    cap = (m.group(1) if m.lastindex else "")
                    if re.fullmatch(r"[\w\-]*(?:true|false|null|undefined|none|xxx+|your[_-]?\w*|"
                                    r"\{\{.*\}\}|\$\{.*\}|%s|<%=.*%>|example|changeme|test|demo)[\w\-]*", cap, re.I):
                        continue
                    if len(set(cap)) < 4: continue
                F["secrets"].append(dict(file=rel, kind=name, severity=sev,
                                         match=val[:120], context=ctx(text, m.start(), m.end())))

        for m in ENDPOINT_RE.finditer(text):
            ep = m.group(1)
            if len(ep) < 4 or ep.startswith("//www.w3.org") or ".w3.org/" in ep: continue
            endpoints[ep].add(rel)

        src_pos = []
        for name, pat in SOURCES:
            for m in re.finditer(pat, text):
                src_pos.append((m.start(), name))
                F["sources"].append(dict(file=rel, kind=name, offset=m.start()))
        src_pos.sort()

        for name, pat, sev in SINKS:
            for m in re.finditer(pat, text):
                near = [n for off, n in src_pos if abs(off - m.start()) <= 700]
                F["sinks"].append(dict(file=rel, kind=name, severity=sev, offset=m.start(),
                                       nearby_sources=sorted(set(near)),
                                       context=ctx(text, m.start(), m.end())))

        pm_starts = [m.start() for m in re.finditer(
            r"addEventListener\s*\(\s*['\"]message['\"]|onmessage\s*=", text)]
        for i, st in enumerate(pm_starts):
            nxt = pm_starts[i + 1] if i + 1 < len(pm_starts) else len(text)
            window = text[st: min(st + 1500, nxt)]
            checked = bool(re.search(r"\.origin\s*(?:===|==|!==|!=|\.(?:indexOf|match|includes|startsWith))", window))
            F["postmessage"].append(dict(file=rel, origin_checked=checked,
                                         severity="info" if checked else "high",
                                         context=re.sub(r"\s+", " ", text[st:st + 260]).strip()))

        for m in re.finditer(r"createElement\s*\(\s*['\"](script|iframe|link|object|embed)['\"]", text):
            window = text[m.start(): m.start() + 800]
            dyn = re.search(r"\.\s*(?:src|href|data)\s*=\s*([^;,)]{1,120})", window)
            if dyn and not re.match(r"\s*['\"]", dyn.group(1)):
                F["dynload"].append(dict(file=rel, tag=m.group(1), severity="medium",
                                         assign=dyn.group(1).strip()[:120],
                                         context=ctx(text, m.start(), m.start() + 200)))

        for name, pat, note in LIBS:
            for m in re.finditer(pat, text[:200000]):
                ver = m.group(1) if m.lastindex else "?"
                F["libs"].append(dict(file=rel, lib=name, version=ver, note=note))

        for name, pat in INTERNALS:
            for m in re.finditer(pat, text):
                F["internals"].append(dict(file=rel, kind=name, match=m.group(0)[:160],
                                           context=ctx(text, m.start(), m.end())))

    # de-dup libs per (file, lib, version)
    seen = set(); libs = []
    for r in F["libs"]:
        k = (r["file"], r["lib"], r["version"])
        if k in seen: continue
        seen.add(k); libs.append(r)
    F["libs"] = libs
    F["endpoints"] = [dict(endpoint=e, files=sorted(f)) for e, f in sorted(endpoints.items())]

    F["secrets"].sort(key=lambda r: sev_rank(r["severity"]))
    F["sinks"].sort(key=lambda r: (0 if r["nearby_sources"] else 1, sev_rank(r["severity"])))

    with open(OUT_JSON, "w") as f:
        json.dump(F, f, indent=2)

    # ------------------------------------------------------------- markdown
    L = []
    A = L.append
    A(f"# JS analysis report\n")
    A(f"- files analysed: **{nfiles}**")
    A(f"- endpoints extracted: **{len(F['endpoints'])}**")
    A(f"- secret candidates: **{len(F['secrets'])}**")
    A(f"- DOM sinks: **{len(F['sinks'])}** "
      f"(**{sum(1 for s in F['sinks'] if s['nearby_sources'])}** with a taint source within 700 chars)")
    A(f"- postMessage listeners: **{len(F['postmessage'])}** "
      f"(**{sum(1 for p in F['postmessage'] if not p['origin_checked'])}** without an origin check)\n")

    A("## 1. Secret candidates\n")
    if not F["secrets"]: A("_none_\n")
    for r in F["secrets"][:200]:
        A(f"- **[{r['severity']}] {r['kind']}** — `{r['file']}`\n"
          f"  - match: `{r['match']}`\n  - ctx: `{r['context'][:300]}`")
    A("")

    A("## 2. DOM-XSS: sinks reached near a taint source\n")
    tainted = [s for s in F["sinks"] if s["nearby_sources"]]
    if not tainted: A("_no sink/source co-location_\n")
    for r in tainted[:200]:
        A(f"- **[{r['severity']}] {r['kind']}** ← sources: {', '.join(r['nearby_sources'])} — `{r['file']}` @{r['offset']}\n"
          f"  - ctx: `{r['context'][:320]}`")
    A("")

    A("## 3. postMessage listeners\n")
    for r in sorted(F["postmessage"], key=lambda x: x["origin_checked"])[:80]:
        flag = "ORIGIN CHECKED" if r["origin_checked"] else "!! NO ORIGIN CHECK !!"
        A(f"- **{flag}** — `{r['file']}`\n  - ctx: `{r['context'][:300]}`")
    if not F["postmessage"]: A("_none_")
    A("")

    A("## 4. Dynamic script / iframe injection\n")
    for r in F["dynload"][:80]:
        A(f"- `<{r['tag']}>` src ← `{r['assign']}` — `{r['file']}`\n  - ctx: `{r['context'][:300]}`")
    if not F["dynload"]: A("_none_")
    A("")

    A("## 5. Library fingerprints\n")
    bylib = collections.defaultdict(set)
    for r in F["libs"]: bylib[(r["lib"], r["note"])].add(r["version"])
    for (lib, note), vers in sorted(bylib.items()):
        A(f"- **{lib}** `{', '.join(sorted(vers))}`\n  - {note}")
    if not bylib: A("_none detected_")
    A("")

    A("## 6. Internal / infra leakage\n")
    byk = collections.defaultdict(list)
    for r in F["internals"]: byk[r["kind"]].append(r)
    for k, rs in byk.items():
        A(f"### {k}")
        seen2 = set()
        for r in rs:
            if r["match"] in seen2: continue
            seen2.add(r["match"])
            A(f"- `{r['match']}`  ({r['file']})")
        A("")
    if not byk: A("_none_\n")

    A("## 7. Extracted endpoints\n```")
    for r in F["endpoints"]:
        A(r["endpoint"])
    A("```")

    open(OUT_MD, "w").write("\n".join(L))
    print(f"[+] {nfiles} files analysed")
    print(f"[+] report  -> {os.path.relpath(OUT_MD, ROOT)}")
    print(f"[+] findings-> {os.path.relpath(OUT_JSON, ROOT)}")
    print(f"    secrets={len(F['secrets'])} endpoints={len(F['endpoints'])} "
          f"tainted_sinks={len(tainted)} postmessage={len(F['postmessage'])} dynload={len(F['dynload'])}")

if __name__ == "__main__":
    main()
