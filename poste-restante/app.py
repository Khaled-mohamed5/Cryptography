#!/usr/bin/env python3
"""POSTE RESTANTE -- a blind dead-drop board.

Leave a message under a cover name, dress the envelope in your own CSS, and
never meet the courier who picks it up. Standard library only::

    python3 app.py            # http://127.0.0.1:8080

Threat model, in one paragraph: every drop is written by a stranger and read by
a stranger, and the station vouches for neither. Courier markup and courier CSS
are sanitized on the way in (``sanitize.py``), then rendered inside a sandboxed,
script-free iframe whose Content-Security-Policy forbids *every* outbound
request. A drop therefore cannot run code in the station's origin, cannot read
another courier's cookie, and cannot learn the IP of anyone who reads it.
"""

import argparse
import hmac
import html
import http.cookies
import os
import re
import secrets
import sys
import threading
import time
from datetime import datetime, timezone
from hashlib import sha256
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import sanitize
from store import SEAL_THRESHOLD, Store

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATE_DIR = os.path.join(BASE_DIR, "templates")
STATIC_DIR = os.path.join(BASE_DIR, "static")
DEFAULT_DATA_DIR = os.path.join(BASE_DIR, "data")

COOKIE_NAME = "pr_courier"
COOKIE_MAX_AGE = 60 * 60 * 24 * 180  # half a year of ledger continuity
MAX_REQUEST_BYTES = 256 * 1024
DROPS_PER_HOUR = 30           # per courier handle
POSTS_PER_WINDOW = 20         # per client address
RATE_WINDOW = 300             # seconds

STATION_CSP = (
    "default-src 'none'; style-src 'self'; img-src 'self' data:; "
    "frame-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
)
# The envelope runs with nothing: no script host, no network, no framing by
# anyone but the station. 'unsafe-inline' covers styles only -- never scripts.
ENVELOPE_CSP = (
    "default-src 'none'; style-src 'unsafe-inline'; form-action 'none'; "
    "base-uri 'none'; frame-ancestors 'self'"
)
# No allow-scripts and no allow-same-origin: the envelope gets an opaque origin
# and no way to execute. allow-popups only so that plain links remain clickable.
ENVELOPE_SANDBOX = "allow-popups allow-popups-to-escape-sandbox"


# --------------------------------------------------------------------------
# templating
# --------------------------------------------------------------------------

_PLACEHOLDER_RE = re.compile(r"\{\{\{(\w+)\}\}\}|\{\{(\w+)\}\}")
_template_cache = {}
_template_lock = threading.Lock()


def load_template(name):
    path = os.path.join(TEMPLATE_DIR, name)
    mtime = os.path.getmtime(path)
    with _template_lock:
        cached = _template_cache.get(name)
        if cached and cached[0] == mtime:
            return cached[1]
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
        _template_cache[name] = (mtime, text)
    return text


def render(name, **context):
    """Fill ``{{name}}`` (escaped) and ``{{{name}}}`` (pre-sanitized) slots.

    Replacements are never rescanned, so a courier writing ``{{csrf}}`` into a
    drop title gets those eight characters back, not a token.
    """
    template = load_template(name)

    def substitute(match):
        raw_key, escaped_key = match.group(1), match.group(2)
        if raw_key is not None:
            return str(context.get(raw_key, ""))
        return html.escape(str(context.get(escaped_key, "")), quote=True)

    return _PLACEHOLDER_RE.sub(substitute, template)


# --------------------------------------------------------------------------
# identity: an opaque handle, not an account
# --------------------------------------------------------------------------

def load_secret(data_dir):
    """Return the station's signing key, minting one on first run."""
    from_env = os.environ.get("POSTE_RESTANTE_SECRET")
    if from_env:
        return from_env.encode("utf-8")
    os.makedirs(data_dir, exist_ok=True)
    path = os.path.join(data_dir, "secret.key")
    if os.path.exists(path):
        with open(path, "rb") as handle:
            value = handle.read().strip()
        if value:
            return value
    value = secrets.token_hex(32).encode("ascii")
    # Written before anyone can read it: the key authenticates every ledger.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(value)
    return value


class Identity:
    def __init__(self, secret):
        self._secret = secret

    def _sign(self, label, value):
        digest = hmac.new(self._secret, ("%s:%s" % (label, value)).encode("utf-8"), sha256)
        return digest.hexdigest()[:32]

    def issue(self):
        handle = secrets.token_hex(8)
        return "%s.%s" % (handle, self._sign("courier", handle))

    def verify(self, cookie_value):
        """Return the courier handle carried by ``cookie_value``, or None."""
        if not cookie_value or "." not in cookie_value:
            return None
        handle, _, signature = cookie_value.partition(".")
        if not re.fullmatch(r"[0-9a-f]{16}", handle or ""):
            return None
        if not hmac.compare_digest(signature, self._sign("courier", handle)):
            return None
        return handle

    def csrf_token(self, handle):
        return self._sign("csrf", handle)

    def csrf_ok(self, handle, token):
        return bool(token) and hmac.compare_digest(token, self.csrf_token(handle))


# --------------------------------------------------------------------------
# rate limiting
# --------------------------------------------------------------------------

class RateLimiter:
    """Fixed-window counter keyed by client address."""

    def __init__(self, limit, window):
        self.limit = limit
        self.window = window
        self._hits = {}
        self._lock = threading.Lock()

    def allow(self, key):
        now = time.time()
        with self._lock:
            if len(self._hits) > 4096:
                cutoff = now - self.window
                self._hits = {k: v for k, v in self._hits.items() if v[1] > cutoff}
            count, started = self._hits.get(key, (0, now))
            if now - started > self.window:
                count, started = 0, now
            count += 1
            self._hits[key] = (count, started)
            return count <= self.limit


# --------------------------------------------------------------------------
# small presentation helpers
# --------------------------------------------------------------------------

_BROWSERS = (
    ("EDGE", r"Edg(?:e|A|iOS)?/([\d.]+)"),
    ("OPERA", r"OPR/([\d.]+)"),
    ("SAMSUNG", r"SamsungBrowser/([\d.]+)"),
    ("FIREFOX", r"Firefox/([\d.]+)"),
    ("CHROME", r"Chrom(?:e|ium)/([\d.]+)"),
    ("SAFARI", r"Version/([\d.]+).*Safari"),
    ("CURL", r"curl/([\d.]+)"),
    ("WGET", r"Wget/([\d.]+)"),
)
_PLATFORMS = (
    ("ANDROID", r"Android"),
    ("IOS", r"iPhone|iPad|iPod"),
    ("WINDOWS", r"Windows NT"),
    ("MACOS", r"Macintosh|Mac OS X"),
    ("LINUX", r"Linux|X11"),
    ("BSD", r"BSD"),
)
_ARCHES = (
    ("AMD64", r"x86_64|Win64|x64|amd64"),
    ("ARM64", r"aarch64|arm64|iPhone|iPad|Android"),
    ("X86", r"i[3-6]86|WOW32"),
)


def agent_readout(user_agent):
    """Render a User-Agent as the footer's ``CHROME 143.0 · LINUX/AMD64`` line."""
    if not user_agent:
        return "UNKNOWN AGENT"
    user_agent = user_agent[:400]
    browser = "UNKNOWN AGENT"
    for name, pattern in _BROWSERS:
        match = re.search(pattern, user_agent)
        if match:
            browser = "%s %s" % (name, match.group(1))
            break
    platform = next((n for n, p in _PLATFORMS if re.search(p, user_agent)), None)
    arch = next((n for n, p in _ARCHES if re.search(p, user_agent)), None)
    if platform and arch:
        return "%s · %s/%s" % (browser, platform, arch)
    if platform:
        return "%s · %s" % (browser, platform)
    return browser


def stamp_time(epoch):
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%d %H:%MZ")


def notice(text, kind=""):
    classes = ("notice " + kind).strip()
    return '<p class="%s">%s</p>' % (html.escape(classes, quote=True), text)


def esc(value):
    return html.escape(str(value), quote=True)


# --------------------------------------------------------------------------
# the station
# --------------------------------------------------------------------------

class Station:
    def __init__(self, store, identity):
        self.store = store
        self.identity = identity
        self.post_limiter = RateLimiter(POSTS_PER_WINDOW, RATE_WINDOW)

    # -- index ------------------------------------------------------------
    def index_page(self, ctx, notices="", title="", body="", css=""):
        drops = self.store.list_drops(ctx.handle)
        return render(
            "index.html",
            notices=notices,
            ledger=self.render_ledger(drops),
            csrf=self.identity.csrf_token(ctx.handle),
            title_value=title,
            body_value=body,
            css_value=css,
            agent=ctx.agent,
            handle=self.file_number(ctx.handle),
        )

    @staticmethod
    def file_number(handle):
        return "%s-%s" % (handle[:4].upper(), handle[4:8].upper())

    @staticmethod
    def render_ledger(drops):
        if not drops:
            return '<li class="empty">// no drops on record. compose one above.</li>'
        rows = []
        for drop in drops:
            count = drop["pickups"]
            label = "1 pickup" if count == 1 else "%d pickups" % count
            state = '<span class="pickups sealed-tag">sealed</span>' if drop["sealed"] else ""
            rows.append(
                '<li>'
                '<span class="idtag">DD-%s</span>'
                '<a class="drop-title" href="/d/%s">%s</a>'
                '%s'
                '<a class="pickups" href="/d/%s">%s</a>'
                '</li>' % (
                    esc(drop["id"][:4].upper()), esc(drop["id"]), esc(drop["title"]),
                    state, esc(drop["id"]), esc(label),
                )
            )
        return "\n".join(rows)

    # -- creating a drop --------------------------------------------------
    def create(self, ctx, form):
        title_raw = form.get("title", "")
        body_raw = form.get("body", "")
        css_raw = form.get("css", "")

        errors = []
        if not ctx.cookie_was_valid:
            # First contact, or a cookie we did not sign: the CSRF token could
            # not have been minted for this handle, so ask for one more pass.
            errors.append("Channel handshake incomplete — the station just issued "
                          "you a handle. Stamp the form again to leave the drop.")
        elif not self.identity.csrf_ok(ctx.handle, form.get("_csrf", "")):
            errors.append("Manifest seal did not match. Reload the counter and try again.")

        title = sanitize.plain_text(title_raw)
        if not title:
            errors.append("A drop needs a designation — a short cover name.")
        if len(body_raw) > sanitize.MAX_BODY:
            errors.append("Message runs past %d characters." % sanitize.MAX_BODY)
        if len(css_raw) > sanitize.MAX_CSS:
            errors.append("Envelope cipher runs past %d characters." % sanitize.MAX_CSS)

        body_html = sanitize.sanitize_html(body_raw)
        envelope_css = sanitize.sanitize_css(css_raw)
        if not errors and not body_html:
            errors.append("The envelope came out empty after sanitizing. "
                          "Plain text, or the allowed markup, will survive.")

        if not errors and not self.post_limiter.allow(ctx.client):
            errors.append("Too many manifests from this line. Wait a few minutes.")
        if not errors and self.store.count_recent_by_owner(
                ctx.handle, int(time.time()) - 3600) >= DROPS_PER_HOUR:
            errors.append("This handle has filled its hourly quota of drops.")

        if errors:
            listing = "".join("<li>%s</li>" % notice(esc(e), "bad") for e in errors)
            return self.index_page(
                ctx,
                notices='<ul class="errors">%s</ul>' % listing,
                title=title_raw[:sanitize.MAX_TITLE],
                body=body_raw[:sanitize.MAX_BODY],
                css=css_raw[:sanitize.MAX_CSS],
            )

        drop_id = self.store.create_drop(
            ctx.handle, title, body_raw[:sanitize.MAX_BODY], body_html,
            css_raw[:sanitize.MAX_CSS], envelope_css,
        )
        dropped = len(css_raw.strip()) > 0 and not envelope_css
        return Redirect("/d/%s?left=1%s" % (drop_id, "&cipher=stripped" if dropped else ""))

    # -- reading a drop ---------------------------------------------------
    def drop_page(self, ctx, drop_id, query):
        drop = self.store.get_drop(drop_id)
        if drop is None:
            return None
        is_owner = drop["owner"] == ctx.handle

        if is_owner:
            pickups = self.store.count_pickups(drop_id)
        else:
            # Only strangers count as pickups; re-reading is not re-collecting.
            pickups = self.store.record_pickup(drop_id, ctx.handle)

        notices = []
        if "left" in query:
            notices.append(notice(
                "Drop left at the counter. <b>Anyone with this link can collect it.</b>", "good"))
        if query.get("cipher") == ["stripped"]:
            notices.append(notice(
                "Your envelope cipher was discarded in full — it asked for something "
                "the station will not carry (a remote fetch, or a property outside "
                "the allowed set).", "bad"))
        if "flagged" in query:
            notices.append(notice("Report logged. A courier will look at this drop.", ""))
        if "already-flagged" in query:
            notices.append(notice("You have already flagged this drop.", ""))

        if drop["sealed"]:
            notices.append(notice(
                "<b>SEALED.</b> This drop drew %d reports and is withheld from pickup."
                % SEAL_THRESHOLD, "bad"))

        if drop["sealed"] and not is_owner:
            envelope = ('<div class="sealed"><strong>Envelope sealed</strong>'
                        'Withheld pending courier review.</div>')
        else:
            envelope = (
                '<iframe class="envelope" src="/d/%s/envelope" sandbox="%s"'
                ' referrerpolicy="no-referrer" loading="lazy"'
                ' title="envelope contents"></iframe>'
                '<div class="envelope-note"><span>Sandboxed · scripts denied ·'
                ' network denied</span><span>drag the lower edge to resize</span></div>'
                % (esc(drop["id"]), esc(ENVELOPE_SANDBOX))
            )

        return render(
            "drop.html",
            title=drop["title"],
            idtag="DD-%s" % drop["id"][:4].upper(),
            ownership="your drop" if is_owner else "collected anonymously",
            state="SEALED" if drop["sealed"] else "CHANNEL SECURE",
            dotclass="dot dead" if drop["sealed"] else "dot",
            created=stamp_time(drop["created_at"]),
            pickups=pickups,
            cipher="CUSTOM" if drop["envelope_css"] else "STATION DEFAULT",
            notices="".join(notices),
            envelope=envelope,
            flagbox=self.render_flagbox(ctx, drop),
            agent=ctx.agent,
            handle=self.file_number(ctx.handle),
        )

    def render_flagbox(self, ctx, drop):
        if self.store.has_flagged(drop["id"], ctx.handle):
            return ('<p class="ref">You have flagged this drop. It stays on the '
                    'courier queue until reviewed.</p>')
        return (
            '<p class="ref flag-intro">Envelopes are unverified. If this '
            'one is a lure, a threat, or someone else&#x27;s private business, say so — '
            '%d independent reports seal it.</p>'
            '<form class="flagform" method="post" action="/d/%s/flag">'
            '<input type="hidden" name="_csrf" value="%s">'
            '<label class="lab" for="f-reason">Reason '
            '<small>optional, 200 characters</small></label>'
            '<input id="f-reason" name="reason" type="text" maxlength="200"'
            ' placeholder="what is wrong with this drop?">'
            '<button class="stamp ghost" type="submit">&#9873; Flag for a courier</button>'
            '</form>' % (SEAL_THRESHOLD, esc(drop["id"]),
                         esc(self.identity.csrf_token(ctx.handle)))
        )

    def envelope_document(self, ctx, drop_id):
        drop = self.store.get_drop(drop_id)
        if drop is None:
            return None
        if drop["sealed"] and drop["owner"] != ctx.handle:
            return Gone()
        body_html = drop["body_html"] or \
            '<p class="empty-envelope">// this envelope is empty.</p>'
        return render(
            "envelope.html",
            id=drop["id"],
            envelope_css=drop["envelope_css"],
            body_html=body_html,
        )

    # -- flagging ---------------------------------------------------------
    def flag(self, ctx, drop_id, form):
        drop = self.store.get_drop(drop_id)
        if drop is None:
            return None
        if not ctx.cookie_was_valid or \
                not self.identity.csrf_ok(ctx.handle, form.get("_csrf", "")):
            return Redirect("/d/%s" % drop_id)
        if not self.post_limiter.allow(ctx.client):
            return Redirect("/d/%s" % drop_id)
        if self.store.has_flagged(drop_id, ctx.handle):
            return Redirect("/d/%s?already-flagged=1" % drop_id)
        reason = sanitize.plain_text(form.get("reason", ""), limit=200) or "(no reason given)"
        self.store.flag_drop(drop_id, ctx.handle, reason)
        return Redirect("/d/%s?flagged=1" % drop_id)


class Redirect:
    def __init__(self, location):
        self.location = location


class Gone:
    pass


class RequestContext:
    __slots__ = ("handle", "cookie_was_valid", "agent", "client")

    def __init__(self, handle, cookie_was_valid, agent, client):
        self.handle = handle
        self.cookie_was_valid = cookie_was_valid
        self.agent = agent
        self.client = client


# --------------------------------------------------------------------------
# HTTP plumbing
# --------------------------------------------------------------------------

DROP_ID_RE = re.compile(r"^[a-z2-9]{6,16}$")

COMMON_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=(), camera=(), microphone=(), interest-cohort=()",
    "Cross-Origin-Opener-Policy": "same-origin",
}


class StationHandler(BaseHTTPRequestHandler):
    server_version = "PosteRestante"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    # -- request helpers --------------------------------------------------
    @property
    def station(self):
        return self.server.station

    def client_key(self):
        if self.server.trust_proxy:
            forwarded = self.headers.get("X-Forwarded-For", "")
            if forwarded:
                return forwarded.split(",")[0].strip()[:64]
        return self.client_address[0] if self.client_address else "-"

    def context(self):
        """Resolve the courier handle for this request, minting one if needed."""
        identity = self.server.identity
        raw = None
        try:
            jar = http.cookies.SimpleCookie(self.headers.get("Cookie", ""))
            morsel = jar.get(COOKIE_NAME)
            raw = morsel.value if morsel else None
        except http.cookies.CookieError:
            raw = None
        handle = identity.verify(raw)
        if handle:
            self._issue_cookie = None
            recognised = True
        else:
            self._issue_cookie = identity.issue()
            handle = identity.verify(self._issue_cookie)
            recognised = False
        return RequestContext(handle, recognised,
                              agent_readout(self.headers.get("User-Agent", "")),
                              self.client_key())

    def read_form(self):
        """Parse an urlencoded body, or return None and close the connection.

        Whenever the body is not read to the end -- too large, or chunked, which
        this server does not decode -- the socket is no longer at a request
        boundary, so it must not be reused for the next request.
        """
        if self.headers.get("Transfer-Encoding"):
            self.close_connection = True
            return None
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.close_connection = True
            return None
        if length < 0 or length > MAX_REQUEST_BYTES:
            self.close_connection = True
            return None
        raw = self.rfile.read(length) if length else b""
        content_type = (self.headers.get("Content-Type") or "").split(";")[0].strip()
        if content_type and content_type != "application/x-www-form-urlencoded":
            return None
        parsed = parse_qs(raw.decode("utf-8", "replace"), keep_blank_values=True)
        return {key: values[0] for key, values in parsed.items()}

    # -- response helpers -------------------------------------------------
    def respond(self, status, body=b"", content_type="text/html; charset=utf-8",
                headers=None, csp=STATION_CSP, cache="no-store"):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Security-Policy", csp)
        self.send_header("Cache-Control", cache)
        for name, value in COMMON_HEADERS.items():
            self.send_header(name, value)
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        cookie = getattr(self, "_issue_cookie", None)
        if cookie:
            attributes = [
                "%s=%s" % (COOKIE_NAME, cookie), "Path=/", "HttpOnly",
                "SameSite=Lax", "Max-Age=%d" % COOKIE_MAX_AGE,
            ]
            if self.server.secure_cookies:
                attributes.append("Secure")
            self.send_header("Set-Cookie", "; ".join(attributes))
            self._issue_cookie = None
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def redirect(self, location):
        self.respond(HTTPStatus.SEE_OTHER, b"", headers={"Location": location})

    def fail(self, status, headline, detail):
        page = (
            '<!doctype html><html lang="en"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width, initial-scale=1">'
            '<title>%s // POSTE RESTANTE</title>'
            '<link rel="stylesheet" href="/static/station.css"></head><body>'
            '<div class="class-bar"><span>TOP SECRET // COURIER EYES ONLY</span></div>'
            '<div class="wrap"><header><div class="kicker">Station &Delta;</div>'
            '<h1>%s</h1><p class="tagline">%s</p></header>'
            '<p><a class="backlink" href="/">&larr; back to the counter</a></p>'
            '</div></body></html>' % (esc(headline), esc(headline), esc(detail))
        )
        self.respond(status, page)

    # -- routing ----------------------------------------------------------
    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query, keep_blank_values=True)

        if path == "/static/station.css":
            return self.serve_stylesheet()
        if path == "/healthz":
            return self.respond(HTTPStatus.OK, b"ok\n", "text/plain; charset=utf-8")

        ctx = self.context()

        if path == "/":
            return self.respond(HTTPStatus.OK, self.station.index_page(ctx))

        match = re.fullmatch(r"/d/([^/]+)", path)
        if match:
            drop_id = match.group(1)
            if not DROP_ID_RE.match(drop_id):
                return self.not_found()
            page = self.station.drop_page(ctx, drop_id, query)
            if page is None:
                return self.not_found()
            return self.respond(HTTPStatus.OK, page)

        match = re.fullmatch(r"/d/([^/]+)/envelope", path)
        if match:
            drop_id = match.group(1)
            if not DROP_ID_RE.match(drop_id):
                return self.not_found()
            document = self.station.envelope_document(ctx, drop_id)
            if document is None:
                return self.not_found()
            if isinstance(document, Gone):
                return self.fail(HTTPStatus.GONE, "Envelope sealed",
                                 "This drop was withheld after repeated reports.")
            return self.respond(
                HTTPStatus.OK, document, csp=ENVELOPE_CSP,
                headers={"X-Frame-Options": "SAMEORIGIN"})

        return self.not_found()

    def do_HEAD(self):
        self.do_GET()

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        ctx = self.context()
        form = self.read_form()
        if form is None:
            return self.fail(HTTPStatus.BAD_REQUEST, "Manifest rejected",
                             "The station reads urlencoded forms, under 256 KB.")

        if path == "/post":
            result = self.station.create(ctx, form)
            if isinstance(result, Redirect):
                return self.redirect(result.location)
            return self.respond(HTTPStatus.OK, result)

        match = re.fullmatch(r"/d/([^/]+)/flag", path)
        if match:
            drop_id = match.group(1)
            if not DROP_ID_RE.match(drop_id):
                return self.not_found()
            result = self.station.flag(ctx, drop_id, form)
            if result is None:
                return self.not_found()
            return self.redirect(result.location)

        return self.not_found()

    def not_found(self):
        self.fail(HTTPStatus.NOT_FOUND, "No such drop",
                  "Nothing was left under that reference — or it was never yours to collect.")

    def serve_stylesheet(self):
        # A fixed filename rather than a path join: nothing here can traverse.
        with open(os.path.join(STATIC_DIR, "station.css"), "rb") as handle:
            body = handle.read()
        self.respond(HTTPStatus.OK, body, "text/css; charset=utf-8",
                     cache="public, max-age=300")

    # -- logging ----------------------------------------------------------
    def log_message(self, fmt, *args):
        # No client addresses in the log: an anonymous board that keeps an
        # access log keyed by IP is not an anonymous board.
        sys.stderr.write("[%s] %s\n" % (
            datetime.now(timezone.utc).strftime("%H:%M:%S"), fmt % args))

    def log_error(self, fmt, *args):
        self.log_message(fmt, *args)


class StationServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, handler, station, identity,
                 secure_cookies=False, trust_proxy=False):
        super().__init__(address, handler)
        self.station = station
        self.identity = identity
        self.secure_cookies = secure_cookies
        self.trust_proxy = trust_proxy


def build_server(host="127.0.0.1", port=8080, data_dir=DEFAULT_DATA_DIR,
                 secure_cookies=False, trust_proxy=False):
    os.makedirs(data_dir, exist_ok=True)
    store = Store(os.path.join(data_dir, "station.db"))
    identity = Identity(load_secret(data_dir))
    station = Station(store, identity)
    return StationServer((host, port), StationHandler, station, identity,
                         secure_cookies=secure_cookies, trust_proxy=trust_proxy)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Run the POSTE RESTANTE station.")
    parser.add_argument("--host", default=os.environ.get("POSTE_RESTANTE_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int,
                        default=int(os.environ.get("POSTE_RESTANTE_PORT", "8080")))
    parser.add_argument("--data-dir", default=os.environ.get(
        "POSTE_RESTANTE_DATA", DEFAULT_DATA_DIR),
        help="where the SQLite database and signing key live")
    parser.add_argument("--secure-cookies", action="store_true",
                        help="add the Secure attribute (required behind HTTPS)")
    parser.add_argument("--trust-proxy", action="store_true",
                        help="read the client address from X-Forwarded-For")
    args = parser.parse_args(argv)

    server = build_server(args.host, args.port, args.data_dir,
                          args.secure_cookies, args.trust_proxy)
    print("POSTE RESTANTE // station open at http://%s:%d" % (args.host, args.port))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstation closed.")
    finally:
        server.server_close()
        server.station.store.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
