"""Sanitizers for courier-supplied markup and envelope ciphers (CSS).

Two independent layers protect a reader who opens a drop:

  1. these sanitizers, which reduce arbitrary input to a known-safe subset, and
  2. the sandboxed iframe + Content-Security-Policy the envelope is served in
     (see ``app.py``), which denies scripts and *every* outbound request.

Neither layer is trusted to be complete on its own.
"""

import re
from html.parser import HTMLParser

MAX_TITLE = 80
MAX_BODY = 20000
MAX_CSS = 8000
MAX_NESTING = 40

# --------------------------------------------------------------------------
# markup
# --------------------------------------------------------------------------

# Tags that survive sanitizing. Deliberately text-only: no <img>, no <video>,
# no <object>. Anything that can name a remote URL turns a "blind" drop into a
# beacon that reports every reader's IP back to whoever left it.
ALLOWED_TAGS = {
    "p", "br", "hr", "div", "span", "small",
    "strong", "b", "em", "i", "u", "s", "mark", "sub", "sup", "abbr",
    "code", "pre", "kbd", "samp", "var",
    "blockquote", "q", "cite",
    "h1", "h2", "h3", "h4", "h5", "h6",
    "ul", "ol", "li", "dl", "dt", "dd",
    "table", "thead", "tbody", "tfoot", "tr", "th", "td", "caption", "colgroup", "col",
    "figure", "figcaption", "details", "summary", "a",
}

VOID_TAGS = {"br", "hr", "col"}

# Tags whose *contents* are dropped along with the tag itself. For every other
# disallowed tag the children are kept, so stray markup degrades to plain text
# instead of vanishing.
DROP_WITH_CONTENT = {
    "script", "style", "iframe", "frame", "frameset", "object", "embed", "applet",
    "form", "input", "button", "select", "option", "textarea", "label", "fieldset",
    "link", "meta", "base", "title", "head", "svg", "math", "template", "noscript",
    "audio", "video", "source", "track", "canvas", "portal",
}

GLOBAL_ATTRS = {"class", "id", "title", "lang", "dir", "style"}
TAG_ATTRS = {
    "a": {"href", "hreflang"},
    "abbr": {"title"},
    "th": {"colspan", "rowspan", "scope", "headers"},
    "td": {"colspan", "rowspan", "headers"},
    "col": {"span"},
    "colgroup": {"span"},
    "ol": {"start", "reversed", "type"},
    "details": {"open"},
    "blockquote": {"cite"},
    "q": {"cite"},
}

SAFE_SCHEMES = ("http://", "https://", "mailto:")
_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_LANG_RE = re.compile(r"^[A-Za-z]{1,8}(-[A-Za-z0-9]{1,8})*$")
# Characters that let a crafted URL smuggle a scheme past a naive prefix check.
_URL_NOISE_RE = re.compile(r"[\x00-\x20\x7f   -‏    　﻿]")


def _safe_url(value):
    """Return ``value`` if it is a fetchable, non-executing URL, else ``None``."""
    if not value:
        return None
    # Strip control characters and exotic whitespace first: browsers ignore them
    # when resolving a URL, so "java\nscript:alert(1)" is a live scheme.
    cleaned = _URL_NOISE_RE.sub("", value).strip()
    if not cleaned:
        return None
    lowered = cleaned.lower()
    if lowered.startswith("//"):
        # Protocol-relative: it reads like a path but leaves for another host.
        # Outbound links are allowed, but they must say so.
        return None
    if lowered.startswith("#") or lowered.startswith("/"):
        return cleaned if len(cleaned) <= 2048 else None
    if any(lowered.startswith(scheme) for scheme in SAFE_SCHEMES):
        return cleaned if len(cleaned) <= 2048 else None
    return None


def _safe_tokens(value):
    tokens = [t for t in (value or "").split() if _TOKEN_RE.match(t)]
    return " ".join(tokens[:16])


def _filter_attrs(tag, attrs):
    permitted = GLOBAL_ATTRS | TAG_ATTRS.get(tag, set())
    kept = []
    for raw_name, raw_value in attrs:
        name = (raw_name or "").lower()
        value = raw_value if raw_value is not None else ""
        # Event handlers are never negotiable, whatever else the tag allows.
        if name.startswith("on") or name not in permitted:
            continue

        if name in ("class", "id", "headers"):
            value = _safe_tokens(value)
            if not value:
                continue
        elif name == "style":
            value = sanitize_declarations(value)
            if not value:
                continue
        elif name in ("href", "cite"):
            safe = _safe_url(value)
            if safe is None:
                continue
            value = safe
        elif name == "lang" or name == "hreflang":
            if not _LANG_RE.match(value):
                continue
        elif name == "dir":
            if value.lower() not in ("ltr", "rtl", "auto"):
                continue
            value = value.lower()
        elif name in ("colspan", "rowspan", "span", "start"):
            if not re.match(r"^-?\d{1,4}$", value.strip()):
                continue
            value = value.strip()
        elif name == "scope":
            if value.lower() not in ("row", "col", "rowgroup", "colgroup"):
                continue
            value = value.lower()
        elif name == "type":
            if value not in ("1", "a", "A", "i", "I"):
                continue
        elif name in ("reversed", "open"):
            value = name
        elif name == "title":
            value = value[:200]

        kept.append((name, value))

    if tag == "a" and any(n == "href" for n, _ in kept):
        # Outbound links leave the station; make them cheap to distrust and
        # impossible to use as a referrer channel back to the drop.
        kept = [(n, v) for n, v in kept if n not in ("rel", "target")]
        kept.append(("rel", "nofollow noopener noreferrer ugc"))
        kept.append(("target", "_blank"))
    return kept


def _escape_text(text):
    return (text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def _escape_attr(value):
    return (value.replace("&", "&amp;").replace("<", "&lt;")
                 .replace(">", "&gt;").replace('"', "&quot;").replace("'", "&#x27;"))


class _Sanitizer(HTMLParser):
    def __init__(self):
        # convert_charrefs re-decodes entities so that "&#x6a;avascript:" cannot
        # slip through as an unrecognised blob; everything is re-escaped on output.
        super().__init__(convert_charrefs=True)
        self.out = []
        self.stack = []
        self.skip_tag = None
        self.skip_depth = 0

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        if self.skip_tag is not None:
            if tag == self.skip_tag and tag not in VOID_TAGS:
                self.skip_depth += 1
            return
        if tag in DROP_WITH_CONTENT:
            self.skip_tag = tag
            self.skip_depth = 1
            return
        if tag not in ALLOWED_TAGS or len(self.stack) >= MAX_NESTING:
            return  # unwrap: the tag goes, its text stays

        attr_html = "".join(
            ' %s="%s"' % (name, _escape_attr(value))
            for name, value in _filter_attrs(tag, attrs)
        )
        if tag in VOID_TAGS:
            self.out.append("<%s%s>" % (tag, attr_html))
        else:
            self.out.append("<%s%s>" % (tag, attr_html))
            self.stack.append(tag)

    def handle_startendtag(self, tag, attrs):
        tag = tag.lower()
        self.handle_starttag(tag, attrs)
        if tag not in VOID_TAGS:
            self.handle_endtag(tag)

    def handle_endtag(self, tag):
        tag = tag.lower()
        if self.skip_tag is not None:
            if tag == self.skip_tag:
                self.skip_depth -= 1
                if self.skip_depth <= 0:
                    self.skip_tag = None
            return
        if tag in VOID_TAGS or tag not in self.stack:
            return
        # Close everything opened inside the tag being closed, so mismatched
        # input can never leave an element hanging open past its content.
        while self.stack:
            open_tag = self.stack.pop()
            self.out.append("</%s>" % open_tag)
            if open_tag == tag:
                break

    def handle_data(self, data):
        if self.skip_tag is None and data:
            self.out.append(_escape_text(data))

    def handle_comment(self, data):
        pass

    def unknown_decl(self, data):
        pass

    def handle_decl(self, decl):
        pass

    def handle_pi(self, data):
        pass

    def result(self):
        while self.stack:
            self.out.append("</%s>" % self.stack.pop())
        return "".join(self.out)


def sanitize_html(raw):
    """Reduce ``raw`` to the allowed markup subset, escaping everything else."""
    if not raw:
        return ""
    parser = _Sanitizer()
    parser.feed(raw[:MAX_BODY])
    parser.close()
    return parser.result().strip()


def plain_text(raw, limit=MAX_TITLE):
    """Collapse ``raw`` to a single line of unstyled text (used for titles)."""
    text = re.sub(r"<[^>]*>", " ", raw or "")
    text = re.sub(r"[\x00-\x1f\x7f]", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:limit]


# --------------------------------------------------------------------------
# envelope ciphers (CSS)
# --------------------------------------------------------------------------

# Properties a courier may set on their envelope. An allowlist rather than a
# blocklist: unknown properties are dropped, so a new browser feature cannot
# quietly become an escape hatch.
ALLOWED_PROPS = {
    # box
    "display", "position", "top", "right", "bottom", "left", "float", "clear",
    "width", "height", "min-width", "min-height", "max-width", "max-height",
    "margin", "margin-top", "margin-right", "margin-bottom", "margin-left",
    "padding", "padding-top", "padding-right", "padding-bottom", "padding-left",
    "box-sizing", "overflow", "overflow-x", "overflow-y", "visibility", "z-index",
    "aspect-ratio", "resize", "isolation", "contain",
    # flex & grid
    "flex", "flex-basis", "flex-direction", "flex-flow", "flex-grow", "flex-shrink",
    "flex-wrap", "align-content", "align-items", "align-self", "justify-content",
    "justify-items", "justify-self", "order", "gap", "row-gap", "column-gap",
    "grid", "grid-area", "grid-auto-columns", "grid-auto-flow", "grid-auto-rows",
    "grid-column", "grid-column-end", "grid-column-start", "grid-row",
    "grid-row-end", "grid-row-start", "grid-template", "grid-template-areas",
    "grid-template-columns", "grid-template-rows", "place-content", "place-items",
    "place-self",
    # colour & paint
    "color", "background", "background-attachment", "background-blend-mode",
    "background-clip", "background-color", "background-image", "background-origin",
    "background-position", "background-repeat", "background-size",
    "opacity", "mix-blend-mode", "filter", "backdrop-filter", "accent-color",
    # border
    "border", "border-top", "border-right", "border-bottom", "border-left",
    "border-color", "border-top-color", "border-right-color", "border-bottom-color",
    "border-left-color", "border-style", "border-top-style", "border-right-style",
    "border-bottom-style", "border-left-style", "border-width", "border-top-width",
    "border-right-width", "border-bottom-width", "border-left-width",
    "border-radius", "border-top-left-radius", "border-top-right-radius",
    "border-bottom-left-radius", "border-bottom-right-radius",
    "border-collapse", "border-spacing", "outline", "outline-color",
    "outline-offset", "outline-style", "outline-width", "box-shadow",
    # type
    "font", "font-family", "font-size", "font-stretch", "font-style",
    "font-variant", "font-weight", "font-feature-settings", "font-kerning",
    "letter-spacing", "line-height", "text-align", "text-decoration",
    "text-decoration-color", "text-decoration-line", "text-decoration-style",
    "text-indent", "text-overflow", "text-shadow", "text-transform",
    "text-wrap", "vertical-align", "white-space", "word-break", "word-spacing",
    "overflow-wrap", "hyphens", "tab-size", "writing-mode", "direction", "quotes",
    # lists, tables, misc
    "list-style", "list-style-position", "list-style-type", "table-layout",
    "caption-side", "empty-cells", "counter-increment", "counter-reset", "content",
    "cursor", "pointer-events", "user-select", "caret-color",
    # motion
    "animation", "animation-delay", "animation-direction", "animation-duration",
    "animation-fill-mode", "animation-iteration-count", "animation-name",
    "animation-play-state", "animation-timing-function",
    "transition", "transition-delay", "transition-duration", "transition-property",
    "transition-timing-function", "transform", "transform-origin", "transform-style",
    "perspective", "perspective-origin", "backface-visibility", "will-change",
    "scroll-behavior",
}

# Every ``name(`` in a value must appear here. ``url`` is absent on purpose: an
# envelope that can fetch is an envelope that can phone home about its reader.
ALLOWED_FUNCS = {
    "rgb", "rgba", "hsl", "hsla", "hwb", "lab", "lch", "oklab", "oklch",
    "color", "color-mix", "var", "calc", "min", "max", "clamp", "env",
    "linear-gradient", "radial-gradient", "conic-gradient",
    "repeating-linear-gradient", "repeating-radial-gradient", "repeating-conic-gradient",
    "cubic-bezier", "steps", "counter", "counters", "fit-content", "minmax", "repeat",
    "translate", "translatex", "translatey", "translatez", "translate3d",
    "rotate", "rotatex", "rotatey", "rotatez", "rotate3d",
    "scale", "scalex", "scaley", "scalez", "scale3d",
    "skew", "skewx", "skewy", "matrix", "matrix3d", "perspective",
    "blur", "brightness", "contrast", "drop-shadow", "grayscale", "hue-rotate",
    "invert", "opacity", "saturate", "sepia",
}

ALLOWED_AT_RULES = {"media", "supports", "keyframes", "-webkit-keyframes"}
MAX_AT_DEPTH = 2

_COMMENT_RE = re.compile(r"/\*.*?\*/", re.S)
_FUNC_RE = re.compile(r"([-A-Za-z_][-A-Za-z0-9_]*)\s*\(")
_SELECTOR_RE = re.compile(r"^[A-Za-z0-9_\-\.\#\*\s,>\+~\[\]\=\"'\(\):\|\^\$!%]*$")
_KEYFRAME_SEL_RE = re.compile(r"^(from|to|\d{1,3}(\.\d+)?%)(\s*,\s*(from|to|\d{1,3}(\.\d+)?%))*$", re.I)
_CONDITION_RE = re.compile(r"^[A-Za-z0-9_\-\.\s,:()\[\]/\+\*=%'\"]*$")
_IDENT_RE = re.compile(r"^-?[A-Za-z_][-A-Za-z0-9_]*$")

# Constructs that have historically turned a stylesheet into a script host or a
# network client. Checked literally in addition to the function allowlist.
_FORBIDDEN_IN_VALUE = (
    "url(", "expression(", "javascript:", "vbscript:", "data:",
    "-moz-binding", "behavior", "image-set(", "element(", "attr(", "\\",
)


def _skip_string(css, i):
    """Return the index just past the string literal starting at ``css[i]``."""
    quote = css[i]
    i += 1
    while i < len(css):
        if css[i] == "\\":
            i += 2
            continue
        if css[i] == quote:
            return i + 1
        i += 1
    return i


def _split_blocks(css):
    """Yield ``(prelude, body)`` pairs; ``body`` is None for ``@rule;`` statements."""
    i = 0
    n = len(css)
    start = 0
    while i < n:
        ch = css[i]
        if ch in "\"'":
            i = _skip_string(css, i)
            continue
        if ch == ";":
            yield css[start:i], None
            i += 1
            start = i
            continue
        if ch == "}":
            # Stray closer: a rule trying to break out of an enclosing block.
            i += 1
            start = i
            continue
        if ch == "{":
            depth = 1
            j = i + 1
            while j < n and depth:
                cj = css[j]
                if cj in "\"'":
                    j = _skip_string(css, j)
                    continue
                if cj == "{":
                    depth += 1
                elif cj == "}":
                    depth -= 1
                j += 1
            body_end = j - 1 if depth == 0 else n
            yield css[start:i], css[i + 1:body_end]
            i = j
            start = i
            continue
        i += 1


def _split_declarations(body):
    parts = []
    depth = 0
    start = 0
    i = 0
    while i < len(body):
        ch = body[i]
        if ch in "\"'":
            i = _skip_string(body, i)
            continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth = max(0, depth - 1)
        elif ch == ";" and depth == 0:
            parts.append(body[start:i])
            start = i + 1
        i += 1
    parts.append(body[start:])
    return parts


def _safe_value(value):
    value = value.strip()
    if not value or len(value) > 500:
        return None
    lowered = value.lower()
    if any(bad in lowered for bad in _FORBIDDEN_IN_VALUE):
        return None
    if any(ch in value for ch in "{}@<>"):
        return None
    for func in _FUNC_RE.findall(lowered):
        if func not in ALLOWED_FUNCS:
            return None
    return value


def sanitize_declarations(body):
    """Sanitize a ``prop: value; ...`` list (a rule body or a style attribute)."""
    if not body:
        return ""
    body = _COMMENT_RE.sub(" ", body)
    kept = []
    for chunk in _split_declarations(body):
        if ":" not in chunk:
            continue
        prop, _, value = chunk.partition(":")
        prop = prop.strip().lower()
        if not prop:
            continue
        if not (prop in ALLOWED_PROPS or (prop.startswith("--") and _IDENT_RE.match(prop[2:] or "x"))):
            continue
        safe = _safe_value(value)
        if safe is None:
            continue
        kept.append("%s: %s" % (prop, safe))
        if len(kept) >= 200:
            break
    return "; ".join(kept)


def _sanitize_selector(selector):
    selector = _COMMENT_RE.sub(" ", selector).strip()
    if not selector or len(selector) > 400:
        return None
    if not _SELECTOR_RE.match(selector):
        return None
    lowered = selector.lower()
    if "url(" in lowered or "expression(" in lowered:
        return None
    return re.sub(r"\s+", " ", selector)


def _sanitize_at_rule(prelude, body, depth):
    match = re.match(r"^@([-A-Za-z]+)\s*(.*)$", prelude.strip(), re.S)
    if not match:
        return None
    name = match.group(1).lower()
    argument = re.sub(r"\s+", " ", match.group(2)).strip()
    if name not in ALLOWED_AT_RULES or body is None or depth >= MAX_AT_DEPTH:
        return None

    if name in ("keyframes", "-webkit-keyframes"):
        if not _IDENT_RE.match(argument):
            return None
        frames = []
        for frame_prelude, frame_body in _split_blocks(body):
            selector = re.sub(r"\s+", " ", _COMMENT_RE.sub(" ", frame_prelude)).strip()
            if frame_body is None or not _KEYFRAME_SEL_RE.match(selector):
                continue
            declarations = sanitize_declarations(frame_body)
            if declarations:
                frames.append("  %s { %s }" % (selector.lower(), declarations))
        if not frames:
            return None
        return "@%s %s {\n%s\n}" % (name, argument, "\n".join(frames))

    # @media / @supports
    if not _CONDITION_RE.match(argument) or "url(" in argument.lower():
        return None
    inner = _sanitize_rules(body, depth + 1)
    if not inner:
        return None
    return "@%s %s {\n%s\n}" % (name, argument, inner)


def _sanitize_rules(css, depth=0):
    out = []
    for prelude, body in _split_blocks(css):
        if prelude.strip().startswith("@"):
            rule = _sanitize_at_rule(prelude, body, depth)
            if rule:
                out.append(rule)
            continue
        if body is None:
            continue  # a declaration floating outside any rule
        selector = _sanitize_selector(prelude)
        if not selector:
            continue
        declarations = sanitize_declarations(body)
        if declarations:
            out.append("%s { %s }" % (selector, declarations))
        if len(out) >= 300:
            break
    return "\n".join(out)


def sanitize_css(raw):
    """Reduce an envelope cipher to rules that cannot script, fetch, or escape."""
    if not raw:
        return ""
    css = _sanitize_rules(_COMMENT_RE.sub(" ", raw[:MAX_CSS]))
    # The result is emitted inside a <style> element, a raw-text context that
    # ends at "</style". Selectors, values and conditions already exclude "<";
    # this is the backstop that makes that a property of the output, not of
    # three separate regexes staying correct.
    return css.replace("<", "")
