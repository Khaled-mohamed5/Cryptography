"""What the station must refuse to carry."""

import os
import random
import sys
import unittest
from html.parser import HTMLParser

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import sanitize  # noqa: E402


class MarkupTests(unittest.TestCase):
    def assertClean(self, raw, *forbidden):
        out = sanitize.sanitize_html(raw)
        for needle in forbidden:
            self.assertNotIn(needle.lower(), out.lower(), "leaked %r from %r" % (needle, raw))
        return out

    def test_keeps_allowed_markup(self):
        out = sanitize.sanitize_html("<p>a <b>bold</b> <em>claim</em></p><ul><li>one</li></ul>")
        self.assertEqual(out, "<p>a <b>bold</b> <em>claim</em></p><ul><li>one</li></ul>")

    def test_drops_script_and_its_contents(self):
        out = self.assertClean("<p>before<script>alert(1)</script>after</p>", "alert", "script")
        self.assertEqual(out, "<p>beforeafter</p>")

    def test_drops_style_element(self):
        self.assertClean("<style>body{background:url(http://x/)}</style>hi", "background", "url(")

    def test_unwraps_unknown_tags_but_keeps_text(self):
        self.assertEqual(sanitize.sanitize_html("<marquee>drift</marquee>"), "drift")

    def test_strips_event_handlers(self):
        self.assertClean('<p onclick="steal()" onmouseover=x>t</p>',
                         "onclick", "onmouseover", "steal")

    def test_rejects_script_schemes(self):
        for href in ("javascript:alert(1)", "JaVaScRiPt:alert(1)",
                     "java\tscript:alert(1)", "java\nscript:alert(1)",
                     "&#106;avascript:alert(1)", "data:text/html,<b>x",
                     "vbscript:msgbox", "\x01javascript:alert(1)"):
            out = sanitize.sanitize_html('<a href="%s">go</a>' % href)
            self.assertNotIn("href", out, "accepted %r" % href)

    def test_keeps_http_links_but_defangs_them(self):
        out = sanitize.sanitize_html('<a href="https://example.test/x">go</a>')
        self.assertIn('href="https://example.test/x"', out)
        self.assertIn("nofollow", out)
        self.assertIn("noreferrer", out)

    def test_no_remote_media(self):
        for tag in ('<img src="http://tracker.test/p.gif">',
                    '<video src="http://tracker.test/v"></video>',
                    '<iframe src="http://evil.test"></iframe>',
                    '<object data="http://evil.test"></object>'):
            self.assertClean(tag, "tracker.test", "evil.test", "<img", "<iframe")

    def test_forms_and_inputs_are_dropped(self):
        self.assertClean('<form action="//evil.test"><input name="p" type="password">'
                         "</form>", "<form", "<input", "evil.test")

    def test_mismatched_tags_cannot_escape(self):
        out = sanitize.sanitize_html("<div><b>x</div></b></p></div>")
        self.assertEqual(out.count("<div"), 1)
        self.assertEqual(out.count("</div>"), 1)
        self.assertEqual(out.count("</b>"), 1)

    def test_text_is_escaped(self):
        out = sanitize.sanitize_html("5 < 6 & 7 > 2")
        self.assertNotIn("< 6", out)
        self.assertIn("&lt;", out)

    def test_style_attribute_is_filtered_not_trusted(self):
        out = sanitize.sanitize_html('<p style="color:red;background:url(http://x/)">t</p>')
        self.assertIn("color: red", out)
        self.assertNotIn("url(", out)

    def test_nesting_is_bounded(self):
        out = sanitize.sanitize_html("<div>" * 500 + "deep" + "</div>" * 500)
        self.assertLessEqual(out.count("<div"), sanitize.MAX_NESTING)
        self.assertIn("deep", out)

    def test_plain_text_flattens_titles(self):
        self.assertEqual(sanitize.plain_text("<b>Bench\n  4</b>  now"), "Bench 4 now")


class CipherTests(unittest.TestCase):
    def test_keeps_ordinary_declarations(self):
        out = sanitize.sanitize_css("body{background:#111;color:#eee}")
        self.assertEqual(out, "body { background: #111; color: #eee }")

    def test_no_remote_fetches(self):
        for css in ("body{background:url(http://tracker.test/p.png)}",
                    "body{background:URL('http://tracker.test/p.png')}",
                    "@font-face{font-family:x;src:url(http://tracker.test/f.woff)}",
                    "body{background-image:image-set(url(http://tracker.test/a))}"):
            self.assertNotIn("tracker.test", sanitize.sanitize_css(css), css)

    def test_import_is_dropped(self):
        out = sanitize.sanitize_css('@import "http://tracker.test/x.css"; a{color:red}')
        self.assertNotIn("import", out)
        self.assertIn("a { color: red }", out)

    def test_legacy_script_vectors(self):
        for css in ("a{behavior:url(#default#time2)}",
                    "a{-moz-binding:url(http://x/b.xml#x)}",
                    "a{width:expression(alert(1))}"):
            self.assertEqual(sanitize.sanitize_css(css), "", css)

    def test_cannot_escape_the_style_element(self):
        # The sanitized cipher is emitted inside <style>, which the HTML parser
        # only leaves on "</style". No input may reintroduce "<".
        for css in ("@media </style><script>alert(1)</script> {a{color:red}}",
                    'a{content:"</style><script>alert(1)</script>"}',
                    "</style><script>alert(1)</script>{}",
                    "a[x='</style>']{color:red}"):
            self.assertNotIn("<", sanitize.sanitize_css(css), css)

    def test_backslash_escapes_are_rejected(self):
        self.assertEqual(sanitize.sanitize_css(r"a{background:\75 rl(http://x/)}"), "")

    def test_media_and_keyframes_survive(self):
        out = sanitize.sanitize_css(
            "@media (max-width:600px){body{color:red}}"
            "@keyframes pulse{from{opacity:0}to{opacity:1}}"
            "a{animation:pulse 2s infinite}")
        self.assertIn("@media (max-width:600px)", out)
        self.assertIn("@keyframes pulse", out)
        self.assertIn("animation: pulse 2s infinite", out)

    def test_unknown_properties_are_dropped(self):
        out = sanitize.sanitize_css("a{color:red;-webkit-magic:on;src:local(x)}")
        self.assertEqual(out, "a { color: red }")

    def test_stray_braces_cannot_reopen_a_block(self):
        out = sanitize.sanitize_css("a{color:red} } b{color:blue}")
        self.assertIn("a { color: red }", out)
        self.assertIn("b { color: blue }", out)

    def test_unterminated_input_terminates(self):
        self.assertIsInstance(sanitize.sanitize_css("a{color:red"), str)
        self.assertIsInstance(sanitize.sanitize_css('a{content:"unclosed'), str)


class _Auditor(HTMLParser):
    """Re-parse sanitized output and record anything the sanitizer promised to drop."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.problems = []

    def handle_starttag(self, tag, attrs):
        if tag not in sanitize.ALLOWED_TAGS:
            self.problems.append("tag %r survived" % tag)
        permitted = (sanitize.GLOBAL_ATTRS | sanitize.TAG_ATTRS.get(tag, set())
                     | {"rel", "target"})
        for name, value in attrs:
            value = value or ""
            if name not in permitted:
                self.problems.append("attr %r on <%s>" % (name, tag))
            if name in ("href", "cite") and not value.lower().startswith(
                    ("http://", "https://", "mailto:", "#", "/")):
                self.problems.append("scheme %r" % value)
            if name == "style" and ("url(" in value.lower() or "expression(" in value.lower()):
                self.problems.append("style %r" % value)

    handle_startendtag = handle_starttag


class FuzzTests(unittest.TestCase):
    """Properties that must hold for inputs nobody thought to write a case for."""

    ALPHABET = list("<>/{}()[]\"'\\;:@&#%*,.-_=!abcXYZ019 \t\n\r") + [
        "<script>", "</style>", "url(", "javascript:", "@media", "@import",
        "expression(", "&#x6a;", "<a href=", "</a>", "body", "color:red",
        "<p onclick=", "<img src=", "<svg onload=", "data:", "-moz-binding",
    ]

    def test_random_input_never_breaks_an_invariant(self):
        rng = random.Random(20260905)  # fixed seed: a failure is reproducible
        for _ in range(2000):
            raw = "".join(rng.choice(self.ALPHABET) for _ in range(rng.randint(0, 120)))
            markup = sanitize.sanitize_html(raw)
            cipher = sanitize.sanitize_css(raw)

            auditor = _Auditor()
            auditor.feed(markup)
            auditor.close()
            self.assertEqual(auditor.problems, [], "%r -> %r" % (raw, markup))

            self.assertNotIn("<", cipher, raw)
            for banned in ("url(", "@import", "expression(", "-moz-binding", "\\"):
                self.assertNotIn(banned, cipher.lower(), raw)

            # Sanitizing is a fixed point: re-running it must change nothing.
            self.assertEqual(sanitize.sanitize_html(markup), markup, raw)
            self.assertEqual(sanitize.sanitize_css(cipher), cipher, raw)


if __name__ == "__main__":
    unittest.main()
