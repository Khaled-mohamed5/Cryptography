"""End-to-end checks against a real station on an ephemeral port."""

import os
import re
import shutil
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request
from http.cookiejar import CookieJar

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import app  # noqa: E402


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Surface 303s instead of following them, so Location can be asserted."""

    def redirect_request(self, *args, **kwargs):
        return None


class Courier:
    """One browser: its own cookie jar, therefore its own handle."""

    def __init__(self, base):
        self.base = base
        self.jar = CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPCookieProcessor(self.jar),
            NoRedirect,
        )

    def get(self, path):
        try:
            with self.opener.open(self.base + path) as response:
                return response.status, response.read().decode("utf-8"), response.headers
        except urllib.error.HTTPError as error:
            return error.code, error.read().decode("utf-8", "replace"), error.headers

    def post(self, path, **fields):
        data = urllib.parse.urlencode(fields).encode("utf-8")
        request = urllib.request.Request(self.base + path, data=data, method="POST")
        try:
            with self.opener.open(request) as response:
                return response.status, response.read().decode("utf-8"), response.headers
        except urllib.error.HTTPError as error:
            return error.code, error.read().decode("utf-8", "replace"), error.headers

    def csrf(self):
        _, body, _ = self.get("/")
        return re.search(r'name="_csrf" value="([^"]+)"', body).group(1)

    def leave_drop(self, title="A drop", body="<p>hello</p>", css=""):
        """Post a drop and return its id."""
        token = self.csrf()
        status, _, headers = self.post("/post", _csrf=token, title=title, body=body, css=css)
        assert status == 303, "expected a redirect, got %s" % status
        return headers["Location"].split("?")[0].rsplit("/", 1)[-1]


class StationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ.pop("POSTE_RESTANTE_SECRET", None)
        cls.data_dir = tempfile.mkdtemp(prefix="poste-restante-test-")
        app.StationHandler.log_message = lambda *args, **kwargs: None
        cls.server = app.build_server("127.0.0.1", 0, cls.data_dir)
        cls.base = "http://127.0.0.1:%d" % cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.server.station.store.close()
        cls.thread.join(timeout=5)
        shutil.rmtree(cls.data_dir, ignore_errors=True)

    def courier(self):
        return Courier(self.base)

    # -- the counter ------------------------------------------------------
    def test_index_issues_a_handle_and_shows_an_empty_ledger(self):
        status, body, headers = self.courier().get("/")
        self.assertEqual(status, 200)
        self.assertIn("no drops on record", body)
        self.assertIn("HttpOnly", headers["Set-Cookie"])
        self.assertIn("SameSite=Lax", headers["Set-Cookie"])

    def test_station_pages_carry_a_restrictive_policy(self):
        _, _, headers = self.courier().get("/")
        self.assertIn("default-src 'none'", headers["Content-Security-Policy"])
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(headers["Referrer-Policy"], "no-referrer")

    def test_station_pages_carry_no_inline_styles(self):
        # style-src is 'self' with no 'unsafe-inline', so a style="" attribute
        # on a station page is dead markup. Keep the styling in the sheet.
        owner = self.courier()
        drop_id = owner.leave_drop(title="Inline check")
        for path in ("/", "/d/" + drop_id):
            self.assertNotIn('style="', owner.get(path)[1], path)

    def test_unknown_paths_and_ids_are_404(self):
        courier = self.courier()
        self.assertEqual(courier.get("/nope")[0], 404)
        self.assertEqual(courier.get("/d/NOT-AN-ID")[0], 404)
        self.assertEqual(courier.get("/d/zzzzzzzzzz")[0], 404)

    def test_stylesheet_is_served(self):
        status, body, headers = self.courier().get("/static/station.css")
        self.assertEqual(status, 200)
        self.assertTrue(headers["Content-Type"].startswith("text/css"))
        self.assertIn(".class-bar", body)

    # -- leaving a drop ---------------------------------------------------
    def test_drop_appears_in_its_owners_ledger_only(self):
        owner = self.courier()
        drop_id = owner.leave_drop(title="Bench 4")
        self.assertIn("Bench 4", owner.get("/")[1])
        self.assertIn("no drops on record", self.courier().get("/")[1])

    def test_post_without_a_seal_is_refused(self):
        courier = self.courier()
        courier.get("/")  # take a cookie so only the token is missing
        status, body, _ = courier.post("/post", title="x", body="y", _csrf="wrong")
        self.assertEqual(status, 200)
        self.assertIn("seal did not match", body)
        self.assertIn("no drops on record", body)

    def test_post_without_a_cookie_is_refused_but_recoverable(self):
        courier = self.courier()
        status, body, _ = courier.post("/post", title="x", body="y", _csrf="anything")
        self.assertEqual(status, 200)
        self.assertIn("handshake", body)

    def test_title_and_body_are_sanitized_on_the_way_in(self):
        owner = self.courier()
        drop_id = owner.leave_drop(
            title="Bench <script>alert(1)</script>",
            body='<p>ok</p><script>alert(2)</script><img src="http://tracker.test/p">')
        _, page, _ = owner.get("/d/" + drop_id)
        self.assertNotIn("<script", page)
        _, envelope, _ = owner.get("/d/%s/envelope" % drop_id)
        self.assertNotIn("<script", envelope)
        self.assertNotIn("tracker.test", envelope)
        self.assertIn("<p>ok</p>", envelope)

    def test_an_empty_envelope_is_refused(self):
        courier = self.courier()
        token = courier.csrf()
        status, body, _ = courier.post("/post", _csrf=token, title="t",
                                       body="<script>alert(1)</script>", css="")
        self.assertEqual(status, 200)
        self.assertIn("empty after sanitizing", body)

    def test_a_fully_rejected_cipher_is_reported_to_its_author(self):
        owner = self.courier()
        token = owner.csrf()
        _, _, headers = owner.post("/post", _csrf=token, title="t", body="<p>x</p>",
                                   css="body{background:url(http://tracker.test/p.png)}")
        self.assertIn("cipher=stripped", headers["Location"])
        _, page, _ = owner.get(headers["Location"])
        self.assertIn("discarded in full", page)

    def test_oversized_and_undecodable_bodies_are_refused(self):
        courier = self.courier()
        courier.get("/")
        request = urllib.request.Request(
            self.base + "/post", data=b"x" * (app.MAX_REQUEST_BYTES + 1024),
            method="POST", headers={"Content-Type": "application/x-www-form-urlencoded"})
        try:
            with courier.opener.open(request) as response:
                self.assertEqual(response.status, 400)
        except urllib.error.HTTPError as error:
            self.assertEqual(error.code, 400)
        except (urllib.error.URLError, ConnectionError):
            pass  # the server may close the connection rather than read it out

        # A body the station cannot parse is rejected, not guessed at.
        request = urllib.request.Request(
            self.base + "/post", data=b"---boundary--", method="POST",
            headers={"Content-Type": "multipart/form-data; boundary=boundary"})
        try:
            with courier.opener.open(request) as response:
                self.assertEqual(response.status, 400)
        except urllib.error.HTTPError as error:
            self.assertEqual(error.code, 400)

    # -- the envelope -----------------------------------------------------
    def test_envelope_is_sandboxed_and_cannot_reach_the_network(self):
        owner = self.courier()
        drop_id = owner.leave_drop()
        _, page, _ = owner.get("/d/" + drop_id)
        self.assertIn('sandbox="allow-popups allow-popups-to-escape-sandbox"', page)
        self.assertNotIn("allow-scripts", page)
        self.assertNotIn("allow-same-origin", page)

        _, _, headers = owner.get("/d/%s/envelope" % drop_id)
        policy = headers["Content-Security-Policy"]
        self.assertIn("default-src 'none'", policy)
        self.assertNotIn("script-src", policy)
        self.assertEqual(headers["X-Frame-Options"], "SAMEORIGIN")

    def test_courier_css_reaches_the_envelope(self):
        owner = self.courier()
        drop_id = owner.leave_drop(css="body{background:#120b06}")
        _, envelope, _ = owner.get("/d/%s/envelope" % drop_id)
        self.assertIn("background: #120b06", envelope)

    # -- pickups ----------------------------------------------------------
    def test_only_strangers_count_as_pickups(self):
        owner = self.courier()
        drop_id = owner.leave_drop()

        for _ in range(3):
            owner.get("/d/" + drop_id)
        self.assertIn("0 pickups", owner.get("/")[1])

        stranger = self.courier()
        stranger.get("/d/" + drop_id)
        stranger.get("/d/" + drop_id)  # same courier, still one pickup
        self.assertIn("1 pickup<", owner.get("/")[1])

        self.courier().get("/d/" + drop_id)
        self.assertIn("2 pickups", owner.get("/")[1])

    # -- flagging ---------------------------------------------------------
    def test_reports_seal_a_drop_and_withhold_the_envelope(self):
        owner = self.courier()
        drop_id = owner.leave_drop(title="Suspicious")

        reporters = [self.courier() for _ in range(app.SEAL_THRESHOLD)]
        for reporter in reporters:
            token = reporter.csrf()
            status, _, headers = reporter.post("/d/%s/flag" % drop_id,
                                               _csrf=token, reason="lure")
            self.assertEqual(status, 303)
            self.assertIn("flagged=1", headers["Location"])

        stranger = self.courier()
        _, page, _ = stranger.get("/d/" + drop_id)
        self.assertIn("Envelope sealed", page)
        self.assertEqual(stranger.get("/d/%s/envelope" % drop_id)[0], 410)
        # The author can still see what they wrote.
        self.assertEqual(owner.get("/d/%s/envelope" % drop_id)[0], 200)

    def test_one_report_per_courier(self):
        owner = self.courier()
        drop_id = owner.leave_drop()
        reporter = self.courier()
        token = reporter.csrf()
        reporter.post("/d/%s/flag" % drop_id, _csrf=token, reason="one")
        _, _, headers = reporter.post("/d/%s/flag" % drop_id, _csrf=token, reason="two")
        self.assertIn("already-flagged", headers["Location"])

    def test_flag_without_a_seal_is_ignored(self):
        owner = self.courier()
        drop_id = owner.leave_drop()
        reporter = self.courier()
        reporter.get("/")
        _, _, headers = reporter.post("/d/%s/flag" % drop_id, _csrf="wrong", reason="x")
        self.assertEqual(headers["Location"], "/d/" + drop_id)
        self.assertEqual(self.server.station.store.count_flags(drop_id), 0)


class ReadoutTests(unittest.TestCase):
    def test_agent_readout(self):
        chrome = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
                  "Chrome/143.0.7499.192 Safari/537.36")
        self.assertEqual(app.agent_readout(chrome), "CHROME 143.0.7499.192 · LINUX/AMD64")
        self.assertEqual(app.agent_readout(""), "UNKNOWN AGENT")
        self.assertIn("FIREFOX", app.agent_readout(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0"))

    def test_readout_cannot_inject_markup(self):
        # The footer escapes it, but keep the readout itself boring too.
        self.assertNotIn("<", app.agent_readout("<script>alert(1)</script>"))


if __name__ == "__main__":
    unittest.main()
