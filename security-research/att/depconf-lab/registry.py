#!/usr/bin/env python3
"""Minimal npm registry, for the dependency-confusion demonstration.

    python3 registry.py <port> <tarball.tgz> <version>

Serves exactly one scoped package so npm's resolution order can be observed.
Localhost only. No dependencies.
"""
import hashlib, json, sys, os
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import unquote

PORT, TGZ, VERSION = int(sys.argv[1]), sys.argv[2], sys.argv[3]
NAME = "@acme-corp/ui-widget"
BLOB = open(TGZ, "rb").read()
SHA1 = hashlib.sha1(BLOB).hexdigest()
SHA512 = "sha512-" + __import__("base64").b64encode(hashlib.sha512(BLOB).digest()).decode()
TARBALL_PATH = f"/{NAME}/-/ui-widget-{VERSION}.tgz"
# the public-registry copy is the one carrying a postinstall script
HAS_SCRIPTS = VERSION == "9.9.9"

PACKUMENT = {
    "name": NAME,
    "dist-tags": {"latest": VERSION},
    "versions": {
        VERSION: {
            "name": NAME,
            "version": VERSION,
            "main": "index.js",
            # npm >=7 consults hasInstallScript in the packument before it will
            # run any lifecycle script, so it must be advertised here.
            "hasInstallScript": HAS_SCRIPTS,
            "scripts": ({"postinstall": "node postinstall.js"} if HAS_SCRIPTS else {}),
            "dist": {
                "tarball": f"http://localhost:{PORT}{TARBALL_PATH}",
                "shasum": SHA1,
                "integrity": SHA512,
            },
        }
    },
}

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        sys.stderr.write(f"[registry:{PORT}] {a[0] % a[1:]}\n")

    def do_GET(self):
        path = unquote(self.path)
        if path.rstrip("/") in (NAME, "/" + NAME.lstrip("/")):
            body = json.dumps(PACKUMENT).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif path == TARBALL_PATH:
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(BLOB)))
            self.end_headers()
            self.wfile.write(BLOB)
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

if __name__ == "__main__":
    print(f"registry on :{PORT} serving {NAME}@{VERSION} from {os.path.basename(TGZ)}")
    HTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
