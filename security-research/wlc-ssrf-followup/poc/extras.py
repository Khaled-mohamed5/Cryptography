"""Two smaller issues reachable from a hostile API response / hostile repo."""

import json
import os
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from wlc import Weblate
from wlc.config import WeblateConfig

PORT = 8100
COUNT = {"n": 0}


class LoopHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):  # noqa: N802
        COUNT["n"] += 1
        # An empty "next" is not None, so list_factory keeps going forever.
        body = json.dumps({"count": 1, "next": "", "results": []}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def test_infinite_pagination():
    server = ThreadingHTTPServer(("127.0.0.1", PORT), LoopHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    client = Weblate(url=f"http://127.0.0.1:{PORT}/api/")
    for _ in client.list_projects():
        pass  # never yields anything
    # unreachable: the generator loops forever; we cap it from the outside


def test_project_config_options():
    """A .weblate in a hostile repo tunes retry behaviour with no restrictions."""
    with tempfile.TemporaryDirectory() as directory:
        with open(os.path.join(directory, ".weblate"), "w") as handle:
            handle.write(
                "[weblate]\n"
                "retries = 900\n"
                "backoff_factor = 120\n"
                "timeout = 86400\n"
                "status_forcelist = 200\n"
                "allowed_methods = GET,POST,PUT,DELETE\n"
            )
        cwd = os.getcwd()
        os.chdir(directory)
        try:
            config = WeblateConfig()
            config.load()
            print("  project config found:", config.find_project_config())
            print("  request options:", config.get_request_options())
            client = Weblate(config=config)
            retry = client.adapter.max_retries
            print(
                f"  effective retry: total={retry.total} "
                f"backoff={retry.backoff_factor} "
                f"forcelist={retry.status_forcelist} "
                f"methods={sorted(retry.allowed_methods)}"
            )
            print(f"  effective timeout: {client.timeout}s")
        finally:
            os.chdir(cwd)


if __name__ == "__main__":
    print("[1] hostile repo .weblate controls retry/timeout behaviour")
    test_project_config_options()

    print("\n[2] empty pagination 'next' -> unbounded request loop")
    thread = threading.Thread(target=test_infinite_pagination, daemon=True)
    thread.start()
    thread.join(timeout=4)
    print(f"  requests issued in 4s against one endpoint: {COUNT['n']}")
    print(f"  generator still running: {thread.is_alive()}")
