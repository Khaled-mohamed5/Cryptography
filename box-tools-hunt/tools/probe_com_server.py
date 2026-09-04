#!/usr/bin/env python3
"""
Box Local Com Server reconnaissance probe.

Maps the local HTTP server Box Tools exposes on 127.0.0.1:17223 (fallback 17224) and
reports on the controls that decide whether a random website can drive it:

  * which endpoints answer, and to which methods
  * whether requests are accepted with NO Origin header at all
  * whether a foreign Origin is accepted, and whether it is reflected in CORS headers
  * whether a foreign Host header is accepted   (-> DNS rebinding)
  * whether preflight is even required
  * whether a WebSocket upgrade is offered

Read-only: it sends requests and reads responses. It does not open files, upload
anything, or modify state. Run it on your own machine with Box Tools installed.

Usage:
    python3 probe_com_server.py
    python3 probe_com_server.py --port 17223 --verbose
    python3 probe_com_server.py --paths extra_paths.txt
"""

import argparse
import http.client
import json
import socket
import sys
import time
import urllib.parse

DEFAULT_PORTS = [17223, 17224]

# The documented entry point, plus the shapes a server like this usually also carries.
DEFAULT_PATHS = [
    "/",
    "/application_request",
    "/status",
    "/ping",
    "/health",
    "/version",
    "/info",
    "/config",
    "/state",
    "/open",
    "/edit",
    "/download",
    "/upload",
    "/file",
    "/files",
    "/session",
    "/token",
    "/auth",
    "/register",
    "/handshake",
    "/applications",
    "/application",
    "/application_response",
    "/box_edit",
    "/boxedit",
    "/api",
    "/api/v1",
    "/shutdown",
    "/quit",
    "/log",
    "/logs",
]

# Origins worth testing, and what a hit on each one means.
ORIGIN_MATRIX = [
    (None,                             "no Origin header (curl / non-browser / stripped)"),
    ("https://app.box.com",            "legitimate Box origin (control case)"),
    ("https://evil.example",           "unrelated attacker origin"),
    ("null",                           "sandboxed iframe / data: URL"),
    ("https://app.box.com.evil.example", "suffix-confusion: allowlist doing a prefix match"),
    ("https://evil-app.box.com",       "subdomain confusion / any *.box.com trusted"),
    ("http://app.box.com",             "scheme downgrade"),
    ("http://127.0.0.1:17223",         "self origin"),
    ("http://localhost",               "localhost origin"),
]

HOST_MATRIX = [
    ("127.0.0.1",             "canonical"),
    ("localhost",             "alias"),
    ("rebind.example.com",    "foreign host -> DNS rebinding is viable if accepted"),
    ("127.0.0.1.nip.io",      "resolves to 127.0.0.1, foreign name"),
    ("0.0.0.0",               "alternate loopback spelling"),
    ("[::1]",                 "IPv6 loopback"),
]

METHODS = ["GET", "POST", "OPTIONS", "PUT", "DELETE", "HEAD"]

RESET = "\033[0m"
BOLD = "\033[1m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"


def c(text, colour):
    return f"{colour}{text}{RESET}" if sys.stdout.isatty() else text


def request(port, path, method="GET", headers=None, body=None, timeout=5):
    """Single raw HTTP request. Returns (status, headers dict, body bytes) or None."""
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        conn.request(method, path, body=body, headers=headers or {})
        resp = conn.getresponse()
        data = resp.read(8192)
        return resp.status, {k.lower(): v for k, v in resp.getheaders()}, data
    except (socket.timeout, OSError, http.client.HTTPException) as exc:
        return ("ERR", {}, str(exc).encode())
    finally:
        try:
            conn.close()
        except Exception:
            pass


def find_ports(ports):
    live = []
    for port in ports:
        sock = socket.socket()
        sock.settimeout(1.5)
        try:
            sock.connect(("127.0.0.1", port))
            live.append(port)
        except OSError:
            pass
        finally:
            sock.close()
    return live


def documented_query(com="probe", timeout_ms=1000):
    """The request shape Box documents for the browser -> com server handshake."""
    return "/application_request?" + urllib.parse.urlencode({
        "application": "BoxEdit",
        "com": com,
        "timeout": timeout_ms,
        "ms": int(time.time() * 1000),
    })


def summarise_body(data, limit=180):
    text = data.decode("utf-8", "replace").strip().replace("\n", " ")
    return text[:limit] + ("…" if len(text) > limit else "")


def probe_paths(port, paths, verbose):
    print(c(f"\n[1] Endpoint discovery on 127.0.0.1:{port}", BOLD))
    found = []
    for path in paths:
        status, headers, body = request(port, path)
        if status == "ERR":
            if verbose:
                print(f"    {path:<28} ERR  {summarise_body(body, 60)}")
            continue
        # 404 with an empty body is the uninteresting baseline.
        interesting = status != 404
        marker = c("HIT ", GREEN) if interesting else "    "
        if interesting or verbose:
            print(f" {marker}{path:<28} {status}  {headers.get('content-type','-'):<28} {summarise_body(body, 90)}")
        if interesting:
            found.append((path, status, headers, body))
    if not found:
        print("    nothing but 404s on the static wordlist — rely on the traffic capture instead")
    return found


def probe_methods(port, path, verbose):
    print(c(f"\n[2] Methods accepted on {path}", BOLD))
    for method in METHODS:
        status, headers, body = request(port, path, method=method)
        allow = headers.get("allow", "")
        extra = f"  Allow: {allow}" if allow else ""
        print(f"    {method:<8} {status}{extra}")


def probe_origins(port, path, verbose):
    """The heart of it: does the server care who is asking?"""
    print(c(f"\n[3] Origin handling on {path}", BOLD))
    print(f"    {'origin':<36} {'status':<7} {'ACAO':<32} {'ACAC':<6} note")
    baseline = None
    results = []
    for origin, note in ORIGIN_MATRIX:
        headers = {} if origin is None else {"Origin": origin}
        status, resp_headers, body = request(port, path, headers=headers)
        acao = resp_headers.get("access-control-allow-origin", "-")
        acac = resp_headers.get("access-control-allow-credentials", "-")
        shown = origin if origin is not None else "(none)"
        print(f"    {shown:<36} {str(status):<7} {acao:<32} {acac:<6} {note}")
        results.append((origin, status, acao, acac, body))
        if origin == "https://app.box.com":
            baseline = (status, body)

    print(c("\n    Verdict:", BOLD))
    legit_status = baseline[0] if baseline else None
    for origin, status, acao, acac, body in results:
        if origin in (None, "https://app.box.com"):
            continue
        if status == legit_status and status not in ("ERR", 403, 401):
            print(c(f"    [!] {origin or '(no Origin)'} gets the same response as app.box.com "
                    f"-> no effective origin check on this endpoint", RED))
        if acao == "*" and acac == "true":
            print(c(f"    [!] ACAO '*' with credentials:true is an invalid, exploitable combination", RED))
        elif acao not in ("-", "*") and origin and acao == origin:
            print(c(f"    [!] Origin reflected verbatim in ACAO for {origin} "
                    f"-> any site can read responses", RED))

    no_origin = next((r for r in results if r[0] is None), None)
    if no_origin and no_origin[1] not in ("ERR", 403, 401):
        print(c("    [!] Requests with NO Origin header are served. A simple <img>/<form>/GET "
                "from any page fires the side effect even if the response is unreadable.", RED))
    print(c("    Reminder: a plain GET is not preflighted. Unreadable != blocked. "
            "Confirm the SIDE EFFECT with tools/origin_test.html.", YELLOW))


def probe_hosts(port, path, verbose):
    print(c(f"\n[4] Host header handling on {path}  (DNS rebinding surface)", BOLD))
    for host, note in HOST_MATRIX:
        status, headers, body = request(port, path, headers={"Host": host})
        flag = ""
        if host not in ("127.0.0.1", "localhost", "[::1]") and status not in ("ERR", 400, 403, 421):
            flag = c("  <-- accepted, rebinding viable", RED)
        print(f"    Host: {host:<24} {str(status):<7} {note}{flag}")


def probe_preflight(port, path):
    print(c(f"\n[5] Preflight behaviour on {path}", BOLD))
    headers = {
        "Origin": "https://evil.example",
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "content-type,x-probe",
    }
    status, resp_headers, _ = request(port, path, method="OPTIONS", headers=headers)
    print(f"    OPTIONS -> {status}")
    for key in ("access-control-allow-origin", "access-control-allow-methods",
                "access-control-allow-headers", "access-control-allow-credentials",
                "access-control-max-age", "vary"):
        if key in resp_headers:
            print(f"      {key}: {resp_headers[key]}")
    if resp_headers.get("access-control-allow-origin") == "https://evil.example":
        print(c("    [!] Preflight approves an arbitrary origin", RED))


def probe_websocket(port, path="/"):
    print(c(f"\n[6] WebSocket upgrade on {path}", BOLD))
    headers = {
        "Upgrade": "websocket",
        "Connection": "Upgrade",
        "Sec-WebSocket-Key": "eHh4eHh4eHh4eHh4eHh4eA==",
        "Sec-WebSocket-Version": "13",
        "Origin": "https://evil.example",
    }
    status, resp_headers, _ = request(port, path, headers=headers)
    if status == 101:
        print(c("    [!] 101 Switching Protocols with a foreign Origin. WebSockets are NOT "
                "subject to the same-origin policy — the server must check Origin itself.", RED))
    else:
        print(f"    {status} — no upgrade offered here")


def probe_traversal_echo(port):
    """Does the server echo or normalise obviously hostile input? Read-only signal only."""
    print(c("\n[7] Input handling signal (read-only)", BOLD))
    probes = {
        "traversal":    "..%2f..%2f..%2ftest.lnk",
        "absolute":     "C%3A%5CUsers%5CPublic%5Ctest.lnk",
        "unc":          "%5C%5C127.0.0.1%5Cshare%5Ctest",
        "unicode_rtlo": "invoice%E2%80%AEgnp.exe",
        "null_byte":    "test.txt%00.exe",
    }
    for name, value in probes.items():
        path = f"/application_request?application=BoxEdit&com=probe&name={value}&ms={int(time.time()*1000)}"
        status, headers, body = request(port, path)
        snippet = summarise_body(body, 70)
        echoed = urllib.parse.unquote(value)[:12] in body.decode("utf-8", "replace")
        note = c("  (input echoed back)", YELLOW) if echoed else ""
        print(f"    {name:<14} {str(status):<7} {snippet}{note}")


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--port", type=int, help="probe only this port")
    parser.add_argument("--paths", help="file with extra paths, one per line")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    ports = [args.port] if args.port else DEFAULT_PORTS
    live = find_ports(ports)
    if not live:
        print(c(f"No listener on {ports}. Is Box Tools running?", RED))
        print("  Windows: Get-NetTCPConnection -LocalPort 17223,17224")
        print("  macOS:   lsof -nP -iTCP:17223 -sTCP:LISTEN")
        return 1

    paths = list(DEFAULT_PATHS)
    if args.paths:
        with open(args.paths) as fh:
            paths.extend(line.strip() for line in fh if line.strip())

    for port in live:
        print(c(f"\n{'=' * 78}\nBox Local Com Server @ 127.0.0.1:{port}\n{'=' * 78}", CYAN))
        found = probe_paths(port, paths, args.verbose)

        # Focus the deep checks on the documented endpoint, plus anything discovered.
        targets = [documented_query()]
        targets += [p for p, *_ in found if p != "/application_request"][:3]

        for target in targets:
            probe_methods(port, target, args.verbose)
            probe_origins(port, target, args.verbose)
            probe_hosts(port, target, args.verbose)
            probe_preflight(port, target)

        probe_websocket(port)
        probe_traversal_echo(port)

        print(c(f"\n[next] Capture real traffic to learn the true parameter set:", BOLD))
        print("       Windows: Wireshark on the loopback adapter, filter tcp.port==17223")
        print("       macOS:   sudo tcpdump -i lo0 -A -s0 'tcp port 17223'")
        print("       Then replay a real request through this script with --paths.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
