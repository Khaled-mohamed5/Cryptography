"""Randomised search for a URL wlc accepts but requests connects elsewhere for."""

import random
import sys
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from wlc import Weblate
from wlc.exceptions import WeblateException

BASE = "http://127.0.0.1:8000/api/"
ADAPTER = HTTPAdapter()
CLIENT = Weblate(url=BASE)
WANT = CLIENT.api_origin

TOKENS = [
    "http:", "//", "/", "\\", "@", ":", "?", "#", ".", "..", "%2e", "%2f", "%5c",
    "%40", "%3a", "%00", "%09", "[", "]", "127.0.0.1", "8000", "169.254.169.254",
    "0", ";", ",", "!", "$", "&", "'", "(", ")", "*", "+", "=", "~", "-", "_",
    "\t", "\n", "\r", " ", "\x00", "\x0b", "\x0c", "%", "a", "%25", "::1",
    "%2500", "\x7f", "\x85", "\xa0", "。", "．", "K", "­",
    "​", "﻿", "⁄", "＠", "／", "localhost", "x",
]


def real_target(url):
    req = requests.Request("GET", url).prepare()
    conn = ADAPTER.get_connection_with_tls_context(req, verify=True)
    return conn.scheme, conn.host, conn.port


def probe(payload):
    try:
        norm = CLIENT.normalize_request_url(payload)
        CLIENT.parse_request_url(norm)
    except WeblateException:
        return None
    except Exception:  # noqa: BLE001
        return None
    try:
        scheme, host, port = real_target(norm)
    except Exception:  # noqa: BLE001
        return None
    got = (scheme, host, port if port is not None else (443 if scheme == "https" else 80))
    if got != WANT:
        return norm, got
    return None


def main(iterations):
    rng = random.Random(1337)
    seen = 0
    hits = 0
    # seed with structured skeletons plus pure random token soup
    for i in range(iterations):
        n = rng.randint(2, 9)
        payload = "".join(rng.choice(TOKENS) for _ in range(n))
        if i % 3 == 0:
            payload = "http://127.0.0.1:8000" + payload
        elif i % 3 == 1:
            payload = "http://" + payload + "127.0.0.1:8000/x"
        seen += 1
        result = probe(payload)
        if result:
            hits += 1
            norm, got = result
            print(f"[BYPASS] payload={payload!r}\n         norm={norm!r} -> {got} (want {WANT})")
            if hits > 20:
                break
    print(f"tried {seen} random payloads, {hits} bypasses")


if __name__ == "__main__":
    main(int(sys.argv[1]) if len(sys.argv) > 1 else 200000)
