"""Differential harness: what wlc validates vs. where requests really connects."""

import requests
from requests.adapters import HTTPAdapter
from wlc import Weblate
from wlc.exceptions import WeblateException

ADAPTER = HTTPAdapter()


def real_target(url):
    """Resolve the actual TCP target requests would use (no network I/O)."""
    req = requests.Request("GET", url).prepare()
    conn = ADAPTER.get_connection_with_tls_context(req, verify=True)
    return (conn.scheme, conn.host, conn.port), req.url


def check(base, payload):
    """Return (verdict, detail). verdict: 'BYPASS' | 'reject' | 'senderr' | 'ok'."""
    w = Weblate(url=base)
    try:
        norm = w.normalize_request_url(payload)
        w.parse_request_url(norm)  # mirrors the session.mount() re-parse
    except WeblateException as e:
        return "reject", str(e)
    except Exception as e:  # noqa: BLE001
        return "senderr", f"validation {type(e).__name__}: {e}"
    try:
        target, prepared = real_target(norm)
    except Exception as e:  # noqa: BLE001
        return "senderr", f"{type(e).__name__}: {e}"
    want = w.api_origin
    got = (
        target[0],
        target[1],
        target[2] if target[2] is not None else (443 if target[0] == "https" else 80),
    )
    if got != want:
        return "BYPASS", f"validated={want} actual={got} norm={norm!r} prepared={prepared!r}"
    return "ok", norm


# ---------------------------------------------------------------- corpus
ATT = "169.254.169.254"

SEPS = []
for _i in range(128):  # every ASCII char, alone and doubled
    _c = chr(_i)
    SEPS += [_c, _c * 2]
SEPS += [
    "%5C", "%2F", "%09", "%00", "%40", "%3A", "%5B", "%5D", "%2E", "%2f%2f",
    "\\/", "/\\", "\\\\", "%5C%5C", "\t\\", "\\\t", "%09%5C", "\r\n", "\n\t",
    "。", "．", "／", "＠", "­", "​", "⁄",
    "️", "℀", " ", "", "　", "﻿", " ",
    "᠎", "‍", "․", "឵", "﷐", "\U0001d7d9",
]
SEPS = list(dict.fromkeys(SEPS))


def corpus(scheme, host, port):
    """Arrangements mixing the legitimate authority with an attacker host."""
    legit = f"{host}:{port}" if port else host
    out = []
    for s in SEPS:
        out += [
            f"{scheme}://{legit}{s}@{ATT}/x",
            f"{scheme}://{legit}{s}{ATT}/x",
            f"{scheme}://{ATT}{s}@{legit}/x",
            f"{scheme}://{ATT}{s}{legit}/x",
            f"{scheme}://{legit}{s}{ATT}:80/x",
            f"{scheme}://{legit}@{s}{ATT}/x",
            f"{scheme}://{legit}{s}/{ATT}/x",
            f"{scheme}://{legit}/{s}{ATT}/x",
            f"//{legit}{s}@{ATT}/x",
            f"//{ATT}{s}@{legit}/x",
            f"/{s}{ATT}/x",
            f"{s}//{ATT}/x",
            f"{scheme}://{legit}{s}[{ATT}]/x",
            f"{scheme}://[{legit}{s}{ATT}]/x",
            f"{scheme}://{legit}:{s}{ATT}/x",
        ]
    return out


BASES = [
    ("http://127.0.0.1:8000/api/", "http", "127.0.0.1", 8000),
    ("https://weblate.example.com/api/", "https", "weblate.example.com", None),
]


if __name__ == "__main__":
    total = bypass = 0
    reasons = {}
    for base, sch, host, port in BASES:
        for p in corpus(sch, host, port):
            total += 1
            verdict, detail = check(base, p)
            reasons[verdict] = reasons.get(verdict, 0) + 1
            if verdict == "BYPASS":
                bypass += 1
                print(f"[BYPASS] base={base}\n         payload={p!r}\n         {detail}")
    print(f"\nchecked {total} payloads -> {reasons}")
