"""Rate-limited, scope-enforcing HTTP layer with evidence capture.

Every request the toolkit makes goes through `ScopedSession`, which:
  * refuses hosts outside the declared program scope (fails closed),
  * paces requests to a configured rate,
  * records a full request/response transcript for report evidence.
"""
from __future__ import annotations

import json
import threading
import time
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests

from .config import (
    AUTH_ONLY_HOSTS,
    IN_SCOPE_HOSTS,
    OUT_OF_SCOPE_HOSTS,
    DEFAULT_SAFETY,
    Safety,
)


class OutOfScopeError(RuntimeError):
    """Raised when something tries to send traffic outside program scope."""


def assert_in_scope(url: str, *, allow_auth_host: bool = False) -> str:
    host = (urllib.parse.urlparse(url).hostname or "").lower()
    if not host:
        raise OutOfScopeError(f"Cannot determine host for URL: {url!r}")

    if any(host == bad or host.endswith("." + bad) for bad in OUT_OF_SCOPE_HOSTS):
        raise OutOfScopeError(f"{host} is explicitly OUT OF SCOPE - refusing.")

    if host in IN_SCOPE_HOSTS:
        return host
    if host in AUTH_ONLY_HOSTS:
        if allow_auth_host:
            return host
        raise OutOfScopeError(
            f"{host} is the third-party IdP (out of scope). It may only be used "
            "for ordinary login, not for testing."
        )

    raise OutOfScopeError(
        f"{host} is not in the program scope allowlist. In scope: "
        f"{', '.join(sorted(IN_SCOPE_HOSTS))}"
    )


class RateLimiter:
    """Simple global pacer. Blocks so total throughput stays under `rps`."""

    def __init__(self, rps: float) -> None:
        self._min_interval = 1.0 / rps if rps > 0 else 0.0
        self._lock = threading.Lock()
        self._next_at = 0.0

    def wait(self) -> None:
        if self._min_interval <= 0:
            return
        with self._lock:
            now = time.monotonic()
            sleep_for = self._next_at - now
            if sleep_for > 0:
                time.sleep(sleep_for)
                now = time.monotonic()
            self._next_at = now + self._min_interval


@dataclass
class Exchange:
    """One request/response pair, retained as finding evidence."""
    seq: int
    timestamp: str
    method: str
    url: str
    request_headers: dict[str, str]
    request_body: Any
    status: int | None
    response_headers: dict[str, str]
    response_body: Any
    elapsed_ms: float
    note: str = ""
    error: str | None = None

    def to_dict(self) -> dict:
        return {
            "seq": self.seq,
            "timestamp": self.timestamp,
            "note": self.note,
            "request": {
                "method": self.method,
                "url": self.url,
                "headers": self.request_headers,
                "body": self.request_body,
            },
            "response": {
                "status": self.status,
                "headers": self.response_headers,
                "body": self.response_body,
                "elapsed_ms": round(self.elapsed_ms, 1),
            },
            "error": self.error,
        }

    def as_curl(self) -> str:
        """Reproduction command for the HackerOne report."""
        parts = [f"curl -i -X {self.method} '{self.url}'"]
        for k, v in self.request_headers.items():
            parts.append(f"  -H '{k}: {v}'")
        if self.request_body is not None:
            body = (
                json.dumps(self.request_body)
                if not isinstance(self.request_body, str)
                else self.request_body
            )
            parts.append("  -d '" + body.replace("'", "'\\''") + "'")
        return " \\\n".join(parts)


_SENSITIVE_HEADERS = {"authorization", "cookie", "set-cookie", "x-api-key"}

_EDGE_BLOCK_NEEDLES = (
    "waf", "blocked by", "access denied", "request blocked",
    "forbidden by", "security rules", "cloudfront", "akamai", "incapsula",
)


def looks_like_edge_block(status: int | None, body: object) -> bool:
    """Distinguish an edge/WAF refusal from the application's own 403.

    An application denial is a considered authorization decision and must be
    reported as-is. An edge block never reached the application at all, and
    says nothing about authorization - conflating the two turns infrastructure
    noise into phantom security findings.
    """
    if status not in (401, 403, 405, 406, 429, 503):
        return False
    if isinstance(body, dict):
        # A GraphQL error envelope means the application answered.
        if "errors" in body or "data" in body:
            return False
        text = str(body.get("message", "")) + " " + str(body.get("error", ""))
    else:
        text = str(body or "")
    low = text.lower()
    return status in (429, 503) or any(n in low for n in _EDGE_BLOCK_NEEDLES)


def _redact_headers(headers: dict[str, str], redact: bool) -> dict[str, str]:
    if not redact:
        return dict(headers)
    out = {}
    for k, v in headers.items():
        if k.lower() in _SENSITIVE_HEADERS:
            tail = v[-6:] if len(v) > 6 else ""
            out[k] = f"<redacted:...{tail}>"
        else:
            out[k] = v
    return out


class ScopedSession:
    """The only thing in the toolkit that is allowed to touch the network."""

    def __init__(self, safety: Safety = DEFAULT_SAFETY) -> None:
        self.safety = safety
        self._session = requests.Session()
        self._limiter = RateLimiter(safety.rate_limit_rps)
        self._seq = 0
        self._lock = threading.Lock()
        self.exchanges: list[Exchange] = []
        self._consecutive_errors = 0

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        json_body: Any = None,
        allow_auth_host: bool = False,
        note: str = "",
        capture: bool = True,
    ) -> Exchange:
        assert_in_scope(url, allow_auth_host=allow_auth_host)
        headers = dict(headers or {})
        headers.setdefault("User-Agent", "SolaIDORKit/1.0 (HackerOne security testing)")
        headers.setdefault("Accept", "application/json")
        if self.safety.identify_as:
            headers.setdefault("X-Bug-Bounty", self.safety.identify_as)
            headers.setdefault("X-HackerOne-Research", self.safety.identify_as)

        self._limiter.wait()
        with self._lock:
            self._seq += 1
            seq = self._seq

        started = time.monotonic()
        status: int | None = None
        resp_headers: dict[str, str] = {}
        resp_body: Any = None
        error: str | None = None
        blocked_attempts = 0

        try:
            resp = self._session.request(
                method,
                url,
                headers=headers,
                json=json_body,
                timeout=self.safety.request_timeout,
            )
            status = resp.status_code
            resp_headers = dict(resp.headers)
            ctype = resp.headers.get("Content-Type", "")
            if "json" in ctype:
                try:
                    resp_body = resp.json()
                except ValueError:
                    resp_body = resp.text[:20000]
            else:
                resp_body = resp.text[:20000]
            # An edge block is transient often enough to be worth retrying;
            # a genuine application response is never retried.
            while (
                looks_like_edge_block(status, resp_body)
                and blocked_attempts < self.safety.waf_retries
            ):
                blocked_attempts += 1
                time.sleep(self.safety.waf_backoff * blocked_attempts)
                resp = self._session.request(
                    method, url, headers=headers, json=json_body,
                    timeout=self.safety.request_timeout,
                )
                status = resp.status_code
                resp_headers = dict(resp.headers)
                try:
                    resp_body = resp.json()
                except ValueError:
                    resp_body = resp.text[:20000]
            if blocked_attempts:
                note = (note + " " if note else "") + f"[{blocked_attempts} WAF retry]"
            self._consecutive_errors = 0
        except requests.RequestException as exc:
            error = f"{type(exc).__name__}: {exc}"
            self._consecutive_errors += 1
            if self._consecutive_errors >= self.safety.max_consecutive_errors:
                raise RuntimeError(
                    f"Aborting: {self._consecutive_errors} consecutive transport "
                    f"errors. Last: {error}"
                ) from exc

        ex = Exchange(
            seq=seq,
            timestamp=datetime.now(timezone.utc).isoformat(),
            method=method.upper(),
            url=url,
            request_headers=_redact_headers(headers, self.safety.redact_tokens),
            request_body=json_body,
            status=status,
            response_headers={
                k: v for k, v in resp_headers.items()
                if k.lower() not in {"set-cookie"}
            },
            response_body=resp_body,
            elapsed_ms=(time.monotonic() - started) * 1000,
            note=note,
            error=error,
        )
        if capture:
            with self._lock:
                self.exchanges.append(ex)
        return ex

    def post(self, url: str, **kw) -> Exchange:
        return self.request("POST", url, **kw)

    def get(self, url: str, **kw) -> Exchange:
        return self.request("GET", url, **kw)

    def put(self, url: str, **kw) -> Exchange:
        return self.request("PUT", url, **kw)

    def save_evidence(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps([e.to_dict() for e in self.exchanges], indent=2, default=str)
        )
