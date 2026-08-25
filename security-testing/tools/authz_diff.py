#!/usr/bin/env python3
"""
authz_diff.py — two-account authorization differ for cross-tenant IDOR / BAC testing.

Harvests object IDs visible to account A, then requests each of those objects as
account B and as an unauthenticated client, and classifies the result.

Designed to be run by the person who holds the bug bounty authorization, against a
target they are permitted to test. Read-only by default.

Safety posture:
  * GET/HEAD only unless --allow-writes is passed explicitly (and even then, never DELETE).
  * Global request budget, enforced before every request.
  * Client-side rate limit, default 2 req/s.
  * An attribution header on every request so the vendor can identify the traffic.
  * Credentials are read from environment variables only. Nothing authenticating is
    written to the config file, the evidence log, or stdout.

Usage:
    export ACCT_A_COOKIE='...'          # copy from your browser devtools
    export ACCT_B_COOKIE='...'
    python3 authz_diff.py --config config.json --dry-run
    python3 authz_diff.py --config config.json --out ../evidence/run1
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Iterable

try:
    import requests
except ImportError:
    sys.exit("requests is required:  pip install requests")


# ---------------------------------------------------------------- safety rails


class Budget:
    """Hard cap on total requests, plus a client-side rate limit."""

    def __init__(self, max_requests: int, rps: float) -> None:
        self.max_requests = max_requests
        self.min_interval = 1.0 / rps if rps > 0 else 0.0
        self.spent = 0
        self._last = 0.0

    def take(self) -> None:
        if self.spent >= self.max_requests:
            raise BudgetExhausted(
                f"request budget of {self.max_requests} exhausted; "
                f"raise safety.max_requests deliberately rather than by accident"
            )
        wait = self._last + self.min_interval - time.monotonic()
        if wait > 0:
            time.sleep(wait)
        self._last = time.monotonic()
        self.spent += 1


class BudgetExhausted(RuntimeError):
    pass


SAFE_METHODS = {"GET", "HEAD"}
NEVER_METHODS = {"DELETE"}


# ---------------------------------------------------------------- data model


@dataclass
class Probe:
    """One resource, fetched as one identity."""

    label: str
    method: str
    url: str
    identity: str
    status: int | None = None
    length: int | None = None
    body_hash: str | None = None
    content_type: str | None = None
    snippet: str = ""
    error: str | None = None


@dataclass
class Finding:
    label: str
    url: str
    verdict: str
    detail: str
    owner_status: int | None
    other_status: int | None
    anon_status: int | None
    evidence: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------- json paths


_PATH_TOKEN = re.compile(r"([^.\[\]]+)|\[(\*|\d+)\]")


def extract(document: Any, path: str) -> list[Any]:
    """Minimal JSONPath subset: 'objects[*].id', 'data.items[0].uuid'."""
    nodes: list[Any] = [document]
    for key, index in _PATH_TOKEN.findall(path):
        nxt: list[Any] = []
        for node in nodes:
            if key:
                if isinstance(node, dict) and key in node:
                    nxt.append(node[key])
            elif index == "*":
                if isinstance(node, list):
                    nxt.extend(node)
            else:
                if isinstance(node, list) and int(index) < len(node):
                    nxt.append(node[int(index)])
        nodes = nxt
    return nodes


# ---------------------------------------------------------------- http


class Identity:
    """An authenticated (or anonymous) client."""

    def __init__(self, name: str, headers: dict[str, str]) -> None:
        self.name = name
        self.session = requests.Session()
        self.session.headers.update(headers)

    @classmethod
    def from_config(
        cls, name: str, spec: dict[str, Any], marker: dict[str, str]
    ) -> "Identity":
        headers = dict(marker)
        headers.setdefault(
            "User-Agent", "authz-diff/1.0 (authorized security testing)"
        )
        headers.update(spec.get("headers", {}))

        for header, env_var in spec.get("headers_from_env", {}).items():
            value = os.environ.get(env_var)
            if not value:
                sys.exit(
                    f"identity '{name}' needs environment variable {env_var}; "
                    f"export it before running (do not put it in the config file)"
                )
            headers[header] = value
        return cls(name, headers)


def fetch(
    identity: Identity,
    method: str,
    url: str,
    label: str,
    budget: Budget,
    timeout: float,
) -> Probe:
    probe = Probe(label=label, method=method, url=url, identity=identity.name)
    try:
        budget.take()
        response = identity.session.request(
            method, url, timeout=timeout, allow_redirects=False
        )
    except BudgetExhausted:
        raise
    except requests.RequestException as exc:
        probe.error = f"{type(exc).__name__}: {exc}"
        return probe

    body = response.content or b""
    probe.status = response.status_code
    probe.length = len(body)
    probe.body_hash = hashlib.sha256(body).hexdigest()[:16]
    probe.content_type = response.headers.get("Content-Type", "")
    probe.snippet = body[:280].decode("utf-8", "replace")
    return probe


# ---------------------------------------------------------------- phases


def harvest(
    owner: Identity, spec: dict[str, Any], budget: Budget, timeout: float, verbose: bool
) -> list[tuple[str, str]]:
    """Collect (object_type, id) pairs visible to the owner account."""
    found: list[tuple[str, str]] = []
    for group in spec:
        name = group["name"]
        url = group["list"]
        probe = fetch(owner, "GET", url, f"harvest:{name}", budget, timeout)

        if probe.error or probe.status != 200:
            print(f"  ! {name}: list returned {probe.status or probe.error}")
            continue
        try:
            document = json.loads(probe.snippet) if probe.length <= 280 else None
            if document is None:
                # re-fetch fully; the snippet is only for evidence
                budget.take()
                document = owner.session.get(url, timeout=timeout).json()
        except (ValueError, requests.RequestException) as exc:
            print(f"  ! {name}: list not parseable as JSON ({exc})")
            continue

        ids: list[str] = []
        for path in group.get("id_paths", ["objects[*].id"]):
            ids.extend(str(v) for v in extract(document, path) if v is not None)

        seen: set[str] = set()
        unique = [i for i in ids if not (i in seen or seen.add(i))]
        limit = group.get("max_ids", 10)
        for object_id in unique[:limit]:
            found.append((name, object_id))
        print(f"  + {name}: harvested {len(unique[:limit])} id(s)")
        if verbose and unique:
            print(f"      {unique[:limit]}")
    return found


def resolve_urls(spec: list[dict[str, Any]], base_url: str) -> None:
    """Substitute {base_url} in place so the config stays target-neutral."""
    base = base_url.rstrip("/")
    if "TARGET-HOST" in base:
        sys.exit(
            "set target.base_url to the asset you are authorized to test "
            "before running"
        )
    for group in spec:
        group["list"] = group["list"].replace("{base_url}", base)
        group["detail"] = [
            template.replace("{base_url}", base)
            for template in group.get("detail", [])
        ]


def build_targets(
    harvested: Iterable[tuple[str, str]], spec: dict[str, Any]
) -> list[tuple[str, str]]:
    """Expand each harvested id into every configured representation of that object."""
    by_name = {group["name"]: group for group in spec}
    targets: list[tuple[str, str]] = []
    for name, object_id in harvested:
        for template in by_name[name].get("detail", []):
            targets.append((f"{name}:{object_id}", template.format(id=object_id)))
    return targets


def classify(owner: Probe, other: Probe, anon: Probe) -> Finding:
    """Decide what the three responses mean."""
    base = dict(
        label=owner.label,
        url=owner.url,
        owner_status=owner.status,
        other_status=other.status,
        anon_status=anon.status,
        evidence={
            "owner": asdict(owner),
            "other": asdict(other),
            "anon": asdict(anon),
        },
    )

    if owner.status != 200:
        return Finding(
            verdict="SKIP",
            detail=f"owner could not read this resource either ({owner.status}); "
            f"nothing to compare against",
            **base,
        )

    if anon.status == 200 and anon.body_hash == owner.body_hash:
        return Finding(
            verdict="CRITICAL",
            detail="unauthenticated client received byte-identical content to the owner "
            "— pre-auth data exposure",
            **base,
        )

    if other.status == 200 and other.body_hash == owner.body_hash:
        return Finding(
            verdict="CONFIRMED",
            detail="second tenant received byte-identical content to the owner "
            "— cross-tenant IDOR",
            **base,
        )

    if other.status == 200:
        delta = abs((other.length or 0) - (owner.length or 0))
        return Finding(
            verdict="INVESTIGATE",
            detail=f"second tenant got 200 but different content "
            f"(len delta {delta}); could be their own object at this id, "
            f"or a partial leak — verify by hand",
            **base,
        )

    if other.status in (401, 403, 404):
        return Finding(
            verdict="DENIED",
            detail=f"correctly refused ({other.status})",
            **base,
        )

    return Finding(
        verdict="INVESTIGATE",
        detail=f"unexpected status {other.status} for the second tenant",
        **base,
    )


# ---------------------------------------------------------------- reporting


VERDICT_ORDER = {
    "CRITICAL": 0,
    "CONFIRMED": 1,
    "INVESTIGATE": 2,
    "DENIED": 3,
    "SKIP": 4,
}


def write_report(findings: list[Finding], out_prefix: str, budget: Budget) -> None:
    os.makedirs(os.path.dirname(out_prefix) or ".", exist_ok=True)

    with open(f"{out_prefix}.jsonl", "w", encoding="utf-8") as handle:
        for finding in findings:
            handle.write(json.dumps(asdict(finding)) + "\n")

    findings.sort(key=lambda f: (VERDICT_ORDER.get(f.verdict, 9), f.label))
    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.verdict] = counts.get(finding.verdict, 0) + 1

    lines = [
        "# Authorization diff results",
        "",
        f"Requests sent: {budget.spent} (budget {budget.max_requests})",
        "",
        "| verdict | count |",
        "|---|---|",
    ]
    for verdict in sorted(counts, key=lambda v: VERDICT_ORDER.get(v, 9)):
        lines.append(f"| {verdict} | {counts[verdict]} |")

    lines += ["", "## Needs attention", ""]
    interesting = [
        f for f in findings if f.verdict in ("CRITICAL", "CONFIRMED", "INVESTIGATE")
    ]
    if not interesting:
        lines.append("_Nothing flagged. Authorization held on every probed resource._")
    for finding in interesting:
        lines += [
            f"### `{finding.verdict}` — {finding.label}",
            "",
            f"- URL: `{finding.url}`",
            f"- owner: `{finding.owner_status}` · "
            f"second tenant: `{finding.other_status}` · "
            f"anonymous: `{finding.anon_status}`",
            f"- {finding.detail}",
            "",
        ]

    with open(f"{out_prefix}.md", "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")

    print(f"\nwrote {out_prefix}.md and {out_prefix}.jsonl")
    for verdict in sorted(counts, key=lambda v: VERDICT_ORDER.get(v, 9)):
        print(f"  {verdict:<12} {counts[verdict]}")


# ---------------------------------------------------------------- entry point


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--out", default="evidence/run")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="print the request plan without sending anything",
    )
    parser.add_argument(
        "--allow-writes",
        action="store_true",
        help="permit non-GET methods from the config (never DELETE)",
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    with open(args.config, encoding="utf-8") as handle:
        config = json.load(handle)

    safety = config.get("safety", {})
    timeout = float(safety.get("timeout_seconds", 20))
    budget = Budget(
        max_requests=int(safety.get("max_requests", 400)),
        rps=float(safety.get("requests_per_second", 2.0)),
    )

    methods = {m.upper() for m in safety.get("allowed_methods", ["GET"])}
    if methods & NEVER_METHODS:
        sys.exit("DELETE is never permitted by this tool; prove read access instead")
    if not methods <= SAFE_METHODS and not args.allow_writes:
        sys.exit(
            f"config requests non-read methods {sorted(methods - SAFE_METHODS)}; "
            f"re-run with --allow-writes if that is genuinely what you intend"
        )

    resolve_urls(config["harvest"], config["target"]["base_url"])

    marker = config["target"].get("marker_header", {})
    if not marker or any("REPLACE" in v for v in marker.values()):
        sys.exit(
            "set target.marker_header to something identifying you, e.g. "
            '{"X-Bug-Bounty": "your-h1-username"} — the vendor needs to be able '
            "to attribute this traffic"
        )

    identities = config["accounts"]
    owner = Identity.from_config("owner", identities["A"], marker)
    other = Identity.from_config("other", identities["B"], marker)
    anon = Identity("anon", dict(marker))

    if args.dry_run:
        print("DRY RUN — no requests will be sent\n")
        print(f"rate limit : {safety.get('requests_per_second', 2.0)} req/s")
        print(f"budget     : {budget.max_requests} requests")
        print(f"methods    : {sorted(methods)}\n")
        for group in config["harvest"]:
            print(f"harvest {group['name']:<24} {group['list']}")
            for template in group.get("detail", []):
                print(f"    replay as owner/other/anon: {template}")
        print("\nEach detail URL is fetched three times: owner, second tenant, anonymous.")
        return 0

    print("phase 1 — harvesting object ids as account A")
    harvested = harvest(owner, config["harvest"], budget, timeout, args.verbose)
    if not harvested:
        print(
            "\nNo ids harvested. Populate account A with real objects first, and check "
            "that its credentials are still valid."
        )
        return 1

    targets = build_targets(harvested, config["harvest"])
    print(f"\nphase 2 — replaying {len(targets)} resource(s) across three identities")

    findings: list[Finding] = []
    try:
        for label, url in targets:
            probes = [
                fetch(who, "GET", url, label, budget, timeout)
                for who in (owner, other, anon)
            ]
            finding = classify(*probes)
            findings.append(finding)
            if finding.verdict in ("CRITICAL", "CONFIRMED", "INVESTIGATE"):
                print(f"  {finding.verdict:<12} {label}  {url}")
            elif args.verbose:
                print(f"  {finding.verdict:<12} {label}")
    except BudgetExhausted as exc:
        print(f"\nstopped early: {exc}")

    print("\nphase 3 — writing results")
    write_report(findings, args.out, budget)

    print(
        "\nVerify every CONFIRMED and CRITICAL by hand in a browser before reporting. "
        "An automated match is a lead, not a finding."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
