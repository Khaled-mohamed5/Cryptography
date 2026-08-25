#!/usr/bin/env python3
"""
har_to_config.py — turn a recorded browser session into an authz_diff config.

Hand-copying endpoint paths out of devtools is slow and you will miss things.
Instead: record a HAR while using the application normally as account A, point
this at it, and get a config.json containing the endpoints the front end really
calls — including the query parameters it uses, which is where the interesting
authorization gaps tend to live.

How to record the HAR:
    1. Log in as account A.
    2. Devtools -> Network. Tick "Preserve log".
    3. Exercise the app: open a list of invoices, open one, view its PDF, open a
       contact, download a receipt. Every feature you touch becomes a test case.
    4. Right-click the request list -> "Save all as HAR with content".

Then:
    python3 har_to_config.py session.har --host my.example.com -o config.json

SECURITY: a HAR file contains your session cookies and every response body from
that browsing session. Treat it like a credential. This script never copies
cookies, headers or bodies into the output, and *.har is gitignored — but delete
the HAR when you are done with it.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import OrderedDict
from typing import Any
from urllib.parse import urlparse, parse_qs, urlencode

# Path segments that are object identifiers rather than route names.
UUID = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
NUMERIC = re.compile(r"^\d+$")
LONG_HEX = re.compile(r"^[0-9a-fA-F]{16,}$")

# Query parameters that only affect paging/presentation. Collapsing these stops
# the same endpoint appearing five times because the UI paged through it.
NOISE_PARAMS = {"limit", "offset", "page", "count", "_", "t", "timestamp", "cb"}

# Static assets. Bundlers emit hashed filenames that look like identifiers, so
# these have to be excluded by extension rather than by shape.
STATIC_SUFFIXES = (
    ".js", ".mjs", ".css", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg",
    ".ico", ".woff", ".woff2", ".ttf", ".eot", ".webp", ".avif",
)


def is_identifier(segment: str) -> bool:
    return bool(
        NUMERIC.match(segment) or UUID.match(segment) or LONG_HEX.match(segment)
    )


def normalize(path: str) -> tuple[str, bool]:
    """Replace id-like segments with {id}. Returns (template, contains_id)."""
    parts = path.split("/")
    found = False
    for index, segment in enumerate(parts):
        if is_identifier(segment):
            parts[index] = "{id}"
            found = True
    return "/".join(parts), found


def significant_query(query: str) -> str:
    """Keep the parameters that change what is returned, drop paging noise."""
    params = parse_qs(query, keep_blank_values=True)
    kept = {k: v for k, v in params.items() if k.lower() not in NOISE_PARAMS}
    return urlencode(sorted(kept.items()), doseq=True)


def find_id_paths(document: Any, prefix: str = "", depth: int = 0) -> list[str]:
    """Locate lists of objects carrying an 'id'-like key, as JSONPath strings."""
    if depth > 4:
        return []

    paths: list[str] = []

    if isinstance(document, list):
        for item in document[:1]:
            if isinstance(item, dict):
                for key in ("id", "uuid", "objectId", "_id"):
                    if key in item:
                        paths.append(f"{prefix}[*].{key}")
                        break
                else:
                    paths.extend(find_id_paths(item, f"{prefix}[*]", depth + 1))
        return paths

    if isinstance(document, dict):
        for key, value in document.items():
            child = f"{prefix}.{key}" if prefix else key
            paths.extend(find_id_paths(value, child, depth + 1))

    return paths


def parse_body(entry: dict[str, Any]) -> Any:
    content = entry.get("response", {}).get("content", {})
    text = content.get("text")
    if not text or "json" not in (content.get("mimeType") or "").lower():
        return None
    try:
        return json.loads(text)
    except ValueError:
        return None


def resource_name(template: str) -> str:
    """The object type a path addresses.

    For a detail path this is the segment *before* the id, not the last one:
    /api/v1/Invoice/{id}/getPdf is an Invoice, so it must be grouped with the
    Invoice collection and tested using ids harvested from it. Taking the last
    segment would file it under 'getPdf' with no ids to replay.
    """
    parts = [p for p in template.strip("/").split("/") if p]
    for index, segment in enumerate(parts):
        if segment == "{id}" and index > 0:
            return parts[index - 1]
    for segment in reversed(parts):
        if not segment.startswith("{"):
            return segment
    return "resource"


def load_entries(har_path: str, host: str | None) -> list[dict[str, Any]]:
    try:
        with open(har_path, encoding="utf-8") as handle:
            har = json.load(handle)
    except (OSError, ValueError) as exc:
        sys.exit(f"could not read HAR: {exc}")

    entries = har.get("log", {}).get("entries", [])
    if not entries:
        sys.exit("HAR contains no entries")

    kept = []
    for entry in entries:
        request = entry.get("request", {})
        if request.get("method") != "GET":
            continue
        parsed = urlparse(request.get("url", ""))
        if host and parsed.netloc != host:
            continue
        if parsed.path.lower().endswith(STATIC_SUFFIXES):
            continue
        # Keep anything addressing a specific object, whatever it returns: a
        # detail endpoint serving a PDF or a file download is precisely the
        # variant that tends to skip the authorization check. Keep non-id URLs
        # only when they return JSON, so they can be mined for collections.
        _, has_id = normalize(parsed.path)
        if parse_body(entry) is None and not has_id:
            continue
        kept.append(entry)
    return kept


def build_groups(
    entries: list[dict[str, Any]], base_url: str
) -> "OrderedDict[str, dict[str, Any]]":
    collections: OrderedDict[str, dict[str, Any]] = OrderedDict()
    details: OrderedDict[str, set[str]] = OrderedDict()

    for entry in entries:
        parsed = urlparse(entry["request"]["url"])
        template, has_id = normalize(parsed.path)
        query = significant_query(parsed.query)
        full = f"{{base_url}}{template}" + (f"?{query}" if query else "")
        name = resource_name(template)

        if has_id:
            details.setdefault(name, set()).add(full)
            continue

        document = parse_body(entry)
        paths = find_id_paths(document) if document is not None else []
        if not paths:
            continue

        existing = collections.get(name)
        if existing is None or len(paths) > len(existing["id_paths"]):
            collections[name] = {
                "name": name,
                "list": full + ("&" if query else "?") + "limit=25",
                "id_paths": sorted(set(paths))[:3],
                "max_ids": 10,
                "detail": [],
            }

    for name, group in collections.items():
        group["detail"] = sorted(details.pop(name, set()))

    # Detail endpoints whose collection we never saw are still worth testing;
    # the user can point them at an id harvested from a different collection.
    for name, urls in details.items():
        collections[f"{name}_orphan"] = {
            "_comment": (
                f"No collection endpoint for '{name}' was seen in the HAR. "
                f"Add a 'list' URL that returns {name} ids, or delete this group."
            ),
            "name": name,
            "list": f"{{base_url}}/CHANGE-ME-collection-returning-{name}-ids",
            "id_paths": ["objects[*].id"],
            "max_ids": 5,
            "detail": sorted(urls),
        }

    return collections


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("har", help="HAR file exported from devtools")
    parser.add_argument("--host", help="only keep requests to this host")
    parser.add_argument("--h1-username", default="REPLACE-WITH-YOUR-H1-USERNAME")
    parser.add_argument("-o", "--out", default="config.json")
    args = parser.parse_args()

    entries = load_entries(args.har, args.host)
    if not entries:
        sys.exit(
            "no candidate GET requests found. Check --host matches the API host "
            "(it is often an api.* subdomain, not the one in the address bar), "
            "and that you exported 'with content'."
        )

    base_url = f"https://{args.host}" if args.host else "https://CHANGE-ME"
    groups = build_groups(entries, base_url)
    if not groups:
        sys.exit(
            "found requests but no JSON collections with object ids in them. "
            "Browse a few list views (invoices, contacts) and re-record."
        )

    config = {
        "_comment": [
            f"Generated by har_to_config.py from {args.har}.",
            "Review before running. Delete groups you do not care about -"
            " every group costs requests from your budget.",
            "No cookies or headers were copied from the HAR. Export those as"
            " ACCT_A_COOKIE / ACCT_B_COOKIE environment variables instead.",
        ],
        "target": {
            "base_url": base_url,
            "marker_header": {"X-Bug-Bounty": args.h1_username},
        },
        "safety": {
            "requests_per_second": 2.0,
            "max_requests": 400,
            "allowed_methods": ["GET"],
            "timeout_seconds": 20,
        },
        "accounts": {
            "A": {"headers_from_env": {"Cookie": "ACCT_A_COOKIE"}},
            "B": {"headers_from_env": {"Cookie": "ACCT_B_COOKIE"}},
        },
        "harvest": list(groups.values()),
    }

    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump(config, handle, indent=2)
        handle.write("\n")

    total_details = sum(len(g["detail"]) for g in groups.values())
    print(f"wrote {args.out}")
    print(f"  {len(entries)} candidate requests from the HAR")
    print(f"  {len(groups)} object type(s), {total_details} detail endpoint(s)")
    for group in groups.values():
        marker = "  (needs a list URL)" if "_comment" in group else ""
        print(f"    {group['name']:<24} {len(group['detail'])} variant(s){marker}")

    print(
        "\nNext: review the file, then\n"
        f"  python3 authz_diff.py --config {args.out} --dry-run"
    )
    if args.h1_username.startswith("REPLACE"):
        print("\nSet --h1-username; authz_diff refuses to run without it.")
    print("\nDelete the HAR when you are done — it contains your session cookies.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
