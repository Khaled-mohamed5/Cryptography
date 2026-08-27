"""Collect real object identifiers belonging to each test account.

Cross-account IDOR testing needs *valid* identifiers. Guessing them is both
unreliable (UUIDs are not enumerable) and unacceptable against production
(a guessed ID could belong to a real customer). So we harvest legitimately:
log in as each account, list what that account genuinely owns, and use those
identifiers as the payloads to replay under the *other* account's token.

Every ID we test with therefore belongs to one of our two authorised test
identities - never to a third party.
"""
from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass
from typing import Any

from .config import Account
from .gql import GraphQLClient
from .recon import SchemaIndex, is_required, unwrap

UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
OBJECTID_RE = re.compile(r"^[0-9a-f]{24}$")
NUMERIC_ID_RE = re.compile(r"^\d{1,12}$")

ID_KEY_HINT = re.compile(r"(^|_)(id|uuid|guid|key)$", re.IGNORECASE)


@dataclass(frozen=True)
class OwnedObject:
    owner: str          # account label the ID was harvested from
    value: str          # the identifier itself
    typename: str       # __typename it appeared under, if known
    json_path: str      # where in the response it was found
    source_field: str   # root field that produced it

    @property
    def display(self) -> str:
        return f"{self.typename or '?'}:{self.value}"


def _looks_like_id(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    if UUID_RE.match(value) or OBJECTID_RE.match(value):
        return True
    if NUMERIC_ID_RE.match(value):
        return True
    # Relay global IDs: base64("TypeName:1234")
    if 8 <= len(value) <= 128 and re.fullmatch(r"[A-Za-z0-9+/=_-]+", value):
        try:
            padded = value + "=" * (-len(value) % 4)
            decoded = base64.b64decode(padded, validate=False).decode("utf-8", "ignore")
            if ":" in decoded and decoded.split(":", 1)[0].isidentifier():
                return True
        except (binascii.Error, ValueError, UnicodeDecodeError):
            pass
    return False


def walk_ids(
    payload: Any,
    *,
    owner: str,
    source_field: str,
    path: str = "$",
    inherited_typename: str = "",
) -> list[OwnedObject]:
    """Recursively pull identifier-shaped values out of a GraphQL response."""
    found: list[OwnedObject] = []

    if isinstance(payload, dict):
        typename = payload.get("__typename") or inherited_typename
        for key, val in payload.items():
            child_path = f"{path}.{key}"
            if isinstance(val, (dict, list)):
                found.extend(
                    walk_ids(
                        val,
                        owner=owner,
                        source_field=source_field,
                        path=child_path,
                        inherited_typename=typename,
                    )
                )
            elif ID_KEY_HINT.search(key) and _looks_like_id(val):
                found.append(
                    OwnedObject(
                        owner=owner,
                        value=str(val),
                        typename=typename,
                        json_path=child_path,
                        source_field=source_field,
                    )
                )
    elif isinstance(payload, list):
        for i, item in enumerate(payload):
            found.extend(
                walk_ids(
                    item,
                    owner=owner,
                    source_field=source_field,
                    path=f"{path}[{i}]",
                    inherited_typename=inherited_typename,
                )
            )
    return found


def listing_fields(index: SchemaIndex, limit: int = 40) -> list[str]:
    """Root query fields that need no required arguments.

    These are the 'show me my stuff' entry points - the natural place to
    discover the identifiers an account legitimately owns.
    """
    out = []
    for f in index.fields_of(index.query_type):
        args = f.get("args") or []
        if any(is_required(a.get("type")) for a in args if a.get("defaultValue") is None):
            continue
        if f["name"].startswith("__"):
            continue
        out.append(f["name"])
        if len(out) >= limit:
            break
    return out


def harvest(
    client: GraphQLClient,
    index: SchemaIndex,
    account: Account,
    *,
    max_fields: int = 40,
) -> tuple[list[OwnedObject], dict[str, str]]:
    """Enumerate what `account` legitimately owns.

    Returns (owned objects, {root_field: status note}).
    """
    owned: list[OwnedObject] = []
    notes: dict[str, str] = {}
    seen: set[tuple[str, str]] = set()

    for fname in listing_fields(index, limit=max_fields):
        field_def = next(
            (f for f in index.fields_of(index.query_type) if f["name"] == fname), None
        )
        if not field_def:
            continue
        ret = unwrap(field_def.get("type"))
        selection = index.build_selection(ret.get("name") or "")
        doc = f"query SolaHarvest {{\n  {fname}{selection}\n}}"

        res = client.execute(
            doc, account=account, note=f"harvest {fname} as {account.label}"
        )
        if not res.has_data:
            notes[fname] = (
                f"no data (HTTP {res.status}) {res.error_text[:120]}".strip()
            )
            continue

        ids = walk_ids(res.data, owner=account.label, source_field=fname)
        fresh = 0
        for obj in ids:
            dedupe_key = (obj.value, obj.typename)
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)
            owned.append(obj)
            fresh += 1
        notes[fname] = f"ok - {fresh} new identifier(s)"

    return owned, notes
