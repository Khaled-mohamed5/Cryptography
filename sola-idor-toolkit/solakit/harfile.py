"""Build a test plan from captured GraphQL traffic instead of introspection.

Production APIs commonly block introspection, and edge WAFs commonly block the
introspection query specifically (it is a well-known signature). Either way the
schema is unavailable - but the schema was only ever a means to an end. What
the engine actually needs is a set of runnable operation documents and the
identifiers to feed them.

Captured traffic supplies both, and supplies them better:

  * the documents are real operations the application itself issues, so they
    validate against the live schema by construction,
  * they carry the exact argument values the app sent, so replays are faithful
    rather than guessed,
  * they already pass whatever the WAF enforces, because the browser sent them.

Accepts a HAR export (DevTools: Network -> Save all as HAR with content), a
JSON array of {query, variables} bodies, or JSON-lines of the same.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .recon import SENSITIVITY, Candidate

# query|mutation [Name] [(...vars...)] {
OP_HEADER_RE = re.compile(
    r"\b(query|mutation|subscription)\s+([A-Za-z_]\w*)?\s*(?:\(([\s\S]*?)\))?\s*\{",
    re.MULTILINE,
)
ANON_OP_RE = re.compile(r"^\s*\{")
VAR_DEF_RE = re.compile(r"\$(\w+)\s*:\s*([A-Za-z_][\w!\[\]]*)")
# first field inside the outer selection set, allowing for an alias
ROOT_FIELD_RE = re.compile(r"\{\s*(?:#[^\n]*\n\s*)*(?:([A-Za-z_]\w*)\s*:\s*)?([A-Za-z_]\w*)")

ID_VAR_RE = re.compile(
    r"^(id|_id|uuid|guid|slug|key|.*_id|.*Id|.*Ids|.*Uuid|.*UUID)$", re.IGNORECASE
)


@dataclass
class CapturedOp:
    op_type: str                        # query | mutation | subscription
    name: str
    document: str
    variables: dict = field(default_factory=dict)
    var_defs: list[tuple[str, str]] = field(default_factory=list)
    root_field: str = ""
    url: str = ""
    response: Any = None

    @property
    def key(self) -> str:
        return f"{self.op_type}.{self.root_field or self.name}"


def parse_document(doc: str) -> tuple[str, str, list[tuple[str, str]], str]:
    """Return (op_type, op_name, [(var, type)], root_field) for a document."""
    m = OP_HEADER_RE.search(doc)
    if m:
        op_type = m.group(1)
        op_name = m.group(2) or ""
        var_block = m.group(3) or ""
        var_defs = VAR_DEF_RE.findall(var_block)
        rest = doc[m.end() - 1:]
    elif ANON_OP_RE.match(doc):
        op_type, op_name, var_defs = "query", "", []
        rest = doc
    else:
        return "query", "", [], ""

    fm = ROOT_FIELD_RE.search(rest)
    root_field = (fm.group(2) if fm else "") or ""
    # Guard against matching a fragment/typename artefact.
    if root_field in ("__typename", "fragment"):
        root_field = ""
    return op_type, op_name, var_defs, root_field


def _iter_bodies(raw: str) -> list[dict]:
    """Yield GraphQL request bodies from HAR / JSON array / JSON-lines."""
    bodies: list[tuple[dict, str, Any]] = []

    def add(obj: Any, url: str = "", response: Any = None) -> None:
        if isinstance(obj, list):          # batched GraphQL
            for item in obj:
                add(item, url, response)
        elif isinstance(obj, dict) and obj.get("query"):
            bodies.append((obj, url, response))

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                add(json.loads(line))
            except json.JSONDecodeError:
                continue
        return [{"body": b, "url": u, "response": r} for b, u, r in bodies]

    entries = None
    if isinstance(parsed, dict) and "log" in parsed:
        entries = (parsed["log"] or {}).get("entries") or []

    if entries is not None:
        for e in entries:
            req = e.get("request") or {}
            url = req.get("url", "")
            post = (req.get("postData") or {}).get("text") or ""
            if not post:
                continue
            resp_text = ((e.get("response") or {}).get("content") or {}).get("text")
            resp: Any = None
            if resp_text:
                try:
                    resp = json.loads(resp_text)
                except (json.JSONDecodeError, TypeError):
                    resp = None
            try:
                add(json.loads(post), url, resp)
            except json.JSONDecodeError:
                continue
    else:
        add(parsed)

    return [{"body": b, "url": u, "response": r} for b, u, r in bodies]


def load_operations(path: Path, *, only_host: str = "") -> list[CapturedOp]:
    """Parse captured traffic into deduplicated operations."""
    raw = path.read_text(errors="replace")
    ops: list[CapturedOp] = []
    seen: set[str] = set()

    for rec in _iter_bodies(raw):
        body, url, response = rec["body"], rec["url"], rec["response"]
        if only_host and url and only_host not in url:
            continue
        doc = body.get("query") or ""
        if not doc.strip():
            continue
        op_type, op_name, var_defs, root_field = parse_document(doc)
        if op_type == "subscription":
            continue
        if "__schema" in doc:            # our own introspection attempt
            continue

        dedupe = f"{op_name}|{root_field}|{len(doc)}"
        if dedupe in seen:
            # Keep the variant that carries variable values.
            if not body.get("variables"):
                continue
        seen.add(dedupe)

        ops.append(CapturedOp(
            op_type=op_type,
            name=op_name or body.get("operationName") or root_field,
            document=doc,
            variables=body.get("variables") or {},
            var_defs=var_defs,
            root_field=root_field,
            url=url,
            response=response,
        ))
    return ops


def _severity_for(text: str) -> str:
    low = text.lower()
    for level in ("critical", "high", "medium"):
        if any(word in low for word in SENSITIVITY[level]):
            return level
    return "low"


def operations_to_candidates(ops: list[CapturedOp]) -> list[Candidate]:
    """Convert captured operations into engine candidates.

    Only operations that take an identifier-shaped variable are useful here:
    those are the ones expressing an authorization decision.
    """
    candidates: list[Candidate] = []
    for op in ops:
        id_vars = [(n, t) for n, t in op.var_defs if ID_VAR_RE.match(n)]
        if not id_vars:
            # Also treat an ID-typed variable as an object reference even when
            # the name does not look like one.
            id_vars = [
                (n, t) for n, t in op.var_defs
                if t.replace("!", "").replace("[", "").replace("]", "").lower()
                in ("id", "uuid")
            ]
        if not id_vars:
            continue

        # Only replay ids whose captured value actually looks like an object
        # reference - skip enum-ish or free-text arguments.
        usable = [
            (n, t) for n, t in id_vars
            if not isinstance(op.variables.get(n), (dict, list, bool))
        ]
        if not usable:
            continue

        cand = Candidate(
            operation=op.op_type,
            field_name=op.root_field or op.name,
            id_args=[{"name": n, "type": {"kind": "SCALAR", "name": t.rstrip("!")}}
                     for n, t in usable],
            other_required_args=[],
            return_type="",
            severity=_severity_for(f"{op.name} {op.root_field}"),
            document=op.document,
            var_names=[n for n, _ in op.var_defs],
            default_variables=dict(op.variables),
            source="captured",
        )
        candidates.append(cand)

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    candidates.sort(key=lambda c: (order[c.severity], c.operation, c.field_name))
    return candidates


def harvest_from_capture(ops: list[CapturedOp], owner: str) -> list:
    """Pull identifiers out of captured request variables and responses.

    A HAR recorded while logged in as one account is itself a harvest: every
    id in it belongs to that account.
    """
    from .harvest import OwnedObject, walk_ids

    found: list[OwnedObject] = []
    seen: set[tuple[str, str]] = set()

    for op in ops:
        for vname, vval in (op.variables or {}).items():
            if ID_VAR_RE.match(vname) and isinstance(vval, str) and len(vval) >= 8:
                k = (vval, "")
                if k not in seen:
                    seen.add(k)
                    found.append(OwnedObject(
                        owner=owner, value=vval, typename="",
                        json_path=f"$.variables.{vname}",
                        source_field=op.root_field or op.name,
                    ))
        if op.response:
            data = op.response.get("data") if isinstance(op.response, dict) else None
            if data:
                for obj in walk_ids(data, owner=owner,
                                    source_field=op.root_field or op.name):
                    k = (obj.value, obj.typename)
                    if k not in seen:
                        seen.add(k)
                        found.append(obj)
    return found


def summarise(ops: list[CapturedOp], candidates: list[Candidate]) -> str:
    q = sum(1 for o in ops if o.op_type == "query")
    m = sum(1 for o in ops if o.op_type == "mutation")
    return (f"{len(ops)} captured operations ({q} queries, {m} mutations) -> "
            f"{len(candidates)} take an object identifier")
