"""Turn a GraphQL schema into a prioritised IDOR/BOLA test plan.

The premise: in a multi-tenant GraphQL API, every root field that accepts a
caller-supplied object identifier is an authorization decision. Each one is a
place the server must ask "does *this* caller own *that* object?" - and each
one is a place that check can be missing. This module enumerates those
decision points and builds a runnable query for each.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

# Scalars we can safely request without a sub-selection.
LEAF_KINDS = {"SCALAR", "ENUM"}

ID_ARG_PATTERN = re.compile(
    r"^(id|_id|uuid|guid|key|slug|"          # bare identifiers
    r".*_id|.*Id|.*Ids|.*UUID|.*Uuid|"        # suffixed identifiers
    r"(user|org|organization|tenant|account|workspace|project|team|member|"
    r"policy|rule|agent|workflow|integration|connector|finding|alert|report|"
    r"detection|protection|apikey|token|secret|credential|invoice|"
    r"subscription|file|document|asset)(Id|Ids|Uuid|Key)?)$",
    re.IGNORECASE,
)

# Return types whose exposure carries the most impact. Tuned for a security
# SaaS: identity, tenancy, secrets, and integration credentials first.
SENSITIVITY = {
    "critical": (
        "apikey", "token", "secret", "credential", "password", "privatekey",
        "connection", "integration", "connector", "webhook", "oauth",
    ),
    "high": (
        "user", "member", "tenant", "organization", "org", "account",
        "workspace", "team", "invite", "invitation", "role", "permission",
        "billing", "invoice", "subscription", "payment", "auditlog", "audit",
    ),
    "medium": (
        "policy", "rule", "protection", "agent", "workflow", "automation",
        "finding", "alert", "detection", "incident", "report", "scan",
        "project", "asset", "resource", "document", "file",
    ),
}


def unwrap(type_ref: dict | None) -> dict:
    """Strip NON_NULL / LIST wrappers down to the named type."""
    cur = type_ref or {}
    seen = 0
    while cur.get("ofType") and seen < 12:
        cur = cur["ofType"]
        seen += 1
    return cur


def type_signature(type_ref: dict | None) -> str:
    """Render a type ref back into GraphQL SDL syntax (Foo, [Foo!]!, ...)."""
    t = type_ref or {}
    kind = t.get("kind")
    if kind == "NON_NULL":
        return type_signature(t.get("ofType")) + "!"
    if kind == "LIST":
        return "[" + type_signature(t.get("ofType")) + "]"
    return t.get("name") or "Unknown"


def is_required(type_ref: dict | None) -> bool:
    return (type_ref or {}).get("kind") == "NON_NULL"


@dataclass
class Candidate:
    """One root field that takes an object identifier."""
    operation: str              # "query" | "mutation"
    field_name: str
    id_args: list[dict]         # args that look like object identifiers
    other_required_args: list[dict]
    return_type: str
    severity: str
    document: str = ""          # runnable GraphQL document
    var_names: list[str] = field(default_factory=list)
    # Real variable values observed in captured traffic. Replaying a captured
    # operation with its own recorded arguments (overriding only the id under
    # test) is far more likely to produce a valid request than guessing.
    default_variables: dict = field(default_factory=dict)
    source: str = "schema"      # "schema" | "captured"

    @property
    def key(self) -> str:
        return f"{self.operation}.{self.field_name}"


class SchemaIndex:
    def __init__(self, schema: dict) -> None:
        self.raw = schema
        self.types: dict[str, dict] = {
            t["name"]: t for t in (schema.get("types") or []) if t.get("name")
        }
        self.query_type = (schema.get("queryType") or {}).get("name")
        self.mutation_type = (schema.get("mutationType") or {}).get("name")

    def fields_of(self, type_name: str | None) -> list[dict]:
        if not type_name:
            return []
        return self.types.get(type_name, {}).get("fields") or []

    def leaf_fields(self, type_name: str, limit: int = 25) -> list[str]:
        """Scalar/enum fields we can request without a sub-selection."""
        out = []
        for f in self.fields_of(type_name):
            if f.get("args"):
                # Skip fields that require arguments - keeps the doc valid.
                if any(is_required(a.get("type")) for a in f["args"]):
                    continue
            named = unwrap(f.get("type"))
            if named.get("kind") in LEAF_KINDS:
                out.append(f["name"])
            if len(out) >= limit:
                break
        return out

    def build_selection(self, type_name: str, depth: int = 2) -> str:
        """Build a selection set for a type, descending only as far as needed."""
        t = self.types.get(type_name) or {}
        kind = t.get("kind")
        if kind in LEAF_KINDS:
            return ""
        if kind in ("UNION", "INTERFACE"):
            # Ask only for __typename plus any leaf fields on the interface.
            leaves = self.leaf_fields(type_name)
            inner = " ".join(["__typename"] + leaves)
            return " { %s }" % inner

        leaves = self.leaf_fields(type_name)
        if leaves:
            return " { %s }" % " ".join(["__typename"] + leaves)

        if depth <= 0:
            return " { __typename }"

        # No scalars at this level: descend into the first object field.
        for f in self.fields_of(type_name):
            if any(is_required(a.get("type")) for a in (f.get("args") or [])):
                continue
            named = unwrap(f.get("type"))
            child = named.get("name")
            if child and child != type_name:
                sub = self.build_selection(child, depth - 1)
                if sub:
                    return " { __typename %s%s }" % (f["name"], sub)
        return " { __typename }"


def _severity_for(return_type: str, field_name: str) -> str:
    haystack = f"{return_type} {field_name}".lower()
    for level in ("critical", "high", "medium"):
        if any(word in haystack for word in SENSITIVITY[level]):
            return level
    return "low"


def _looks_like_id(arg: dict) -> bool:
    name = arg.get("name", "")
    named = unwrap(arg.get("type"))
    type_name = (named.get("name") or "").lower()
    if ID_ARG_PATTERN.match(name):
        return True
    # An `ID` scalar in any argument position is an object reference.
    return type_name in ("id", "uuid", "objectid")


def find_candidates(index: SchemaIndex) -> list[Candidate]:
    """Enumerate every root field that takes a caller-supplied identifier."""
    candidates: list[Candidate] = []

    for op, type_name in (("query", index.query_type), ("mutation", index.mutation_type)):
        for f in index.fields_of(type_name):
            args = f.get("args") or []
            id_args = [a for a in args if _looks_like_id(a)]
            if not id_args:
                continue
            other_required = [
                a for a in args
                if a not in id_args
                and is_required(a.get("type"))
                and a.get("defaultValue") is None
            ]
            ret = unwrap(f.get("type"))
            ret_name = ret.get("name") or "Unknown"
            cand = Candidate(
                operation=op,
                field_name=f["name"],
                id_args=id_args,
                other_required_args=other_required,
                return_type=ret_name,
                severity=_severity_for(ret_name, f["name"]),
            )
            _attach_document(index, cand)
            candidates.append(cand)

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    candidates.sort(key=lambda c: (order[c.severity], c.operation, c.field_name))
    return candidates


def _attach_document(index: SchemaIndex, cand: Candidate) -> None:
    """Render a runnable, variable-parameterised document for a candidate."""
    var_defs: list[str] = []
    arg_pairs: list[str] = []
    var_names: list[str] = []

    for a in cand.id_args:
        vname = a["name"]
        var_defs.append(f"${vname}: {type_signature(a.get('type'))}")
        arg_pairs.append(f"{a['name']}: ${vname}")
        var_names.append(vname)

    # Required non-id args still have to be supplied for the document to
    # validate; they are filled with placeholders the caller can override.
    for a in cand.other_required_args:
        vname = a["name"]
        var_defs.append(f"${vname}: {type_signature(a.get('type'))}")
        arg_pairs.append(f"{a['name']}: ${vname}")
        var_names.append(vname)

    selection = index.build_selection(cand.return_type)
    header = f"{cand.operation} SolaIdorProbe"
    if var_defs:
        header += "(" + ", ".join(var_defs) + ")"
    cand.document = (
        f"{header} {{\n  {cand.field_name}"
        + ("(" + ", ".join(arg_pairs) + ")" if arg_pairs else "")
        + f"{selection}\n}}"
    )
    cand.var_names = var_names


def summarise(candidates: list[Candidate]) -> str:
    by_sev: dict[str, int] = {}
    for c in candidates:
        by_sev[c.severity] = by_sev.get(c.severity, 0) + 1
    queries = sum(1 for c in candidates if c.operation == "query")
    muts = len(candidates) - queries
    parts = [f"{len(candidates)} identifier-taking root fields "
             f"({queries} queries, {muts} mutations)"]
    for level in ("critical", "high", "medium", "low"):
        if by_sev.get(level):
            parts.append(f"{by_sev[level]} {level}")
    return " | ".join(parts)
