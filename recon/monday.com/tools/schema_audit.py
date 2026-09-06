#!/usr/bin/env python3
"""
schema_audit.py - audit a GraphQL SDL for hidden surface and risky fields.

    python3 schema_audit.py schema.sdl -o schema-audit

Three passes, all offline:

  1. REACHABILITY. Walks the type graph from Query and Mutation and reports
     every type that is DEFINED but NOT REACHABLE. On a federated supergraph
     those orphans are the tell for root fields that exist at runtime but were
     stripped from the published SDL - undocumented API surface, which is
     exactly where authorization gaps live. Each orphan namespace becomes a
     one-request probe.

  2. RISKY FIELDS. Fields that return or accept credentials, fields whose own
     documentation describes an auth mechanism, server-side fetch sinks
     (callback/webhook URLs), and cross-tenant identifiers taken as arguments.

  3. PROBES. Emits ready-to-send GraphQL documents for the orphan namespaces.

Regex-based, not a real GraphQL parser: good enough for auditing an SDL,
and it has no dependencies.
"""

import argparse
import json
import os
import re
import sys
from collections import defaultdict

BUILTIN = {"Int", "Float", "String", "Boolean", "ID"}

# type Foo / input Foo / enum Foo / interface Foo / union Foo / scalar Foo
DEF_RE = re.compile(
    r'^(?P<kind>type|input|enum|interface|union|scalar)\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)'
    r'(?P<rest>[^\n{=]*)(?P<body>[={].*?)?$',
    re.M)

TYPEREF_RE = re.compile(r'\b([A-Z][A-Za-z0-9_]*)\b')


def strip_descriptions(sdl):
    """Blank out docstrings so their prose is not mistaken for type refs."""
    sdl = re.sub(r'"""(?:.|\n)*?"""', lambda m: "\n" * m.group(0).count("\n"), sdl)
    sdl = re.sub(r'"(?:[^"\\\n]|\\.)*"', "", sdl)
    return sdl


def parse_blocks(sdl):
    """name -> {kind, body, start, end} using brace matching on the raw text."""
    blocks = {}
    lines = sdl.split("\n")
    i = 0
    header = re.compile(
        r'^(type|input|enum|interface|union|scalar)\s+([A-Za-z_][A-Za-z0-9_]*)')
    while i < len(lines):
        m = header.match(lines[i])
        if not m:
            i += 1
            continue
        kind, name = m.group(1), m.group(2)
        if kind in ("scalar",):
            blocks[name] = {"kind": kind, "body": "", "line": i + 1}
            i += 1
            continue
        if kind == "union":
            body = lines[i]
            blocks[name] = {"kind": kind, "body": body, "line": i + 1}
            i += 1
            continue
        depth = lines[i].count("{") - lines[i].count("}")
        buf = [lines[i]]
        j = i + 1
        while j < len(lines) and depth > 0:
            buf.append(lines[j])
            depth += lines[j].count("{") - lines[j].count("}")
            j += 1
        blocks[name] = {"kind": kind, "body": "\n".join(buf), "line": i + 1}
        i = j
    return blocks


def refs_of(body):
    """Type names referenced from a block body, descriptions removed."""
    clean = strip_descriptions(body)
    # drop the header line so the type's own name is not a self-reference
    clean = "\n".join(clean.split("\n")[1:]) if "\n" in clean else ""
    return {n for n in TYPEREF_RE.findall(clean) if n not in BUILTIN}


def reachable_from(roots, blocks, graph):
    seen = set()
    stack = [r for r in roots if r in blocks]
    while stack:
        cur = stack.pop()
        if cur in seen:
            continue
        seen.add(cur)
        for nxt in graph.get(cur, ()):
            if nxt in blocks and nxt not in seen:
                stack.append(nxt)
    return seen


# --------------------------------------------------------------------------- #
# risk rules: (label, regex over a single field/arg line, why it matters)
# --------------------------------------------------------------------------- #
RISK_RULES = [
    ("returns_credential",
     r'\b\w*(token|secret|credential|password|api_key|apikey|signing)\w*\s*:\s*(String|ID)',
     "field value is itself a credential"),
    ("credential_type",
     r':\s*\[?\w*(Token|Secret|Credential)\w*\]?!?\s*$',
     "returns a credential-bearing type"),
    ("tenant_arg",
     r'\b(account_id|account_slug|user_id|owner_id|creator_id|service_user_id|agent_id)\s*:\s*\[?(ID|String)',
     "takes another tenant's identifier as an argument - IDOR surface"),
    ("fetch_sink",
     r'\b(callback_url|webhook_url|url|redirect_url|redirectUrl|remote_url|image_url|upload_url|public_url)\w*\s*:\s*String',
     "server-side fetch or redirect sink - SSRF / open redirect"),
    ("html_sink",
     r'\b(html|markdown|body|content|delta_format|template_html)\s*:\s*(String|JSON)',
     "rich content sink - stored XSS"),
    ("bypass_flag",
     r'\b\w*(bypass|skip|force|mock|override|as_admin|internal)\w*\s*:\s*Boolean',
     "explicit safety-check bypass flag"),
]

# descriptions that describe an auth mechanism or an admin path
DOC_RULES = [
    ("doc_auth_mechanism",
     r'(needed for authentication|requires a valid [\w-]*header|skips authorization|'
     r'without authorization|bypass|admin only|admin privileges|requires account admin)'),
    ("doc_internal",
     r'(internal (micro)?service|service-to-service|never logged|not work in the playground)'),
]


def audit_fields(blocks):
    hits = []
    for name, b in blocks.items():
        for ln, line in enumerate(b["body"].split("\n"), start=b["line"]):
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            bare = strip_descriptions(line)
            for label, rx, why in RISK_RULES:
                if re.search(rx, bare, re.I):
                    hits.append({"type": name, "line": ln, "rule": label,
                                 "why": why, "text": s[:200]})
            for label, rx in DOC_RULES:
                if re.search(rx, line, re.I):
                    hits.append({"type": name, "line": ln, "rule": label,
                                 "why": "the schema's own docs flag this",
                                 "text": s[:200]})
    return hits


def root_fields(blocks, root):
    """Top-level field names on Query/Mutation."""
    if root not in blocks:
        return set()
    out = set()
    for line in blocks[root]["body"].split("\n"):
        m = re.match(r'\s{2}([a-z_][A-Za-z0-9_]*)\s*[(:]', line)
        if m:
            out.add(m.group(1))
    return out


def guess_probe(type_name, blocks):
    """Emit a probe document for an orphaned namespace-looking type."""
    b = blocks.get(type_name)
    if not b:
        return None
    fields = []
    for line in b["body"].split("\n"):
        m = re.match(r'\s{2}([a-z_][A-Za-z0-9_]*)\s*[(:]', line)
        if m:
            fields.append(m.group(1))
    if not fields:
        return None
    snake = re.sub(r'(?<!^)(?=[A-Z])', "_", type_name).lower()
    snake = snake.replace("_queries", "").replace("_mutations", "").replace("_namespace", "")
    return {"suspected_root_field": snake, "type": type_name,
            "fields": fields[:8],
            "probe": "{ %s { __typename } }" % snake}


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("sdl", help="path to the SDL file")
    ap.add_argument("-o", "--output", default="schema-audit")
    args = ap.parse_args()

    sdl = open(args.sdl, encoding="utf-8", errors="replace").read()
    os.makedirs(args.output, exist_ok=True)

    blocks = parse_blocks(sdl)
    graph = {n: refs_of(b["body"]) for n, b in blocks.items()}

    roots = [r for r in ("Query", "Mutation", "Subscription") if r in blocks]
    live = reachable_from(roots, blocks, graph)
    orphans = sorted(set(blocks) - live)

    q, m = root_fields(blocks, "Query"), root_fields(blocks, "Mutation")

    # namespace-shaped orphans are the highest-value probes
    ns = [t for t in orphans
          if blocks[t]["kind"] == "type"
          and re.search(r'(Queries|Mutations|Namespace)$', t)]
    probes = [p for p in (guess_probe(t, blocks) for t in ns) if p]

    hits = audit_fields(blocks)
    by_rule = defaultdict(list)
    for h in hits:
        by_rule[h["rule"]].append(h)

    # ---- write out ---------------------------------------------------------
    with open(os.path.join(args.output, "orphans.txt"), "w") as fh:
        for t in orphans:
            fh.write(f"{blocks[t]['kind']:<10} {t}\n")
    with open(os.path.join(args.output, "findings.jsonl"), "w") as fh:
        for h in hits:
            fh.write(json.dumps(h) + "\n")
    with open(os.path.join(args.output, "probes.graphql"), "w") as fh:
        for p in probes:
            fh.write(f"# {p['type']} -> fields: {', '.join(p['fields'])}\n")
            fh.write(p["probe"] + "\n\n")

    rp = os.path.join(args.output, "report.md")
    with open(rp, "w") as fh:
        fh.write("# GraphQL schema audit\n\n")
        fh.write(f"- types defined: **{len(blocks)}**\n")
        fh.write(f"- reachable from Query/Mutation: **{len(live)}**\n")
        fh.write(f"- **orphaned (defined but unreachable): {len(orphans)}**\n")
        fh.write(f"- Query root fields: {len(q)} · Mutation root fields: {len(m)}\n\n")

        fh.write("## Orphaned namespaces (probe these first)\n\n")
        if probes:
            for p in probes:
                fh.write(f"### `{p['type']}`\n")
                fh.write(f"- suspected root field: `{p['suspected_root_field']}`\n")
                fh.write(f"- fields: {', '.join('`%s`' % f for f in p['fields'])}\n")
                fh.write(f"- probe: `{p['probe']}`\n\n")
        else:
            fh.write("_none found_\n\n")

        fh.write("## Risky fields\n\n")
        order = ["doc_auth_mechanism", "returns_credential", "credential_type",
                 "doc_internal", "bypass_flag", "tenant_arg", "fetch_sink", "html_sink"]
        for rule in order:
            rows = by_rule.get(rule, [])
            if not rows:
                continue
            fh.write(f"### {rule} ({len(rows)})\n\n")
            seen = set()
            for h in rows[:60]:
                key = (h["type"], h["text"])
                if key in seen:
                    continue
                seen.add(key)
                fh.write(f"- `{h['type']}` L{h['line']} — {h['text']}\n")
            if len(rows) > 60:
                fh.write(f"\n_({len(rows) - 60} more in findings.jsonl)_\n")
            fh.write("\n")

        fh.write("## All orphaned types\n\n```\n")
        for t in orphans:
            fh.write(f"{blocks[t]['kind']:<10} {t}\n")
        fh.write("```\n")

    print(f"[*] types={len(blocks)} reachable={len(live)} orphans={len(orphans)}")
    print(f"[*] risky-field hits={len(hits)}  namespace probes={len(probes)}")
    print(f"[*] report: {rp}")


if __name__ == "__main__":
    main()
