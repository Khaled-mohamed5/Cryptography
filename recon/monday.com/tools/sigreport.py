#!/usr/bin/env python3
"""Print signatures for the fields that exist only without an API-Version header.

Reads what schema-diff.sh collected:
  <out>/only-unversioned.<Query|Mutation>.txt   the field names
  <out>/args.<Query|Mutation>.json              introspected args for that type

A field whose arguments include an account_id or user_id is the interesting
case: reachable with an ordinary token, and absent from every published version.
"""
import json, os, re, sys

out, risk = sys.argv[1], sys.argv[2]
RED, DIM, RST = "\033[31m", "\033[2m", "\033[0m"


def typename(t):
    if not t:
        return "?"
    return t.get("name") or typename(t.get("ofType")) or t.get("kind", "?")


ID_ARG = re.compile(r"(account|user|board|item|asset|update|team|workspace|doc)_?id", re.I)

takes_id, other = [], []
for tname in ("Query", "Mutation"):
    names_path = os.path.join(out, f"only-unversioned.{tname}.txt")
    args_path = os.path.join(out, f"args.{tname}.json")
    if not (os.path.exists(names_path) and os.path.exists(args_path)):
        continue
    want = {l.strip() for l in open(names_path) if l.strip()}
    try:
        fields = json.load(open(args_path))["data"]["__type"]["fields"]
    except Exception:
        continue
    for f in fields:
        if f["name"] not in want or not re.search(risk, f["name"], re.I):
            continue
        args = ", ".join(
            f"{a['name']}: {typename(a.get('type'))}" for a in (f.get("args") or [])
        )
        line = f"  {tname}.{f['name']}({args})"
        (takes_id if ID_ARG.search(args) else other).append(line)

for line in takes_id:
    print(f"{RED}{line}   <-- takes an id{RST}")
for line in other:
    print(f"{DIM}{line}{RST}")
if not takes_id and not other:
    print("  none resolved")
