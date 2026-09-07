# monday.com — final assessment

**Result: no submittable vulnerability found in the GraphQL API.**

Two accounts under the operator's control, B (`36786355`) attacking C
(`36786534`), across six runs and roughly forty-four distinct vectors. Every one
was refused. This is a conclusion about the target, not an unfinished test.

Do not submit anything from this. There is nothing here that survives triage.

---

## Why everything failed, in one sentence

monday resolves objects **inside the caller's tenant**, so an identifier from
another account is not a candidate to be authorised or refused — it does not
exist.

```
set_board_permission   control B → B's own board   SUCCEEDED
                       attack  B → C's board       Couldn't find Board with 'id'=5103704617
```

The control proves B can change a board role. The attack does not say
"forbidden"; it says the board is not there. That single design answered
`boards(ids:)`, `items(ids:)`, `users(ids:)`, `assets(ids:)`,
`board_dependencies`, `aggregate`, `app_subscriptions`, `app_installs` and every
other id-addressed probe. Retrying that shape in new clothing was never going to
produce a finding.

## What was tested

| surface | result |
|---|---|
| BOLA — boards, items, users, assets, updates, dependencies | `[]` — tenant-scoped |
| `aggregate`, `app_subscriptions`, `app_installs` | 404 / 403 |
| `dependency_column_config`, `export_graph` | echo the argument, no data |
| `webhooks` on a foreign board | 500 — a crash, not a decision |
| 48 undocumented Query fields | resolve, return nothing of C's |
| `audit_logs(user_id: <C's>)` | empty — pass, but C has no audit history |
| 103 undocumented Mutation fields | signatures read, three tested |
| `import_doc_from_html` | strips script, event handlers, `javascript:`, iframes |
| `add_subscribers_to_object` | control OK, C has no object to attack |
| `set_board_permission` | control OK, attack: board not found |
| 9 form-token mutations | control OK, attack DENIED — all nine |
| session cookies after logout | **never tested** |

## The one genuinely interesting observation

`form(formToken:)` behaved unlike everything else:

```
control B → B's own form   SUCCEEDED
attack  B → C's form       User unauthorized to perform action
```

**Found, then refused.** The formToken namespace is global — tenant scoping is
not in that path, and an explicit ownership check is the only thing standing
there. That made it the one surface where the question was open rather than
answered by architecture.

It is answered now. All nine form mutations refuse cross-account. Five of them
gave the strongest evidence in the engagement: the control errored on call shape
while the attack returned DENIED, which only happens if **ownership is checked
before input validation**. That is the correct order and it is deliberate.

Worth recording for future work, not for a report: form tokens are 32 hex
characters, ~116 bits, no shared structure. Not enumerable. The risk model for
forms is possession of a shared link, and monday guards it.

## Six runs, four of them invalid

Four runs produced conclusions that were not earned, all from defects in this
repo's tooling rather than anything monday did:

1. Needles matched an **echoed argument** — `dependency_column_config` and
   `export_graph` return `board_id` because you passed it in.
2. The introspection query **omitted `args`**, so no probe ever carried C's
   `account_id`. The run measured "does this field answer me", not the
   cross-tenant question.
3. Selection sets were **hardcoded to `{ id }`** on result types that have no
   `id`. Rejected at validation, never reached a resolver, measured nothing.
4. A classifier called an **argument-free query** a cross-tenant hit —
   `object_types_unique_keys` is a public app catalogue.

Plus `create_form` called with `board_id` when it wants
`destination_workspace_id`, and `set_form_password` with a guessed input field.

The recurring error is one thing: **a query rejected before a resolver runs
measures nothing, and reporting it as a negative result is worse than not
running it.** `probe_form_sweep.py` now carries `SHAPE` as a distinct verdict so
that mistake is structural rather than a judgement call.

None of the four was concealing a finding. Every corrected run passed too.

## What is actually left

**One test, five minutes, browser only.** It has been in RUNBOOK step 7 since the
beginning and has never been run:

The session JWT carries **no `exp` claim** (recorded in `data/targets.md`, and
verifiable by decoding a cookie already in hand). Whether that matters depends
on server-side enforcement:

1. DevTools → Application → Cookies on account B
2. Copy `dapulse_session` and `jwt_session_token`
3. Log out
4. Replay a request with the saved cookies

Still 200 → session invalidation is broken, and that is a finding on its own
with no second account, no BOLA and no schema work behind it. Rejected → the
missing claim is cosmetic and this target is closed.

Second variant, no effort: leave a session untouched for a week and replay it.
Still valid → no idle timeout.

## After that

The API is hardened. The surfaces never touched are the web application, which
is where the original crawl actually pointed:

- `/nhp` — 93 Next.js chunks, `_buildManifest.js`, `/_next/data/<buildId>/`
- `/l/` — a WordPress install, a different codebase with a different history
- Webflow marketing pages
- `tools/webidor.sh` — written for `/users/<id>/user_profile`, never run

Realistically: monday runs a mature programme and hundreds of researchers have
walked this API. Finding BOLA in `boards(ids:)` was never likely. The value in
what is here is the method and the tooling, both of which transfer to a target
that has had less attention.

## Housekeeping

Both API tokens are `me:write` with **no expiry**. Revoke them (avatar →
Developer → My Access Tokens), log out of both accounts, and delete
`.cookies-a` / `.cookies-b`.

Test artefacts left on the accounts: several forms named `sweep-form-*` and
`canary-form-*`, a document titled `DOCCANARY*` on account B, a file column on
C's board, and `canary.txt`. Harmless, but tidy them up.
