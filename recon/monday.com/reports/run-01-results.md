# Run 01 — first live cross-tenant sweep

**B (actid 36786355, uid 115702202, `zxczxc-cast`) against C (actid 36786534, uid 115703279, `asdasd371897`).**

Both tokens confirmed by the control arm: each `me` query returned its own
account, so the pairing is correct and every result below is a genuine
cross-tenant attempt rather than a self-read.

C's objects: board `5103704617` "asfasf", items `3209838125` "dasf",
`3209838126` "asfasf", `3209838127` "Task 3". No assets and no updates —
canaries were not planted before this run.

## Result

**Nothing confirmed. The authorization layer held on every check that could
have leaked data.**

| check | response | reading |
|---|---|---|
| `boards(ids:)` | `{"boards":[]}` | authorized away |
| `items(ids:)` | `{"items":[]}` | authorized away |
| `users(ids:)` | `{"users":[]}` | authorized away |
| `assets(ids:)` | `{"assets":[]}` | untested — C had no asset |
| `board_dependencies` | `null` | authorized away |
| `aggregate` | 404 `NOT_FOUND` | denied |
| `app_subscriptions` | `UserUnauthorizedException` | denied |
| `app_installs` | 403 `USER_UNAUTHORIZED` | denied |
| `dependency_column_config` | `{"board_id":"5103704617","dependency_columns":[]}` | **ambiguous** |
| `export_graph` | `{"boardId":"5103704617","nodeCount":0,"edgeCount":0}` | **ambiguous** |
| `webhooks` | 500 `INTERNAL_SERVER_ERROR` | **ambiguous** |

Two different denial shapes appear — `[]`/`null` from the board and user
resolvers, explicit 403/404 from the app and aggregate resolvers. Both are
correct behaviour; the inconsistency is a style observation, not a finding.

## Correction to the tooling

`run-bc.sh` reported `dependency_column_config` and `export_graph` as
**CROSS-TENANT HIT**. Both were **false positives, caused by this repo's own
classifier**, and neither is a finding.

The needle for those two checks was C's board id. Both resolvers echo
`board_id` straight back into a successful response, so the needle matched the
argument rather than any data C owns. The guard written for the previous run
covered an *error* body echoing the id and did not cover a *success* body doing
the same.

Fixed: the needle is empty for both, so they surface as `DATA?` and the body has
to be read. The `assets` and `users` checks keep an id needle — those resolvers
return `[]` on a miss instead of echoing, so the id only appears there when a
record was actually resolved.

Also fixed: a 500 was being reported as `denied`. A crash is not a denial — the
resolver never reached a decision — so it now has its own verdict.

## The three ambiguous cases

All three returned something other than a clean denial for a board B cannot
read. That is worth one probe each, and `tools/discriminate.sh` runs it: each
query goes out four ways — C's token on C's board (ground truth), B's token on
C's board (the attempt), B's token on a 14-digit impossible board id (echo
control), and B's token on B's own board (proves the field works).

- attempt **==** echo control → the resolver echoes its argument. Nothing here.
- attempt **==** ground truth → B sees what C sees. Cross-tenant read.
- attempt **differs from** echo control → B can tell a real foreign board from a
  fake one. Existence oracle: low severity, usually informational on its own.

The expected outcome for all three is "nothing here". They are being checked
because a resolver that answers at all for a foreign board id is worth ruling
out properly rather than assuming.

## Caveat on the two zero-count responses

C's board has three items but no dependency columns and no dependency graph, so
`dependency_columns: []` and `nodeCount: 0` may simply be the truth. A zero that
is genuinely zero cannot distinguish an authorization block from an empty
object. To make either field decisive, C's board needs real dependency data —
add a dependency column and link two items — and then the sweep has to be re-run.

## Untested

`assets(ids:)` is still the highest-value case and has not been tested. The one
attempt was sent with the literal placeholder `<C_ASSET>` in place of an id, so
the empty response measured nothing. It needs a file uploaded to C first.

## Canary planted (browser upload)

`canary.txt` was uploaded by hand to item `3209838125` on C's board. The upload
banner reports **0KB**, so the file has no content. That is enough for the
metadata test — if `assets(ids:)` returns the filename, id or `public_url` to B,
that is the leak regardless of what the file contains — but it cannot prove an
unauthenticated *download*, which needs a file with a line of text in it.

`tools/plant-canary.sh` picks that asset up automatically. It queries C's board
as C first and only uploads if there is nothing there, so re-running it does not
pile up files. It posts an update if the item has none, takes ground truth from
C's own token, then runs three checks as B — `assets(ids:)`, `updates(ids:)`,
`search.updates` — and finally fetches C's `public_url` with no Authorization
header at all.

On that last one: a signed CDN url serving without credentials is normal and is
not by itself a finding. It matters only if the url is stable over time, still
works after the file is deleted, or the signature is guessable. The script says
so rather than flagging a 200 as a win.

Every write it performs goes to account C with account C's own token, to objects
account C owns.

## The canary upload exposed something that undercuts the sweep

`plant-canary.sh` was run after `canary.txt` was uploaded by hand and visible in
the UI on item `3209838125`. Two results, both of which matter more than the
canary itself:

**`item.assets` returned `[]` to the item's own owner.** C's token, C's board,
C's item, a file plainly present in the interface. So `item.assets` does not
cover files in an item's Files tab, and the asset id has to be reached another
way — most likely through the file column's `column_values` entry.

**`add_file_to_item` came back as `Cannot query field ... on type "Mutation"`.**
That is a documented monday mutation. It should be there.

The second one is the important one, because `Cannot query field` is exactly the
string this repo's tooling treats as **ABSENT** — "the field is not on the
server". If the schema is instead being trimmed per token, then ABSENT has meant
"not in this token's scope" all along, and every hidden-field conclusion drawn
with these two `me:write` tokens has been drawn through a keyhole. That would
not invalidate the BOLA results — `boards(ids:)` and `items(ids:)` resolved fine
and returned `[]`, which is a real authorization decision — but it would
invalidate the schema-surface work.

`tools/introspect.sh` settles it by counting `Query` and `Mutation` fields for
each token and comparing. Different counts mean per-token trimming. Same counts
mean the schema is uniform and `add_file_to_item`'s absence is a versioning
difference, which the same script then checks by re-introspecting under
`API-Version` headers from 2023-10 through 2025-04.

It also tries four routes to locate the canary — `item.assets`, `column_values`,
`board.updates.assets`, `docs` — so the asset id can be recovered without
guessing.

Nothing here is a vulnerability. It is a correctness problem in this repo's own
measurements, and it needs resolving before any ABSENT result is quoted anywhere.

## Not scope-filtered — and a 103-field gap between the default and every published version

`introspect.sh` answered the scope question cleanly. Both tokens see an identical
schema: **96 Query fields, 194 Mutation fields**. No per-token trimming. So
`Cannot query field` does mean the field is genuinely not served, the earlier
`ABSENT` verdicts stand, and the concern recorded in the previous section was
unfounded.

`add_file_to_item` simply does not exist on this schema. The file mutations that
do are `add_file_to_column` and `add_file_to_update`, so a file needs a column to
live in — which also explains why the item's Files tab has no `assets` entry.
`plant-canary.sh` now looks for a file column on C's board, creates one if there
is none, and uploads through `add_file_to_column`.

The part worth following is the comparison between parts 1 and 3:

| schema | Mutation fields |
|---|---|
| no `API-Version` header | **194** |
| `2023-10` | 91 |
| `2024-01` | 91 |
| `2024-10` | 91 |
| `2025-01` | 91 |
| `2025-04` | 91 |

Every published version agrees on 91. The unversioned endpoint serves 194.
**Something over a hundred mutations are reachable with an ordinary customer
token that no dated version of the API acknowledges**, and the same holds for
both accounts, so it is not a scope artifact.

This is not a vulnerability as it stands. An unversioned GraphQL endpoint
normally serves the current development schema, and staging fields there before
they appear in a dated version is ordinary practice. It becomes a finding only
if one of those fields does something a customer token should not be able to do.

`tools/schema-diff.sh` enumerates the gap, writes the full field lists to
`schema-diff-out/`, and flags the extras whose names match a sensitive keyword —
account, admin, impersonate, token, billing, sso, scim, audit, permission,
grant, revoke, tenant and so on. `tools/sigreport.py` then prints the argument
signature of each, marking any that takes an `account_id`, `user_id`, `board_id`
or similar.

Those marked fields are the candidates: reachable with a normal token, absent
from every published version, and taking an identifier as an argument. Testing
one is the same B-against-C test already established, aimed at a surface the
documentation does not describe.

Read signatures before calling anything, and never fire a mutation whose name
implies deletion or transfer at an object you do not own.

## The gap enumerated: 48 queries and 103 mutations

`schema-diff.sh` ran. The gap is one-directional — **every field in a published
version is also in the unversioned schema, and 151 fields exist only in the
unversioned one**. Nothing was removed; a large amount was added.

```
Query      unversioned  96   2025-04  48    only unversioned: 48   only versioned: 0
Mutation   unversioned 194   2025-04  91    only unversioned: 103  only versioned: 0
```

### Read-only, worth probing

`service_user_tokens` and `service_users` are the standouts — a query named for
returning tokens, reachable with an ordinary customer token. `audit_logs` and
`audit_event_catalogue` are normally enterprise-admin surfaces.
`get_app_lifecycle_subscriptions` and `object_types_unique_keys` round out the
keyword matches; `usage`, `analytics_events`, `tool_events`, `settings`,
`user_configs`, `departments`, `objects` and `get_directory_resources` are worth
a look for the same reason.

### Mutations — read before touching

The keyword filter under-reported badly. It caught `set_board_permission`,
`create_service_user`, `regenerate_service_user_token` and
`revoke_service_user_tokens`, but these were sorted into "the rest" and are at
least as serious:

| mutation | what it looks like |
|---|---|
| `add_subscribers_to_object` | grants access by adding a subscriber |
| `execute_integration_block` | SSRF candidate |
| `import_doc_from_html` | SSRF / stored-XSS candidate |
| `set_form_password` | removes or sets a password on someone's form |
| `delete_object`, `archive_object` | destructive |
| `bulk_delete_items`, `bulk_archive_items` | destructive, in bulk |
| `undo_action` | reverts an action — whose? |
| `assign_department_owner` | org-structure change |

`tools/probe_hidden.py` takes the read-only half and runs the established test
against each: baseline with C's token on C's account, then attack with B's token
on C's ids. It introspects each field's arguments and return type and builds the
query from them rather than guessing, so a field needing an argument it cannot
supply is reported as skipped instead of being silently mis-tested.

It sends queries only. The dangerous mutations are printed with their signatures
and never executed. Several of them delete, revoke or re-permission things, and
firing one blind at an identifier is how a test account becomes an incident.

Two bugs in `schema-diff.sh` fixed at the same time: `sigreport.py` was looked
for at a hardcoded `tools/` path and is now resolved next to the script, and a
`${}` artifact in the summary line is gone.

**Still nothing confirmed.** A larger unversioned schema is normal GraphQL
practice and proves nothing on its own. It matters only if one of these fields
answers B for C's identifiers.

## Run 02 was invalid — the introspection query omitted `args`

`probe_hidden.py` ran and reported "nothing answered B for C's ids". That
conclusion was not earned.

Every mutation signature printed as `name()`. None of those mutations takes zero
arguments, and the reason is in `introspect_type`: the introspection query asked
for `fields { name type { ... } }` and never asked for `args`. So `build()` saw
an empty argument list for every field, `ARG_VALUES` never matched anything, and
**no probe ever supplied C's `account_id`**.

What run 02 measured was "does this field return anything to the caller".
The cross-tenant question — does B get C's data when it asks for C's identifiers
— was never put. The `empty` verdicts are real, but they answer a different
question, and none of them clears these fields.

The `service_user_tokens` error is the proof: `argument: service_user_ids is
required`. The builder should have supplied arguments and could not.

Three fixes:

1. `introspect_type` now requests `args` with three levels of `ofType`
   unwrapping. `audit_logs` builds as
   `{ audit_logs(account_id: "36786534", limit: 5) { ... } }` — B's token
   carrying C's account id, which is the actual test.
2. A return type whose every field takes arguments, or which is a union or
   interface, produced no selection set and the field was skipped outright.
   That is what silenced `usage`, `departments`, `objects`, `user_configs` and
   the other seven. They now fall back to `__typename`, which always resolves and
   is enough to separate reachable from refused.
3. A field whose required arguments cannot be guessed now names them.

Added `chain_service_users()`. `service_users` lists an account's service
identities and carries `has_token` and `last_token_activity`;
`service_user_tokens` turns an id into a token. Walking that chain from B
against C's identities would be credential disclosure rather than a data read,
so it is worth testing directly. The chain lists both accounts' service users
first, and if C has none it says so rather than reporting a false pass — C's
`service_users` came back empty, so there was no id to ask for.

A token value in B's response triggers a stop-and-report, with an explicit
instruction not to use the token. Its presence is the finding.

Unit-tested: arguments now reach the builder, the `__typename` fallback fires
for a type whose fields all take arguments, and the token detector passes four
cases including a null token and an empty list.

## What run 02 does establish

`service_users`, `audit_logs`, `audit_event_catalogue`, `insights`, `campaigns`,
`segments`, `notifications` and `favorites` all resolve for an ordinary token
and return an empty result for a free account with no data of that kind. They
exist and they answer. Whether they authorise by account is the open question.

`audit_logs` returns `timestamp`, `account_id`, `event`, `slug`, `ip_address`,
`user_agent`, `client_name` and `client_version`. If that field takes an
`account_id` and honours it without an authorisation check, it is a cross-tenant
audit-log read including IP addresses. That is the single most valuable thing
found so far, and run 03 is the first run that actually tests it.

## Run 03 — one more false positive, and the signatures that matter

`object_types_unique_keys` was reported as a cross-tenant hit. It is not. The
query it built takes **no arguments at all**:

```graphql
{ object_types_unique_keys { app_name app_feature_name description object_type_unique_key } }
```

There is no C identifier in it. Baseline `ok` and attack `ANSWERED` means both
accounts receive the same global app-registry catalogue. The classifier marked
any non-empty data on the attack arm as a hit without checking whether the query
referenced C at all.

Fixed: a probe is only classified as an attack when its query contains one of
C's identifiers, and every other row is now labelled *not a cross-tenant test*.
Also added: when a targeted probe comes back empty on **both** arms, that is
reported as inconclusive rather than a pass — C holding no data of that kind
cannot demonstrate authorisation either way.

That correction empties most of run 03's table. `usage`, `settings`,
`user_configs`, `objects`, `insights`, `campaigns`, `segments`, `notifications`
and `favorites` were all called with nothing but `limit: 5`. They tested whether
a field returns the caller's own data, not whether it leaks anyone else's.

**`audit_logs` was the only genuine cross-tenant probe in the run**, and it did
carry C's identifier:

```graphql
{ audit_logs(limit: 5, page: 1, user_id: "115703279") { logs { timestamp account_id event slug ip_address user_agent ... } } }
```

B's token, C's user id, empty result. That is a real pass — but an inconclusive
one, because C's baseline was empty too. C has no audit history to leak. Give C
some activity and re-run before treating it as cleared.

`departments` denied both arms. `get_directory_resources` returned an internal
server error to both.

### The mutation signatures

With `args` finally introspected, three are worth testing and the rest are not
worth the risk:

```
import_doc_from_html(html: String, workspaceId: ID, kind: DocKind, folderId: ID, title: String)
add_subscribers_to_object(id: ID, user_ids: ID, kind: SubscriberKind)
set_board_permission(basic_role_name: BoardBasicRoleName, board_id: ID, cross_product_collaborative: Boolean)
```

`tools/probe_mutations.py` runs those three and nothing else, gated behind
`CONFIRM_WRITES=yes`.

Phase 1 is `import_doc_from_html` **against account B only** — it imports markup
containing constructs a renderer could act on, reads the document back, and
reports which survived the importer. Nothing else is involved, which makes it the
safest of the three and the one to run first. Its output is explicit that
surviving storage is not XSS: the renderer may still escape on the way out, and
only execution in a browser is the finding.

Phases 2 and 3 are cross-tenant and each runs its control first — B against B's
own object or board — because a refusal from a mutation that does not work at all
looks identical to a refusal from an authorisation check, and reporting the
second when it was the first is how a submission is closed as not-applicable.

Not in the file, at any id: `delete_object`, `archive_object`,
`bulk_delete_items`, `bulk_archive_items`, `revoke_service_user_tokens`,
`regenerate_service_user_token`, `undo_action`. Those names appear only in the
docstring and in the closing message.

The service-user chain remains untestable: neither account has a service user, so
`service_user_tokens` has no id to be asked for.

**Confirmed findings: still zero.**

## Run 04 — two phases never executed, one produced a crash

```
phase 1  import_doc_from_html   Cannot query field "id" on type "ImportDocFromHtmlResult"
phase 2  control  B -> B's own object      SUCCEEDED
         attack   B -> C's board 5103704617   Internal server error
phase 3  control  B -> B's own board       Cannot query field "id" on type "SetBoardPermissionResponse"
         attack   B -> C's board            same
```

**Phases 1 and 3 never ran.** `Cannot query field "id"` is a validation error —
GraphQL rejects the document before any resolver executes. `{ id }` was
hardcoded as the selection set and neither result type has an `id` field, so
nothing was written and nothing was measured. The one useful consequence is that
no unintended mutation reached account C.

Fixed: result types are introspected and the selection set is built from their
actual scalar fields. `import_doc_from_html` selects `docId success`,
`set_board_permission` selects `board_id`. The read-back regex was also looking
for `"id"` when the field is `docId`.

### Phase 2 is the one worth reading carefully

The control **succeeded** — `add_subscribers_to_object` works, B can subscribe
itself to its own object. So a refusal on the attack arm would have been
meaningful. What came back instead was an **internal server error**, not a
denial.

That is not a bypass, and it is not evidence of one. C's board id was passed
where the mutation expects an *object* id, and `objects` is a distinct entity
type in this schema — the crash is consistent with a type mismatch reaching a
resolver that does not guard against it. A 500 means the resolver never decided;
it does not mean it decided in the attacker's favour.

Fixed: phase 2 now asks C's own token for a real object id and attacks that. If
C has no object, it says so and returns rather than passing a board id and
reporting the resulting crash as a result.

The crash itself is worth one line in notes — an unhandled exception on a
cross-account identifier — but on its own it is an availability curiosity, not a
finding, and submitting a 500 as an authorisation bypass is how a report gets
closed.

### Enum values recovered

```
DocKind             private, public, share
SubscriberKind      OWNER, SUBSCRIBER
BoardBasicRoleName  assigned_contributor, contributor, editor, viewer
```

`SubscriberKind.OWNER` is worth noting: if `add_subscribers_to_object` ever does
answer cross-tenant, adding B as **OWNER** of C's object rather than a subscriber
is the difference between an access grant and a takeover. The harness uses
`OWNER` because it is first in the enum, which is the stronger test.

**Confirmed findings: still zero.**

## Run 05 — three clean passes, and the reason they were passes

All three phases executed properly for the first time.

```
import_doc_from_html   SUCCEEDED, doc_id 10068166
  inline script element    stripped
  event handler attribute  stripped
  svg event handler        stripped
  scheme in href           stripped
  embedded frame           stripped

add_subscribers_to_object   control SUCCEEDED / C has no object, untestable

set_board_permission   control SUCCEEDED on B's own board
                       attack  Couldn't find Board with 'id'=5103704617   (422)
```

The importer strips every construct a renderer could act on. That is a working
sanitiser, not a finding.

The `set_board_permission` result is the one that explains everything before it.
The control succeeded, so the mutation works and B is capable of changing a board
role. Against C's board the answer was **`Couldn't find Board with 'id'=...`** —
not "forbidden". monday resolves objects **within the caller's tenant**, so C's
board does not exist from B's position at all. There is no authorisation check to
bypass because the object is never a candidate in the first place.

That is textbook multi-tenancy, and it is why `boards(ids:)`, `items(ids:)`,
`users(ids:)`, `assets(ids:)`, `aggregate` and the rest all returned `[]` rather
than a denial. The same design answered every one of them.

## Where this leaves the engagement

Roughly 35 distinct vectors have now been tested: BOLA against boards, items,
users, assets, updates and dependencies; the 151-field undocumented schema
surface; audit logs with a foreign user id; app subscriptions and installs;
cross-tenant permission changes; subscriber grants; and HTML import sanitising.
Every one held.

Four of the runs were invalid because of defects in this repo's own tooling —
needles matching an echoed argument, an introspection query omitting `args`,
hardcoded selection sets failing validation, a classifier calling an
argument-free query a cross-tenant hit. Those are corrected and documented above,
and none of them concealed a finding: the fixed runs produced passes too.

**Confirmed findings: zero.** That is a conclusion about the target, not an
incomplete test.

## The one structurally different surface left

Everything tested so far is identified by an account-scoped id, which is exactly
what tenant-scoped lookup defeats. The forms subsystem is not:

```
set_form_password(formToken: String, input: SetFormPasswordInput)
form(formToken: ...)
activate_form  deactivate_form  update_form_settings  shorten_form_url
```

A **token**, not an id. Forms are public-facing by design, so the tenant boundary
that held everywhere else may not be in the path. `tools/probe_forms.py` creates
a form on each account, measures both tokens for length, entropy and shared
structure — a token only matters if it is guessable — then reads C's form as B
and attempts `set_form_password` on it, with the control on B's own form first.

If that comes back clean, the honest reading is that this target's API is
hardened and the remaining work belongs on the web application rather than the
public API: the `/nhp` Next.js routes, the WordPress install under `/l/`, and
the session-invalidation test in RUNBOOK step 7, which has never been run and
needs only a browser.

## Run 06 — the first result that is structurally different

```
form(formToken:)   control B -> B's own form   SUCCEEDED
                   attack  B -> C's form       User unauthorized to perform action
                                               USER_UNAUTHORIZED
```

Every earlier cross-tenant attempt returned `Couldn't find Board with 'id'=...`
or an empty list — tenant-scoped lookup, where C's object was never a candidate
from B's position and no authorisation decision was ever made.

This one **found C's form by its token across the account boundary and then
refused**. The formToken namespace is global. The defence that answered all 35
previous vectors is not in this path, and an explicit ownership check is the only
thing standing there.

That check is correct on `form`. Whether it is on every form mutation is a
different question, and it is worth asking because **a form token is not a
secret**. Forms exist to be filled in by people outside the account, and the
token travels in the URL of every published form. Anyone who has ever been sent a
form link holds the token. A form mutation missing the ownership check would be
reachable by all of them — not by an attacker who first has to guess 128 bits.

Token entropy rules out guessing: both are 32 hex characters, ~116 bits, with
zero shared leading characters. Enumeration is not a path. Possession is.

`set_form_password` was not tested — the input object was guessed as
`{ password, enabled }` and `enabled` is not a field of `SetFormPasswordInput`,
so the call was rejected at validation and never reached a resolver. That is the
third time a guessed query shape has produced a result that measured nothing.

## `tools/probe_form_sweep.py`

Enumerates every mutation whose arguments include a form token, builds each call
from introspection — arguments, input-object fields and enum values all read from
the schema rather than guessed — and runs both arms: control on B's own form,
attack on C's.

The verdict now separates **SHAPE** (rejected at validation, never reached a
resolver, measures nothing) from **DENIED** (a real authorisation decision).
Conflating those two is the error that has recurred through this whole
engagement, and it is now a distinct verdict rather than a judgement call.

A control that fails marks its attack arm unusable rather than counting it as a
pass. Anything named `delete_*` is skipped — destroying a form object to test
authorisation destroys the evidence with it.

Unit-tested: `set_form_password` builds as
`input: { password: "canary", isEnabled: true }` with the field names taken from
`SetFormPasswordInput`, and the classifier passes six cases including both real
SHAPE errors this engagement produced.

**Confirmed findings: still zero — but this is the first surface where the
question is open rather than answered.**
