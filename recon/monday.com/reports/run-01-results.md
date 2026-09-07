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
