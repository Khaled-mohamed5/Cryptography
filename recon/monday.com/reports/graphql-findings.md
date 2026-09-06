# monday.com GraphQL — findings from the published SDL

Source: `https://api.monday.com/v2/get_schema?format=sdl` (fetched by the user, BUG-03).
This is a **federated supergraph** SDL — the roots are labelled "Root query/mutation type
for the Dependencies service", but the merged document carries types from every subgraph.

Everything below is derived from reading the schema. **None of it is tested.** Each item
says what to send and what result would confirm it.

**Testing needs an API token.** Get one from a free account: avatar → Developer →
My Access Tokens. Send it as `Authorization: <token>` to `https://api.monday.com/v2`.
For anything marked *cross-tenant*, you need **two accounts** — token A, target B.

---

# TIER A — the schema documents its own weaknesses

These five are not inference. The schema's own descriptions say the dangerous part out loud.

## GQL-01 — `dependency_column_config` authenticates from user-supplied arguments

**Severity:** Critical if the resolver trusts them · **Confidence:** the schema says it plainly

```graphql
dependency_column_config(
  board_id: ID!,
  account_id: ID!,   # "The account ID (needed for authentication)"
  user_id: ID!       # "The user ID (needed for authentication)"
): DependencyColumnConfigResult
```

**Why this matters.** Authentication is supposed to come from the session or token. Here the
caller *passes in* the account and user they are authenticating as. If the resolver uses these
arguments rather than cross-checking them against the token's real identity, then supplying
another tenant's `account_id` reads that tenant's board configuration. This is the textbook
shape of broken authentication, and it is the single most promising item in the schema.

**Test** — with account A's token, pass account B's IDs:

```bash
curl -s https://api.monday.com/v2 -H "Authorization: $TOKEN_A" \
  -H 'Content-Type: application/json' -d '{"query":"{
    dependency_column_config(board_id: \"<B_BOARD>\", account_id: \"<B_ACCOUNT>\", user_id: \"<B_USER>\") {
      board_id dependency_columns { id account_id board_id data }
    } }"}'
```

**Confirmed if:** it returns config for a board you do not own. Also try your *own* board id
with someone else's `account_id`/`user_id` — a mismatch that still succeeds proves the
arguments are not validated against the token.

## GQL-02 — `service_user_tokens` is a query that returns API tokens

**Severity:** Critical if under-authorised · **Confidence:** the schema says it plainly

```graphql
service_user_tokens(service_user_ids: [ID!]!): [ServiceUserToken!]

type ServiceUserToken { service_user_id: ID   token: String }   # "The API token."
```

**Why this matters.** A read query whose return value *is* a credential. The only thing
standing between a caller and other service users' API tokens is the resolver's authorisation
check on the `service_user_ids` array. Arrays of IDs are exactly where per-element
authorisation gets missed — the check is often written against the *caller*, not against each
requested ID.

Three mutations sit next to it and compound the surface, all taking a bare
`service_user_id: ID!`:

```graphql
create_service_user(name: String!, title: String): CreateServiceUserResult
regenerate_service_user_token(service_user_id: ID!): String   # returns the new token
revoke_service_user_tokens(service_user_id: ID!): Boolean     # DoS an integration
```

**Test.** `{ service_users { id name has_token } }` to enumerate, then
`{ service_user_tokens(service_user_ids: ["<id>"]) { token } }` — first as a **non-admin
member** of your own account, then with an id from another account.

**Confirmed if:** a non-admin gets a token back, or any cross-account id resolves.
`regenerate_service_user_token` against an id you do not own is the same bug with a write.

## GQL-03 — `export_events` documents an internal auth header

**Severity:** High · **Confidence:** the schema says it plainly

> "Export events for a board within a date range. **Requires a valid X-Tool-Execution-Secret header.**"

**Why this matters.** A shared-secret header, named in the public schema, on a query that dumps
board events with `limit` up to 1000 and `offset` paging. Naming it tells an attacker exactly
what to hunt for in JS bundles, CI logs, and app configs. Worth checking: does the resolver
*require* it, or does it fall back to normal auth when the header is absent?

**Test:** call `export_events(board_id: "<yours>", limit: 1)` with a normal token and **no**
header. **Confirmed if:** it returns data — the documented gate is not enforced.

## GQL-04 — `ActivityLogInternalQueries.logs` — "skips authorization"

**Severity:** Critical if reachable · **Confidence:** the schema says it plainly

```graphql
type ActivityLogInternalQueries {
  "Internal activity log entries for boards or users — skips authorization,
   entity whitelisting, and always includes boardless events"
  logs(board_ids: [ID!], user_ids: [ID!], ...): ActivityLogsPage
  event_counts(group_by: ActivityGroupBy!, ...): EventCountsResult
}
```

**Why this matters.** A type whose documented purpose is to bypass authorisation, shipped in
the schema served to the public internet. It is **not reachable** from `Query` (see GQL-05) —
which is the point: it exists, and the only thing hiding it is the absence of a root field.

**Test:** try the field names a Rails/GraphQL codebase would use:

```graphql
{ activity_log_internal { logs(board_ids: ["<not yours>"]) { logs { id event data } } } }
{ activity_logs_internal { logs(board_ids: ["<not yours>"]) { logs { id event } } } }
{ internal_activity_log { logs(board_ids: ["<not yours>"]) { logs { id event } } } }
```

**Confirmed if:** any resolves. A `Cannot query field "x" on type "Query"` error is a clean
negative; **"Field must have selections"** or a permissions error means the field *exists*.

## GQL-05 — the SDL hides whole namespaces that exist at runtime

**Severity:** High (this is the finding that unlocks the others) · **Confidence:** structural

Many types are fully defined but **unreachable from `Query`/`Mutation`**. On a federated
supergraph that is the fingerprint of root fields stripped from the published SDL while the
resolvers stay live. Undocumented surface is where authorisation gaps survive, because nobody
tests what nobody can see.

| Orphaned namespace | What it would expose |
|---|---|
| `VibeQueries` / `VibeMutations` | AI app builder: `apps(as_admin: Boolean)`, `chat_messages`, `code_files`, `ai_actions(systemPrompt:)`, `assets` |
| `ActivityLogInternalQueries` | GQL-04 |
| `ActivityLogQueries` | account-wide activity logs |
| `Intelligence` | `relevant_boards`, `relevant_docs`, `relevant_people`, `context { user { email } }`, `assigned_boards(user_id:)` |
| `LookupNamespace` | `boards(query:)` lookup by name |
| Magic Solution (`CreateMagicSolutionPayload`, `InternalCallbackInput`) | see GQL-08 |
| `MyTasksResponse`, `ProcessEventsInput` | task engine, takes `account_id`+`user_id` as inputs |
| `UserPermits`, `CreateApiUserResult`, `CreateMultipleUsersResult` | user creation and permission introspection |
| `AutomationsPage`, `BoardAutomationCreateInput` | board automation CRUD |
| `RunPromptResult` / `RunPromptConfigInput` | raw LLM access with `system_prompt` |
| `SnapshottableWorkspace`, migration types | tenant snapshot / restore |
| `ExportResult` / `ExportOptionsInput` | board export to XLSX/CSV |

**The sharpest one:** `SearchNamespace` publicly exposes only `items`, `boards`, `docs`,
`workspaces` — but the schema also defines `SearchUpdateResults`, `SearchUserResults`,
`SearchMeetingResults`, `SearchOverviewResults`, `SearchTimelineItemResults`, plus
`MeetingSearchAccess`, `MeetingSearchFieldsInput`, `PersonsInput`, `BoostConfigurationInput`,
`RerankingStrategy`, and `Search { LEXICAL SEMANTIC HYBRID }`.

So there are hidden search fields over **updates** (private comments), **users** (emails),
**meetings** (`summary`, `talking_points`, `action_points`, `attendee_emails`, transcripts) and
**timeline items** (email `from`/`to`/`cc`/`bcc`). A search index is the classic place for a
missing tenant filter, and these are the highest-value corpora on the platform.

**Test — one request each:**

```graphql
{ search { updates(query: "password")  { results { id indexed_data { body board_id } } } } }
{ search { users(query: "a")           { results { indexed_data { name email } } } } }
{ search { meetings(query: "a")        { results { indexed_data { title summary attendee_emails } } } } }
{ search { timeline_items(query: "a")  { results { indexed_data { content title } } } } }
{ search { overviews(query: "a")       { results { indexed_data { name } } } } }
{ vibe { apps(as_admin: true) { id name } } }
{ intelligence { context { user { email } account { name } } } }
{ lookup { boards(query: "a") { results { id } } } }
```

**Read the errors carefully.** `Cannot query field` = absent. Anything else — a type error, an
argument error, a permission denial — means **the field exists** and you have found hidden
surface. Then check whether results cross the tenant boundary.

---

# TIER B — strong, conventional bugs

## GQL-06 — `update_custom_agent`: optional `agent_id` → agent takeover

**Severity:** High · **Confidence:** strong inference

```graphql
input UpdateCustomAgentInput {
  "The ID of the custom agent to update. Optional when the agent updates itself
   (inferred from the calling agent identity)."
  agent_id: ID
  callback_url: String   # "New HTTPS callback URL for agent event notifications."
}

type UpdateCustomAgentPayload {
  success: Boolean
  "new secret used to sign callback requests, returned when a callback_url is set/updated"
  signing_secret: String
}
```

**Why this matters.** An ID that is *optional because it is normally inferred* is the classic
IDOR: the resolver has a happy path that ignores it, so the explicit path often skips the
ownership check. And the payoff is unusually good — repointing another agent's `callback_url`
at your server hijacks its event stream, **and the mutation hands you the new `signing_secret`**,
so you can also sign valid requests.

**Test:** call it with an explicit `agent_id` belonging to another agent (or another account).
**Confirmed if:** `success: true` or a `signing_secret` comes back.

## GQL-07 — user administration: domain change + confirmation bypass

**Severity:** High · **Confidence:** needs a non-admin test

```graphql
update_email_domain(input: UpdateEmailDomainAttributesInput!): UpdateEmailDomainResult
  # UpdateEmailDomainAttributesInput { user_ids: [ID!]!  new_domain: String! }

update_multiple_users(
  user_updates: [UserUpdateInput!]!,        # UserAttributesInput includes `email`
  bypass_confirmation_for_claimed_domains: Boolean,
  use_async_mode: Boolean                   # "can handle more than 200 users at once"
): UpdateUserAttributesResult

update_users_role(user_ids: [ID!]!, new_role: BaseRoleName, role_id: ID)
activate_users / deactivate_users(user_ids: [ID!]!)
```

**Why this matters.** Changing a user's email is an account-takeover primitive: point it at a
domain you control, then run password reset. `bypass_confirmation_for_claimed_domains` is,
by its own name, a switch that removes the confirmation step. `update_users_role` with
`new_role: ADMIN` is straight privilege escalation. The error enums say a lot about what *is*
checked — `CANNOT_UPDATE_SELF`, `EXCEEDS_BATCH_LIMIT` — and self-protection without a
corresponding others-protection is a familiar pattern.

**Test as a plain MEMBER, not an admin:** try `update_users_role(user_ids: ["<self>"],
new_role: ADMIN)`, then against another user. Then `update_email_domain` for a user who is
not you. **Confirmed if:** any succeeds without admin rights.

## GQL-08 — `InternalCallbackInput` — an internal-SSRF shaped input

**Severity:** High if reachable · **Confidence:** the type exists; the mutation is hidden

```graphql
"Configuration for internal microservice callback. Used for service-to-service communication."
input InternalCallbackInput {
  service_name: String!   # "The name of the internal Monday service to call."
  path: String!           # "The path/endpoint on the service to call."
}
input ModifyMagicSolutionInternalCallbackInput { service_name: String!  path: String! }
```

**Why this matters.** This is not a URL allow-list — it is a service name and a free-form path,
handed to the backend to call *internal* services. If the mutation that consumes it
(`create_magic_solution` / `modify_magic_solution`, both orphaned per GQL-05) accepts
user-controlled values, that is SSRF straight into the internal service mesh. Alongside it:

```graphql
input MagicSolutionFileInput { url: String!  ... }   # "HTTPS URL of the file to attach."
```
— a server-side fetch of an attacker-supplied URL, the ordinary SSRF sink.

**Test:** first find the mutation (`create_magic_solution`, `magic_solution_create`), then
whether `internal_callback` is accepted with an arbitrary `service_name`/`path`.

## GQL-09 — billing: mocked subscriptions and arbitrary discounts

**Severity:** Medium–High (payment bypass class) · **Confidence:** untested

```graphql
set_mock_app_subscription(
  app_id: ID!,
  partial_signing_secret: String!,   # "The last 10 characters of the app's signing secret."
  plan_id: String, max_units: Int, is_trial: Boolean, renewal_date: Date
): AppSubscription

grant_marketplace_app_discount(app_id: ID!, account_slug: String!, data: GrantMarketplaceAppDiscountData!)
create_marketplace_app_discount(app_id: ID!, account_slug: String!, discount_data: ...)
batch_extend_trial_period(account_slugs: [String!]!, app_id: ID!, duration_in_days: Int!, plan_id: String!)
```

**Why this matters.** Three separate angles:

1. `set_mock_app_subscription` is a **dev facility exposed in the production schema**. Its only
   gate is knowledge of the *last 10 characters* of a signing secret — a partial-secret check,
   which is weaker than it looks and is the sort of thing that gets compared with `==` and no
   rate limit. If mocked subscriptions drive real entitlement, this is paid features for free.
2. `grant_marketplace_app_discount` takes an arbitrary `account_slug` and a `discount: Int!`
   with **no documented maximum**. Try `discount: 100` on an account that is not yours; try
   values above 100 and negative values.
3. `batch_extend_trial_period` takes up to 5 arbitrary `account_slugs` and up to 365 days.

**Test:** the discount mutations against another account's slug (slugs are public — they are in
every monday URL). **Confirmed if:** it applies to an account you have no relationship with.

## GQL-10 — `User.encrypt_api_token` — a per-user credential on a queryable type

**Severity:** Medium–High · **Confidence:** untested

```graphql
"The token of the user for email to board."
encrypt_api_token: String @deprecated(reason: "... will be removed in later versions.")
```

Deprecated is not removed, and `users(...)` returns up to **1000 users per page**. If this
field is not separately authorised, one query harvests a token for every user in the account.

**Test:**
```graphql
{ users(limit: 50) { id name email encrypt_api_token } }
```
as a **non-admin member**, then via `boards { subscribers { encrypt_api_token } }` — nested
paths frequently miss the check the top-level field has. **Confirmed if:** you get any token
that is not your own.

---

# TIER C — worth a pass, lower expected payout

- **SSRF sinks (~12).** `create_webhook(url:)`, `create_project(callback_url:)`,
  `create_portfolio(callback_url:)`, `connect_project_to_portfolio(callback_url:)`,
  `convert_board_to_project`, `use_template(callback_url_on_complete:)`,
  `create_app(webhook_url:)`, `LifecycleEventInput.webhook_url`,
  `ConnectCustomAgentInput.callback_url` / `avatar_url`, `MagicSolutionFileInput.url`,
  `UpdateUserProfilePictureInput.photo_url`. Standard drill: `169.254.169.254`, `localhost`,
  DNS rebinding, redirect-to-internal. The `avatar_url` and `photo_url` ones are the best
  candidates — image fetchers follow redirects more often than webhook senders do.
- **Stored XSS.** `import_doc_from_html(html: String!)`, `create_update(body:)` ("html
  formatted body"), `update_article_block(content: JSON!)`, `create_doc_block(content: JSON!)`,
  `AttributesInput.link` (a URL inside rich text → `javascript:`),
  `CampaignsEmailCampaign.template_html`.
- **Alias-based rate-limit bypass.** `complexity { before after query reset_in_x_seconds }` is
  exposed on both roots — it tells you your own budget, which makes it easy to test whether
  aliasing one field N times is counted once or N times.
- **`audit_logs`** returns IP addresses, user agents, device names. Check it is admin-only —
  call it as a plain member.
- **`ask_developer_docs(query:)`** and **`knowledge_base_search`** — LLM-backed, so prompt
  injection and the usual "make it repeat its instructions" probing.
- **`aggregate(query: AggregateQueryInput!)`** — a SQL-like engine over board data
  (`SUM`, `COUNT_DISTINCT`, `CASE`, `group_by`). Test whether `from: { id: "<board you cannot
  read>" }` is authorised, and whether aggregates leak values you cannot read directly
  (a classic inference channel: `MIN`/`MAX` over a hidden column).

---

# Test order

1. **GQL-05 probes** — one request each, no auth complexity, and they tell you what actually
   exists. Do this first; everything else may live behind one of these.
2. **GQL-01** — cheapest possible critical, needs only two accounts.
3. **GQL-02** — `{ service_users { id } }` first, as a non-admin.
4. **GQL-10** — one query, immediate answer.
5. **GQL-06 / GQL-07** — need setup, but the highest severity if they land.

Two accounts is the whole methodology: **token A, target B.** Anything that crosses that line
is a real finding. Anything that stays inside one account is usually intended behaviour.

Scope: monday.com runs a public bug bounty — confirm the API is in scope, and note that
several of these mutations are destructive (`delete_object`, `bulk_delete_items`,
`revoke_service_user_tokens`). Test them only against your own accounts.
