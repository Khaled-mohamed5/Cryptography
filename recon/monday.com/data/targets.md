# Test accounts

Identifiers only. **No cookies, tokens or session values in this file, ever.**
Session material goes in `.cookies-a` / `.cookies-b`, which are gitignored.

## Account A

| | |
|---|---|
| slug / host | `img-src1h1aaah1` — `img-src1h1aaah1.monday.com` |
| account_id | `36388263` |
| user_id | `112886052` |
| email | `hishamapes20+112@gmail.com` |
| region | `euc1` |
| plan | free (`is_paying_account=false`) |

## Account B

| | |
|---|---|
| slug / host | `zxczxc-cast` — `zxczxc-cast.monday.com` |
| account_id | `36786355` |
| user_id | `115702202` |
| email | `hishamapes20+1122@gmail.com` |
| region | `euc1` |
| plan | free |

## Other accounts in the same browser profile — not recorded here

The `monday_slug_details` cookie carries the name, email, user id and account id
of **every** account the browser has ever signed into. That profile had three
more besides A and B, one of them under a different person's name.

They are deliberately not written down in this repo, and they are not test
targets. **Only test against accounts you personally control** — pointing any of
this at someone else's account is unauthorised access, bug bounty scope or not.

Two accounts is all the method needs. A and B are enough.

Worth noting as its own observation: `monday_slug_details` is a non-HttpOnly
cookie containing cross-account email addresses and user ids, readable by any
script on `*.monday.com`. It is your own data, so it is not a finding by itself
— but it is what an XSS anywhere on the domain would harvest first.

## Still needed for the GraphQL work

Session cookies authenticate the **web app**. `api.monday.com/v2` wants an API
token, which is a different credential:

> avatar → Developer → My Access Tokens → copy

Get one from each account:

```bash
export MONDAY_TOKEN='<token from account A>'
export MONDAY_TOKEN_B='<token from account B>'
```

## Canaries — do this before testing

Put something unmistakable in account B so a cross-tenant hit is unambiguous:

1. Board named `CANARY-BOARD`
2. Item named `CANARY-ITEM-<random>`
3. File `canary.txt` containing `CANARY-<random>` — note its asset id
4. A comment containing `CANARY-UPD-<random>` — note its update id

Then record the ids here as you collect them:

| object | id in account B |
|---|---|
| board_id | |
| item_id | |
| asset_id | |
| update_id | |
| doc_id | |

## Cleanup when finished

- delete `.cookies-a` and `.cookies-b`
- log both accounts out (this invalidates `dapulse_session`)
- revoke the API tokens you created
