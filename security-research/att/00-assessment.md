# acenpw.att.com — pre-submission assessment

**Verdict: do not submit yet. What we have is a recon artifact, not a vulnerability.**

## The evidence in hand

```
https://acenpw.att.com [302] [0] [2.20.114.32] [Akamai,Nginx,WP Engine,WordPress]
```

Field by field:

| Field | Meaning | Security relevance |
|---|---|---|
| `302` | HTTP redirect | None. Redirects are the normal state of the web. |
| `0` | Content-Length 0 | None. Expected for a redirect. |
| `2.20.114.32` | Akamai edge IP (AS20940) | None. Shared CDN edge. |
| `Akamai,Nginx,WP Engine,WordPress` | Wappalyzer-style fingerprints | Tells us the stack. Not a finding on its own. |

A technology fingerprint is a *starting point for testing*, not a result.

## Subdomain takeover is ruled out

The obvious hypothesis for "WP Engine on a corporate subdomain" is a dangling CNAME.
Resolution says otherwise:

```
acenpw.att.com
  -> acenpw.att.com.edgekey.net      (Akamai production edge hostname)
  -> e11697.dscx.akamaiedge.net
  -> 2.16.234.16                      (live Akamai edge)
```

A takeover needs a CNAME pointing at an **unclaimed** provider endpoint — for WP Engine
that is a `*.wpengine.com` target serving WP Engine's "Site not found" page, with the
install name still registerable. Here the chain terminates on a live Akamai edge property
that AT&T controls. There is nothing to claim.

Even if it *were* dangling, AT&T's policy excludes it outright:

> Abandoned CNAME records require a social engineering component to successfully exploit,
> they are excluded unless there is an existing link from a company resource to the
> invalid CNAME.

## Scope and payout reality

- `acenpw.att.com` is not in the 25-asset table individually, so it falls under
  **Other Assets** — In scope, max severity Critical, **bounty eligible**. Good.
- It is **not** a Focus Asset. Policy: *"Only Focus Assets will be awarded at the top of
  the reward range (High, Critical). All other Assets will be awarded at the lower end."*
- Practical ceiling here: a High pays around $1,000, not $3,000. A Low pays $50.

## Cost of submitting anyway

A report containing only "this host returns 302 and runs WordPress" closes as **N/A** or
**Informative**. On HackerOne that lowers your Signal and Impact scores, and a poor Signal
score restricts which programs you can submit to at all. One weak report is cheap; a
pattern of them is not.
