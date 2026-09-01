# HackerOne submission — ready to paste

## Title

```
CORS misconfiguration on agsdesktop.att.com/broker/xml: arbitrary origin reflected with credentials enabled
```

## Asset

`agsdesktop.att.com` — *Other Assets*, in scope

## Weakness

CWE-942: Permissive Cross-domain Policy with Untrusted Domains
(if unavailable, search "CORS" or use CWE-346: Origin Validation Error)

## Severity

**Medium** — see Severity Rationale.

---

## Summary

`https://agsdesktop.att.com/broker/xml` reflects the value of the request's `Origin` header
into `Access-Control-Allow-Origin` without validation, while also returning
`Access-Control-Allow-Credentials: true`.

Any website can therefore issue a cross-origin request to this endpoint with the visitor's
cookies attached and **read the response**. The host is an Omnissa/VMware Horizon gateway, so
the affected sessions belong to users of AT&T's virtual desktop infrastructure.

The endpoint accepts `Content-Type: application/x-www-form-urlencoded`, which is CORS-
safelisted. The attack is therefore a *simple request* and triggers **no preflight**, so no
`OPTIONS` policy check limits it.

---

## Steps to reproduce

**1. Send a request with an arbitrary `Origin`:**

```bash
curl -s -i -X POST https://agsdesktop.att.com/broker/xml \
  -H 'Origin: https://evil-test.example.com' \
  -H 'Content-Type: application/x-www-form-urlencoded; charset=UTF-8' \
  --data-binary "<?xml version='1.0' encoding='UTF-8'?><broker version='14.0'><do-submit-authentication><screen><name>disclaimer</name><params><param><name>accept</name><values><value>true</value></values></param></params></screen></do-submit-authentication></broker>" \
  | grep -i 'access-control'
```

**Observed response headers:**

```
access-control-allow-origin: https://evil-test.example.com
access-control-allow-credentials: true
```

The server echoes an origin it has no relationship with, and permits credentialed reads from it.

**2. Confirm in a browser.**

Serve the attached `cors-agsdesktop.html` from any origin (e.g. `python3 -m http.server 8000`)
and open it. The page performs a cross-origin `fetch` with `credentials: 'include'` and renders
the response body — demonstrating that a third-party site can read responses from this endpoint.

---

## Impact

An attacker hosts a page and induces a user with an active `agsdesktop.att.com` session to
visit it — no interaction beyond loading the page is required. Script on that page can then
issue authenticated requests to the Horizon broker API and read the responses.

The broker API at `/broker/xml` is the interface a Horizon client uses to authenticate,
enumerate entitled desktops and applications, and obtain session details. Responses readable
under an authenticated session therefore include the user's authentication state and their
entitlements — that is, which internal virtual desktops and applications a given AT&T user can
reach.

Because this is a VDI gateway, affected users are internal staff and contractors rather than
consumers.

I have not obtained credentials for this system, so this report demonstrates the
misconfiguration itself and the cross-origin read primitive, not the retrieval of any specific
user's data. Determining exactly which broker responses are exposed would require an
authenticated session belonging to someone else, which the program does not authorise.

---

## Severity rationale

Rated **Medium** rather than High: the vulnerability is fully proven, but the sensitivity of
what is readable depends on the authenticated broker responses, which I have not accessed.
Severity may reasonably be higher if the broker exposes session tokens or entitlement data to
an authenticated caller.

Suggested vector: `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N`

---

## Remediation

Do not reflect the `Origin` header. Compare it against a fixed allowlist and emit
`Access-Control-Allow-Origin` only on an exact match:

```
if (origin in {"https://agsdesktop.att.com"}) {
    Access-Control-Allow-Origin: <that exact value>
}
```

Since the client is served from the same origin as the API, cross-origin access appears
unnecessary — removing both CORS headers entirely would be the safest fix. If credentialed
cross-origin access is genuinely required, `Access-Control-Allow-Credentials: true` must never
be paired with a reflected origin. Keep `Vary: Origin` on any origin-dependent response.

---

## Testing performed

- One `curl` request with a modified `Origin` header
- One browser page load performing a cross-origin `fetch`

No credentials were used, guessed, or obtained. No other user's session or data was accessed.
No authenticated action was performed against the system.
