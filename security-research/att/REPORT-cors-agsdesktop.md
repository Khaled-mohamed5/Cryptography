# agsdesktop.att.com CORS — assessment: DO NOT SUBMIT (as of current evidence)

## What is true

`https://agsdesktop.att.com/broker/xml` reflects an arbitrary `Origin` into
`Access-Control-Allow-Origin` and returns `Access-Control-Allow-Credentials: true`:

```
$ curl -s -i -X POST https://agsdesktop.att.com/broker/xml \
    -H 'Origin: https://evil-test.example.com' ...

access-control-allow-origin: https://evil-test.example.com
access-control-allow-credentials: true
```

That is a genuine misconfiguration. A browser PoC served from `http://localhost:8001`
confirmed the response body is readable cross-origin.

## Why it is not exploitable

The session cookie is `SameSite=Lax`:

```
Set-Cookie: ACCESSPOINTSESSIONID=...; path=/; secure; HTTPOnly; SameSite=Lax
```

`Lax` sends the cookie on same-site requests and cross-site **top-level navigations** only —
never on a cross-site POST, `fetch`, or XHR. The PoC's `credentials: 'include'` therefore
attached no session, and the broker returned a **404 error page** rather than a broker response.

Confirmed by the PoC output: the readable body was
`<title>404 Not Found</title> ... The page you requested is not available.`

**An attacker can read only unauthenticated responses.** The credentialed cross-origin read
that the CORS headers appear to allow cannot occur while the cookie remains `SameSite=Lax`.

## Verdict

Not submittable on current evidence. The program excludes:

> Theoretical security issues with no realistic exploit scenario(s) or attack surfaces
>
> Issues determined to be low impact

A report claiming an attacker can read authenticated data would be disproven by the
`Set-Cookie` header on the same endpoint. Filing it costs Signal score for no gain.

## What would make it submittable

**Find a cookie on this host with `SameSite=None`.** If any cookie carrying authentication or
session state is set with `SameSite=None; Secure`, it *will* travel on a cross-site `fetch`,
and the CORS reflection becomes immediately exploitable.

```bash
curl -s -i https://agsdesktop.att.com/portal/webclient/ | grep -i 'set-cookie'
curl -s -i https://agsdesktop.att.com/broker/xml -X POST \
  -H 'Content-Type: application/x-www-form-urlencoded; charset=UTF-8' \
  --data-binary "<?xml version='1.0' encoding='UTF-8'?><broker version='14.0'><do-submit-authentication><screen><name>disclaimer</name><params><param><name>accept</name><values><value>true</value></values></param></params></screen></do-submit-authentication></broker>" \
  | grep -i 'set-cookie'
```

**Checked — no SameSite=None cookie exists.** The only cookie set on this host is:

```
Set-Cookie: ACCESSPOINTSESSIONID=e55952ef-...; path=/; secure; HTTPOnly; SameSite=Lax
```

The revival condition does not hold. This finding is defence-in-depth only. **Closed, not filed.**

## Also closed on this host

- **XXE** — `disallow-doctype-decl=true` rejects the DTD outright; XInclude is not processed.
- Security posture is otherwise strong: strict CSP, `frame-ancestors 'none'`, HSTS preload,
  `nosniff`, HttpOnly + Secure + SameSite cookies.
