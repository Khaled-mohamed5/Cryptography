# bnc-businessmessaging.att.com — IPMS API surface

Recovered from `labssoft-web-min.js` (940,447 bytes), served publicly.

**This host differs from every other target assessed today: no Akamai, no Bot Manager, no
CloudFront.** Tengine (nginx fork) on `173.209.210.194`, outside AT&T's usual ranges. Responses
here carry real information — a `200` means something.

Stack is a decade old: jQuery 1.9.1 (Feb 2013), Knockout 3.4.0, Bootstrap 3, an `ie-eight.js`
shim.

## API inventory

| Endpoint | Function | Interest |
|---|---|---|
| `/ipms/ipmRS/auth/v1` · `/v2` | Authentication | **Version skew** |
| `/ipms/ipmRS/addressbook/v1` · `/v2` | Contacts — PII | **IDOR + version skew** |
| `/ipms/ipmRS/message/v1` · `/v2` | Message content | **IDOR + version skew** |
| `/ipms/ipmRS/AccountManagers/v1` · `/v2` | Account management | **Privileged + version skew** |
| `/messageFileStorage/auth/v1/login` | **Second, separate auth system** | High |
| `/messageFileStorage/v1/` | File storage | High |
| `/transfers/cloud2ipms` · `/ipms2cloud` | Server-side cloud fetch | **SSRF candidate** |
| `/cloudaccounts` · `/clouds` | OAuth-linked cloud storage | High |
| `/files/` `/folders/` `/photofiles/` `/recipientfiles/` `/thumbnails/` | File access by identifier | **IDOR candidates** |
| `/ipms/cloudfiles/v1` | Cloud file listing | IDOR |
| `/conversation/` `/groups` `/users` `/link/` | Core objects | IDOR |
| `/reports/daily` | Reporting | Medium |
| `/requestOptIn/` | Opt-in flow | Medium |

## Lead 1 — v1 and v2 exposed side by side

Four API families ship both versions publicly: `auth`, `addressbook`, `message`,
`AccountManagers`.

The recurring vulnerability in this shape is that **v1 predates an authorisation check that v2
added**. Deprecated versions stay routed for backwards compatibility and stop receiving
security fixes. If `/v2/` enforces a check that `/v1/` does not, the same operation performed
against v1 crosses an authorisation boundary.

Test by differential: perform an identical operation against v1 and v2 and compare status codes
and payloads. A v2 that returns `403` where v1 returns `200` is the finding.

## Lead 2 — the file tree is not the classic connector

```js
$(...).fileTree({ listFolder: b.cloudFilesManager.listFolder, cloudId: a, ... })
```

It is wired to `cloudFilesManager.listFolder` with a **`cloudId`** parameter, not the usual
`jqueryFileTree.php` connector. So the traversal candidate is not `dir=../../` — it is
**`cloudId` as an IDOR**: can one user enumerate another user's linked cloud account?

## Lead 3 — SSRF via cloud transfer

`/transfers/cloud2ipms` moves a file from a cloud provider into IPMS, meaning **the server
fetches a remote resource**. If any URL, host, or path component is attacker-controlled, that is
server-side request forgery. The bundle's OAuth handling (`oauth_request`, `getServiceAuthURL`,
error code `7401`) confirms real outbound integrations.

## Not a lead

`/libs/ffmpeg_asm.js` is ffmpeg compiled to asm.js and runs **in the browser**. There is no
server-side ffmpeg here, so ffmpeg CVEs do not apply.

jQuery 1.9.1 is old enough to match several published XSS and prototype-pollution CVEs. **The
version alone is not reportable** — the program excludes low-impact and theoretical issues. It
is only a finding if the application passes attacker-controlled input into a vulnerable sink and
the result is demonstrated.

## First test — unauthenticated baseline

Every endpoint above presumably requires a session. Establish which, if any, do not. Status
codes only, no data retrieved:

```bash
for p in /ipms/ipmRS/auth/v1 /ipms/ipmRS/auth/v2 \
         /ipms/ipmRS/addressbook/v1 /ipms/ipmRS/addressbook/v2 \
         /ipms/ipmRS/message/v1 /ipms/ipmRS/message/v2 \
         /ipms/ipmRS/AccountManagers/v1 /ipms/ipmRS/AccountManagers/v2 \
         /ipms/cloudfiles/v1 /messageFileStorage/v1/ /reports/daily /users /clouds; do
  printf '%-42s ' "$p"
  curl -s -o /dev/null -m 15 -w '%{http_code}\n' "https://bnc-businessmessaging.att.com$p"
  sleep 2
done
```

Thirteen requests, spaced. Interpretation:

- **401 / 403 everywhere** — authorisation enforced consistently. Progress needs an account.
- **v1 answers where v2 rejects** — the version-skew finding. Stop and capture it.
- **200 with data anywhere** — unauthenticated access to a messaging API. Capture the minimum
  needed to prove it and stop; do not enumerate.

## Boundaries

This platform carries real customers' messages, contacts, and files.

- Prove an authorisation failure with the smallest possible response, then stop
- Never enumerate identifiers to reach another customer's data — one request establishing that
  a boundary fails is the finding; a dump of what is behind it is a policy violation
- No credential testing against `/auth/` or `/messageFileStorage/auth/v1/login`
