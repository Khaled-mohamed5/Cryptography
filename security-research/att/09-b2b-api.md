# b2b.att.com — Integration Server admin API surface

Recovered from `main.a928d6ddfa6c3cd9.js` (4,041,044 bytes), served publicly without
authentication. The console is a modern Angular build (Angular 19+, Beasties inliner), not the
legacy JSP UI. Ten hosts serve a byte-identical page (`dd7f7df3d16ce713ec1e99f69f4e5588`), so
this is one deployment behind ten names.

## The endpoints

| Endpoint | What it exposes | Sensitivity |
|---|---|---|
| `/admin/server/env` | Server environment | **Extreme** — env vars routinely hold credentials |
| `/admin/jdbc/pool` | JDBC connection pools | **Extreme** — DB connection strings |
| `/admin/jdbc/driver`, `/admin/jdbc/function` | Database layer config | **Extreme** |
| `/admin/thread-dump` | Thread dumps | **Extreme** — in-memory data |
| `/admin/sessions` | Active sessions | **Extreme** — other users |
| `/invoke/wm.server.access/userUpdate` | **Modifies users** | **Never touch — write operation** |
| `/admin/server/internal/setting`, `/admin/server/setting/` | Server configuration | High |
| `/admin/log/security`, `/admin/logger/security` | Security logs | High |
| `/admin/log/{server,error,session,service,messaging}` | Operational logs | High |
| `/admin/log/guaranteedDelivery{Inbound,Outbound}` | B2B transaction delivery | High |
| `/admin/adapters/connection`, `/admin/adapters/describe/` | Adapter connections | High |
| `/admin/package`, `/admin/service/cache`, `/admin/service/running/` | Deployed packages/services | Medium |
| `/admin/dashboard/*` | Metrics, circuit breaker state | Medium |
| `/admin/thread` | Thread listing | Medium |
| `/admin/server/statistics` | Server statistics | Low |
| `/admin/navigation/license` | License information | Low |
| `/invoke/wm.server/ping` | Health check | **Lowest — designed to be harmless** |
| `/invoke/wm.server/login`, `/logout` | Authentication | n/a |

## The one question that matters

**Does the server enforce authentication on these, or only the Angular UI?**

The client-side console obviously gates them. The test is whether the *server* does.

## Test methodology — least sensitive first

Establish the answer using the **most harmless endpoint available**, never the most valuable one.

```bash
curl -s -o /dev/null -w 'ping    -> %{http_code}\n' https://b2b.att.com/invoke/wm.server/ping
sleep 3
curl -s -o /dev/null -w 'license -> %{http_code}\n' https://b2b.att.com/admin/navigation/license
```

Status codes only — `-o /dev/null` means no response data is retrieved.

- **401 / 403** → authorisation is enforced. No finding. Stop; the answer is the same for every
  other endpoint, since they share the same middleware.
- **200** → the server does not authenticate its admin API. **Stop immediately.**

## If it returns 200

That is a Critical finding, and it is already fully proven. Capture a minimal body from
`/admin/navigation/license` or `/admin/server/statistics` as evidence, then stop.

**Do not then query `/admin/server/env`, `/admin/jdbc/pool`, `/admin/thread-dump`, or
`/admin/sessions`.** Those return credentials, connection strings, memory contents, and other
users' sessions. Retrieving them:

- is not needed — the boundary failure is already demonstrated by a low-sensitivity endpoint
- accesses data the program does not authorise: *"You may only exploit, investigate, or target
  vulnerabilities against your own accounts"*
- triggers the mandatory declaration clause for inadvertent access to customer, employee, or
  business information
- converts a clean Critical report into a policy violation, and plausibly into unauthorised
  access to production infrastructure

**Never send `/invoke/wm.server.access/userUpdate` under any circumstances.** It is a write
operation that modifies user accounts. There is no read-only way to test it and no legitimate
reason to call it.

The report writes itself from a status code and one harmless response body. Impact is argued
from the endpoint inventory above — which came from a public file — not from data pulled out
of AT&T's production middleware.
