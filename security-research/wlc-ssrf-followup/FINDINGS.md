# wlc — follow-up review of the GHSA-4cv2-373j-7jw8 fix

Target: [WeblateOrg/wlc](https://github.com/WeblateOrg/wlc)
Versions reviewed: 2.1.0 (vulnerable), 2.1.1 (advisory fix), **2.2.0 (current release, all testing below)**
Test environment: Python 3.11.15, requests 2.34.2, urllib3 2.7.0 (matches `wlc`'s floor of
`requests>=2.33.0`, `urllib3>=2.7.0`)

## 0. What the advisory fix actually changed

The 2.1.1 fix replaced every `urllib.parse.urlparse` call in `wlc/client.py` with
`urllib3.util.parse_url`, so validation now runs through the same parser the HTTP transport
uses. 2.2.0 added further hardening: `allow_redirects=False` plus an explicit 3xx rejection,
`auth is not None` rejection in `parse_request_url`, `_NoNetrcAuth` to suppress ambient
credentials, removal of the automatic `should_verify_ssl` downgrade, and redaction of
sensitive headers in debug logging.

## 1. Negative result: the parser-differential class is closed

Two independent searches for a string that `wlc` validates as same-origin but that `requests`
connects elsewhere for:

| harness | payloads | bypasses |
|---|---|---|
| `differ.py` — structured corpus: every ASCII char (single + doubled) plus percent-encodings and Unicode confusables, in 15 positional arrangements, over 2 base URLs | 8,820 | 0 |
| `fuzz2.py` — randomised token-soup mutation fuzzing | 150,000 | 0 |

Both compare `Weblate.normalize_request_url()` against the **real** TCP target, resolved the
way `requests` resolves it (`HTTPAdapter.get_connection_with_tls_context` →
`_urllib3_request_context` → `conn.host/port`), not against a second parse.

The structural reason there is nothing to find: `PreparedRequest.prepare_url` **rebuilds** the
netloc from the very `parse_url` components `wlc` validated, so the connection host can no
longer diverge from the validated host. Two candidate tricks were specifically ruled out:

* The mirrored backslash payload `http://127.0.0.1:8000\@169.254.169.254/…` — `wlc` validates
  host `127.0.0.1`, and the `\` lands in the path. It does **not** re-serialize into a hostile
  authority because `urllib3.util.Url.__new__` forces a leading `/` onto any path, in every
  urllib3 version. Even if it did, 2.2.0's `auth is not None` check catches it on the second
  parse in `invoke_request`.
* `requests` picks the connection host with stdlib `urlparse` (`_urllib3_request_context`),
  i.e. the differential is *inverted* relative to the original report — but unreachable, since
  the string it parses was rebuilt from the validated components.

**Do not spend more time on URL string parsing here.** The remaining issues are elsewhere.

## 2. Finding A — the origin allowlist is name-based, so DNS rebinding restores the primitive

`normalize_request_url` compares `(scheme, host, port)` as *strings*. The connection is opened
by resolving that hostname at send time. A hostile server that controls its own DNS answers the
second lookup with any address it likes; the origin check still passes because the *name* never
changed.

This is exactly the reporter's own remediation #2 from the original report ("reject requests to
private/internal/link-local IP ranges"), which was not implemented — only remediation #1 was.

### Confirmed end-to-end against the real CLI (not component-level)

No `wlc` code is patched. Only `socket.getaddrinfo` is overridden, in the CLI's own process via
`PYTHONPATH`, which is precisely what an attacker controls for their own domain (TTL 0).
The front-end sends `Connection: close` so the pooled connection cannot be reused.

```
$ WLC_POC_DNS=1 PYTHONPATH=poc wlc --url http://weblate.test:8099/api/ \
      --key SECRET-API-TOKEN-123 --allow-insecure-http list-projects

[dns] lookup #1 weblate.test -> 127.0.0.1     <- attacker front-end
[dns] lookup #2 weblate.test -> 127.0.0.2     <- "internal-only" host

[internal] !!! received a request from wlc !!!
[internal] GET /api/projects/?page=2 HTTP/1.1
[internal]   Host: weblate.test:8099
[internal]   user-agent: wlc/2.2.0
[internal]   Authorization: Token SECRET-API-TOKEN-123
```

The full request — and the API token — is delivered to a host `wlc` was never configured for
and that the origin check exists to keep it away from.

### Honest impact matrix

| transport | what reaches the rebound address |
|---|---|
| `http://` (loopback dev default, `--allow-insecure-http`, or an `[insecure_http]` origin) | complete HTTP request **including `Authorization: Token …`** |
| `https://` | TCP connection + TLS ClientHello (517 bytes, SNI intact) — verified. The request is **not** delivered: the handshake fails unless the internal host serves a cert valid for the attacker's name |
| `https://` with `[insecure_ssl]` enabled for that origin | complete request, as with plain HTTP |

So over HTTPS this is a network-reach primitive (internal port probing, triggering
connect-sensitive services), and over HTTP it is the full original primitive plus credential
disclosure to the internal host.

Reproduce: `python poc/servers.py 8099`, then the command above.
TLS variant: `python poc/servers_tls.py 8443 poc/cert.pem poc/key.pem` with
`REQUESTS_CA_BUNDLE` pointed at the cert (disable any ambient `HTTPS_PROXY`).

### Suggested fix

Resolve the host once, validate the resulting address against the configured origin's address
set, and pin it for the connection (a custom `HTTPAdapter`/`PoolManager` with the resolved
address, or an explicit check that the resolved address is not private/link-local unless the
configured API URL itself is). Name-only comparison cannot survive an attacker-controlled zone.

## 3. Finding B — an auto-discovered `.weblate` replays non-idempotent operations

`WeblateConfig.find_project_config()` walks up from the CWD looking for `.weblate` /
`.weblate.ini` / `weblate.ini`, so any repository the victim clones can supply one. The code
already treats that file as semi-untrusted: `_read_config` strips `allow_insecure_http` /
`allow_insecure_ssl`, and `_validate_project_overrides` refuses to pair an unscoped key with a
project-supplied URL.

Retry and timeout options were left outside that boundary. A `.weblate` that simply **omits
`url`** never triggers `_validate_project_overrides` at all, yet still controls:

```ini
[weblate]
retries = 900
backoff_factor = 120
timeout = 86400
status_forcelist = 200
allowed_methods = GET,POST,PUT,DELETE
```

`status_forcelist = 200` makes urllib3 retry **successful** responses, and widening
`allowed_methods` makes it retry non-idempotent ones. Measured with `retries = 5`:

```
one wlc push -> 6 HTTP requests hit the server:
    POST /api/components/demo/x/repository/
    … (6 identical POSTs)
```

The victim's own URL and token are used, against their real Weblate server. At `retries = 900`
with `backoff_factor = 120` (urllib3 caps a single backoff at 120 s) that is 900 replays of a
`push` / `upload` / `delete`, and a client that hangs for up to ~30 hours.
Verified settings are accepted: `poc/extras.py`, `poc/replay.py`.

**Fix:** clamp `retries`, `backoff_factor`, `timeout`, and `allowed_methods` when the values come
from project configuration (or strip them there, as the insecure flags already are), and reject
2xx entries in `status_forcelist`.

## 4. Finding C — unbounded pagination loop (low)

`list_factory` loops `while path is not None`. An empty string is not `None`, and
`urljoin(base, "")` returns the base, so `{"next": ""}` re-requests the same endpoint forever:

```
requests issued in 4s against one endpoint: 92
generator still running: True
```

A `next` pointing at itself does the same. **Fix:** treat a falsy `next` as the end of pagination,
and bound the number of pages followed.

## 5. Finding D — unhandled exceptions on hostile responses (low)

A response without `results` crashes with a raw traceback instead of `WeblateException`:

```
File ".../wlc/client.py", line 399, in list_factory
    for item in data["results"]:
KeyError: 'results'
```

Same for a non-mapping object in a `MAPPINGS` field (`TypeError` from `**value`) and for a
non-string `next` (`TypeError` from `urljoin`). **Fix:** validate response shape and raise
`WeblateException`.

## Files

| path | purpose |
|---|---|
| `differ.py` | structured validation-vs-real-target differential harness |
| `fuzz2.py` | randomised parser-differential fuzzer |
| `poc/sitecustomize.py` | attacker-controlled DNS (TTL 0) for the real CLI process |
| `poc/servers.py` | HTTP rebinding PoC — front-end + internal service |
| `poc/servers_tls.py` | HTTPS rebinding PoC — TLS front-end + raw internal listener |
| `poc/extras.py` | project-config options + unbounded pagination |
| `poc/replay.py` | retry replay of a non-idempotent POST |
