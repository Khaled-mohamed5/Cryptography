# WAPTLab CRM — Full Source-Code Bug & Vulnerability Review

**Target:** `WAPTLab` (Laravel 10.49.1 / PHP 8.2) — intentionally vulnerable multi-tenant CRM
**Scope:** static review of `app/`, `routes/`, `resources/views/`, `config/`, `database/`, `docker/`
**Date:** 2026-08-23

> The lab README advertises 20 planned vulnerability classes. This review found **42 security findings**
> (9 critical, 16 high, 15 medium, 2 low/info) plus **23 functional bugs**. Two of the README's planned items (**XFF header SQLi**, **APP_DEBUG=true**)
> are **not present in this snapshot** — see §10.

Severity legend: 🔴 Critical · 🟠 High · 🟡 Medium · ⚪ Low/Info

---

## 1. Injection

### 1.1 🔴 SQL Injection in the CSV/XML ingestion pipeline
**`app/Http/Controllers/CsvImportController.php:183-188`**

```php
//$stmt = $pdo->prepare("INSERT INTO `values` (entity_id, attribute_id, value, ...) VALUES (?, ?, ?, ...)");
//$stmt->execute([$entityId, $attrId, $value]);
$sql = "INSERT INTO `values` (entity_id, attribute_id, value, created_at, updated_at)
        VALUES ($entityId, $attrId, $value, NOW(), NOW())";
$pdo->query($sql);          // ← line 187
```

Every other statement in this method is a prepared statement (lines 162, 171, 178). This one was
deliberately downgraded: `$value` is a **raw CSV cell** (line 169, `$row[$i]`) concatenated straight
into the SQL string, and it is not even wrapped in quotes.

* **Sink:** `PDO::query()` — multi-statement is off, but sub-selects, `LOAD_FILE()`, and
  `INSERT ... SELECT` all work. Because the value is unquoted, the attacker does not even need to
  break out of a string literal.
* **Source:** an uploaded CSV cell, or — through the XML/XSLT branch (§1.4) — the text content of an
  `<record>` child element.
* **Connection:** `mysql_hr` or `mysql_support` (line 137), authenticating as **root** (`.env`
  `DB_SECOND_USERNAME=root`), so the injection reads every database on the instance, including
  `admin_db` and the `flags` tables.
* **Example cell:** `(SELECT flag FROM admin_db.flags LIMIT 1)` — lands verbatim in the VALUES list.

**Fix:** restore the prepared statement that is commented out on lines 183-184.

---

### 1.2 🔴 Server-Side Template Injection → RCE on CRM export
**`app/Http/Controllers/CrmController.php:30-45`**

```php
foreach ($rows as &$row) {
    foreach ($row as $key => $value) {
        if (is_string($value) && (str_contains($value, '{{') || str_contains($value, '{!!'))) {
            $row[$key] = \Illuminate\Support\Facades\Blade::render($value, $context);   // line 34
```

`Blade::render()` **compiles the string to PHP and executes it**. The controller explicitly looks for
template markers in user data and then evaluates them — this is arbitrary code execution, not just
template injection. `$rows` comes from the JSON request body (line 16), fully attacker-controlled.

**Why the WAF does not stop it.** `SecurityFiltersMiddleware` is on this route, but its SSTI rule
(`SecurityFiltersMiddleware.php:201`) is:

```php
if (preg_match('/(?<!@)\{\{.*?\}\}/s', $value, ...)) {   // only matches {{ ... }}
```

It never matches the **raw-echo** syntax `{!! ... !!}`, which line 32 explicitly accepts. And the
dangerous-function list (lines 147-151) contains only browser APIs — `alert`, `eval`, `open`,
`document.write` — so PHP callables such as `system`, `shell_exec`, `passthru`, `file_get_contents`
and `file_put_contents` pass straight through.

**Payload shape:** `{"db":"hr","rows":[{"x":"{!! <php-callable> !!}"}]}` → RCE as the web user.

**Fix:** never render user data as a template. Pass rows as *data* to a fixed view; delete lines 30-45.

---

### 1.3 🔴 XXE on every endpoint (global middleware)
**`app/Http/Middleware/ParseXmlRequests.php:11-24`**

```php
if ($contentType && str_contains($contentType, 'xml')) {
    $content = $request->getContent();
    $xml = simplexml_load_string($content, "SimpleXMLElement", LIBXML_NOENT | LIBXML_DTDLOAD);  // line 17
```

`LIBXML_NOENT` **substitutes** entities and `LIBXML_DTDLOAD` **loads external DTDs** — the exact pair
that enables classic and out-of-band XXE. This middleware is registered in the **global** stack
(`app/Http/Kernel.php:19`), so it runs before routing on *any* request whose `Content-Type` merely
*contains* the string `xml` — including `application/xml`, `text/xml`, and `application/soap+xml`.

The published API spec advertises the entry point: `public/swagger/openapi.yaml` documents that
`POST /api/check_email_status` accepts `application/xml`. That route is also stripped of throttling
(`routes/api.php:26`), so it can be hit at will, unauthenticated.

Both file read (`file:///etc/passwd`) and OOB exfiltration (parameter entity → attacker HTTP/DNS
endpoint) work. The parsed values are merged into the request (line 23), so read data can also be
reflected back through whatever endpoint you target.

**Fix:** drop `LIBXML_NOENT | LIBXML_DTDLOAD`; add `LIBXML_NONET`. On PHP < 8.0 also call
`libxml_disable_entity_loader(true)`.

---

### 1.4 🔴 XXE in the CSV importer's XML branch
**`app/Http/Controllers/CsvImportController.php:36-64`**

```php
@libxml_disable_entity_loader(false);          // line 40 — entity loading forced ON
libxml_use_internal_errors(true);
...
$dom->loadXML($xmlContent, LIBXML_NOENT | LIBXML_DTDLOAD | LIBXML_DTDATTR);   // line 52
```

A second, independent XXE. Entity resolution is *deliberately re-enabled* on line 40, and the
comment above it says so. Resolved entity content becomes `$child->nodeValue` (line 60) → written to
the temp CSV (line 124) → **fed into the SQL injection of §1.1**. That chain turns file-read into
database write, and the imported rows are visible in the dashboard, giving a clean read-back channel.

Reached via `POST /csv` with `filetype=1` and `async=1` (see §9.6 — both are hidden fields the UI
never sends, `resources/views/csv_upload.blade.php:46-48`).

---

### 1.5 🟠 XSLT injection — user-supplied stylesheet (ERP export)
**`app/Http/Controllers/ErpExportController.php:18, 41-48`**

```php
$xsltString = $data['xslt'] ?? null;      // line 18 — stylesheet comes from the request body
...
$xsl = new DOMDocument;
$xsl->loadXML($xsltString);               // line 42
$proc = new XSLTProcessor;
$proc->importStylesheet($xsl);            // line 46
$result = $proc->transformToXML($xml);    // line 48
```

The client sends the *stylesheet*, not just the data. The front end hard-codes a benign one
(`dashboard/index.blade.php:357-379`), but nothing server-side pins it. No `setSecurityPrefs()` call
is made, so libxslt runs with PHP's defaults: **reading** files and network resources is permitted.

* `<xsl:value-of select="document('file:///etc/passwd')"/>` → local file read
* `<xsl:copy-of select="document('http://elasticsearch:9200/_cat/indices')"/>` → SSRF into the
  Docker network, with the response returned in the downloaded XML
* `unparsed-text()` / `document()` against `http://169.254.169.254/` → cloud metadata

**Fix:** keep the stylesheet server-side. If user XSLT is truly required, call
`$proc->setSecurityPrefs(XSL_SECPREF_READ_FILE | XSL_SECPREF_WRITE_FILE | XSL_SECPREF_CREATE_DIRECTORY | XSL_SECPREF_READ_NETWORK | XSL_SECPREF_WRITE_NETWORK)`.

---

### 1.6 🟠 XSLT injection — uploaded stylesheet
**`app/Http/Controllers/CsvImportController.php:66-97`**

```php
$xslDoc = new \DOMDocument();
$xslDoc->load($filePath, LIBXML_NOENT | LIBXML_DTDLOAD | LIBXML_DTDATTR);   // line 69
$proc = new \XSLTProcessor();
$proc->importStylesheet($xslDoc);                                          // line 76
$transformed = $proc->transformToXML($xmlSource);                          // line 78
```

Same class of issue as §1.5, reached by uploading a file with `filetype=2`. The transform output is
re-parsed with entity loading enabled *again* (line 86) and then flows into the §1.1 SQL injection.

---

### 1.7 🟡 Elasticsearch index / path injection via `db`
**`routes/web.php:124-125` and `147-149`**

```php
$index = $db . '_data';
$response = Http::get("http://elasticsearch:9200/{$index}/_search");
```

`$db` is a raw query parameter interpolated into an ES **URL path**. Beyond the tenant bypass of
§2.1, a value such as `hr_data/_search?size=10000&q=*&x=` rewrites the endpoint and its parameters;
`_all`, `*`, and `../` reach indices and APIs the route never intended to expose. The backing
Elasticsearch is 1.5.1 (§8.1), which has no authentication at all.

---

## 2. Broken Access Control

### 2.1 🔴 Tenant/DB switching — the `admin` database is not in the blocklist
**`routes/web.php:75`, `103-113`, `116-135`, `138-166`**

```php
$restrictedDbs = ['hr', 'support'];                    // line 75

$db = $request->query('db', $user->role);              // line 106
if (in_array($db, $restrictedDbs) && $user->role !== $db) {
    abort(403, 'Forbidden');                           // line 109
}
```

The check is a **blocklist of two values**. Any `db` outside `['hr','support']` skips the comparison
entirely. `?db=admin` builds index `admin_data`, which `IndexEavToEs.php:36-45` populates from the
`mysql_admin` connection — the database `MultiConnectionSeeder.php:64-74` seeds with the admin flag.
Every one of the three routes (`/dashboard`, `/api/dashboard/data`, `/api/search`) has the same hole.

`/api/dashboard/data` additionally defaults to `'hr'` (line 118) rather than the caller's role, so an
account whose role is `support` reads HR data by simply omitting the parameter.

**Fix:** allowlist. `if (!in_array($db, ['hr','support'], true) || $db !== $user->role) abort(403);`

---

### 2.2 🟠 IDOR — CSV row download has no ownership check
**`app/Http/Controllers/CrmController.php:85-100`** and **`app/Http/Controllers/CrmV1Controller.php:101-120`**

```php
public function downloadRow($id)
{
    $path = storage_path("app/crm_rows/{$id}.json");   // line 87
    if (!file_exists($path)) abort(404);
    $data = json_decode(file_get_contents($path), true);
```

No owner column, no tenant column, no lookup against the caller. Any authenticated user downloads any
saved row by guessing `$id`. And `$id` is attacker-chosen at save time (`saveRow`, lines 75-77:
`$rowData['id']` is used verbatim as the filename), so ids are not even unpredictable — they are
whatever the *other* tenant's rows contain, which the ES search endpoints hand you.

`CrmV1Controller` bolts on `checkCrossDbEntityMatch()`, but that is a *content-overlap heuristic*
(§2.5), not an authorization check.

---

### 2.3 🟠 IDOR — CRM record view
**`app/Http/Controllers/CrmRowController.php:50-54`**, **`DashboardController.php:129-133`**

```php
public function viewCrm($id)
{
    $crm = CrmMain::findOrFail($id);   // no tenant/user scoping
    return response()->json($crm);
}
```

`crm_main` rows carry `source_db` (`database/migrations/2025_10_09_043223_create_crm_main_table.php:11`)
but it is never compared to the caller's role. Sequential integer ids enumerate the whole table
across tenants.

---

### 2.4 🟡 IDOR — arbitrary user profile, and unrestricted user directory
**`app/Http/Controllers/UserProfileController.php:150-154`**, **`UsersController.php:15-29`**

```php
public function show($id) { $user = User::findOrFail($id); return view('profile.show', compact('user')); }
```

```php
$users = User::on('mysql')->get();          // every user, every role
```

`/users` is behind `auth` only — no `role` middleware — so any registered account enumerates the full
directory (names, emails, roles). Paired with §4.2 (`{!! $user->email !!}`) this becomes the delivery
surface for stored XSS against every other user.

---

### 2.5 🟡 `checkCrossDbEntityMatch()` is not an authorization control
**`app/Http/Controllers/CrmV1Controller.php:15-72`**

```php
$matches = DB::connection($oppositeConnection)->table('values')
    ->select('entity_id', 'value')
    ->whereIn(DB::raw('LOWER(value)'), $values)->get();      // line 45-49
...
if ($entityWithMultipleMatches->isNotEmpty()) {
    abort(403, 'Forbidden: record overlaps with protected data in the opposite DB.');
}
```

Three problems:

1. It queries the **opposite tenant's database with root credentials** to decide access — the check
   itself is a cross-tenant read primitive. Timing and the 403/200 split turn it into an **oracle**:
   probe one value at a time and the response tells you whether it exists in the other tenant.
2. It only fires for roles `hr` and `support` (line 24) — every other role, including anything an
   admin creates, is returned early and unrestricted.
3. It blocks on *content overlap*, so it fails open for any record whose values happen not to
   collide, and fails closed for legitimate records that do.

---

## 3. Path Traversal & File Handling

### 3.1 🔴 Arbitrary file read via forged JWT — hardcoded fallback secret
**`app/Http/Controllers/CrmController.php:231`, `243-282`**

```php
$secret = env('CRM_CSV_JWT_SECRET', 'password123');    // line 231 (save) and line 251 (view)
$token  = $this->jwtEncode(['path' => $realPath], $secret, ...);
...
$payload  = $this->jwtDecode($token, $secret);
$realPath = $payload['path'];
$fullPath = storage_path('app/') . $realPath;          // line 267 — no normalisation
if (!file_exists($fullPath)) abort(404);
return response()->file($fullPath);                    // line 281
```

`CRM_CSV_JWT_SECRET` **is not defined in `.env`**, so the literal fallback `password123` is the live
signing key. The HMAC verification on line 187 is correct — and completely pointless, because the
attacker holds the key.

Forge `{"path":"../../../../etc/passwd","exp":<future>}`, sign with `password123`, request
`GET /crm/view?path=<jwt>` → arbitrary file read as the web user: `/etc/passwd`, `/proc/self/environ`,
`/var/www/html/.env` (which contains `APP_KEY`, root DB credentials, SMTP credentials and the
`APP_SECRET` flag). `APP_KEY` disclosure then means session-cookie forgery and, in Laravel, a
deserialization path.

The comment on lines 265-266 confirms the traversal is deliberate; the hardcoded secret makes it
*reachable without ever calling `saveCsv`*.

**Fix:** store only an opaque id, resolve it to a path server-side, and validate with
`realpath()` that the result stays under `storage/app/crm_csv/`.

---

### 3.2 🟠 Elasticsearch snapshot path traversal proxy
**`routes/web.php:367-437`**

```php
$hostWithPort = $parsed['host'] . ':' . ($parsed['port'] ?? 80);
$allowedHosts = ['localhost:9200', 'elasticsearch:9200'];
if (!in_array($hostWithPort, $allowedHosts)) { ... 403 ... }
...
$decodedPath = urldecode($parsed['path']);              // line 404 — decoded, then only prefix-matched
preg_match('#^/_snapshot/my_backup/([^/]+)#', $decodedPath, $matches);
...
$ch = curl_init($url);                                  // line 419 — the ORIGINAL url, not the validated one
```

The validation parses one string and the request sends **another**. `$decodedPath` is used for the
snapshot-name check, but `curl_init($url)` receives the untouched user URL, so anything after the
snapshot name — `%2e%2e%2f`, `..;/`, encoded traversal — reaches Elasticsearch unmodified. The route
is **unauthenticated** (registered outside every auth group).

The impact is set by the container config: ES 1.5.1 runs `privileged: true` with the **host root
filesystem mounted at `/mnt/all`** and `path.repo` including it (`docker-compose.yml:61-73`). A
traversal in the snapshot API therefore reaches the *host* filesystem, not just the container's.

Line 431 hands out a flag for `..` + HTTP 400 — the intended solve — but the underlying proxy is a
genuine unauthenticated traversal primitive.

---

### 3.3 🟡 Attacker-controlled filenames on write
**`CrmController.php:75-79`**, **`CrmV1Controller.php:89-93`**, **`CrmController.php:221-225`**

```php
$id = isset($rowData['id']) && $rowData['id'] !== '' ? (string) $rowData['id'] : uniqid();
Storage::disk('local')->put("crm_rows/{$id}.json", json_encode($rowData));
```

`id` is JSON-supplied and goes into the path with no allowlist. Flysystem 3 rejects `..` segments,
and `'throw' => false` (`config/filesystems.php:36`) makes the rejection silent — so this is
contained today, but it is one config flag away from arbitrary write. `saveCsv` is better (it calls
`basename()`, line 222) but still lets the client dictate the stored name, enabling overwrite of
other users' exports.

**Fix:** `$id = (string) Str::uuid();` — never let the client name a file.

---

## 4. Cross-Site Scripting

### 4.1 🟠 Stored XSS — profile description rendered unescaped
**`resources/views/profile/show.blade.php:57`**

```blade
{!! $user->description ? $user->description : '<em class="text-muted">No description provided.</em>' !!}
```

`{!! !!}` is Blade's **raw** echo. `description` is user-controlled
(`UserProfileController.php:166-179`, validated only as `nullable|string`) and stored verbatim. The
edit form is a rich-text editor (`profile/edit.blade.php:175`) so HTML is expected — but nothing
sanitises it on the way in or the way out.

`SecurityFiltersMiddleware` is **not** on `POST /profile` (see `routes/web.php:193` — the group has
`security.filters`, but its tag blocklist at line 177 omits `img`, `a`, `details`, `body`, and every
`on*` handler, so `<img src=x onerror=...>` passes anyway).

Viewing a profile is enough to trigger it, and `/user_profile/{id}` is open to any authenticated user
(§2.4) — worm-able across the tenant.

---

### 4.2 🟠 Stored XSS — user email rendered unescaped in the directory
**`resources/views/users/index.blade.php:106`**

```blade
<td class="text-muted">{!! $user->email ?? '—' !!}</td> {{-- غير مُفلتر --}}
```

The comment translates to "not filtered". Adjacent cells use the safe `{{ }}` (lines 104-105); only
`email` was switched to raw. `email` is accepted at registration and at profile update with Laravel's
`email` rule, which permits quoted local parts — `"<img src=x onerror=alert(1)>"@example.com` is a
*valid* address by RFC 5322 and by Laravel's validator. Payload fires for every user who opens
`/users`, including admins.

---

### 4.3 🟠 DOM XSS — dashboard table built with `innerHTML`
**`resources/views/dashboard/index.blade.php:263-271`**

```js
tbody.innerHTML = data.map(r => `
  <tr>
    ${attrs.map(a => `<td>${String(r[a] ?? '')}</td>`).join('')}        // line 265
```

Row values come from Elasticsearch, which is populated from the EAV tables — i.e. from CSV imports
and from `/attributes` and `/entity-values` submissions. Any stored `<img onerror>` executes for
every dashboard viewer. `innerHTML` on untrusted data with no escaping is the sink.

**Fix:** build cells with `document.createElement('td')` + `textContent`.

---

### 4.4 🟠 XSS via broken attribute quoting (`data-row`)
**`resources/views/dashboard/index.blade.php:267`**

```js
<button class="btn btn-sm btn-success download-btn"
        data-row='${JSON.stringify(r).replace(/'/g,"\\'")}'>
```

The attribute is delimited by **single quotes**, and the escaping is JavaScript's `\'` — a *backslash*
escape. HTML attribute parsing does not honour backslashes: the first `'` in the data closes the
attribute regardless of the backslash in front of it. A record whose `name` is
`' onmouseover=alert(1) x='` breaks out of the attribute and injects a live event handler. This is
the README's "XSS via malformed quoting in name/email".

**Fix:** JSON-encode then HTML-escape (`&#39;`), or stash the row in a JS `Map` keyed by index and
put only the index in the attribute.

---

### 4.5 🟡 DOM XSS — attribute names injected into `innerHTML`
**`resources/views/entity_values/create.blade.php:96-105`**

```js
div.innerHTML = `
    <label class="form-label">... ${attrName}</label>
    <input type="hidden" name="attributes[${attrId}][id]" value="${attrId}">
    <input type="text" name="attributes[${attrId}][value]" ... placeholder="Enter value for ${attrName}">
`;
```

`attrName` is `chk.dataset.name`, sourced from the `attributes` table. Attribute names are created by
any authenticated user via `POST /attributes` (`AttributeController.php:40-56`, validated only as
`required|string`) and by CSV header rows (`CsvImportController.php:154`). Second-order stored XSS,
and `${attrName}` also lands inside a quoted `placeholder=` attribute — attribute-context breakout as
well as element context.

---

### 4.6 🟡 Stored XSS via SVG avatar fetched by the server
**`app/Http/Controllers/UserProfileController.php:91-97`, `110-125`**

```php
} elseif (str_contains($mime, 'svg')) { $extension = 'svg'; }
...
\Storage::disk('public')->put($relativePath, $body);       // raw remote body, unsanitised
$user->avatar = 'storage/' . $relativePath;
```

The remote response body is written verbatim to a **public** disk (`config/filesystems.php:39-45`,
symlinked to `public/storage`) with an `.svg` extension. Rendering inside `<img>` is inert, but
`/storage/avatars/avatar_<id>_<ts>.svg` loaded directly executes its `<script>` **on the application's
own origin** — same-origin session theft. Note the extension can also be forced through the URL path
(lines 94-97) even when the content type disagrees.

---

### 4.7 🟡 Outdated CKEditor 4.14.0 loaded from CDN
**`resources/views/profile/edit.blade.php:173`**

```html
<script src="https://cdn.ckeditor.com/4.14.0/standard/ckeditor.js"></script>
```

CKEditor 4.14.0 (released 2020) is affected by multiple published XSS issues fixed in 4.16.x-4.17.x
(HTML data processor / paste-filter bypasses). Loaded over the network with no SRI hash, so a
compromised or MITM'd CDN response also executes on the CRM origin. This is the README's "outdated
frontend component".

---

## 5. Server-Side Request Forgery

### 5.1 🔴 `/swagger_ui` — unauthenticated SSRF, hostname filter skipped entirely
**`routes/web.php:287-361`**

```php
$parsed = parse_url($remote);
$host = $parsed['host'] ?? '';
if (filter_var($host, FILTER_VALIDATE_IP)) {              // line 326 — ONLY if host is a literal IP
    if (filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        if (preg_match('/^(127\.|10\.|192\.168\.|169\.254\.|172\.(1[6-9]|2[0-9]|3[0-1]))/', $host)) {
            return response()->json(['error' => 'private ipv4 blocked'], 403);
        }
    }
}
$ch = curl_init(); curl_setopt_array($ch, [
    CURLOPT_URL => $remote, CURLOPT_FOLLOWLOCATION => true, ...                  // lines 337-345
]);
```

The whole filter is wrapped in `if (host is an IP literal)`. **`http://localhost:9200/` is not an IP
literal**, so the block never runs. Neither does it run for `elasticsearch`, `mysql`,
`metadata.google.internal`, or any attacker-controlled hostname resolving to 127.0.0.1.

Even for IP literals the regex is bypassable: `http://2130706433/` (decimal), `http://0177.0.0.1/`
(octal), `http://127.1/`, `http://[::ffff:127.0.0.1]/`, `http://0.0.0.0:9200/`.

And `CURLOPT_FOLLOWLOCATION => true` with no post-redirect revalidation means *any* allowed host can
302 the fetch to an internal one. The route is unauthenticated, and the response body is echoed back
(line 359), making this a **fully readable** SSRF. Note the helper functions written for this
(`is_private_ip()` at line 240, `resolve_host_ips()` at line 272) are defined and **never called**.

---

### 5.2 🔴 `/es/fetch/{host}/{path?}` — the SSRF guard compares two attacker-controlled values
**`routes/web.php:206-232`**

```php
$headerHost = $request->header('X-Host', $request->header('Host'));
if ($host !== $headerHost) { ... 403 ... }               // line 211
...
$url = "{$scheme}://{$host}/" . ltrim($path, '/');
$response = Http::get($url);                             // line 225
return response($response->body(), $response->status()); // line 227 — full response returned
```

The "check" requires the URL segment to equal the `X-Host` header — and **the client sends both**.
`GET /es/fetch/elasticsearch:9200/_search?size=10000` with `X-Host: elasticsearch:9200` fetches
anything on the Docker network. Unauthenticated, and the upstream body is returned verbatim.

---

### 5.3 🟠 `/profile/fetch-image` — blocklist SSRF, redirect not revalidated
**`app/Http/Controllers/UserProfileController.php:30-72`**

```php
$parsed = parse_url($imageUrl);
$host = strtolower($parsed['host'] ?? '');
$blockedPatterns = ['/^localhost$/', '/^127\./', '/^10\./', '/^192\.168\./',
                    '/^172\.(1[6-9]|2[0-9]|3[0-1])\./', '/::1/'];       // lines 35-42
...
curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
curl_setopt($ch, CURLOPT_MAXREDIRS, 10);                                 // lines 62-63
```

The comment on line 29 admits it: *"Parse only first host (no DNS resolution)"*.

* **Bypass 1 — DNS:** `http://127.0.0.1.nip.io/` or any attacker-owned A record pointing at
  127.0.0.1. The regex sees a normal hostname.
* **Bypass 2 — redirect:** serve a `302 Location: http://169.254.169.254/…` from a public host. Ten
  redirects are followed with **no re-check**.
* **Bypass 3 — encoding:** `http://2130706433/`, `http://0x7f000001/`, `http://127.1/`.
* **Bypass 4 — missed ranges:** `169.254.0.0/16` (metadata), `100.64.0.0/10` (CGNAT), `0.0.0.0`, and
  every internal *hostname* (`mysql`, `elasticsearch`).

The response body is stored and served back (line 114) and the final URL is returned (line 145), so
this is a readable SSRF, not blind.

---

### 5.4 🟡 `/elasticsearch` — second-order SSRF via `file_get_contents`
**`routes/web.php:390`**

```php
$snapshotsList = @file_get_contents($snapshotsUrl);
```

`allow_url_fopen` fetch built from `$parsed['host']` and `$parsed['port']`. Combined with §3.2 the
same route is both an SSRF and a traversal proxy, and the `@` suppression hides failures.

---

## 6. Open Redirect & OAuth

### 6.1 🟡 Open redirect — `//host` path trick on `/dashboard/{any}`
**`routes/web.php:475-497`**

```php
$after = substr($fullPath, strlen('/dashboard'));
if (strpos($after, '//') === 0) {                  // line 483
    $dest = 'https:' . $after;                     // line 485  →  https://evil.tld/...
    return redirect()->away($dest);                // line 491
}
```

`GET /dashboard//evil.tld/anything` → `302 Location: https://evil.tld/anything`. No allowlist, no
same-origin check. The route also explicitly opts out of bot detection
(`->withoutMiddleware(BotDetectionMiddleware::class)`, line 497) and sits outside every auth group,
so it is reachable unauthenticated — ideal for phishing links that carry the CRM's real domain.

---

### 6.2 🟠 OAuth `redirect_uri` validated by **suffix** match → code theft
**`app/Http/Controllers/OauthController.php:50-62`**

```php
$allowedSuffix = parse_url($request->getSchemeAndHttpHost(), PHP_URL_HOST);   // e.g. "localhost"
$reqHost = parse_url($request->redirect_uri, PHP_URL_HOST);
...
if (!Str::endsWith($reqHost, $allowedSuffix)) { return abort(400, 'Invalid redirect_uri'); }
```

`Str::endsWith()` on a **host string** with no leading-dot boundary. `evil-localhost`,
`notlocalhost`, `attackerlocalhost` all end with `localhost` and are accepted. If the app runs on
`crm.example.com`, then `evilcrm.example.com` *and* `xyzcrm.example.com` pass.

The `oauth_clients` table stores a `redirect_uris` column (`OauthClientsSeeder.php:16`, cast to array
in `OauthClient.php:7`) — the registered value is **never consulted**. The authorization code is then
appended and the browser redirected away (lines 98-101), handing the code to the attacker's host;
`/api/oauth/token` accepts it because it only checks the code's *stored* `redirect_uri` matches what
the client replays (`OauthApiController.php:40`) — the same attacker value.

Additional weaknesses in the same flow:

* **No PKCE**, and no `state` enforcement — `state` is optional (line 39) and never verified.
* `showAuthorizeForm` defaults `redirect_uri` to a hardcoded external URL (line 17).
* Client secret compared with `!==` (`OauthApiController.php:28`) — not constant-time; use `hash_equals()`.
* Client secret stored in plaintext (`OauthClientsSeeder.php:15`: `secret_456789`).

**Fix:** exact string match against the client's registered `redirect_uris`.

---

## 7. Authentication, Session & Anti-Automation

### 7.1 🟠 Rate limiting disabled for HTTP/2 (and HTTP/1.0)
**`app/Providers/RouteServiceProvider.php:27-38`**

```php
$protocol = $request->server('SERVER_PROTOCOL');
if (str_starts_with($protocol, 'HTTP/1.1')) {
    return Limit::perMinute(10)->by($request->user()?->id ?: $request->ip());
}
return Limit::none();                     // line 37 — HTTP/2, HTTP/1.0, anything else
```

This limiter is applied to **both** route groups (lines 41-46), so it is the *only* throttle on login,
OTP verification, and password reset. Speak HTTP/2 (or HTTP/1.0) and every brute-force protection in
the application disappears. `SERVER_PROTOCOL` is also proxy-reported, not trustworthy.

---

### 7.2 🟡 OTP brute force — no attempt counter, predictable generator
**`app/Http/Controllers/OtpController.php:28-57`**, **`LoginController.php:29-33`**, **`EmailVerificationController.php:16`**

```php
if ($request->otp != $user->otp_code) {           // line 42 — loose ==, no attempt counter
    return back()->with('error', 'Invalid OTP code.');
}
```

A wrong code just re-renders the form. The code stays valid for the full 5 minutes
(`LoginController.php:31`), so the search space is 10⁶ with unlimited tries — and §7.1 removes the
only throttle. Generation uses `rand()` (`LoginController.php:29`, `EmailVerificationController.php:16`),
not a CSPRNG; use `random_int(100000, 999999)`. The comparison is `!=`, not `===` — string/int
juggling.

`EmailVerificationController::sendOtp` (line 12) will also mail an OTP to **any address** with no
throttle: mail bombing / spam relay through the CRM's SMTP credentials.

---

### 7.3 🟡 Bot-detection backdoor
**`app/Http/Middleware/BotDetectionMiddleware.php:34-37`**

```php
if (!empty($userAgent) && stripos($userAgent, 'solverfileexpect_2222') !== false) {
    return $next($request);        // skips every check below
}
```

A hardcoded magic User-Agent bypasses the entire WAF-ish layer. Beyond that, the detector is
header-only (lines 44-78): every signal it checks — UA, `Accept-Language`, `Connection`,
`Accept-Encoding`, `Referer` — is attacker-controlled, so it is trivially defeated by copying a real
browser's headers.

---

### 7.4 🟡 `SecurityFiltersMiddleware` is a blocklist WAF with structural gaps
**`app/Http/Middleware/SecurityFiltersMiddleware.php`**

| Line | Rule | Gap |
|---|---|---|
| 201 | SSTI `\{\{.*?\}\}` | misses `{!! !!}` — the exact syntax §1.2 executes |
| 147-151 | "dangerous functions" | browser APIs only; `system`, `exec`, `passthru`, `shell_exec`, `file_put_contents` all pass |
| 177 | tag blocklist | no `img`, `a`, `details`, `body`, `input`, `marquee`; no `on*` handler rule at all (lines 189-198 are empty stubs where that filter used to be) |
| 210-221 | SQLi keywords `and,or,union,where,limit` | needs **two distinct** keywords; `1'/**/oR/**/1=1-- -` is one keyword; comment-splitting and `||`/`&&` evade it entirely |
| 135-144 | SSRF | only literal private **IPv4**; hostnames, IPv6, decimal/octal encodings pass |
| 35-46 | input collection | `$request->all()` + raw body — **headers, cookies and route parameters are never inspected** |

It also runs on only two route groups, so `/profile`, `/swagger_ui`, `/es/fetch`, `/elasticsearch`
and `/dashboard/{any}` are unfiltered.

---

### 7.5 🟡 Permissive CORS on the API
**`config/cors.php:18-32`** — `'paths' => ['api/*']`, `'allowed_origins' => ['*']`,
`'allowed_headers' => ['*']`. Any website can script-read `/api/*` responses. `supports_credentials`
is `false`, which limits it to unauthenticated data — but §7.6's enumeration endpoint is exactly that.

Note `routes/api.php:24` tries to strip CORS with `withoutMiddleware(\Fruitcake\Cors\HandleCors::class)`
while the kernel registers `\Illuminate\Http\Middleware\HandleCors` (`Kernel.php:20`) — **the class
names differ, so the call is a no-op** and CORS stays enabled.

---

### 7.6 🟡 Username enumeration with throttling explicitly removed
**`routes/api.php:24-27`**, **`app/Http/Controllers/Api/EmailStatusController.php:23-30`**

```php
Route::withoutMiddleware([\Fruitcake\Cors\HandleCors::class])
    ->post('/check_email_status', [EmailStatusController::class, 'check'])
    ->withoutMiddleware('throttle')          // rate limit deliberately removed
```

```php
$exists = User::where('email', $email)->exists();
return response()->json([... 'exists' => $exists, 'message' => $exists ? 'Email exists in the system' : 'Email not found']);
```

Unauthenticated, unthrottled, CORS-readable oracle over the entire user table. The login page depends
on it (`auth/login.blade.php:114-127`), so removing the endpoint means reworking that flow — return a
uniform response and gate it behind a throttle instead.

---

### 7.7 🟠 SAML assertion parsed twice — signature-wrapping surface
**`app/Http/Controllers/SamlController.php:63-128`** *(dormant — routes commented out at `web.php:445-447`)*

`processResponse()` validates the signature, but the controller then **re-parses the raw XML by hand**
and takes NameID and attributes from *anywhere* in the document (lines 88-100) rather than from the
node the signature covered. That is the classic XML Signature Wrapping setup: append an unsigned
assertion carrying `email = admin@target`, keep the signed one intact, and the manual XPath picks the
attacker's copy. Compounding it:

* `InResponseTo` is only checked when a request id happens to be in session (line 124) — replay of an
  IdP-initiated response passes.
* Audience is only validated `if ($aud)` exists (line 114) — omit the element, skip the check.
* Users are **auto-provisioned** from the asserted email (lines 136-142), so a forged assertion
  creates the account it then logs into.

**Fix:** use `$auth->getAttributes()` / `$auth->getNameId()` and delete the manual XPath block.

---

### 7.8 ⚪ `2fa_passed` is set but never enforced
`OtpController.php:54` writes `session(['2fa_passed' => true])`; nothing reads it. The `2fa`
middleware (`CheckOtp.php:13`) only checks `otp_pending`, so 2FA state is tracked by the *absence* of
a flag rather than the presence of a positive assertion. `POST /dashboard/load-column`
(`web.php:45-47`) carries `auth` but **not** `2fa`.

---

## 8. Infrastructure & Secrets

### 8.1 🔴 Elasticsearch 1.5.1, privileged, host root filesystem mounted
**`docker-compose.yml:57-75`**

```yaml
elasticsearch:
    image: niche/elasticsearch:1.5.1
    user: root
    privileged: true
    ports: ["9200:9200", "9300:9300"]        # published to the host
    environment:
      path.repo: "/usr/share/elasticsearch/snapshots,/mnt/all"
    volumes:
      - /:/mnt/all   # 🧠 يسمح بالوصول لكل ملفات النظام من داخل الكونتينر
```

Four compounding problems: a 2015 release with well-known unauthenticated RCE and traversal issues; no
authentication whatsoever; ports published on the host (`0.0.0.0:9200`); and `path.repo` pointing at
`/mnt/all`, which **is the host's root filesystem**, inside a `privileged: true` container running as
root. Any of the SSRF primitives in §5 reaches `:9200`, and the snapshot API then reads and writes
host files. This is a container-escape-equivalent configuration.

---

### 8.2 🟠 MySQL published with root/root
**`docker-compose.yml:44-55`**, **`docker/init.sql:6-12`**

```yaml
ports: ["3306:3306"]
environment: { MYSQL_ROOT_PASSWORD: root }
```
```sql
CREATE USER IF NOT EXISTS 'root'@'%' IDENTIFIED BY 'root';
GRANT ALL PRIVILEGES ON crm_main.* TO 'root'@'%'; ...
```

Root from any host with a guessable password, exposed on the host interface. Every application
connection uses it (`config/database.php` — `mysql`, `mysql_hr`, `mysql_support`, `mysql_admin` all
default to root), which is why §1.1's injection reads across all four schemas. The app needs four
least-privilege users, one per schema.

---

### 8.3 🟠 Live secrets shipped in the archive
**`.env`**

```
APP_KEY=base64:oclHuzqiIlbfz5Nbgzi26MQdP585YtmT5c3oKe6L0h0=
APP_SECRET="NUA{7e3c2d1f-9b6a-4cde-a123-0f1e2d3c4b5a}"
DB_PASSWORD=root  /  DB_ADMIN_PASSWORD=root
MAIL_USERNAME=b1b09f2e2f16cc  /  MAIL_PASSWORD=673e0a12bb4fe5
```

`.env` is `.gitignore`d but **is present in the distributed archive**. `APP_KEY` disclosure is the
serious one: it signs and encrypts every session cookie and every `encrypt()` payload — with it, an
attacker forges sessions for any user. Working Mailtrap SMTP credentials are also included. The
`APP_SECRET` value is a flag, and §3.1 provides the read primitive to retrieve it.

**Fix:** rotate `APP_KEY` and the SMTP credentials; ship `.env.example` only.

---

### 8.4 🟠 SAML private key committed to the repository
`storage/saml/saml-private.pem` is git-tracked (verified with `git ls-files`) and loaded by
`config/saml.php:15`. Anyone with the repository can sign as the Service Provider. Rotate the key
pair and move it to a secret store.

---

### 8.5 🟡 `APP_ENV=local`, and the debug flag has been toggled before
`.env` sets `APP_DEBUG=false` (and `docker-compose.yml:13` repeats it), so the README's item 16 is
**not currently active**. But `APP_ENV=local` with `spatie/laravel-ignition` installed means flipping
one flag turns every exception into a page that renders stack frames **and the full environment
including `APP_KEY` and DB credentials**. Git history shows commit `f0bd9d9 "Change APP_DEBUG from
true to false"` — it was on. Set `APP_ENV=production`.

---

### 8.6 ⚪ Information disclosure — shipped artefacts and headers
* `output.txt` (1.2 MB) is a complete `tree` of the source layout, shipped in the archive.
* `supervisord.log` (56 KB) ships with runtime output.
* `robots.txt` is `Disallow:` (empty) — everything indexable.
* No `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, or `Referrer-Policy`
  anywhere in the middleware stack — a CSP alone would blunt §4.1-4.6.
* `config/session.php:171` — `'secure' => env('SESSION_SECURE_COOKIE')` and `SESSION_SECURE_COOKIE`
  is not set in `.env`, so session cookies are sent over plain HTTP.

---

## 9. Functional Bugs (non-security)

These are ordinary defects — several of them break the very features that carry the vulnerabilities.

### 9.1 Fatal: `ProcessCsvJobs` calls a method that does not exist
**`app/Console/Commands/ProcessCsvJobs.php:19`**
```php
CsvImportController::processCsvJob($job);
```
`CsvImportController` has no `processCsvJob()` — only `showForm()` and `upload()`. `php artisan csv:process` dies with *Call to undefined method*.

### 9.2 Fatal: `DashboardController` uses `CrmMain` without importing it
**`app/Http/Controllers/DashboardController.php:108, 115, 131`** — the file imports `Attribute`,
`ElasticService`, `DB` and `Auth` (lines 3-7) but **not** `App\Models\CrmMain`. PHP resolves the
unqualified name to `App\Http\Controllers\CrmMain` → *Class not found* in `loadRow()` and `viewCrm()`.

### 9.3 `DashboardColumnController` inserts columns that don't exist
**`app/Http/Controllers/DashboardColumnController.php:21-26`**
```php
DB::table('crm_main')->insert(['column_name' => $column, 'value' => $val, ...]);
```
`crm_main` has `source_db`, `source_row_id`, `data` (migration `2025_10_09_043223:9-15`). Both
`column_name` and `value` are unknown, and the NOT NULL `source_db`/`data` are missing →
`POST /dashboard/load-column` always throws a SQL error.

### 9.4 `/api/oauth/token` cannot resolve its controller
**`routes/api.php:4`** imports `App\Http\Controllers\OauthApiController`, but the class is declared
`namespace App\Http\Controllers\Api;` (`app/Http/Controllers/Auth/OauthApiController.php:2`) while
living in the `Auth/` **directory**. Three-way mismatch: the import path, the declared namespace, and
the file path all disagree — PSR-4 autoloading fails and the route 500s. The whole OAuth token
exchange is dead.

### 9.5 Duplicate route registrations silently drop handlers
* `routes/api.php:19` and `:29` both declare `GET /api/user` — the later `auth.token` version wins and
  the Sanctum one is unreachable.
* `Auth::routes()` is called twice (`routes/web.php:44` and `:365`) — the second registration replaces
  the first for every auth route.

### 9.6 CSV upload never actually imports
**`routes/web.php:89-99`**
```php
$async = $request->input('async', 0);
if ($async != 1) { return back()->with('success', 'Upload scheduled successfully and will be processed.'); }
```
The form (`resources/views/csv_upload.blade.php:34-55`) never sends `async`, and the hidden inputs that
would are commented out (lines 46-48). So the UI always reports success and imports nothing; there is
no queue or worker to pick the "scheduled" file up either.

### 9.7 The CSV `INSERT` is syntactically broken for ordinary data
**`CsvImportController.php:186`** — because `$value` is interpolated **unquoted**, a normal cell like
`Jane` produces `VALUES (1, 2, Jane, NOW(), NOW())` → *Unknown column 'Jane' in field list*. Import
only succeeds if cells carry their own quotes. The SQLi (§1.1) and this bug are the same line.

### 9.8 PDF export references an uninstalled package
**`CrmController.php:55`** — `\Barryvdh\DomPDF\Facade\Pdf::loadHTML($html)`. `barryvdh/laravel-dompdf`
is **not** in `composer.json` and **not** in `vendor/` (only a maintainer email string matches in
`composer.lock`). `POST /crm/export` with `format=pdf` is a fatal *Class not found*.

### 9.9 The export button can never succeed
**`resources/views/dashboard/index.blade.php:350-352`**
```js
const result = await exportRes.json();
window.open(result.url, '_blank');
```
`exportData()` returns **HTML** (`CrmController.php:60`) or a PDF download — never JSON with a `url`.
`res.json()` throws, the `catch` fires, and the user always sees "Failed to export HTML/PDF".

### 9.10 `dashboard/view-crm.blade.php` is an empty file
0 bytes. `DashboardController::viewCrm()` (line 132) renders it → blank page.

### 9.11 Undefined route breaks the attribute-values page
**`resources/views/attributes/values.blade.php:81`** — `route('attributes.values.destroy', ...)`.
Only `attributes.index`, `attributes.store`, `attributes.values` and `attributes.values.store` are
registered (`routes/web.php:174-178`) → *Route [attributes.values.destroy] not defined*, 500 for the
whole page whenever any value exists.

### 9.12 Stray identifier breaks Swagger UI
**`resources/views/swagger.blade.php:15`** — a bare `route` token sits inside the
`DOMContentLoaded` handler. `ReferenceError: route is not defined` aborts the callback, so
`SwaggerUIBundle` never initialises and `/swagger_ui` renders an empty page.

### 9.13 OTP screen shows a session key that is never set
**`resources/views/auth/otp.blade.php:17, 26`** use `session('email')`, but `OtpController::showForm()`
passes `email` as a **view variable** (`OtpController.php:25`). The address is blank and the hidden
field posts empty.

### 9.14 Periodic-request detector computes garbage
**`app/Http/Middleware/DetectPeriodicRequests.php:35-47`**
```php
$timestamps = array_filter($timestamps, fn($t) => $t >= $now - $this->windowSeconds);
...
for ($i = 1; $i < count($timestamps); $i++) { $diffs[] = $timestamps[$i] - $timestamps[$i - 1]; }
```
`array_filter` **preserves keys**, so after the first eviction the array is keyed `[3,4,5,…]` while the
loop indexes `[1..count-1]` → undefined-key warnings and `null` diffs. Line 58 then compares a
**count** against a **seconds** value (`count($timestamps) >= $this->windowSeconds`), mixing units.
Add `array_values()` and a separate request-count threshold.

### 9.15 `SessionTimerMiddleware` is dead code
Not present in `$middleware`, `$middlewareGroups`, or `$middlewareAliases` in `app/Http/Kernel.php` —
never executes.

### 9.16 `OtpSettingsController` is unroutable and renders a missing view
No route references it, and `index()` returns `view('otp-settings.index')`
(`OtpSettingsController.php:14`) — the only OTP settings view is `resources/views/auth/otp-settings.blade.php`.

### 9.17 `XffLog` model and migration are orphaned
`app/Models/XffLog.php` and `database/migrations/2025_10_11_000000_create_xff_logs_table.php` exist,
but nothing in `app/`, `routes/`, or `database/` writes to `xff_logs`. Dead schema — and the reason
the README's XFF SQLi cannot be reproduced (§10).

### 9.18 `ErpExportController` crashes on non-XML-safe column names
**`ErpExportController.php:33`**
```php
$c->appendChild($xml->createElement($key, htmlspecialchars($value ?? '')));
```
`$key` is a raw JSON key. Any name starting with a digit or containing a space/symbol raises
`DOMException: Invalid Character Error`. Separately, `htmlspecialchars()` **before** `createElement()`
double-escapes: `&` becomes `&amp;amp;` in the output.

### 9.19 `downloadRow` breaks on nested data
**`CrmController.php:93-94`**, **`CrmV1Controller.php:113-114`**
```php
$csv = implode(',', array_keys($data)) . "\n" .
       implode(',', array_map(fn($v) => '"' . str_replace('"', '""', $v) . '"', $data));
```
`str_replace()` on an array/object element raises *Array to string conversion*; any nested JSON value
corrupts the CSV. There is also no `Storage`-relative check that `$data` decoded to an array at all.

### 9.20 `EsSnapshot` default path is a Windows path
**`app/Console/Commands/EsSnapshot.php:13`** — `{--path=C:/mnt/backup}` while the container is Linux
and `docker-compose.yml:69` sets `path.repo` to `/usr/share/elasticsearch/snapshots`. The declared
default never matches; the fallback on line 22 is only reached when the option is absent, which it
never is.

### 9.21 `TemplateController` hands out a flag as a template placeholder
**`app/Http/Controllers/TemplateController.php:76`** — `'flag' => 'NUA{SSTI_IS_COOL}'` is in the
allowlist, so sending `{{ flag }}` in a description returns the flag without any injection at all.

### 9.22 `DashboardController::index/data/search` are unreachable
`routes/web.php:168` comments out `Route::get('/dashboard', [DashboardController::class, 'dashboard'])`
in favour of the inline closure (lines 103-113); `data()` and `search()` are likewise superseded by
the inline `/api/dashboard/data` and `/api/search` closures. Three controller methods — the ones with
the **correct** `$db !== $user->role` check (lines 18, 31, 79) — are dead, while the weaker inline
copies serve traffic.

### 9.23 Documentation/port mismatch
`README.md` tells the user to browse `http://localhost:8080/`, `docker-compose.yml:8` publishes
`8000:8000`, and `openapi.yaml:13` says `http://127.0.0.1:8000/api`.

---

## 10. README items not reproducible in this snapshot

| README item | Status |
|---|---|
| **#1 SQLi — header-assisted (X-Forwarded-For)** | **Absent.** `XffLog` + `xff_logs` migration exist, but no code writes or reads them (§9.17). There is no header→SQL sink anywhere in `app/`. The vulnerable logger appears to have been removed before packaging. |
| **#16 Debug mode enabled (APP_DEBUG)** | **Not active.** `.env` and `docker-compose.yml` both set `false`; git commit `f0bd9d9` turned it off. `APP_ENV=local` + Ignition keeps it one flag away (§8.5). |

All 18 other README items map to findings above:
#2→1.1, #3→3.1, #4→6.1, #5→6.2, #6→2.2, #7→2.1, #8→1.2/9.21, #9→1.2, #10→5.1, #11→5.3,
#12→4.1, #13→4.4, #14→3.2, #15→8.3/8.6, #17→4.7, #18→8.1, #19→1.3/1.4, #20→1.5/1.6.

---

## 11. Fix priority

1. **§1.1** restore the prepared statement (one-line change, removes root-level DB compromise)
2. **§1.2** delete the `Blade::render()` loop (removes RCE)
3. **§3.1** stop trusting a client-supplied path; remove the `password123` fallback
4. **§8.1 / §8.2** unpublish ports 9200/3306, drop `privileged`, remove the `/:/mnt/all` mount, upgrade ES
5. **§1.3** remove `LIBXML_NOENT | LIBXML_DTDLOAD` from the global XML middleware
6. **§2.1** replace the `db` blocklist with an allowlist tied to `$user->role`
7. **§5.1 / §5.2** delete the two unauthenticated fetch routes outright
8. **§8.3 / §8.4** rotate `APP_KEY`, SMTP credentials and the SAML key pair
9. **§4.1 / §4.2** replace `{!! !!}` with `{{ }}`, or sanitise with an HTML purifier
10. **§7.1** make the rate limiter unconditional
