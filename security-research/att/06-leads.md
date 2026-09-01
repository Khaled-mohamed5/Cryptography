# accsupport.att.com — two live leads

Bundle: 1,092,892 bytes. Source map: **HTTP 200 — exposed.**

---

## LEAD 1 (priority) — role is a URL segment

```
path:"/:role/:type?/:cat?/:sub?
```

The application's only real route takes **`:role` as the first path segment**, with three
optional segments after it. Every page is `/<role>/<type>/<cat>/<sub>`.

### Why this matters

A role that lives in the URL is a role the *client* asserts. The question worth answering:

> Does the backend independently verify the caller's role, or does it trust the value the
> client put in the path?

If the app fetches `/api/tickets` differently depending on `:role`, and the API accepts that
role without checking the session, then changing one URL segment crosses an authorisation
boundary. That is **broken access control** — a real, payable finding class, unlike anything
a path scanner produces.

### How to work it

1. Recover the valid role values from the source map (Lead 3), then grep:
   ```bash
   grep -rn "role" src/ --include=*.js | grep -iE "admin|agent|internal|employee|dealer|customer|support" | head -40
   ```
2. For each role, load the route and watch the network tab. Does the API request change?
3. The decisive test: take a request the app makes under a privileged role and **replay it
   with your own low-privilege session cookie**.
   - Returns `403`/`401` → server-side authorisation works. No finding. Move on.
   - Returns `200` with data you should not see → **finding**.

### Boundary — read before testing

`/api/application` on a community-assistance portal may hold real applicants' personal data.

- If a privileged view renders, **stop immediately**. Do not browse, page through, or export.
- The proof is *that the boundary failed*, not *what was behind it*. A screenshot of the
  admin UI loading, or an API returning `200` where `403` was expected, is a complete PoC.
- Harvesting records to "show impact" converts a valid report into a policy violation. The
  program requires you to declare any inadvertent access to real data.
- Verify with two accounts you own wherever possible.

---

## LEAD 2 — the two API endpoints

```
"/api/application
"/api/tickets
```

Support tickets and program applications: both are per-user record stores, which is the
classic IDOR shape.

```bash
# Unauthenticated baseline — what do they return with no session?
curl -s -o /dev/null -w '%{http_code}\n' https://accsupport.att.com/api/tickets
curl -s -o /dev/null -w '%{http_code}\n' https://accsupport.att.com/api/application

# Method handling
curl -s -X OPTIONS -i https://accsupport.att.com/api/tickets | head -20
```

Then, authenticated as yourself, look for an identifier — `id`, `ticketId`, `applicationId`,
`accountNumber` — in any request. If changing it returns another party's record, that is IDOR.
Confirm with a second account of your own; never by reading a stranger's data.

**The regex under-reported here.** Only four fragments matched because endpoints built with
template literals or concatenation (`` `${BASE}/tickets/${id}` ``) do not appear as literal
strings. The source map fixes this.

---

## LEAD 3 (do this first) — the source map is exposed

```
curl -s -o /dev/null -w '%{http_code}\n' .../main.1e5c16f4.js.map   →  200
```

The original un-minified source is published: real variable names, comments, file layout.

```bash
curl -s https://accsupport.att.com/static/js/main.1e5c16f4.js.map -o main.js.map
python3 tools/unmap.py main.js.map ./src
```

Then read the actual code:

```bash
# every endpoint, including dynamically built ones
grep -rnoE '`[^`]*\$\{[^`]*\}[^`]*`' src/ --include=*.js | grep -i api | head -40
grep -rn "axios\|fetch(" src/ --include=*.js | head -40

# authorisation logic — the interesting part
grep -rniE "isadmin|hasrole|permission|authoriz|canview|canedit" src/ --include=*.js | head -40
```

**Is the exposed map itself reportable?** On its own, no — information disclosure with no
direct impact, and the program excludes low-impact issues. Its value is as a tool. If it
reveals a hardcoded credential or an internal endpoint you can then demonstrate access to,
report *that*, and cite the map as how you found it.

---

## Worth a look, lower priority

```
https://attone--c.vf.force.com/articles/Knowledge/sales-integrity-hub
```

A Salesforce Visualforce community (`--c` = custom domain). Salesforce communities have a
well-known misconfiguration class around guest-user object permissions.

Caveats: it is a distinct asset, not `att.com`, and the program excludes *"security
vulnerabilities in third-party products or websites that are not under AT&T's direct
control."* An AT&T-configured community is arguably in their control, but confirm scope
before spending time there.

## Confirmed noise — do not chase

`core-js` · `react` · `redux` · `nextjs.org/docs` · `dashjs` · `hls.js` · `googletagmanager` ·
`w3.org` namespaces · `schema.org` · `fb.me` · `stackoverflow.com` — library and framework
strings compiled into the bundle.

`forms.office.com` and `bit.ly` links are third-party content, out of scope.
