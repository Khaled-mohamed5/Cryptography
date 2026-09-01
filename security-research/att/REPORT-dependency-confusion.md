# HackerOne submission — ready to paste

---

## Title

```
Unclaimed public npm scope @att-bit used by AT&T production applications enables dependency confusion
```

## Asset

`accsupport.att.com` (AT&T Connected Communities Portal) — *Other Assets*, in scope

## Weakness

CWE-427: Uncontrolled Search Path Element

## Severity

**Medium** — see the Severity Rationale section. Do not select High or Critical.

---

## Summary

AT&T production JavaScript served from `accsupport.att.com` imports packages from the private
npm scope `@att-bit`. That scope is **not registered on the public npm registry**.

Any build that resolves `@att-bit/*` against public npm — rather than AT&T's internal registry
— currently fails. If a third party registers the scope, those builds would instead install
attacker-controlled packages. npm executes `preinstall`/`postinstall` scripts automatically, so
this would mean code execution on the machine performing the build.

I have not registered the scope and have not published any package. This report documents the
precondition only.

---

## Steps to reproduce

**1. Confirm AT&T production code depends on the `@att-bit` scope.**

```bash
curl -s https://accsupport.att.com/ | grep -oE '/static/js/main\.[a-f0-9]+\.js'
curl -s https://accsupport.att.com/static/js/main.1e5c16f4.js.map -o main.js.map
grep -o '@att-bit/[a-z.-]*' main.js.map | sort -u
```

Returns package names including:

```
@att-bit/duc.components.checkbox
@att-bit/duc.components.modal
@att-bit/duc.components.radio-group
@att-bit/duc.components.select
@att-bit/duc.components.text-area
@att-bit/duc.components.text-field
```

**2. Confirm the scope is unregistered on public npm.**

```bash
for p in checkbox modal select text-field text-area radio-group; do
  printf '%-46s ' "@att-bit/duc.components.$p"
  curl -s -o /dev/null -w '%{http_code}\n' \
    "https://registry.npmjs.org/@att-bit%2Fduc.components.$p"
done
```

Observed:

```
@att-bit/duc.components.checkbox               404
@att-bit/duc.components.modal                  404
@att-bit/duc.components.select                 404
@att-bit/duc.components.text-field             404
@att-bit/duc.components.text-area              404
@att-bit/duc.components.radio-group            404
```

`404` from `registry.npmjs.org` confirms no package exists under `@att-bit` publicly, and the
scope is available for registration by anyone.

---

## Impact

npm resolves packages by name. A build resolving `@att-bit/*` against the public registry
today fails; if the scope were registered by a third party, the same build would install that
party's package instead of AT&T's internal one.

Because npm runs lifecycle scripts on install, this would give the scope owner code execution
in the context of whatever performs the install — typically CI runners or developer
workstations, which commonly hold source code, registry credentials, and deployment access.

Configurations where a scoped package falls through to the public registry include:

- a CI runner provisioned without the internal registry entry for this scope
- a container build that does not mount the organisation's `.npmrc`
- a developer running `npm install` outside the corporate network
- a new repository copying `package.json` without the corresponding `.npmrc`

**I have not attempted to determine whether any AT&T build actually falls back**, as doing so
would require registering the scope and executing code on AT&T infrastructure. This report
therefore establishes the precondition, not a demonstrated compromise.

Prior work on this class: Alex Birsan, *"Dependency Confusion: How I Hacked Into Apple,
Microsoft and Dozens of Other Companies"* (2021).

---

## Severity rationale

Rated **Medium** deliberately.

Successful exploitation would be High or Critical, but it depends on a misconfiguration whose
presence I cannot verify without attacking AT&T's build infrastructure. Claiming High or
Critical here would overstate what the evidence supports.

Suggested vector, if one is required:
`CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H`

---

## Remediation

Register the `@att-bit` scope on the public npm registry under an AT&T-controlled account and
publish placeholder packages for each name in use. This is free and permanently removes the
possibility of a third party claiming it.

Additionally, enforce scope-to-registry mapping so `@att-bit` can never resolve publicly:

```ini
# .npmrc
@att-bit:registry=https://<internal-registry>/
```

Distribute that configuration to all CI images and developer environments.

---

## Testing performed

- Retrieved publicly served JavaScript and its source map from `accsupport.att.com`
- Issued HTTP GET requests to the public npm registry API

No packages were registered or published. No AT&T system was authenticated to, modified, or
accessed beyond publicly served static files.

## Demonstration

I have deliberately not registered the `@att-bit` scope or published any package under it.
Doing so would execute code on AT&T build infrastructure, which falls under the program's
exclusion of attacks against AT&T infrastructure, and would take place on the public npm
registry rather than on an in-scope AT&T asset.

If the security team would like this demonstrated further, please advise how you would like to
proceed. Note that registering the scope is also the remediation, so AT&T claiming it directly
both resolves the issue and removes any need for a third-party demonstration.
