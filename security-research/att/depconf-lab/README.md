# Dependency confusion — self-contained demonstration

Reproduces npm's scoped-package resolution behaviour end to end **on localhost**. Nothing is
published to any public registry; no third-party system is contacted.

## Run

```bash
./run-poc.sh
```

## What it does

Two local registries stand in for the two a real build sees:

| Port | Role | Serves |
|---|---|---|
| 4873 | the organisation's private registry | `@acme-corp/ui-widget@1.0.0`, no scripts |
| 4874 | the public registry | `@acme-corp/ui-widget@9.9.9`, with a `postinstall` |

Then it installs the same dependency twice, changing **one line of `.npmrc`**:

**Scenario A** — scope mapped to the internal registry
```
registry=http://localhost:4874/
@acme-corp:registry=http://localhost:4873/
```
→ installs `1.0.0` from the internal registry. No script runs.

**Scenario B** — scope mapping absent
```
registry=http://localhost:4874/
```
→ resolution falls through to the public registry, installs `9.9.9`, and **`postinstall`
executes**, printing hostname, username and working directory.

That single missing line is the whole vulnerability.

## Why the postinstall matters

npm runs `preinstall`/`postinstall` automatically on install. Whoever controls the package at a
given name therefore gets code execution in the context of whatever performs the install —
typically a CI runner or a developer workstation.

The demo script is deliberately inert: it prints, writes a marker to the system temp directory,
and contacts nothing.

## Notes

- `--unsafe-perm` is passed because npm drops privileges for lifecycle scripts when running as
  root. On a normal user account it is unnecessary.
- `registry.py` advertises `hasInstallScript` in the packument; npm ≥7 consults that flag before
  it will run any lifecycle script, so a registry that omits it will appear to "not run scripts".

## Scope of what this proves

It demonstrates **the mechanism**: that an unclaimed name on a registry earlier in the
resolution order results in arbitrary code execution at install time.

It does **not** demonstrate that any particular organisation's builds fall through — that
depends on their `.npmrc` distribution and is only observable from inside their environment, or
by claiming their namespace, which is an attack rather than a test.

For a report, pair this with the two independently verifiable facts:

1. the target's published code imports from the scope
2. the scope returns `404` on the public registry
