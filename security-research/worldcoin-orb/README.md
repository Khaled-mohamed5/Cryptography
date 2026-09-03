# Worldcoin Orb — security review

Review of the in-scope Worldcoin Orb repositories, performed against the
public sources on 2026-09-03.

| Repository | Commit reviewed | Result |
|---|---|---|
| `worldcoin/orb-software` | `2b4f54dd31ec72b8cafd4d16f5906f8b95b389f3` | 1 critical, 2 low |
| `worldcoin/orb-secure-element` | `4773bf5` | 2 informational |
| `worldcoin/orb-firmware` | `a092441` | no issues found |
| `worldcoin/orb-rustzone` | `8899fe1` | no issues found |
| `worldcoin/orb-core` | `9c8e1af` | no issues found |
| `worldcoin/orb-messages`, `orb-relay-messages` | — | no issues found |

## Findings

| # | Title | Severity |
|---|---|---|
| [ORB-01](findings/ORB-01-update-agent-signature-scope.md) | OTA manifest signature does not cover `sources` or `system_components`, allowing installation of arbitrary unsigned images | **Critical** |
| [ORB-02](findings/ORB-02-loader-verify-strict.md) | `update-agent-loader` uses non-strict Ed25519 verification | Low |
| [ORB-03](findings/ORB-03-loader-random-key-fallback.md) | Loader silently falls back to a random verifying key when built without a pinned pubkey | Low |
| [ORB-04](findings/ORB-04-secure-element-never-fail.md) | `NEVER_FAIL` build path emits a forged signature and exits successfully | Informational |
| [ORB-05](findings/ORB-05-secure-element-hygiene.md) | Memory-handling hygiene issues in `orb-secure-element.c` | Informational |

ORB-01 is the one worth submitting. It has a runnable proof of concept in
[`poc/`](poc/) that verifies against the real `orb-update-agent-core` code.

A paste-ready HackerOne write-up of ORB-01 is in
[`HACKERONE-SUBMISSION.md`](HACKERONE-SUBMISSION.md). Attach
`poc/poc_signature_scope.rs` and `poc/expected-output.txt` to the report.

## Reproducing the PoC

```sh
git clone https://github.com/worldcoin/orb-software
cd orb-software
git checkout 2b4f54dd31ec72b8cafd4d16f5906f8b95b389f3

cp /path/to/poc/poc_signature_scope.rs update-agent/core/tests/
cat /path/to/poc/dev-deps.toml >> update-agent/core/Cargo.toml

cargo test -p orb-update-agent-core --test poc_signature_scope -- --nocapture
```

Expected output is in [`poc/expected-output.txt`](poc/expected-output.txt).

## Scope note

Only the source repositories listed above were reviewed. No testing was
performed against Worldcoin infrastructure, live Orbs, or any deployed
endpoint — every finding here comes from source analysis, and the PoC runs
entirely locally against the open-source crate.
