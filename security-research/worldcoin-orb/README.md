# Worldcoin Orb — security review

Review of the in-scope Worldcoin Orb repositories, performed against the
public sources on 2026-09-03.

| Repository | Commit reviewed | Result |
|---|---|---|
| `worldcoin/orb-software` | `2b4f54dd31ec72b8cafd4d16f5906f8b95b389f3` | 1 critical, 1 high, 2 low |
| `worldcoin/orb-secure-element` | `4773bf5` | 2 informational |
| `worldcoin/orb-firmware` | `a092441` | no issues found |
| `worldcoin/orb-rustzone` | `8899fe1` | no issues found |
| `worldcoin/orb-core` | `9c8e1af` | 1 high (with orb-software) |
| `worldcoin/orb-messages`, `orb-relay-messages` | — | no issues found |

## Findings

| # | Title | Severity |
|---|---|---|
| [ORB-01](findings/ORB-01-update-agent-signature-scope.md) | OTA manifest signature does not cover `sources` or `system_components`, allowing installation of arbitrary unsigned images | **Critical** |
| [ORB-02](findings/ORB-02-loader-verify-strict.md) | `update-agent-loader` uses non-strict Ed25519 verification | Low |
| [ORB-03](findings/ORB-03-loader-random-key-fallback.md) | Loader silently falls back to a random verifying key when built without a pinned pubkey | Low |
| [ORB-04](findings/ORB-04-secure-element-never-fail.md) | `NEVER_FAIL` build path emits a forged signature and exits successfully | Informational |
| [ORB-05](findings/ORB-05-secure-element-hygiene.md) | Memory-handling hygiene issues in `orb-secure-element.c` | Informational |
| [ORB-06](findings/ORB-06-unauthenticated-magic-qr-network-takeover.md) | Unauthenticated QR codes reset an Orb's Wi-Fi config and move it onto an attacker's network | **High** |

**ORB-06 is the one to submit.** It needs no assumed compromise, no MITM and no
secret, so it survives the program's exclusion list — see
[`ELIGIBILITY-ASSESSMENT.md`](ELIGIBILITY-ASSESSMENT.md). Paste-ready write-up:
[`HACKERONE-SUBMISSION-ORB-06.md`](HACKERONE-SUBMISSION-ORB-06.md); attach the
two QR images and the crate in [`poc-orb06/`](poc-orb06/).

**ORB-01 should not be submitted as a bounty claim.** The defect is real and the
PoC in [`poc/`](poc/) runs against the real `orb-update-agent-core` code, but
every entry point it needs is on the program's exclusion list. The write-up in
[`HACKERONE-SUBMISSION.md`](HACKERONE-SUBMISSION.md) is kept for reference and
for a possible hardening report.

## Reproducing the PoCs

**ORB-06** — runs standalone, no clone needed:

```sh
cd poc-orb06 && cargo run
```

`poc-orb06/src/upstream/` holds `orb-connd/src/service/{wifi,mecard}.rs` copied
verbatim; only import paths and the error type were changed so they build
outside the workspace. Expected output: [`poc-orb06/expected-output.txt`](poc-orb06/expected-output.txt).
The two attack QR codes are `step1-magic-reset.png` and `step2-attacker-wifi.png`.

**ORB-01** — needs the upstream tree:

```sh
git clone https://github.com/worldcoin/orb-software
cd orb-software
git checkout 2b4f54dd31ec72b8cafd4d16f5906f8b95b389f3

cp /path/to/poc/poc_signature_scope.rs update-agent/core/tests/
cat /path/to/poc/dev-deps.toml >> update-agent/core/Cargo.toml

cargo test -p orb-update-agent-core --test poc_signature_scope -- --nocapture
```

Expected output is in [`poc/expected-output.txt`](poc/expected-output.txt).

## Coverage

[`COVERAGE.md`](COVERAGE.md) records what was examined and found sound — the
production surface (only ten crates ship), every attacker-reachable QR and
network input, the firmware DFU/UART bounds, and the crypto that is correctly
implemented. It also lists five hardening observations that are real but not
worth a bounty submission.

## Scope note

Only the source repositories listed above were reviewed. No testing was
performed against Worldcoin infrastructure, live Orbs, or any deployed
endpoint — every finding here comes from source analysis, and the PoC runs
entirely locally against the open-source crate.
