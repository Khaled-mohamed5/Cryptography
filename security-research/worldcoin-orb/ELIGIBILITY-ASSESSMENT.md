# Eligibility assessment — ORB-01 against the TFH HackerOne policy

Written after reading the published program policy (last updated 2026-08-04).

**Recommendation: do not submit ORB-01 to HackerOne as written.**

## Why

ORB-01 is a real defect. It is also, as framed, excluded by the program policy
on at least four independent grounds. Each one alone is enough to close the
report.

### 1. Every precondition is on the exclusion list

The finding needs one of three entry points. The policy rules out all three:

| ORB-01 precondition | Policy text |
|---|---|
| Compromised update backend or CDN | *"Findings that assume a compromised backend, Orb, or client, or that target non-authoritative fields the backend re-checks, are ineligible."* |
| TLS interception of the claim fetch | *"Attacks requiring MITM or physical access to a user's device"* |
| Local write access to the cached claim | *"Findings that require prior compromise of the target as a precondition for exploitation"* |

The Orb-specific section repeats the point: *"Any vulnerability that assumes
prior compromise. All vulnerabilities should be applicable to production devices
and exploitable remotely, from any of the available remotely accessible
interfaces."*

This is the fatal one. The whole argument for ORB-01's severity is *"the
signature is what should contain a backend or CDN compromise."* The program has
stated that the backend is its trust anchor and that findings premised on
backend compromise are out of scope. That is a threat-model decision on their
side, and it is theirs to make.

### 2. No PoC against a running production instance

*"Vulnerabilities reported in open-source repositories owned by TFH or Worldcoin
Foundation that are based solely on source code review without a working proof
of concept or video demonstrating the issue is reproducible against the running
production instance."*

Our PoC is a unit test against the open-source crate. It proves the signature
scope claim, which is exactly what it was built to prove — but it is not a
production-instance reproduction, and the policy asks for one.

There is a documented path for device-only findings:

> *"If an exploit can only be performed on an actual device, and after careful
> consideration by the TFH team, a test environment can be supplied to the
> researcher for PoC development and execution."*

That path exists, but it does not rescue ORB-01, because ORB-01 still fails
criterion 1 regardless of where it is demonstrated.

### 3. It is precisely the submission shape they call out

*"AI-assisted reports produced from reading our public source are the most
common false positive we receive."*

The policy has a whole section for this. A source-review finding with stated
preconditions that land in the excluded set is the archetype it describes.

### 4. Offline / command-line tooling

*"Findings on non-production surfaces, including devnet or testnet ... offline or
command-line tools ..."*

This does not apply to `update-agent` itself (a production on-device daemon),
but it does cover ORB-04 and ORB-05 in `orb-secure-element`, which are
command-line signing tools. Those were already only informational.

## Cost of submitting anyway

Reports closed as N/A or Informative reduce HackerOne signal, and signal gates
private program invitations. Trading that for an estimated low chance of a
reward is a bad trade on a report we can already predict the objection to.

If you want to submit despite this, the honest framing is a hardening report
with no bounty expectation, saying up front that you have read the exclusions
and believe the signature-scope issue is worth fixing anyway. Some programs
appreciate that; it should not be presented as a bounty claim.

## What would make a finding eligible here

The bar, read off the policy:

- Production asset, production instance.
- Remotely exploitable from an interface the Orb actually exposes.
- No assumed prior compromise of backend, Orb, or client.
- Working PoC, or a device-only finding credible enough that TFH offers a test
  environment.

For the Orb repositories specifically, that points at input paths reachable by
an unprivileged remote party rather than at the update trust chain:

- **Relay protocol handling** — `orb-relay-client`, `orb-relay-messages`, and
  the `AppAuthenticatedData` verification. Messages here originate from the
  World App, i.e. from a party the Orb does not control.
- **QR code path** — `qr-link` plus the `orb-core` scan plans. A malicious QR
  code is attacker-supplied input over the Orb's intended input channel and does
  not require prior compromise. (`qr-link` itself reviewed clean; the consumers
  of `decode_qr_with_version` were not audited in depth — note that it accepts
  an empty `app_authenticated_data_hash` when the payload is exactly 16 bytes,
  which is worth tracing into the callers.)
- **Wi-Fi / backend provisioning** — `orb-backend-connect`,
  `wpa-supplicant-interface`.

Outside the Orb repos, the Primary Assets with live production instances are
`developer.worldcoin.org`, the smart contracts, and the World App — all of which
permit the production-reproducible PoC the policy asks for.

## Status of the existing write-up

`HACKERONE-SUBMISSION.md` is kept because the technical content is accurate and
the issue is worth fixing. It should not be filed as a bounty submission in its
current form.
