# Outcome and what it means for further work here

**ORB-06 was closed as a duplicate of an existing Informative report.**

Two separate facts are packed into that:

1. **Duplicate** — someone had already reported it. That is unsurprising in
   hindsight. The trigger string is `magic_action:reset_wifi_credentials`, sitting
   in a public repository inside a unit test. Any researcher grepping orb-core
   for hardcoded constants finds it in minutes. Nothing about it required deep
   analysis, which is exactly why it was already taken.

2. **Informative** — TFH does not treat it as a vulnerability. Read together
   with the policy, the implied threat model is that physical proximity to an
   Orb is trusted: an Orb is deployed operator equipment, the magic QR is
   intended recovery tooling, and someone standing in front of the device with a
   printed QR is not in their adversary model.

That second point is the useful one, and it generalises.

## What this rules out

The Orb's attack surface splits into three parts, and this outcome closes two of
them:

| Surface | Status |
|---|---|
| **Proximate** (QR scanner, CAN, UART, physical ports) | Treated as trusted — ORB-06 establishes this |
| **Backend-trusting** (OTA claims, relay messages, jobs) | Excluded by policy: "findings that assume a compromised backend, Orb, or client are ineligible" — this is what sank ORB-01 |
| **Remote, unauthenticated** | The only eligible category |

And from [`COVERAGE.md`](COVERAGE.md), the third category is close to empty. Of
the ten crates that actually ship, none binds a network listener. Zenoh runs on a
unix socket with multicast disabled. The relay client and `orb-security-utils`
both pin CAs. The remote surface is a small number of outbound, pinned, TLS 1.3
connections.

## What that means

Reading these repositories is unlikely to yield another eligible finding. The
combination is structurally unfavourable:

- The source is public, so anything cheap to find has been found — as ORB-06
  demonstrated directly.
- The remote surface is small and well built.
- The two large surfaces that remain are both outside the program's adversary
  model.
- The policy separately requires "a working proof of concept reproducible
  against the running production instance", which source review cannot supply
  for a device nobody outside TFH owns.

## Where the program actually pays

From the published stats: the top bounty range is $1,500–$15,000, and Primary
Assets at critical severity go to $15,000–$25,000. The Primary Assets with live
production instances a researcher can legitimately test are:

- `developer.worldcoin.org`
- the smart contracts (Address Book)
- World App (iOS and Android)

Those permit the production-reproducible PoC the policy demands. The Orb repos
do not, for anyone without a device.

## Kept anyway

The analysis in this directory stands on its technical merits and is worth
keeping as a record — particularly [`COVERAGE.md`](COVERAGE.md), which documents
what was checked and found sound. ORB-01 remains an unresolved question about the
OTA trust chain that TFH may want to look at on their own terms, even though it
is not a bounty candidate under the current policy.
