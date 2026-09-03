# ORB-01 — OTA manifest signature does not cover `sources` or `system_components`

**Severity:** Critical
**Asset:** `worldcoin/orb-software` (Primary Asset, Critical)
**Commit:** `2b4f54dd31ec72b8cafd4d16f5906f8b95b389f3`
**Component:** `update-agent`, `update-agent/core`
**CWE:** CWE-345 (Insufficient Verification of Data Authenticity), CWE-347 (Improper Verification of Cryptographic Signature)

## Summary

An update claim is a JSON document with three security-relevant parts:

| Field | Contents | Signed? |
|---|---|---|
| `manifest` | component names, versions, **sizes, sha256 hashes** | **yes** |
| `sources` | per-component **download URL, sha256 hash, size, mime type** | **no** |
| `system_components` | per-component **write destination**: block device, raw offset, GPT label, CAN address | **no** |

The Ed25519 signature in `manifest-sig` is computed over the raw bytes of the
`manifest` object only. `sources` and `system_components` are outside it.

On their own that would be acceptable, because the signed `manifest` carries the
sha256 of every component and the agent could re-check the installed bytes
against it. It does not: for `mime_type: "application/octet-stream"`,
`Component::process()` is a no-op, so the signed hash is never compared to
anything. The only hash ever verified on that path is `sources[name].hash` —
a value the attacker supplies alongside the blob it describes.

The result is that an attacker who can present a claim to the update agent can
install arbitrary content at an arbitrary offset on the boot device **while
replaying a genuine, unmodified, validly signed Worldcoin manifest**. No key
compromise and no signature forgery is required.

## Root cause

`update-agent/core/src/claim.rs:174-178` — only `manifest_raw` is signed:

```rust
crate::signatures::verify_signature(
    manifest_pubkey,
    signature,
    manifest_raw.as_bytes(),   // <-- `sources` and `system_components` not covered
)?;
```

`update-agent/src/component.rs:262-268` — the attacker-chosen `mime_type`
selects whether the signed hash is checked at all:

```rust
pub fn process(&mut self, dst: &Path, current_slot: Slot) -> eyre::Result<()> {
    match self.source.mime_type {
        MimeType::OctetStream => Ok(()),          // <-- no manifest hash check
        MimeType::XZ => self.process_compressed(dst),
        MimeType::ZstdBidiff => self.process_bidiff(dst, current_slot),
    }
}
```

`self.manifest_component.hash()` is only ever read inside `process_helper()`
(`component.rs:122` and `component.rs:152`), which is reached exclusively from
`process_compressed` and `process_bidiff`. `mime_type` has exactly one use in
the whole crate — the `match` above — so nothing else constrains it.

`update-agent/src/component.rs:739-743` — the only hash actually verified for an
`OctetStream` component:

```rust
util::check_hash(&path, &source.hash)   // `source` is unsigned attacker input
```

`update-agent/src/update/raw.rs:44-69` — the write destination, also unsigned:

```rust
let offset = if slot == Slot::B && self.is_redundant() {
    self.size + self.offset
} else {
    self.offset
};
ensure!(block_dev_len >= src_len + offset, ...);   // only a device-length bound
block_dev.seek(std::io::SeekFrom::Start(offset))?;
std::io::copy(&mut src, &mut block_dev)
```

`self.device` resolves to `/dev/mtdblock0` for `qspi` or the root block device
for `ssd` (`core/src/components.rs:74-81`).

## Exploit chain

1. Obtain any legitimate signed claim (it is served to Orbs by the fleet API and
   cached on-device at `<workspace>/claim.json`).
2. Copy `manifest` and `manifest-sig` across byte for byte. The signature stays
   valid — `UncheckedManifest` deserializes through `serde_json::value::RawValue`
   and signs the exact original bytes, so no canonicalisation subtleties arise.
3. Rewrite the unsigned `sources` entry:
   - `mime_type` → `"application/octet-stream"`, which disables the signed-hash check
   - `url` → any `https://` host the attacker controls, or a `file://` path
   - `hash`/`size` → those of the attacker's payload
4. Optionally rewrite the unsigned `system_components` entry to
   `{"type":"raw","value":{"device":"qspi","offset":0,...}}` to redirect the
   write from its intended partition to the bootloader region.
5. `ClaimBuilder::build()` verifies the signature — it passes. `find_components_without_sources`
   and `find_components_not_in_system` pass, since only names are matched.
6. `fetch()` downloads the payload and checks it against the attacker's own
   `source.hash` — it passes.
7. `process()` returns `Ok(())` without touching the signed hash.
8. `do_install()` writes the payload to the attacker-chosen destination, or for
   `main_mcu` / `sec_mcu` passes it to `orb-mcu-util ... image update`
   (`component.rs:276-324`).

## Preconditions

The attacker must be able to present a claim to the agent. Any one of:

- **Compromise of the update backend or its CDN.** This is precisely the
  scenario the manifest signature exists to contain: with it, a compromised
  backend can only serve genuinely signed images; without it, the backend can
  serve anything. The signature currently provides none of that containment.
- **TLS interception of the claim fetch.** `update-agent/src/client.rs:26-31`
  documents a deliberate decision not to pin certificates, relying on the system
  root store:
  > "We explicitly do not pin certificates and default to using the system's
  > root CAs in the update-agent."
  That is a defensible availability trade-off *only* while the payload signature
  is sound. Note the sibling crate `orb-security-utils` does pin a small CA set
  (`security-utils/src/reqwest.rs`), so the unpinned client is specific to the
  update path.
- **Local write access to the cached claim.** `claim.rs:299-304` reads
  `<workspace>/claim.json` back from disk in recovery mode, and
  `LocalOrRemote::parse` accepts plain paths and `file://` URLs as sources, so
  the whole chain also works fully offline.

## Impact

Persistent arbitrary code execution on the Orb. Writing to raw offset 0 of the
QSPI device targets the bootloader, i.e. below the OS; writing to a GPT label
targets any partition; the `main_mcu`/`sec_mcu` names hand the payload to the
MCU flashing tool. Because the payload is installed with a valid Worldcoin
signature on the manifest, nothing in the update path logs an anomaly.

Note that the MCU secondary slot is separately protected: `bootloader/prj.conf`
sets `CONFIG_BOOT_SIGNATURE_TYPE_ECDSA_P256=y`, so MCUboot still validates MCU
images before swapping them. The Jetson-side partition and raw writes have no
equivalent gate in this path.

## Proof of concept

`poc/poc_signature_scope.rs` builds against the unmodified
`orb-update-agent-core` crate and drives the real
`ClaimVerificationContext` deserializer. Output:

```
=== tampered claim ACCEPTED with a valid, unforged signature ===
  signed manifest hash : aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  unsigned source hash : b6f0c98b42d02b948ed61387716b123165aab0cf1eecd6e8fd0d27ae8da2aed8
  unsigned source url  : Remote(Url { scheme: "https", host: Some(Domain("attacker.example")), path: "/pwn.img", .. })
  unsigned destination : Raw(Raw { device: Qspi, offset: 0, size: 1024, redundancy: Single })
  => arbitrary payload installed to an arbitrary offset
```

The test also asserts the baseline (an honest claim is accepted) so the result
is not an artefact of a malformed fixture.

## Remediation

The minimal fix that closes the chain:

1. **Check the signed hash on every path.** Replace the `OctetStream` arm with a
   verification against `self.manifest_component.hash()` and `.size`, matching
   what `process_helper` already does for the other two mime types:

   ```rust
   MimeType::OctetStream => check_existing_component(
       &self.on_disk,
       self.manifest_component.size,
       self.manifest_component.hash(),
   ),
   ```

   This alone reduces `sources` to a hint about where to fetch bytes from,
   which is the role the doc comment on `Source` already describes.

2. **Bring `sources` and `system_components` under the signature.** Sign the
   whole claim rather than the manifest sub-object, or add the source hashes and
   destinations to the signed manifest. Without this, an attacker can still
   redirect a *legitimately signed* component to a different partition or raw
   offset — a weaker but real primitive.

3. Consider rejecting `Raw` destinations for `device: qspi` at offsets that
   overlap the bootloader, as defence in depth.

## Timeline

- 2026-09-03 — issue identified and PoC written during source review.
