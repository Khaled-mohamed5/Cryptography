# HackerOne submission — copy/paste ready

Everything below the line is the report body. Fill the H1 metadata fields first:

| H1 field | Value |
|---|---|
| **Title** | OTA update signature does not cover `sources` or `system_components`, allowing installation of arbitrary unsigned images on the Orb |
| **Asset** | `https://github.com/worldcoin/orb-software` (Primary Asset, Critical) |
| **Weakness** | CWE-347 Improper Verification of Cryptographic Signature (secondary: CWE-345) |
| **Severity** | High — `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H` (8.1). See *Severity rationale*. |
| **Attachments** | `poc_signature_scope.rs`, `expected-output.txt` |

---

## Summary

`orb-update-agent` gates OTA installs on an Ed25519 signature over the update
claim. That signature covers only the claim's `manifest` object. The `sources`
object (per-component download URL, sha256 and mime type) and the
`system_components` object (per-component write destination — block device, raw
offset, GPT label, CAN address) are outside the signed bytes.

That would still be safe, because the signed `manifest` carries a sha256 for
every component and the agent could check installed bytes against it. It does
not. When a component's `mime_type` is `application/octet-stream`,
`Component::process()` is a no-op and the signed hash is never read. The only
hash verified on that path is `sources[name].hash` — a value supplied by
whoever supplied the blob.

Consequently an attacker who can present a claim to the update agent can install
arbitrary content at an arbitrary offset on the boot device **while replaying a
genuine, byte-identical, validly signed Worldcoin manifest**. No key compromise
and no signature forgery is involved.

I have a runnable proof of concept that drives the real
`ClaimVerificationContext` deserializer in the unmodified `orb-update-agent-core`
crate and shows a tampered claim being accepted.

## Affected version

Repository `worldcoin/orb-software`, commit
`2b4f54dd31ec72b8cafd4d16f5906f8b95b389f3` (`main`, 2026-09-02). All line
numbers below refer to that commit.

## Vulnerability details

### 1. The signature covers only `manifest`

`update-agent/core/src/claim.rs:174-178`:

```rust
crate::signatures::verify_signature(
    manifest_pubkey,
    signature,
    manifest_raw.as_bytes(),   // sources and system_components are not covered
)?;
```

`manifest_raw` is captured through `serde_json::value::RawValue`
(`claim.rs:388-403`), so the exact original bytes of the `manifest` sub-object
are what get verified. The signature itself is implemented correctly —
`verify_strict`, keys pinned by SHA-256 (`core/src/pubkeys.rs`). The problem is
purely its scope.

The other two top-level objects are deserialized straight out of the untrusted
document (`core/src/claim.rs:369-380`, serde attributes elided):

```rust
pub struct UncheckedClaim {
    version: String,
    manifest: UncheckedManifest,
    #[serde(rename = "manifest-sig")]
    signature: Option<String>,
    pub sources: HashMap<String, Source>,            // unsigned
    system_components: crate::Components,            // unsigned
}
```

The only cross-checks applied to them are name-existence checks
(`find_components_without_sources`, `find_components_not_in_system`,
`claim.rs:149-162`). Neither compares a hash, a size, or a destination.

### 2. The signed hash is skipped for `octet-stream`

`update-agent/src/component.rs:262-268`:

```rust
pub fn process(&mut self, dst: &Path, current_slot: Slot) -> eyre::Result<()> {
    match self.source.mime_type {
        MimeType::OctetStream => Ok(()),          // signed hash never checked
        MimeType::XZ => self.process_compressed(dst),
        MimeType::ZstdBidiff => self.process_bidiff(dst, current_slot),
    }
}
```

`self.manifest_component.hash()` — the signed value — is read at exactly two
places, `component.rs:122` and `component.rs:152`, both inside
`process_helper()`. `process_helper()` is reached only from `process_compressed`
and `process_bidiff`. The `OctetStream` arm reaches neither, and the component's
signed `size` is likewise never checked on that path.

`mime_type` has exactly one use in the entire crate — the `match` above — so
nothing constrains an attacker's choice of it:

```
$ grep -rn "mime_type" update-agent/src update-agent/core/src | grep -v tests
update-agent/src/component.rs:263:        match self.source.mime_type {   # the dispatch above
update-agent/core/src/claim.rs:45:    pub mime_type: MimeType,           # the field declaration
```

### 3. The only hash actually checked is the attacker's own

`update-agent/src/component.rs:739-743`:

```rust
util::check_hash(&path, &source.hash)   // `source` is unsigned attacker input
```

### 4. The write destination is attacker-chosen too

`update-agent/src/update/raw.rs:44-69`:

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

`self.device` resolves to `/dev/mtdblock0` for `"qspi"` or the root block device
for `"ssd"` (`core/src/components.rs:74-81`). So a `Raw` destination with
`offset: 0` on `qspi` targets the bootloader region. For components named
`main_mcu` or `sec_mcu`, `do_install()` instead hands the blob to
`orb-mcu-util --can-fd image update` (`component.rs:276-324`).

### Full chain

1. Obtain any legitimate signed claim. It is served by the fleet API
   (`GET /api/v2/orbs/{id}/claim`) and cached on-device at
   `<workspace>/claim.json` (`claim.rs:94-96`, `claim.rs:317-324`).
2. Copy `manifest` and `manifest-sig` across byte for byte — the signature
   stays valid.
3. Rewrite the unsigned `sources` entry: `mime_type` →
   `"application/octet-stream"`, `url` → an attacker-controlled `https://` host
   (or a `file://` path), `hash`/`size` → those of the attacker payload.
4. Optionally rewrite the unsigned `system_components` entry to
   `{"type":"raw","value":{"device":"qspi","offset":0,...}}`.
5. `ClaimBuilder::build()` verifies the signature — passes.
6. `fetch()` checks the download against the attacker's own `source.hash` — passes.
7. `process()` returns `Ok(())` without touching the signed hash.
8. `do_install()` writes the payload to the attacker-chosen destination.

## Steps to reproduce

The PoC builds against the unmodified crate and exercises the real deserializer.
It runs entirely locally — no Worldcoin infrastructure is contacted.

```sh
git clone https://github.com/worldcoin/orb-software
cd orb-software
git checkout 2b4f54dd31ec72b8cafd4d16f5906f8b95b389f3

# attachment 1
cp /path/to/poc_signature_scope.rs update-agent/core/tests/

# the PoC needs a few test-only deps
cat >> update-agent/core/Cargo.toml <<'TOML'

[dev-dependencies]
serde_json = { workspace = true, features = ["raw_value"] }
base64.workspace = true
sha2.workspace = true
hex = "0.4.3"
TOML

cargo test -p orb-update-agent-core --test poc_signature_scope -- --nocapture
```

The PoC uses a locally generated Ed25519 key in place of the real manifest key,
because the point being demonstrated is that the attacker never needs to touch
the key at all — the tampered fields simply are not in the signed message. The
`legitimate_claim_is_accepted` test establishes the baseline so the result is
not an artefact of a malformed fixture.

### Observed output

```
running 3 tests
[local] claim pointing at /tmp/evil.img accepted
[baseline] honest claim accepted
test local_file_source_is_accepted_too ... ok
test legitimate_claim_is_accepted ... ok

=== tampered claim ACCEPTED with a valid, unforged signature ===
  signed manifest hash : aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  unsigned source hash : b6f0c98b42d02b948ed61387716b123165aab0cf1eecd6e8fd0d27ae8da2aed8
  unsigned source url  : Remote(Url { scheme: "https", host: Some(Domain("attacker.example")), path: "/pwn.img", .. })
  unsigned destination : Raw(Raw { device: Qspi, offset: 0, size: 1024, redundancy: Single })
  => arbitrary payload installed to an arbitrary offset

test tampered_claim_with_untouched_signature_is_still_accepted ... ok

test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

The signature verified. The blob that would be installed, the host it comes
from, and the offset it lands at were all chosen by the attacker.

## Impact

Persistent arbitrary code execution on the Orb, at or below the OS.

- Raw offset 0 on the QSPI device targets the bootloader, i.e. beneath the root
  filesystem and beneath any OS-level integrity control.
- A GPT label targets any partition on the root block device.
- Component names `main_mcu` / `sec_mcu` route the payload into the MCU flashing
  tool.

Because the manifest signature genuinely validates, the update path logs a
normal, correctly signed update. Nothing in `update-agent` records an anomaly.

The security property the manifest signature is meant to establish — *only
images signed by Worldcoin can be installed on an Orb* — does not hold. The
practical consequence is that the signature does not contain a compromise of the
update backend or its CDN, which is the main thing a payload signature is for.

One mitigating detail, stated for completeness: the MCU secondary slot is
independently protected. `orb-firmware/bootloader/prj.conf` sets
`CONFIG_BOOT_SIGNATURE_TYPE_ECDSA_P256=y`, so MCUboot still validates MCU images
before swapping them. The Jetson-side partition and raw writes have no
equivalent gate in this path.

## Preconditions

Stating these plainly, since they drive severity. The attacker needs to get a
claim in front of the update agent. Any one of:

- **Compromise of the update backend or its CDN.** This is the scenario the
  manifest signature exists to contain. With a sound signature, a compromised
  backend can only serve genuinely signed images; as implemented, it can serve
  anything.
- **TLS interception of the claim fetch.** `update-agent/src/client.rs:26-31`
  documents a deliberate decision not to pin certificates:
  > *"We explicitly do not pin certificates and default to using the system's
  > root CAs in the update-agent."*
  That is a reasonable availability trade-off **only** while the payload
  signature is sound, and it is specific to this crate — the sibling
  `orb-security-utils` does pin a small CA set
  (`security-utils/src/reqwest.rs:81-91`). So the update path is the one place
  where transport trust is broad *and* payload trust is broken.
- **Local write access to the cached claim.** `claim.rs:299-304` reads
  `<workspace>/claim.json` back from disk in recovery mode, and
  `LocalOrRemote::parse` accepts plain paths and `file://` URLs as sources
  (`core/src/file_location.rs:55-72`), so the chain also works fully offline.
  The PoC's third test covers this variant.

## Severity rationale

I scored `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H` = **8.1 High**, taking `AC:H`
because the attacker needs one of the positions above rather than being able to
reach the agent unaided.

I would not object to Critical: the affected repository is a Primary Asset rated
Critical, the outcome is bootloader-level persistence, and the flaw removes the
single control that is supposed to make a backend or CDN compromise survivable
rather than fleet-ending. I have deliberately not tested against any Worldcoin
infrastructure, so I am not asserting any particular entry point is reachable
today — I will defer to your rating.

## Suggested remediation

**1. Check the signed hash on every path.** The minimal change that closes the
chain — replace the `OctetStream` arm so it validates against the signed
manifest values, matching what `process_helper` already does for the other two
mime types:

```rust
MimeType::OctetStream => check_existing_component(
    &self.on_disk,
    self.manifest_component.size,
    self.manifest_component.hash(),
),
```

This reduces `sources` to a hint about where to fetch bytes from, which is the
role the doc comment on `Source` already describes
(`core/src/claim.rs:40-41`).

**2. Bring `sources` and `system_components` under the signature.** Sign the
whole claim rather than the `manifest` sub-object, or move the source hashes and
destinations into the signed manifest. Without this, an attacker can still
redirect a *legitimately signed* component to a different partition or raw
offset — a weaker primitive, but a real one.

**3. Defence in depth.** Consider rejecting `Raw` destinations on `qspi` at
offsets overlapping the bootloader, and adding a regression test that asserts a
claim whose `sources` differ from a previously signed claim is rejected.

## Disclosure

Source-code analysis only. No testing was performed against Worldcoin
infrastructure, live Orbs, or any deployed endpoint. The PoC runs locally
against the open-source crate. Happy to hold public disclosure until you have
shipped a fix.
