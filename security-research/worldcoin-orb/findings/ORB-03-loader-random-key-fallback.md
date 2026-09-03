# ORB-03 — Loader silently falls back to a random verifying key

**Severity:** Low
**Asset:** `worldcoin/orb-software`
**Component:** `update-agent-loader/src/lib.rs:36-38`

## Detail

```rust
let vk: VerifyingKey = BUILD_TIME_PUBKEY
    .map(|b64| { ... })
    .unwrap_or_else(|| {
        SigningKey::generate(&mut rand::thread_rng()).verifying_key()
    });
```

If `ORB_UPDATE_AGENT_LOADER_PUBKEY` is unset at build time, the loader is built
with a freshly generated random public key whose private half is discarded.

This fails **closed** — no signature can ever verify against it, so a build with
this defect cannot be tricked into running an unsigned binary. The problem is
that the failure is silent and only manifests at runtime, as a signature
verification error indistinguishable from a genuinely bad payload. A build
that should not have been produced at all instead ships and breaks in the field.

## Remediation

Make the missing environment variable a build failure:

```rust
const BUILD_TIME_PUBKEY: &str = env!("ORB_UPDATE_AGENT_LOADER_PUBKEY");
```

or keep `option_env!` and add a `compile_error!` guard for release profiles, in
the same style as the existing `allow_http` guard at `download.rs:81-82`.
