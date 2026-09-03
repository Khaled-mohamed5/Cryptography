# ORB-02 — `update-agent-loader` uses non-strict Ed25519 verification

**Severity:** Low
**Asset:** `worldcoin/orb-software`
**Component:** `update-agent-loader/src/memfile.rs:268`

## Detail

The loader downloads a binary and `fexecve`s it, gating on an Ed25519 signature.
It verifies with `Verifier::verify`:

```rust
pubkey.verify(data, &signature).map_err(|e| { ... })?;
```

`update-agent/core/src/signatures.rs:29` uses `verify_strict` for the same
primitive. `verify_strict` additionally rejects small-order public keys and
non-canonical `R`/`A` encodings, which is what makes signature verification
agree across implementations.

Because the verifying key here is fixed at build time
(`ORB_UPDATE_AGENT_LOADER_PUBKEY`) and is not attacker-supplied, this is not
exploitable as a forgery — the practical consequence is signature malleability:
a third party who observes a signed binary can produce a different byte sequence
that also verifies. It is worth fixing for consistency with the rest of the
codebase and to avoid depending on the key-provenance argument.

## Remediation

Use `verify_strict` here as well.

## Note on ordering

`memfile.rs:264-265` truncates the memfd *before* calling `verify`. The
truncated file is not returned on the error path (`self` is consumed and
dropped, and the `MemFile<Verified>` is only constructed after verification
succeeds), so this is not exploitable — but verifying before mutating would be
the clearer order.
