# Coverage and negative results

What was examined and found sound, so the two reported findings are read
against a known surface rather than an unknown one.

## Establishing the production surface

Only ten crates in `orb-software` carry `debian/` packaging and a systemd unit,
so those are what actually runs on an Orb:

```
attest  orb-backend-status  orb-connd  orb-jobs-agent  orbd
se050-reprovision  supervisor  ui  update-agent  update-verifier
```

`wt-video` (a WebTransport video server that binds a port and uses a
self-signed identity), `orb-core/agent-iroh` (a P2P QUIC endpoint) and
`experiments/orb-blob` have no packaging. Under the program's exclusion of
"non-production surfaces" they are out of scope, which is why the unauthenticated
video server is not reported — worth confirming with TFH that it never ships.

## Attacker-reachable input paths

| Surface | Result |
|---|---|
| **Operator QR** (`magic_action:*`) | **ORB-06** — unauthenticated, acts before verification |
| **Wi-Fi QR** (MeCard) | **ORB-06** — unsigned; guard defeated by the magic QR |
| **User QR** (`decode_qr`, `userid:…`) | Sound. Fails closed: if the backend supplies `authenticated_app_data` but the QR carries no hash, `user_status.rs:168-174` rejects the signup |
| **NETCONFIG QR** | Signed (ECDSA P-256, pinned keys). `split_once("SIG:")` scope was checked for a parse/verify mismatch — the MeCard parser stops at the `SIG:` token, and appended fields cannot round-trip through strict base64, so no bypass |
| **Relay / World App messages** | `relay-client/src/tls.rs` pins CAs via `orb_security_utils::certs::all_pem_certs()` |
| **Zenoh pub/sub** | Production config is `unixsock-stream//run/zenohd/zenohd.sock` with `scouting/multicast/enabled: false`. The `tcp/0.0.0.0:7447` config exists only under `tests/` |
| **CAN / UART / DFU** | See below |
| **Backend jobs** (`orb-jobs-agent`) | `shell.rs` uses `Command::new().args()` with no shell, so no injection. Job authenticity depends on the backend, which the program treats as the trust anchor |

## orb-firmware

- `dfu_load` (`lib/dfu/dfu.c:60-134`) bounds every write: `size` is checked
  against both `DFU_BLOCK_SIZE_MAX` and `sizeof(dfu_state.bytes)`, block numbers
  must be sequential, and `wr_idx + size` is re-checked before the `memcpy`.
- `bootloader/prj.conf` sets `CONFIG_BOOT_SIGNATURE_TYPE_ECDSA_P256=y`, so
  MCUboot validates images before swapping — a DFU write alone cannot boot
  attacker code.
- The UART ring buffer cannot over-read: `uart_messaging.c:112-116` only accepts
  a message once `USED_BYTES(read, write) >= payload_size + HEADER_SIZE`, and
  `USED_BYTES` is masked to below the buffer size, so `length < buffer_size`
  always holds when `buf_read_circular` runs.

Two arithmetic notes that are not reachable as written but are worth tightening:
`dfu.c:165` computes `block_count * DFU_BLOCK_SIZE_MAX` in `uint32_t`, which can
wrap for a large attacker-supplied `block_count`; and `dfu.c:222` divides by
`dfu_state.block_count`, which a `block_count` of 0 would make a divide-by-zero.
Both are gated by earlier checks on the paths I traced.

## Cryptographic implementations reviewed and found correct

- `update-agent/core/src/signatures.rs` — `verify_strict`, the right choice.
- `update-agent/core/src/pubkeys.rs` — keys pinned by SHA-256, JWK parsing
  rejects private keys and non-Ed25519 curves.
- `orb-security-utils` — pins a small CA set, TLS 1.3 minimum, redirects
  disabled. `dangerously-allow-http` appears only in `[dev-dependencies]`.
- `orb-relay-messages` `AppAuthenticatedData` — length-prefixed BLAKE3 with
  version and `device_public_key` binding; the legacy unprefixed format is
  documented and rejected once `device_public_key` is set.

## Hardening observations (informational, not submitted)

1. **`AppAuthenticatedData::verify` takes the digest length from the caller.**
   `rust/src/lib.rs:73-91` derives the BLAKE3 XOF output length from
   `external_hash.len()` and only rejects the empty case, so a 1-byte hash is
   compared as 1 byte. `decode_qr_with_version` returns `payload[16..]` with no
   length check, so the QR chooses that length. No production consumer of the
   *new* `verify` is visible in these repositories — orb-core pins an older
   `orb-qr-link` revision and uses the previous API — so this is reported as a
   library-hardening note rather than an exploitable path. Enforcing a fixed
   32-byte digest would remove the question.

2. **`se050-reprovision`'s systemd unit has none of the hardening the other
   nine units carry** — no `ProtectSystem`, `NoNewPrivileges`,
   `CapabilityBoundingSet` or `SystemCallFilter`, where every sibling service
   sets all of them. Not attacker-reachable (oneshot at boot), but inconsistent.

3. **`orb-connd` secure-storage privilege drop fails open on misconfiguration.**
   `secure_storage/subprocess.rs:69-80`: if the `connd` user or group is
   missing, the subprocess is spawned with the parent's uid/gid instead, with
   only a warning. A packaging error would silently remove the privilege
   separation. Failing closed would be safer.

4. **Job-log redaction is command-scoped.** `job_system/sanitize.rs:16` limits
   `COMMANDS_TO_SANITIZE` to `wifi_add`, so any other job carrying a field named
   `pwd`/`token`/`secret` is logged verbatim. Redacting by key name regardless of
   command would be the safer default.

5. **`update-agent` does not use `orb-security-utils`.** It builds its own
   reqwest client on system roots (`client.rs:26-31`) with the trade-off
   documented in a comment. Defensible while the payload signature is sound —
   see ORB-01 for why that matters more than it appears.
