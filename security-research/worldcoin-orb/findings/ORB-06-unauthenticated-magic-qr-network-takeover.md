# ORB-06 — Unauthenticated QR codes reset an Orb's network config and move it onto an attacker's Wi-Fi

**Severity:** `CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:L/VI:H/VA:N/SC:L/SI:L/SA:N`
(VA/SA deliberately scored None — the config wipe is an availability effect the
program excludes as DoS, and the reported issue is the network redirection.)
**Assets:** `worldcoin/orb-core` (Primary, Critical), `worldcoin/orb-software` (Primary, Critical)
**Commits:** orb-core `9c8e1af`, orb-software `2b4f54dd31ec72b8cafd4d16f5906f8b95b389f3`
**CWE:** CWE-306 (Missing Authentication for Critical Function), CWE-862 (Missing Authorization)

## Summary

Two of the Orb's QR-code inputs carry no authentication of any kind:

1. `magic_action:reset_wifi_credentials` — a **plaintext public constant** that
   makes the Orb wipe its saved Wi-Fi configuration.
2. A standard MeCard Wi-Fi QR (`WIFI:T:WPA;S:…;P:…;;`) — unsigned network
   credentials the Orb will join.

A signed QR format exists (`NETCONFIG:v1.0;…;SIG:…`, ECDSA P-256) and is
correctly implemented, but neither path above uses it. The first QR disables
the guard that would otherwise restrict the second.

Anyone able to hold a phone screen or a sheet of paper in front of an
unattended Orb can therefore make it drop its network configuration and
associate with an access point they control. No key, no operator credential,
no prior compromise of the backend, Orb, or client.

## Why the magic string is not a secret

It is a public constant in open-source code, and appears in orb-core's own
unit tests (`src/plans/qr_scan/operator.rs:75-76`):

```rust
{
    let code = "magic_action:reset_wifi_credentials";
    assert!(matches!(Data::try_parse(code), Some(Data::MagicResetWifi)));
}
```

The matcher is a bare regex over the QR text
(`src/plans/qr_scan/operator.rs:11-22`):

```rust
static MAGIC_QR_CODE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?x) ^ magic_action : (?P<magic_action>[\w]+) $").expect("bad regex")
});
```

## Root cause

### 1. The magic action runs before the operator QR is verified

`orb-core/src/plans/mod.rs`, self-serve path (lines 761-772):

```rust
let operator_qr_code =
    self.scan_operator_qr_code(orb, None).await?.expect("to never timeout");
let Some(operator_qr_code) =
    self.handle_magic_operator_qr_code(orb, operator_qr_code).await?   // <-- acts here
else {
    continue;
};
let Some((_, operator_location_data)) =
    self.verify_operator_qr_code(orb, &operator_qr_code, qr_capture_start).await?  // <-- verifies here
```

The same ordering appears in the standard path (lines 823-838), where
`handle_magic_operator_qr_code` at line 832 precedes `verify_operator_qr_code`
at line 837. In both, the magic action executes on an **unverified** QR, so no
operator identity is ever involved.

Note the self-serve scan passes `None` as the timeout — the Orb waits
indefinitely for a QR. That is the normal idle state of an unattended
self-serve Orb.

### 2. The action wipes network config and then solicits a Wi-Fi QR

`orb-core/src/plans/mod.rs:998-1007` dispatches to `reset_wifi_and_ensure_network`
(`mod.rs:742-747`):

```rust
pub async fn reset_wifi_and_ensure_network(&self, orb: &mut Orb) -> Result<()> {
    network::reset().await?;                              // wpa_supplicant restore-default-config
    wifi::Plan.ensure_network_connection(orb).await?;     // then asks for a Wi-Fi QR
    orb.reset_rgb_camera().await?;
    Ok(())
}
```

`ensure_network_connection` (`src/plans/wifi/mod.rs:43-58`) finds the Orb
disconnected — it just wiped the config — and **prompts for a Wi-Fi QR with no
timeout**, joining whatever it is shown:

```rust
network::Status::Connected { has_internet: false }
| network::Status::Disconnected
| network::Status::InProgress => {
    has_requested_qr_code = true;
    match qr_scan::Plan::new(None, false).run(orb).await? {
        Ok((credentials, _)) => {
            network::join(credentials).await?;
```

So step 2 is not something the attacker must force — the device asks for it.

### 3. On the orb-software side, the same design disables the connectivity guard

`orb-connd/src/service/dbus.rs:107-130` does gate unsigned Wi-Fi QRs:

```rust
let can_apply_wifi_qr = has_no_connectivity || within_magic_qr_timespan;
if !can_apply_wifi_qr {
    return Err(e("we already have internet connectivity, use signed qr instead"));
}
```

but `apply_magic_reset_qr` (`dbus.rs:267-292`) — which itself takes **no
arguments and performs no verification** — satisfies both halves of that
disjunction:

```rust
for profile in wifi_profiles { ... self.nm.remove_profile(&profile.id).await?; }  // -> has_no_connectivity
self.magic_qr_applied_at.write(|val| *val = Utc::now())?;                          // -> within_magic_qr_timespan
```

with `MAGIC_QR_TIMESPAN_MIN = 10` (`service/mod.rs:78`). The error string
"use signed qr instead" shows the signed path is the intended control; the
magic QR removes the need for it.

## Steps to reproduce

Two QR codes, generated in `poc-orb06/`:

| Step | QR payload |
|---|---|
| 1 | `magic_action:reset_wifi_credentials` |
| 2 | `WIFI:T:WPA;S:ORB-EVIL-AP;P:attackerpassword;;` |

1. Stand in front of an idle self-serve Orb and present QR 1 to the operator
   scanner. The Orb wipes its Wi-Fi configuration and begins asking for
   network credentials.
2. Present QR 2. The Orb joins `ORB-EVIL-AP`.

The included `poc-orb06/` crate runs the parsing and dispatch offline. Its
`src/upstream/` files are copied verbatim from
`orb-connd/src/service/{wifi,mecard}.rs`; only import paths and the error type
were adjusted so they build outside the workspace. The magic-QR regex and
dispatch are reproduced verbatim from orb-core, which does not build
standalone.

```
$ cargo run
step 1 — QR payload: "magic_action:reset_wifi_credentials"
         parsed as : Some(ResetWifi)
step 2 — QR payload: "WIFI:T:WPA;S:ORB-EVIL-AP;P:attackerpassword;;"
         parsed as : Credentials { auth: Wpa, ssid: "ORB-EVIL-AP", psk: Some(***), hidden: false }
negative controls pass (unknown action rejected, SSID-less QR rejected)
```

## Impact

An unauthenticated party in visual range of an Orb gains a persistent
network-level position against it: control of DHCP, DNS, routing, and the
captive-portal/connectivity-check response
(`orb-connd` `connectivity_check_uri`, `dbus.rs:296`).

Being deliberate about what this is and is not:

- It is **not** direct code execution. Backend traffic is TLS, and
  `orb-security-utils` pins a small CA set for several services
  (`security-utils/src/reqwest.rs:81-91`).
- The configuration wipe on its own is an availability effect, which the
  program excludes as DoS. **That is not the finding.** The finding is the
  unauthenticated *redirection* of the device onto an attacker-chosen network,
  which is an access-control failure.
- It converts "attacker needs a network position against an Orb" from a
  precondition into an outcome. Any weakness that assumes such a position —
  including `update-agent`'s documented decision not to pin certificates
  (`update-agent/src/client.rs:26-31`) — becomes reachable by anyone who can
  show the device two QR codes.

## Preconditions

Physical presence in front of an Orb's scanner, which is the device's intended
public input channel. No prior compromise of backend, Orb, or client; no MITM
position beforehand; no credential or secret.

## Suggested remediation

1. **Authenticate the magic actions.** They already have the right primitive:
   route `magic_action:*` through the same ECDSA P-256 signed envelope as
   `NETCONFIG`, with a nonce or timestamp so a photographed QR cannot be
   replayed.
2. **Verify before acting.** Move `handle_magic_operator_qr_code` after
   `verify_operator_qr_code` in both call sites, so a magic action requires a
   valid operator QR.
3. **Drop the timespan bypass.** `within_magic_qr_timespan` exists only to let
   an unsigned Wi-Fi QR through after a magic reset. If magic actions are
   signed, this disjunct can go, leaving the signed NETCONFIG path as the sole
   way to configure networking on a connected Orb.
4. Consider requiring physical confirmation on the device (a button, or the
   operator app) for actions that clear device state.

## Related, lower severity

`apply_netconfig_qr` (`orb-connd/src/service/dbus.rs:173-191`) is the signed
path, but its replay protection has two gaps:

- `check_ts: bool` is supplied by the D-Bus caller, so the freshness check can
  simply be turned off.
- The check is one-sided:

  ```rust
  let delta = now - netconf.created_at;
  if delta.num_minutes() > 10 { return Err(e("qr code was created more than 10min ago")); }
  ```

  A `created_at` in the future yields a negative `delta`, which passes. A
  signed QR carrying a future timestamp is accepted indefinitely. Bounding
  `delta.abs()` would close this.
