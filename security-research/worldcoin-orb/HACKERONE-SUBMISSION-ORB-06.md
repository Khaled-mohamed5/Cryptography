# HackerOne submission — ORB-06 (copy/paste ready)

| H1 field | Value |
|---|---|
| **Title** | Unauthenticated QR codes reset an Orb's Wi-Fi configuration and move it onto an attacker-controlled network |
| **Asset** | `https://github.com/worldcoin/orb-core` (Primary Asset, Critical) — also affects `worldcoin/orb-software` |
| **Weakness** | CWE-306 Missing Authentication for Critical Function |
| **Severity** | `CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:L/VI:H/VA:N/SC:L/SI:L/SA:N` — see *Severity* |
| **Attachments** | `step1-magic-reset.png`, `step2-attacker-wifi.png`, `poc-orb06/` (source) |

---

## Summary

Two of the Orb's QR-code inputs carry no authentication:

1. `magic_action:reset_wifi_credentials` — a plaintext public constant that makes the Orb wipe its saved Wi-Fi configuration.
2. A standard MeCard Wi-Fi QR (`WIFI:T:WPA;S:…;P:…;;`) — unsigned credentials the Orb will join.

A signed QR format exists (`NETCONFIG:v1.0;…;SIG:…`, ECDSA P-256, `orb-connd/src/service/netconfig.rs:84`) and is implemented correctly. Neither path above uses it, and the first QR removes the guard that would otherwise restrict the second.

Anyone who can hold a phone screen or a printed sheet in front of an unattended Orb can make it drop its network configuration and associate with an access point they control. No key, no operator credential, no prior compromise of backend, Orb, or client, and no pre-existing network position.

## Affected versions

- `worldcoin/orb-core` @ `9c8e1af`
- `worldcoin/orb-software` @ `2b4f54dd31ec72b8cafd4d16f5906f8b95b389f3`

## The magic string is not a secret

It is a public constant in open-source code and appears in orb-core's own unit tests (`src/plans/qr_scan/operator.rs:75-76`):

```rust
let code = "magic_action:reset_wifi_credentials";
assert!(matches!(Data::try_parse(code), Some(Data::MagicResetWifi)));
```

The matcher is a bare regex over the QR text (`operator.rs:11-22`):

```rust
static MAGIC_QR_CODE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?x) ^ magic_action : (?P<magic_action>[\w]+) $").expect("bad regex")
});
```

## Root cause

### 1. The magic action executes before the operator QR is verified

`orb-core/src/plans/mod.rs`, self-serve path (761-772):

```rust
let operator_qr_code =
    self.scan_operator_qr_code(orb, None).await?.expect("to never timeout");
let Some(operator_qr_code) =
    self.handle_magic_operator_qr_code(orb, operator_qr_code).await?    // acts here
else { continue; };
let Some((_, operator_location_data)) =
    self.verify_operator_qr_code(orb, &operator_qr_code, qr_capture_start).await?;  // verifies here
```

Same ordering in the standard path: `handle_magic_operator_qr_code` at line 832 precedes `verify_operator_qr_code` at line 837. In both, the action runs on an **unverified** QR, so no operator identity is involved at any point.

The self-serve scan passes `None` for the timeout — the Orb waits indefinitely. That is the normal idle state of an unattended self-serve Orb.

### 2. The action wipes the config, then asks for a Wi-Fi QR itself

`mod.rs:998-1007` dispatches to `reset_wifi_and_ensure_network` (`mod.rs:742-747`):

```rust
network::reset().await?;                            // wpa_supplicant restore-default-config
wifi::Plan.ensure_network_connection(orb).await?;   // then solicits a Wi-Fi QR
```

`ensure_network_connection` (`src/plans/wifi/mod.rs:43-58`) finds the device disconnected — it just wiped the config — and prompts for a Wi-Fi QR **with no timeout**, joining whatever it is shown:

```rust
has_requested_qr_code = true;
match qr_scan::Plan::new(None, false).run(orb).await? {
    Ok((credentials, _)) => { network::join(credentials).await?; }
```

Step 2 is not something the attacker must force; the device requests it.

### 3. On the orb-software side, the same design voids the connectivity guard

`orb-connd/src/service/dbus.rs:107-130` does gate unsigned Wi-Fi QRs:

```rust
let can_apply_wifi_qr = has_no_connectivity || within_magic_qr_timespan;
if !can_apply_wifi_qr {
    return Err(e("we already have internet connectivity, use signed qr instead"));
}
```

`apply_magic_reset_qr` (`dbus.rs:267-292`) takes no arguments and performs no verification, and satisfies **both** halves:

```rust
for profile in wifi_profiles { self.nm.remove_profile(&profile.id).await?; }  // -> has_no_connectivity
self.magic_qr_applied_at.write(|val| *val = Utc::now())?;                     // -> within_magic_qr_timespan
```

`MAGIC_QR_TIMESPAN_MIN = 10` (`service/mod.rs:78`). The error string "use signed qr instead" shows the signed path is the intended control; the magic QR removes the need for it.

## Steps to reproduce

Attached QR codes:

| Step | QR payload | File |
|---|---|---|
| 1 | `magic_action:reset_wifi_credentials` | `step1-magic-reset.png` |
| 2 | `WIFI:T:WPA;S:ORB-EVIL-AP;P:attackerpassword;;` | `step2-attacker-wifi.png` |

1. In front of an idle self-serve Orb, present QR 1 to the operator scanner. The Orb wipes its Wi-Fi configuration and begins asking for network credentials.
2. Present QR 2. The Orb joins `ORB-EVIL-AP`.

The attached `poc-orb06/` crate exercises the parsing and dispatch offline. `src/upstream/` is copied **verbatim** from `orb-connd/src/service/{wifi,mecard}.rs`; only import paths and the error type were changed so the files build outside the workspace. The magic-QR regex and dispatch are reproduced verbatim from orb-core, which does not build standalone.

```
$ cargo run
step 1 — QR payload: "magic_action:reset_wifi_credentials"
         parsed as : Some(ResetWifi)
step 2 — QR payload: "WIFI:T:WPA;S:ORB-EVIL-AP;P:attackerpassword;;"
         parsed as : Credentials { auth: Wpa, ssid: "ORB-EVIL-AP", psk: Some(***), hidden: false }
negative controls pass (unknown action rejected, SSID-less QR rejected)
```

I have not run this against a production Orb — I do not have one, and your policy asks researchers not to tamper with fielded hardware. Per the Orb-device section of the policy, I am reporting it for evaluation and am happy to develop the on-device PoC if you supply a test environment.

## Impact

An unauthenticated party in visual range of an Orb gains a persistent network-level position against it: control of DHCP, DNS, routing, and the connectivity-check response (`orb-connd` `connectivity_check_uri`, `dbus.rs:296`).

Being precise about what this is and is not:

- It is **not** direct code execution. Backend traffic is TLS and `orb-security-utils` pins a small CA set for several services (`security-utils/src/reqwest.rs:81-91`).
- The configuration wipe alone is an availability effect, which your policy excludes as DoS. **That is not what I am reporting.** The finding is the unauthenticated *redirection* of the device onto an attacker-chosen network — an access-control failure, not a DoS.
- It converts "attacker holds a network position against an Orb" from a precondition into an outcome. Any issue that assumes such a position — including `update-agent`'s documented decision not to pin certificates (`update-agent/src/client.rs:26-31`) — becomes reachable by someone who can show the device two QR codes.

## Preconditions

Physical presence in front of an Orb's scanner, which is the device's intended public input channel. No prior compromise of backend, Orb, or client. No MITM position beforehand. No credential or secret.

I want to be straightforward about the one judgement call here: your policy excludes "attacks requiring MITM or physical access to a user's device". I do not believe that applies, because an Orb is deployed operator equipment rather than a user's device, presenting a QR is the scanner's designed function rather than physical tampering, and the network position is the result of the attack rather than a precondition for it. If you read that exclusion differently, I would rather you told me than spent triage time on it.

## Severity

```
CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:L/VI:H/VA:N/SC:L/SI:L/SA:N
```

Two notes on how I scored this.

**Availability is deliberately scored at None.** Wiping the network configuration
does cause an availability impact, but your policy excludes device DoS, and an
outage is not what I am reporting. The finding is the unauthenticated
*redirection* of the device onto an attacker-chosen network — an access-control
failure. I have left `VA` and `SA` at `N` so the score reflects only that.

**`AV:P` is the conservative choice.** CVSS 4.0 defines Physical as requiring the
attacker to "physically touch or manipulate" the component, and the attacker
never touches the Orb — the QR scanner is the device's designed input channel,
which arguably makes `AV:L` ("accessing the target system locally, e.g. keyboard,
console") the better fit and raises the score. Optical proximity inputs are not
cleanly covered by either. I will defer to your rating.

Confidentiality is `L` rather than `H` because backend traffic is TLS; the
attacker sees DNS and traffic metadata, not protected content. Integrity is `H`
because the attacker fully controls which network the device joins.

## Suggested remediation

1. **Authenticate the magic actions.** The right primitive is already present: route `magic_action:*` through the same ECDSA P-256 signed envelope as `NETCONFIG`, with a nonce or timestamp so a photographed QR cannot be replayed.
2. **Verify before acting.** Move `handle_magic_operator_qr_code` after `verify_operator_qr_code` at both call sites, so a magic action requires a valid operator QR.
3. **Remove the timespan bypass.** `within_magic_qr_timespan` exists only to let an unsigned Wi-Fi QR through after a magic reset. Once magic actions are signed, that disjunct can go, leaving signed NETCONFIG as the only way to configure networking on a connected Orb.
4. Consider requiring on-device confirmation (a button press, or the operator app) for actions that clear device state.

## Related, lower severity — replay gaps in the signed path

`apply_netconfig_qr` (`orb-connd/src/service/dbus.rs:173-191`) is the signed path, but its freshness check has two gaps:

- `check_ts: bool` comes from the D-Bus caller, so the check can be switched off.
- The comparison is one-sided:

  ```rust
  let delta = now - netconf.created_at;
  if delta.num_minutes() > 10 { return Err(e("qr code was created more than 10min ago")); }
  ```

  A `created_at` in the future gives a negative `delta`, which passes. A signed QR carrying a future timestamp is accepted indefinitely. Bounding `delta.abs()` closes this.

Happy to split this into its own report if you would prefer.

## Disclosure

Source-code analysis plus offline PoC. No testing against Worldcoin infrastructure, live Orbs, or any deployed endpoint. Happy to hold disclosure until a fix ships.
