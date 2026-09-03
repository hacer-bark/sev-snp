//! Hardware-bound key derivation: what the secure processor will and will not
//! reproduce.
//!
//! Run inside an SEV-SNP guest as root: `cargo run --example derive_key`.
//!
//! The AMD secure processor holds root secrets that never leave the chip and
//! will derive a 32-byte key from one of them mixed with facts about the
//! running VM. Nothing is stored anywhere: the same request on the same machine
//! reproduces the same key, and a change to any bound fact produces a
//! different one. That is what makes it a sealing primitive — encrypt with a
//! key bound to the launch measurement and the ciphertext becomes unreadable if
//! the guest image is tampered with, with no server to ask and no secret to
//! ship.
//!
//! This example deliberately never prints key material. It shows only whether
//! two derivations produced the same key, which is the property that matters
//! and the only one that is safe to put on a terminal.

use sev_snp::{AttestationReport, DerivedKey, Error, Firmware, KeyRequest, RootKey, TcbVersion};

fn main() -> Result<(), Error> {
    let firmware = Firmware::open()?;
    if !firmware.can_derive_keys() {
        println!("Key derivation needs /dev/sev-guest, which is not open.");
        println!("configfs-TSM implements attestation reports only. Try as root.");
        return Ok(());
    }

    // The report tells us what this platform will accept as bindings: its
    // committed TCB bounds `bind_tcb`, and its launch SVN bounds
    // `bind_guest_svn`.
    let report = firmware.report(&[0u8; 64])?;
    println!(
        "platform: {} firmware {}",
        describe(&report),
        report.current_firmware()
    );
    println!();

    determinism(&firmware)?;
    binding_sensitivity(&firmware)?;
    privilege_separation(&firmware)?;
    rollback_resistance(&firmware, &report)?;
    root_key_choice(&firmware)?;
    refused_bindings(&firmware, &report);

    println!();
    println!("Recommended sealing key for data at rest:");
    println!("  KeyRequest::new()");
    for (call, why) in [
        (".bind_measurement()", "dies if the guest image changes"),
        (
            ".bind_guest_policy()",
            "dies if the VM is relaunched debuggable",
        ),
        (
            ".bind_tcb(report.reported_tcb())",
            "dies on firmware rollback",
        ),
    ] {
        println!("      {call:<34} // {why}");
    }
    println!();
    println!("Feed the result to a KDF or AEAD; do not use it as a cipher key directly.");
    Ok(())
}

/// The same request must always reproduce the same key, or the primitive is
/// useless for sealing.
fn determinism(firmware: &Firmware) -> Result<(), Error> {
    let request = KeyRequest::new().bind_measurement();
    let first = firmware.derive_key(&request)?;
    let second = firmware.derive_key(&request)?;

    println!("determinism");
    report_pair("same request, twice", &first, &second, Expect::Same);
    Ok(())
}

/// Each binding must actually change the key, or it is not protecting anything.
fn binding_sensitivity(firmware: &Firmware) -> Result<(), Error> {
    let baseline = KeyRequest::new();
    let unbound = firmware.derive_key(&baseline)?;

    println!();
    println!("binding sensitivity (each compared against an unbound key)");

    let variants = [
        ("measurement", baseline.bind_measurement()),
        ("guest policy", baseline.bind_guest_policy()),
        ("family id", baseline.bind_family_id()),
        ("image id", baseline.bind_image_id()),
        ("guest svn", baseline.bind_guest_svn(0)),
    ];

    for (name, request) in variants {
        let key = firmware.derive_key(&request)?;
        report_pair(name, &unbound, &key, Expect::Different);
    }
    Ok(())
}

/// A lower-privileged VMPL must not be able to derive the key a higher one
/// gets. The VMPL is mixed in whether or not any field is selected.
fn privilege_separation(firmware: &Firmware) -> Result<(), Error> {
    let at_vmpl0 = firmware.derive_key(&KeyRequest::new().vmpl(0))?;

    println!();
    println!("privilege separation");
    for level in 1..=KeyRequest::MAX_VMPL {
        match firmware.derive_key(&KeyRequest::new().vmpl(level)) {
            Ok(key) => report_pair(
                &format!("vmpl 0 vs vmpl {level}"),
                &at_vmpl0,
                &key,
                Expect::Different,
            ),
            Err(e) => println!("  vmpl {level:<21} refused: {e}"),
        }
    }
    Ok(())
}

/// Binding the TCB makes sealed data unreadable after a firmware downgrade.
///
/// Deriving against an older TCB is permitted — that is how a guest reads data
/// it sealed before an update — so the two keys existing and differing is
/// exactly the property that makes rollback detectable.
fn rollback_resistance(firmware: &Firmware, report: &AttestationReport) -> Result<(), Error> {
    let current = report.reported_tcb();
    // A version 2 report carries no CPUID, so the TCB layout is unknown and the
    // raw value cannot be decomposed; step the whole word down instead.
    let older = report.product().map_or_else(
        || TcbVersion::from_raw(current.raw().saturating_sub(1)),
        |product| {
            let mut parts = current.decode(product);
            parts.microcode = parts.microcode.saturating_sub(1);
            parts.encode(product)
        },
    );

    println!();
    println!("rollback resistance");
    let at_current = firmware.derive_key(&KeyRequest::new().bind_tcb(current))?;
    match firmware.derive_key(&KeyRequest::new().bind_tcb(older)) {
        Ok(at_older) => report_pair(
            "current TCB vs older",
            &at_current,
            &at_older,
            Expect::Different,
        ),
        Err(e) => println!("  older TCB refused by firmware: {e}"),
    }
    Ok(())
}

/// VCEK keys are bound to this physical chip; VMRK keys follow a migrated VM.
fn root_key_choice(firmware: &Firmware) -> Result<(), Error> {
    println!();
    println!("root key choice");
    let vcek = firmware.derive_key(&KeyRequest::new().root_key(RootKey::Vcek))?;
    match firmware.derive_key(&KeyRequest::new().root_key(RootKey::Vmrk)) {
        Ok(vmrk) => report_pair("VCEK vs VMRK", &vcek, &vmrk, Expect::Different),
        Err(e) => println!("  VMRK unavailable (no migration agent): {e}"),
    }
    Ok(())
}

/// The firmware enforces the anti-rollback rules itself; a request that breaks
/// them fails rather than quietly returning a usable key.
fn refused_bindings(firmware: &Firmware, report: &AttestationReport) {
    println!();
    println!("bindings the firmware refuses");

    // The guest SVN mixed in must not exceed the one in the ID block at launch,
    // which is the ratchet that stops an old image deriving a new image's key.
    let above_launch = report.guest_svn().saturating_add(1);
    let svn_label = format!("guest svn {above_launch}");
    match firmware.derive_key(&KeyRequest::new().bind_guest_svn(above_launch)) {
        Ok(_) => println!(
            "  {svn_label:<26} accepted (launch svn is {})",
            report.guest_svn()
        ),
        Err(e) => println!("  {svn_label:<26} refused: {e}"),
    }

    // A VMPL outside 0..=3 is rejected before it ever reaches the firmware.
    let vmpl_label = format!("vmpl {}", KeyRequest::MAX_VMPL.saturating_add(1));
    match firmware.derive_key(&KeyRequest::new().vmpl(KeyRequest::MAX_VMPL.saturating_add(1))) {
        Ok(_) => println!("  {vmpl_label:<26} unexpectedly accepted"),
        Err(e) => println!("  {vmpl_label:<26} refused: {e}"),
    }
}

/// Whether two derivations were supposed to match.
#[derive(Clone, Copy)]
enum Expect {
    Same,
    Different,
}

/// Prints the relationship between two keys, never the keys themselves.
fn report_pair(label: &str, left: &DerivedKey, right: &DerivedKey, expect: Expect) {
    let identical = left.as_bytes() == right.as_bytes();
    let held = match expect {
        Expect::Same => identical,
        Expect::Different => !identical,
    };
    let relation = if identical { "identical" } else { "distinct" };
    let verdict = if held { "ok" } else { "UNEXPECTED" };
    println!("  {label:<26} {relation:<9} {verdict}");
}

fn describe(report: &AttestationReport) -> String {
    report
        .product()
        .map_or_else(|| "unknown product".to_owned(), |p| p.to_string())
}
