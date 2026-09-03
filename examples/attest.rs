//! Exercises every guest operation this crate exposes.
//!
//! Run inside an SEV-SNP guest: `cargo run --example attest`.
//!
//! Doubles as the pattern for feature-portable code. Key derivation and each
//! transport exist only when their cargo feature is on, so anything that
//! touches them sits behind a matching `#[cfg]` — which means a build with the
//! wrong features fails here rather than in production.

use rand::RngExt;
use sev_snp::{AttestationReport, Firmware, ReportRequest, Transport, detect};

fn main() -> Result<(), sev_snp::Error> {
    match detect::capabilities() {
        Some(c) => println!(
            "capabilities: sev={} sev_es={} sev_snp={} vmpls={} c_bit={}",
            c.sev(),
            c.sev_es(),
            c.sev_snp(),
            c.num_vmpls(),
            c.c_bit_position()
        ),
        None => println!("capabilities: CPUID leaf 0x8000001F absent"),
    }
    println!("running inside an SNP guest: {}", detect::is_snp_guest());

    let firmware = Firmware::open()?;
    println!("transport: {:?}", firmware.transport());

    // A fresh nonce is what makes the report non-replayable.
    let nonce: [u8; 64] = rand::rng().random();
    let report = firmware.report(&nonce)?;
    // The crate rejects a report that is not bound to the nonce, so reaching
    // here already proves it; assert anyway, since this example is also the
    // place someone looks to see what the guarantee is.
    assert_eq!(report.report_data(), &nonce, "report is bound to our nonce");

    println!("\n{report:#?}");
    if let Some(parts) = report.reported_tcb_parts() {
        println!("\nreported TCB: {parts}");
    }

    let extended = firmware.extended_report(&nonce)?;
    if extended.certificates.is_empty() {
        println!("\ncertificates: none provisioned by the host (fetch from AMD KDS)");
    } else {
        println!("\ncertificates: {:?}", extended.certificates.entries());
    }

    #[cfg(feature = "sev-guest")]
    derive_keys(&firmware, &report)?;
    #[cfg(not(feature = "sev-guest"))]
    println!("\nkey derivation: compiled out (`sev-guest` feature is off)");

    match firmware.report_with(&ReportRequest::new().vmpl(3)) {
        Ok(r) => println!("\nVMPL 3 report obtained, vmpl field = {}", r.vmpl()),
        Err(e) => println!("\nVMPL 3 report refused: {e}"),
    }

    // Every transport in this build must agree on what it measures.
    println!();
    #[cfg(feature = "configfs")]
    compare_transport(Transport::ConfigFs, &nonce, &report)?;
    #[cfg(feature = "sev-guest")]
    compare_transport(Transport::Ioctl, &nonce, &report)?;

    Ok(())
}

/// Opens one transport on its own and checks it sees the same guest.
fn compare_transport(
    transport: Transport,
    nonce: &[u8; 64],
    reference: &AttestationReport,
) -> Result<(), sev_snp::Error> {
    match Firmware::open_with(transport) {
        Ok(one) => {
            let report = one.report(nonce)?;
            let extended = one.extended_report(nonce)?;
            println!(
                "{transport:?}: report v{} measurement matches={} certs={}",
                report.version(),
                report.measurement() == reference.measurement(),
                extended.certificates.len()
            );
        }
        Err(e) => println!("{transport:?}: unavailable ({e})"),
    }
    Ok(())
}

/// The same request must reproduce the same key, and a different binding must
/// not.
#[cfg(feature = "sev-guest")]
fn derive_keys(firmware: &Firmware, report: &AttestationReport) -> Result<(), sev_snp::Error> {
    use sev_snp::{KeyRequest, RootKey};

    if !firmware.can_derive_keys() {
        println!("\nkey derivation: /dev/sev-guest not open (try as root)");
        return Ok(());
    }

    let sealing = KeyRequest::new()
        .bind_measurement()
        .bind_guest_policy()
        .bind_tcb(report.reported_tcb());

    let first = firmware.derive_key(&sealing)?;
    let again = firmware.derive_key(&sealing)?;
    assert_eq!(
        first.as_bytes(),
        again.as_bytes(),
        "derivation is deterministic"
    );

    let other = firmware.derive_key(&sealing.bind_family_id())?;
    assert_ne!(
        first.as_bytes(),
        other.as_bytes(),
        "bindings change the key"
    );

    println!(
        "\nderived a stable {}-byte key bound to the image",
        first.as_bytes().len()
    );

    match firmware.derive_key(&KeyRequest::new().root_key(RootKey::Vmrk)) {
        Ok(_) => println!("VMRK derivation available (guest has a migration agent)"),
        Err(e) => println!("VMRK derivation unavailable, as expected: {e}"),
    }
    Ok(())
}
