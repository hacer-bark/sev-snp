//! Exercises every guest operation this crate exposes.
//!
//! Run inside an SEV-SNP guest: `cargo run --example attest`.

use rand::RngExt;
use sev_snp::{Firmware, KeyRequest, ReportRequest, RootKey, Transport, detect};

fn main() -> Result<(), sev_snp::Error> {
    match detect::capabilities() {
        Some(c) => println!(
            "capabilities: sev={} sev_es={} sev_snp={} vmpls={} c_bit={}",
            c.sev, c.sev_es, c.sev_snp, c.num_vmpls, c.c_bit_position
        ),
        None => println!("capabilities: CPUID leaf 0x8000001F absent"),
    }
    println!("running inside an SNP guest: {}", detect::is_snp_guest());

    let fw = Firmware::open()?;
    println!(
        "transport: {:?}, key derivation available: {}",
        fw.transport(),
        fw.can_derive_keys()
    );

    // A fresh nonce is what makes the report non-replayable.
    let nonce: [u8; 64] = rand::rng().random();
    let report = fw.report(&nonce)?;
    assert_eq!(report.report_data(), &nonce, "report is bound to our nonce");

    println!("\n{report:#?}");
    if let Some(parts) = report.reported_tcb_parts() {
        println!("\nreported TCB: {parts}");
    }

    let ext = fw.extended_report(&nonce)?;
    if ext.certificates.is_empty() {
        println!("\ncertificates: none provisioned by the host (fetch from AMD KDS)");
    } else {
        println!("\ncertificates: {:?}", ext.certificates.entries());
    }

    // The same request must reproduce the same key, and a different binding
    // must not.
    if fw.can_derive_keys() {
        let sealing = KeyRequest::new()
            .bind_measurement()
            .bind_guest_policy()
            .bind_tcb(report.reported_tcb());

        let a = fw.derive_key(&sealing)?;
        let b = fw.derive_key(&sealing)?;
        assert_eq!(a.as_bytes(), b.as_bytes(), "derivation is deterministic");

        let other = fw.derive_key(&sealing.bind_family_id())?;
        assert_ne!(a.as_bytes(), other.as_bytes(), "bindings change the key");

        println!(
            "\nderived a stable {}-byte key bound to the image",
            a.as_bytes().len()
        );
        println!("first 8 bytes: {:02x?}", &a.as_bytes()[..8]);

        match fw.derive_key(&KeyRequest::new().root_key(RootKey::Vmrk)) {
            Ok(_) => println!("VMRK derivation available (guest has a migration agent)"),
            Err(e) => println!("VMRK derivation unavailable, as expected: {e}"),
        }
    }

    match fw.report_with(&ReportRequest::new().vmpl(3)) {
        Ok(r) => println!("\nVMPL 3 report obtained, vmpl field = {}", r.vmpl()),
        Err(e) => println!("\nVMPL 3 report refused: {e}"),
    }

    // Both transports must agree: the same nonce at the same VMPL yields the
    // same report apart from the signature nonce the firmware adds.
    for transport in [Transport::ConfigFs, Transport::Ioctl] {
        match Firmware::open_with(transport) {
            Ok(one) => {
                let r = one.report(&nonce)?;
                let e = one.extended_report(&nonce)?;
                println!(
                    "{transport:?}: report v{} measurement matches={} certs={}",
                    r.version(),
                    r.measurement() == report.measurement(),
                    e.certificates.entries().len()
                );
            }
            Err(err) => println!("{transport:?}: unavailable ({err})"),
        }
    }

    Ok(())
}
