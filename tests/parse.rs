//! Parsing checks against a real report and against randomised round-trips.

use rand::RngExt;
use sev_snp::{
    AttestationReport, CertKind, CertTable, Fms, Product, SignatureAlgo, SigningKey, TcbParts,
    TcbVersion,
};

/// A version 5 report captured from a Milan (Zen 3) guest.
///
/// It exercises the interesting combination: the newest report layout on the
/// oldest supported silicon, which is exactly the case that breaks if report
/// version is inferred from the processor generation.
const MILAN_V5: &[u8] = include_bytes!("data/report-v5-milan.bin");

#[test]
fn parses_a_real_v5_report_from_a_zen3_machine() {
    let report = AttestationReport::parse(MILAN_V5).expect("golden report parses");

    assert_eq!(report.version(), 5);
    assert_eq!(report.vmpl(), 0);
    assert_eq!(report.signature_algo(), SignatureAlgo::EcdsaP384Sha384);
    assert_eq!(report.signer_info().signing_key(), SigningKey::Vcek);

    // Zen 3, and the version 5 layout still decodes the legacy TCB fields.
    assert_eq!(report.cpuid_fms(), Some(Fms::new(0x19, 0x01, 0x01)));
    assert_eq!(report.product(), Some(Product::Milan));
    let tcb = report.reported_tcb_parts().expect("v3+ carries CPUID");
    assert_eq!(tcb.fmc, None, "Zen 3 has no FMC field");
    assert_eq!(
        (tcb.bootloader, tcb.tee, tcb.snp, tcb.microcode),
        (4, 0, 29, 222)
    );

    // Fields that only exist from version 5.
    assert_eq!(report.launch_mit_vector(), Some(0x0b));
    assert_eq!(report.current_mit_vector(), Some(0x0b));

    // The policy has SMT allowed plus the mandatory reserved bit, nothing else.
    assert!(report.policy().smt_allowed());
    assert!(report.policy().reserved_bit_set());
    assert!(!report.policy().debug_allowed());
    assert_eq!(report.policy().unknown_bits(), 0);

    assert!(report.platform_info().smt_enabled());
    assert!(report.platform_info().alias_check_complete());
    assert_eq!(report.platform_info().unknown_bits(), 0);

    // The signature covers everything before it, and decodes to two P-384
    // scalars rather than the 72-byte little-endian fields on the wire.
    assert_eq!(report.signed_bytes().len(), 0x2A0);
    let sig = report.ecdsa_signature().expect("ECDSA report");
    assert_ne!(sig.r_be(), [0u8; 48]);
    assert_ne!(sig.s_be(), [0u8; 48]);
    assert_eq!(sig.r_be()[47], report.signature()[0], "r is byte-reversed");
}

#[test]
fn report_rejects_short_and_ancient_inputs() {
    assert!(AttestationReport::parse(&MILAN_V5[..1183]).is_err());

    let mut v1 = MILAN_V5.to_vec();
    v1[0..4].copy_from_slice(&1u32.to_le_bytes());
    assert!(AttestationReport::parse(&v1).is_err());
}

#[test]
fn tcb_version_round_trips_on_every_generation() {
    let mut rng = rand::rng();
    let svns: [u8; 5] = rng.random();

    for product in [
        Product::Milan,
        Product::Genoa,
        Product::Bergamo,
        Product::Turin,
    ] {
        let has_fmc = product == Product::Turin;
        let parts = TcbParts {
            fmc: has_fmc.then_some(svns[0]),
            bootloader: svns[1],
            tee: svns[2],
            snp: svns[3],
            microcode: svns[4],
        };
        assert_eq!(parts.encode(product).decode(product), parts, "{product}");
    }

    // The same 64 bits mean different things on Zen 3 and Zen 5: what Milan
    // reads as the bootloader SVN, Turin reads as the FMC SVN.
    let raw = TcbVersion::from_raw(u64::from_le_bytes([1, 2, 3, 4, 0, 0, 5, 6]));
    assert_eq!(raw.decode(Product::Milan).bootloader, 1);
    assert_eq!(raw.decode(Product::Milan).snp, 5);
    assert_eq!(raw.decode(Product::Turin).fmc, Some(1));
    assert_eq!(raw.decode(Product::Turin).snp, 4);
}

#[test]
fn fms_round_trips_through_cpuid_encoding() {
    for fms in [
        Fms::new(0x19, 0x01, 0x01), // Milan
        Fms::new(0x19, 0x11, 0x02), // Genoa
        Fms::new(0x1A, 0x02, 0x00), // Turin
    ] {
        assert_eq!(Fms::from_cpuid_1_eax(fms.to_cpuid_1_eax()), fms);
    }
}

#[test]
fn cert_table_reads_entries_and_rejects_out_of_bounds_offsets() {
    const VCEK: [u8; 16] = [
        0x63, 0xda, 0x75, 0x8d, 0xe6, 0x64, 0x45, 0x64, 0xad, 0xc5, 0xf4, 0xb9, 0x3b, 0xe8, 0xac,
        0xcd,
    ];
    let mut rng = rand::rng();
    let body: [u8; 64] = rng.random();

    // One entry, a zero terminator, then the certificate body.
    let mut blob = Vec::new();
    blob.extend_from_slice(&VCEK);
    blob.extend_from_slice(&48u32.to_le_bytes()); // offset
    blob.extend_from_slice(&(body.len() as u32).to_le_bytes());
    blob.extend_from_slice(&[0u8; 24]);
    blob.extend_from_slice(&body);

    let table = CertTable::parse(&blob).expect("well-formed table");
    let vcek = table.get(CertKind::Vcek).expect("VCEK present");
    assert_eq!(vcek.data(), body);

    // An offset past the end of the blob must not be readable.
    let mut bad = blob.clone();
    bad[16..20].copy_from_slice(&9999u32.to_le_bytes());
    assert!(CertTable::parse(&bad).is_err());

    assert!(CertTable::parse(&[]).expect("empty is legal").is_empty());
}
