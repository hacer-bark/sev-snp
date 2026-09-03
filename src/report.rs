//! The SEV-SNP attestation report.
//!
//! One binary layout spans every report version AMD has shipped: the structure
//! is always [`AttestationReport::SIZE`] bytes and newer revisions only claim
//! space that older ones reserved. This module parses the fields common to all
//! versions unconditionally, and returns `Option` for the ones that only exist
//! from a given version onwards, so the same code path serves a Zen 3 machine
//! emitting a version 2 report and a Zen 5 machine emitting version 5.

use crate::bytes_at;
use crate::error::{Error, ParseError, Result};
use crate::policy::{GuestPolicy, PlatformInfo, SignatureAlgo, SignerInfo};
use crate::tcb::{Fms, Product, TcbParts, TcbVersion};
use std::fmt;

/// A parsed SEV-SNP attestation report.
///
/// The report is a signed statement by the AMD secure processor about the
/// launch measurement, policy and firmware state of this VM, plus 64 bytes of
/// caller-supplied [`report_data`](Self::report_data) that binds it to a
/// challenge.
#[derive(Clone)]
pub struct AttestationReport {
    raw: [u8; Self::SIZE],
}

impl AttestationReport {
    /// Size of the report structure in bytes, identical for every version.
    pub const SIZE: usize = 0x4A0;

    /// Length of the region covered by the signature.
    ///
    /// The signature is computed over everything preceding it.
    pub const SIGNED_LEN: usize = 0x2A0;

    /// Lowest report version this crate can interpret.
    pub const MIN_VERSION: u32 = 2;

    /// Highest report version this crate will accept.
    ///
    /// Newer revisions only claim reserved space, so a version this crate has
    /// never heard of still parses correctly — but the field has to be bounded
    /// by *something*, or any 1184-byte blob whose first word happens to be
    /// large passes for a report. AMD is at version 5; the headroom here
    /// absorbs the next several revisions without pretending a TDX quote
    /// (whose header reads as version 131076) is an SEV-SNP report.
    pub const MAX_VERSION: u32 = 16;

    /// Parses a report from its ABI representation.
    ///
    /// Newer versions than this crate knows about are accepted: unrecognised
    /// fields stay reachable through [`as_bytes`](Self::as_bytes).
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::TooShort`] if `bytes` is smaller than
    /// [`Self::SIZE`], or [`ParseError::UnsupportedReportVersion`] if the
    /// report announces a version outside
    /// [`Self::MIN_VERSION`] to [`Self::MAX_VERSION`] inclusive.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let raw = bytes_at::<{ Self::SIZE }>(bytes, 0).ok_or(ParseError::TooShort {
            what: "attestation report",
            need: Self::SIZE,
            got: bytes.len(),
        })?;

        let report = Self { raw };
        let version = report.version();
        if !(Self::MIN_VERSION..=Self::MAX_VERSION).contains(&version) {
            return Err(Error::Parse(ParseError::UnsupportedReportVersion(version)));
        }
        Ok(report)
    }

    /// The report exactly as the firmware produced it.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::SIZE] {
        &self.raw
    }

    /// The bytes covered by [`signature`](Self::signature).
    ///
    /// Hash this with SHA-384 to verify the report against a VCEK or VLEK.
    #[must_use]
    pub const fn signed_bytes(&self) -> &[u8] {
        match self.raw.split_at_checked(Self::SIGNED_LEN) {
            Some((signed, _)) => signed,
            // Unreachable: SIGNED_LEN is less than SIZE.
            None => &self.raw,
        }
    }

    /// Report structure version, within
    /// [`Self::MIN_VERSION`] to [`Self::MAX_VERSION`] inclusive.
    #[must_use]
    pub const fn version(&self) -> u32 {
        self.u32_at(0x00)
    }

    /// Guest security version number supplied in the ID block at launch.
    #[must_use]
    pub const fn guest_svn(&self) -> u32 {
        self.u32_at(0x04)
    }

    /// The launch policy the guest owner pinned at VM start.
    #[must_use]
    pub const fn policy(&self) -> GuestPolicy {
        GuestPolicy::from_raw(self.u64_at(0x08))
    }

    /// Family ID from the ID block, chosen by the guest owner.
    #[must_use]
    pub const fn family_id(&self) -> &[u8; 16] {
        self.field(0x10)
    }

    /// Image ID from the ID block, chosen by the guest owner.
    #[must_use]
    pub const fn image_id(&self) -> &[u8; 16] {
        self.field(0x20)
    }

    /// The VMPL the report was requested at.
    #[must_use]
    pub const fn vmpl(&self) -> u32 {
        self.u32_at(0x30)
    }

    /// Algorithm used to produce [`signature`](Self::signature).
    #[must_use]
    pub const fn signature_algo(&self) -> SignatureAlgo {
        SignatureAlgo::from_raw(self.u32_at(0x34))
    }

    /// TCB version currently running on the platform.
    #[must_use]
    pub const fn current_tcb(&self) -> TcbVersion {
        TcbVersion::from_raw(self.u64_at(0x38))
    }

    /// Host platform configuration.
    #[must_use]
    pub const fn platform_info(&self) -> PlatformInfo {
        PlatformInfo::from_raw(self.u64_at(0x40))
    }

    /// How the report was signed and what the host chose to reveal.
    #[must_use]
    pub const fn signer_info(&self) -> SignerInfo {
        SignerInfo::from_raw(self.u32_at(0x48))
    }

    /// The 64 bytes of caller-supplied data bound into this report.
    ///
    /// This is the field that makes a report fresh: put a verifier-supplied
    /// nonce, or a hash of a public key, here.
    #[must_use]
    pub const fn report_data(&self) -> &[u8; 64] {
        self.field(0x50)
    }

    /// SHA-384 launch measurement of the guest's initial memory image.
    #[must_use]
    pub const fn measurement(&self) -> &[u8; 48] {
        self.field(0x90)
    }

    /// Data supplied by the host at launch. Not guest-controlled.
    #[must_use]
    pub const fn host_data(&self) -> &[u8; 32] {
        self.field(0xC0)
    }

    /// SHA-384 digest of the ID public key that signed the ID block.
    #[must_use]
    pub const fn id_key_digest(&self) -> &[u8; 48] {
        self.field(0xE0)
    }

    /// SHA-384 digest of the author public key that signed the ID key.
    #[must_use]
    pub const fn author_key_digest(&self) -> &[u8; 48] {
        self.field(0x110)
    }

    /// Identifier for this guest, stable across reports from the same VM.
    #[must_use]
    pub const fn report_id(&self) -> &[u8; 32] {
        self.field(0x140)
    }

    /// Report ID of this guest's migration agent.
    #[must_use]
    pub const fn report_id_ma(&self) -> &[u8; 32] {
        self.field(0x160)
    }

    /// The TCB version the report was signed against.
    ///
    /// This, not [`current_tcb`](Self::current_tcb), selects the VCEK that
    /// verifies the signature.
    #[must_use]
    pub const fn reported_tcb(&self) -> TcbVersion {
        TcbVersion::from_raw(self.u64_at(0x180))
    }

    /// Processor family, model and stepping. Present from report version 3.
    #[must_use]
    pub fn cpuid_fms(&self) -> Option<Fms> {
        let &[family, model, stepping] = self.field::<3>(0x188);
        (self.version() >= 3).then(|| Fms::new(family, model, stepping))
    }

    /// The processor product that produced this report.
    ///
    /// Present from report version 3, which is when AMD started including
    /// CPUID identification. On a version 2 report the product must come from
    /// somewhere else, such as the local CPU via [`crate::detect`].
    #[must_use]
    pub fn product(&self) -> Option<Product> {
        self.cpuid_fms().map(Product::from_fms)
    }

    /// Unique identifier of the physical processor.
    ///
    /// Reads as all zeros when [`SignerInfo::chip_key_masked`] is set, or when
    /// the report was signed by a VLEK rather than a VCEK.
    #[must_use]
    pub const fn chip_id(&self) -> &[u8; 64] {
        self.field(0x1A0)
    }

    /// The lowest TCB version the platform can be rolled back to.
    #[must_use]
    pub const fn committed_tcb(&self) -> TcbVersion {
        TcbVersion::from_raw(self.u64_at(0x1E0))
    }

    /// Firmware version currently running.
    #[must_use]
    pub const fn current_firmware(&self) -> FirmwareVersion {
        let &[build, minor, major] = self.field::<3>(0x1E8);
        FirmwareVersion {
            major,
            minor,
            build,
        }
    }

    /// Firmware version the platform has committed to.
    #[must_use]
    pub const fn committed_firmware(&self) -> FirmwareVersion {
        let &[build, minor, major] = self.field::<3>(0x1EC);
        FirmwareVersion {
            major,
            minor,
            build,
        }
    }

    /// The TCB version in effect when this guest was launched.
    #[must_use]
    pub const fn launch_tcb(&self) -> TcbVersion {
        TcbVersion::from_raw(self.u64_at(0x1F0))
    }

    /// Mitigation vector in effect at launch. Present from report version 5.
    ///
    /// Each bit records a hardware mitigation that was active. Pass it to
    /// `KeyRequest::bind_launch_mit_vector` to make a derived key depend on the
    /// mitigation state.
    #[must_use]
    pub fn launch_mit_vector(&self) -> Option<u64> {
        (self.version() >= 5).then(|| self.u64_at(0x1F8))
    }

    /// Mitigation vector currently in effect. Present from report version 5.
    #[must_use]
    pub fn current_mit_vector(&self) -> Option<u64> {
        (self.version() >= 5).then(|| self.u64_at(0x200))
    }

    /// The raw 512-byte signature field.
    #[must_use]
    pub const fn signature(&self) -> &[u8; 512] {
        self.field(0x2A0)
    }

    /// The signature decoded as ECDSA P-384 components.
    ///
    /// Returns `None` unless [`signature_algo`](Self::signature_algo) is
    /// [`SignatureAlgo::EcdsaP384Sha384`].
    #[must_use]
    pub fn ecdsa_signature(&self) -> Option<EcdsaP384Signature<'_>> {
        if self.signature_algo() == SignatureAlgo::EcdsaP384Sha384 {
            Some(EcdsaP384Signature {
                r: self.field(0x2A0),
                s: self.field(0x2E8),
            })
        } else {
            None
        }
    }

    /// Splits [`reported_tcb`](Self::reported_tcb) into named fields.
    ///
    /// Returns `None` on a version 2 report, which carries no CPUID
    /// identification; use [`TcbVersion::decode`] with an externally known
    /// product in that case.
    #[must_use]
    pub fn reported_tcb_parts(&self) -> Option<TcbParts> {
        self.product().map(|p| self.reported_tcb().decode(p))
    }

    const fn u32_at(&self, offset: usize) -> u32 {
        u32::from_le_bytes(*self.field(offset))
    }

    const fn u64_at(&self, offset: usize) -> u64 {
        u64::from_le_bytes(*self.field(offset))
    }

    /// Borrows a fixed-size field out of the report.
    ///
    /// Every offset used here is a compile-time constant that lies inside a
    /// report, so the slice always exists. Falling back to a static zero field
    /// rather than indexing keeps the function total: an out-of-range offset
    /// would be a bug in this module, not a reason to panic in a caller's
    /// attestation path.
    const fn field<const N: usize>(&self, offset: usize) -> &[u8; N] {
        match self.raw.split_at_checked(offset) {
            Some((_, tail)) => match tail.first_chunk::<N>() {
                Some(field) => field,
                None => const { &[0u8; N] },
            },
            None => const { &[0u8; N] },
        }
    }
}

impl fmt::Debug for AttestationReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = f.debug_struct("AttestationReport");
        s.field("version", &self.version())
            .field("guest_svn", &self.guest_svn())
            .field("policy", &self.policy())
            .field("vmpl", &self.vmpl())
            .field("signature_algo", &self.signature_algo())
            .field("current_tcb", &self.current_tcb())
            .field("reported_tcb", &self.reported_tcb())
            .field("committed_tcb", &self.committed_tcb())
            .field("launch_tcb", &self.launch_tcb())
            .field("platform_info", &self.platform_info())
            .field("signer_info", &self.signer_info())
            .field("measurement", &Hex(self.measurement()))
            .field("report_data", &Hex(self.report_data()))
            .field("host_data", &Hex(self.host_data()))
            .field("report_id", &Hex(self.report_id()))
            .field("chip_id", &Hex(self.chip_id()))
            .field("current_firmware", &self.current_firmware())
            .field("committed_firmware", &self.committed_firmware());
        if let Some(fms) = self.cpuid_fms() {
            s.field("cpuid_fms", &fms);
        }
        if let Some(v) = self.launch_mit_vector() {
            s.field("launch_mit_vector", &format_args!("{v:#x}"));
        }
        if let Some(v) = self.current_mit_vector() {
            s.field("current_mit_vector", &format_args!("{v:#x}"));
        }
        s.finish_non_exhaustive()
    }
}

struct Hex<'a>(&'a [u8]);

impl fmt::Debug for Hex<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

/// A `major.minor.build` firmware version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FirmwareVersion {
    /// Major version.
    pub major: u8,
    /// Minor version.
    pub minor: u8,
    /// Build number.
    pub build: u8,
}

impl fmt::Display for FirmwareVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.build)
    }
}

/// An ECDSA P-384 signature in AMD's wire format.
///
/// Both components are 72-byte little-endian fields, which is not what most
/// signature verifiers want; [`r_be`](Self::r_be) and [`s_be`](Self::s_be)
/// convert to the 48-byte big-endian integers used by SEC1 and RFC 5480.
///
/// Borrowed from the report rather than copied, so decoding a signature costs
/// nothing until a component is actually converted.
#[derive(Clone, Copy)]
pub struct EcdsaP384Signature<'a> {
    /// The `r` component, little-endian, zero-padded to 72 bytes.
    pub r: &'a [u8; 72],
    /// The `s` component, little-endian, zero-padded to 72 bytes.
    pub s: &'a [u8; 72],
}

impl EcdsaP384Signature<'_> {
    /// The `r` component as a 48-byte big-endian integer.
    #[must_use]
    pub fn r_be(&self) -> [u8; 48] {
        to_be_48(self.r)
    }

    /// The `s` component as a 48-byte big-endian integer.
    #[must_use]
    pub fn s_be(&self) -> [u8; 48] {
        to_be_48(self.s)
    }
}

impl fmt::Debug for EcdsaP384Signature<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EcdsaP384Signature")
            .field("r", &Hex(&self.r_be()))
            .field("s", &Hex(&self.s_be()))
            .finish()
    }
}

/// Reverses the low 48 bytes of an AMD little-endian field component.
///
/// The upper 24 bytes are always zero for P-384; they are ignored rather than
/// checked, because a non-zero value there would already have failed signature
/// verification.
fn to_be_48(le: &[u8; 72]) -> [u8; 48] {
    let mut out = *le.first_chunk::<48>().unwrap_or(&[0u8; 48]);
    out.reverse();
    out
}
