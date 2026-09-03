//! The SEV-SNP attestation report.
//!
//! One binary layout spans every report version AMD has shipped: the structure
//! is always [`AttestationReport::SIZE`] bytes and newer revisions only claim
//! space that older ones reserved. This module parses the fields common to all
//! versions unconditionally, and returns `Option` for the ones that only exist
//! from a given version onwards, so the same code path serves a Zen 3 machine
//! emitting a version 2 report and a Zen 5 machine emitting version 5.

use crate::error::{ParseError, Result};
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

    /// Parses a report from its ABI representation.
    ///
    /// Fails only if the buffer is too short or announces a version older than
    /// [`Self::MIN_VERSION`]. Newer versions are accepted: unrecognised fields
    /// stay reachable through [`as_bytes`](Self::as_bytes).
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let raw: [u8; Self::SIZE] = bytes
            .get(..Self::SIZE)
            .ok_or(ParseError::TooShort {
                what: "attestation report",
                need: Self::SIZE,
                got: bytes.len(),
            })?
            .try_into()
            .expect("slice is exactly SIZE bytes");

        let report = Self { raw };
        if report.version() < Self::MIN_VERSION {
            return Err(ParseError::UnsupportedReportVersion(report.version()).into());
        }
        Ok(report)
    }

    /// The report exactly as the firmware produced it.
    pub fn as_bytes(&self) -> &[u8; Self::SIZE] {
        &self.raw
    }

    /// The bytes covered by [`signature`](Self::signature).
    ///
    /// Hash this with SHA-384 to verify the report against a VCEK or VLEK.
    pub fn signed_bytes(&self) -> &[u8] {
        &self.raw[..Self::SIGNED_LEN]
    }

    /// Report structure version, at least [`Self::MIN_VERSION`].
    pub fn version(&self) -> u32 {
        self.u32_at(0x00)
    }

    /// Guest security version number supplied in the ID block at launch.
    pub fn guest_svn(&self) -> u32 {
        self.u32_at(0x04)
    }

    /// The launch policy the guest owner pinned at VM start.
    pub fn policy(&self) -> GuestPolicy {
        GuestPolicy::from_raw(self.u64_at(0x08))
    }

    /// Family ID from the ID block, chosen by the guest owner.
    pub fn family_id(&self) -> &[u8; 16] {
        self.array_at::<16>(0x10)
    }

    /// Image ID from the ID block, chosen by the guest owner.
    pub fn image_id(&self) -> &[u8; 16] {
        self.array_at::<16>(0x20)
    }

    /// The VMPL the report was requested at.
    pub fn vmpl(&self) -> u32 {
        self.u32_at(0x30)
    }

    /// Algorithm used to produce [`signature`](Self::signature).
    pub fn signature_algo(&self) -> SignatureAlgo {
        SignatureAlgo::from_raw(self.u32_at(0x34))
    }

    /// TCB version currently running on the platform.
    pub fn current_tcb(&self) -> TcbVersion {
        TcbVersion::from_raw(self.u64_at(0x38))
    }

    /// Host platform configuration.
    pub fn platform_info(&self) -> PlatformInfo {
        PlatformInfo::from_raw(self.u64_at(0x40))
    }

    /// How the report was signed and what the host chose to reveal.
    pub fn signer_info(&self) -> SignerInfo {
        SignerInfo::from_raw(self.u32_at(0x48))
    }

    /// The 64 bytes of caller-supplied data bound into this report.
    ///
    /// This is the field that makes a report fresh: put a verifier-supplied
    /// nonce, or a hash of a public key, here.
    pub fn report_data(&self) -> &[u8; 64] {
        self.array_at::<64>(0x50)
    }

    /// SHA-384 launch measurement of the guest's initial memory image.
    pub fn measurement(&self) -> &[u8; 48] {
        self.array_at::<48>(0x90)
    }

    /// Data supplied by the host at launch. Not guest-controlled.
    pub fn host_data(&self) -> &[u8; 32] {
        self.array_at::<32>(0xC0)
    }

    /// SHA-384 digest of the ID public key that signed the ID block.
    pub fn id_key_digest(&self) -> &[u8; 48] {
        self.array_at::<48>(0xE0)
    }

    /// SHA-384 digest of the author public key that signed the ID key.
    pub fn author_key_digest(&self) -> &[u8; 48] {
        self.array_at::<48>(0x110)
    }

    /// Identifier for this guest, stable across reports from the same VM.
    pub fn report_id(&self) -> &[u8; 32] {
        self.array_at::<32>(0x140)
    }

    /// Report ID of this guest's migration agent.
    pub fn report_id_ma(&self) -> &[u8; 32] {
        self.array_at::<32>(0x160)
    }

    /// The TCB version the report was signed against.
    ///
    /// This, not [`current_tcb`](Self::current_tcb), selects the VCEK that
    /// verifies the signature.
    pub fn reported_tcb(&self) -> TcbVersion {
        TcbVersion::from_raw(self.u64_at(0x180))
    }

    /// Processor family, model and stepping. Present from report version 3.
    pub fn cpuid_fms(&self) -> Option<Fms> {
        (self.version() >= 3).then(|| Fms::new(self.raw[0x188], self.raw[0x189], self.raw[0x18A]))
    }

    /// The processor product that produced this report.
    ///
    /// Present from report version 3, which is when AMD started including
    /// CPUID identification. On a version 2 report the product must come from
    /// somewhere else, such as the local CPU via [`crate::detect`].
    pub fn product(&self) -> Option<Product> {
        self.cpuid_fms().map(Product::from_fms)
    }

    /// Unique identifier of the physical processor.
    ///
    /// Reads as all zeros when [`SignerInfo::chip_key_masked`] is set, or when
    /// the report was signed by a VLEK rather than a VCEK.
    pub fn chip_id(&self) -> &[u8; 64] {
        self.array_at::<64>(0x1A0)
    }

    /// The lowest TCB version the platform can be rolled back to.
    pub fn committed_tcb(&self) -> TcbVersion {
        TcbVersion::from_raw(self.u64_at(0x1E0))
    }

    /// Firmware version currently running.
    pub fn current_firmware(&self) -> FirmwareVersion {
        FirmwareVersion {
            build: self.raw[0x1E8],
            minor: self.raw[0x1E9],
            major: self.raw[0x1EA],
        }
    }

    /// Firmware version the platform has committed to.
    pub fn committed_firmware(&self) -> FirmwareVersion {
        FirmwareVersion {
            build: self.raw[0x1EC],
            minor: self.raw[0x1ED],
            major: self.raw[0x1EE],
        }
    }

    /// The TCB version in effect when this guest was launched.
    pub fn launch_tcb(&self) -> TcbVersion {
        TcbVersion::from_raw(self.u64_at(0x1F0))
    }

    /// Mitigation vector in effect at launch. Present from report version 5.
    ///
    /// Each bit records a hardware mitigation that was active. Pass this to
    /// [`KeyRequest::bind_launch_mit_vector`](crate::KeyRequest::bind_launch_mit_vector)
    /// to make a derived key depend on the mitigation state.
    pub fn launch_mit_vector(&self) -> Option<u64> {
        (self.version() >= 5).then(|| self.u64_at(0x1F8))
    }

    /// Mitigation vector currently in effect. Present from report version 5.
    pub fn current_mit_vector(&self) -> Option<u64> {
        (self.version() >= 5).then(|| self.u64_at(0x200))
    }

    /// The raw 512-byte signature field.
    pub fn signature(&self) -> &[u8; 512] {
        self.array_at::<512>(0x2A0)
    }

    /// The signature decoded as ECDSA P-384 components.
    ///
    /// Returns `None` unless [`signature_algo`](Self::signature_algo) is
    /// [`SignatureAlgo::EcdsaP384Sha384`].
    pub fn ecdsa_signature(&self) -> Option<EcdsaP384Signature> {
        if self.signature_algo() != SignatureAlgo::EcdsaP384Sha384 {
            return None;
        }
        Some(EcdsaP384Signature {
            r: *self.array_at::<72>(0x2A0),
            s: *self.array_at::<72>(0x2E8),
        })
    }

    /// Splits [`reported_tcb`](Self::reported_tcb) into named fields.
    ///
    /// Returns `None` on a version 2 report, which carries no CPUID
    /// identification; use [`TcbVersion::decode`] with an externally known
    /// product in that case.
    pub fn reported_tcb_parts(&self) -> Option<TcbParts> {
        self.product().map(|p| self.reported_tcb().decode(p))
    }

    fn u32_at(&self, off: usize) -> u32 {
        u32::from_le_bytes(*self.array_at::<4>(off))
    }

    fn u64_at(&self, off: usize) -> u64 {
        u64::from_le_bytes(*self.array_at::<8>(off))
    }

    /// Borrows a fixed-size field. Offsets are compile-time constants inside
    /// this module and every one of them is covered by a round-trip test, so
    /// the slice length always matches.
    fn array_at<const N: usize>(&self, off: usize) -> &[u8; N] {
        self.raw[off..off + N]
            .try_into()
            .expect("field lies within the report")
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
        s.finish()
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
#[derive(Clone, Copy)]
pub struct EcdsaP384Signature {
    /// The `r` component, little-endian, zero-padded to 72 bytes.
    pub r: [u8; 72],
    /// The `s` component, little-endian, zero-padded to 72 bytes.
    pub s: [u8; 72],
}

impl EcdsaP384Signature {
    /// The `r` component as a 48-byte big-endian integer.
    pub fn r_be(&self) -> [u8; 48] {
        to_be_48(&self.r)
    }

    /// The `s` component as a 48-byte big-endian integer.
    pub fn s_be(&self) -> [u8; 48] {
        to_be_48(&self.s)
    }
}

impl fmt::Debug for EcdsaP384Signature {
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
    let mut out = [0u8; 48];
    for (dst, src) in out.iter_mut().zip(le[..48].iter().rev()) {
        *dst = *src;
    }
    out
}
