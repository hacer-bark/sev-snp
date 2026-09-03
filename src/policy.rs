//! Bitfields carried inside an attestation report.
//!
//! Every type here keeps the raw value it was built from and exposes named
//! accessors on top. Bits that AMD adds in a later ABI revision are therefore
//! never lost — [`GuestPolicy::raw`] and friends always round-trip, and the
//! `unknown_bits` helpers make forward-compatible checks explicit rather than
//! turning an unrecognised bit into a parse failure.

use std::fmt;

/// The launch policy the guest owner pinned at VM start.
///
/// Bits 15:0 hold the minimum SEV-SNP ABI version the guest requires; the rest
/// are feature switches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GuestPolicy(u64);

impl GuestPolicy {
    /// Bits this crate knows how to name.
    const KNOWN: u64 = 0x03FF_FFFF;

    /// Wraps a raw policy value.
    pub const fn from_raw(raw: u64) -> Self {
        Self(raw)
    }

    /// The underlying 64-bit value.
    pub const fn raw(self) -> u64 {
        self.0
    }

    /// Minimum SEV-SNP ABI minor version required to run this guest.
    pub const fn abi_minor(self) -> u8 {
        self.0 as u8
    }

    /// Minimum SEV-SNP ABI major version required to run this guest.
    pub const fn abi_major(self) -> u8 {
        (self.0 >> 8) as u8
    }

    /// Simultaneous multithreading is permitted on the host.
    pub const fn smt_allowed(self) -> bool {
        self.bit(16)
    }

    /// Reserved bit 17, which the ABI requires to be set on a valid policy.
    pub const fn reserved_bit_set(self) -> bool {
        self.bit(17)
    }

    /// Association with a migration agent is permitted.
    pub const fn migrate_ma_allowed(self) -> bool {
        self.bit(18)
    }

    /// Debugging is permitted, which lets the host read guest memory.
    ///
    /// A relying party should normally refuse a report with this set.
    pub const fn debug_allowed(self) -> bool {
        self.bit(19)
    }

    /// The guest must run on a single socket.
    pub const fn single_socket_required(self) -> bool {
        self.bit(20)
    }

    /// CXL memory may be attached to the guest.
    pub const fn cxl_allowed(self) -> bool {
        self.bit(21)
    }

    /// The guest requires AES-256-XTS memory encryption.
    pub const fn mem_aes_256_xts_required(self) -> bool {
        self.bit(22)
    }

    /// Running average power limit reporting must be disabled.
    pub const fn rapl_disabled(self) -> bool {
        self.bit(23)
    }

    /// The guest requires ciphertext hiding for DRAM.
    pub const fn ciphertext_hiding_dram_required(self) -> bool {
        self.bit(24)
    }

    /// Page swapping by the host is disabled for this guest.
    pub const fn page_swap_disabled(self) -> bool {
        self.bit(25)
    }

    /// Policy bits set that this crate does not have a name for.
    ///
    /// Non-zero means the guest was launched under a policy from a newer ABI
    /// revision. Inspect it before treating an absent feature flag as "off".
    pub const fn unknown_bits(self) -> u64 {
        self.0 & !Self::KNOWN
    }

    const fn bit(self, n: u32) -> bool {
        self.0 & (1 << n) != 0
    }
}

impl fmt::Display for GuestPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "abi={}.{}", self.abi_major(), self.abi_minor())?;
        for (name, set) in [
            ("smt", self.smt_allowed()),
            ("migrate-ma", self.migrate_ma_allowed()),
            ("debug", self.debug_allowed()),
            ("single-socket", self.single_socket_required()),
            ("cxl", self.cxl_allowed()),
            ("aes-256-xts", self.mem_aes_256_xts_required()),
            ("rapl-dis", self.rapl_disabled()),
            ("ciphertext-hiding", self.ciphertext_hiding_dram_required()),
            ("page-swap-dis", self.page_swap_disabled()),
        ] {
            if set {
                write!(f, " {name}")?;
            }
        }
        Ok(())
    }
}

/// Host platform configuration at the time the report was signed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PlatformInfo(u64);

impl PlatformInfo {
    const KNOWN: u64 = 0xBF;

    /// Wraps a raw platform info value.
    pub const fn from_raw(raw: u64) -> Self {
        Self(raw)
    }

    /// The underlying 64-bit value.
    pub const fn raw(self) -> u64 {
        self.0
    }

    /// Simultaneous multithreading is enabled on the host.
    pub const fn smt_enabled(self) -> bool {
        self.bit(0)
    }

    /// Transparent secure memory encryption is enabled.
    pub const fn tsme_enabled(self) -> bool {
        self.bit(1)
    }

    /// Memory is protected by error correcting codes.
    pub const fn ecc_enabled(self) -> bool {
        self.bit(2)
    }

    /// Running average power limit reporting is disabled.
    pub const fn rapl_disabled(self) -> bool {
        self.bit(3)
    }

    /// Ciphertext hiding is enabled for DRAM.
    pub const fn ciphertext_hiding_dram_enabled(self) -> bool {
        self.bit(4)
    }

    /// Alias detection has completed since the last reset with no aliases found.
    ///
    /// This is the platform's attestable mitigation for the BadRAM class of
    /// attacks (AMD-SB-3015); a relying party that cares about physical memory
    /// aliasing should require it.
    pub const fn alias_check_complete(self) -> bool {
        self.bit(5)
    }

    /// SEV-TIO (trusted I/O) is enabled.
    pub const fn tio_enabled(self) -> bool {
        self.bit(7)
    }

    /// Platform info bits set that this crate does not have a name for.
    pub const fn unknown_bits(self) -> u64 {
        self.0 & !Self::KNOWN
    }

    const fn bit(self, n: u32) -> bool {
        self.0 & (1 << n) != 0
    }
}

impl fmt::Display for PlatformInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for (name, set) in [
            ("smt", self.smt_enabled()),
            ("tsme", self.tsme_enabled()),
            ("ecc", self.ecc_enabled()),
            ("rapl-dis", self.rapl_disabled()),
            ("ciphertext-hiding", self.ciphertext_hiding_dram_enabled()),
            ("alias-check-complete", self.alias_check_complete()),
            ("tio", self.tio_enabled()),
        ] {
            if set {
                if !first {
                    f.write_str(" ")?;
                }
                f.write_str(name)?;
                first = false;
            }
        }
        if first {
            f.write_str("none")?;
        }
        Ok(())
    }
}

/// Which key signed the attestation report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SigningKey {
    /// Versioned Chip Endorsement Key: unique to this physical processor.
    Vcek,
    /// Versioned Loaded Endorsement Key: provisioned by the cloud provider.
    Vlek,
    /// No key; the report is unsigned.
    None,
    /// A signing key kind this crate does not recognise.
    Unknown(u8),
}

/// How the report was signed and what the host chose to reveal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SignerInfo(u32);

impl SignerInfo {
    /// Wraps a raw signer info value.
    pub const fn from_raw(raw: u32) -> Self {
        Self(raw)
    }

    /// The underlying 32-bit value.
    pub const fn raw(self) -> u32 {
        self.0
    }

    /// The guest was launched with an ID block that includes an author key.
    pub const fn author_key_enabled(self) -> bool {
        self.0 & 1 != 0
    }

    /// The host masked the chip ID, so `CHIP_ID` in the report reads as zeros.
    pub const fn chip_key_masked(self) -> bool {
        self.0 & 2 != 0
    }

    /// The key that signed the report.
    pub const fn signing_key(self) -> SigningKey {
        match ((self.0 >> 2) & 0x7) as u8 {
            0 => SigningKey::Vcek,
            1 => SigningKey::Vlek,
            7 => SigningKey::None,
            other => SigningKey::Unknown(other),
        }
    }
}

impl fmt::Display for SignerInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.signing_key())?;
        if self.author_key_enabled() {
            f.write_str(" author-key")?;
        }
        if self.chip_key_masked() {
            f.write_str(" chip-key-masked")?;
        }
        Ok(())
    }
}

/// The algorithm used to sign the report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SignatureAlgo {
    /// The report is not signed.
    None,
    /// ECDSA over P-384 with SHA-384.
    EcdsaP384Sha384,
    /// An algorithm this crate does not recognise.
    Unknown(u32),
}

impl SignatureAlgo {
    /// Interprets a raw `SIGNATURE_ALGO` value.
    pub const fn from_raw(raw: u32) -> Self {
        match raw {
            0 => Self::None,
            1 => Self::EcdsaP384Sha384,
            other => Self::Unknown(other),
        }
    }
}
