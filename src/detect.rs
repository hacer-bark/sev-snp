//! Detecting SEV, SEV-ES and SEV-SNP support from inside the guest.
//!
//! `CPUID(0x8000_001F)` reports what the processor exposes to this VM. Inside an
//! SNP guest the leaf is served from the guest CPUID table the firmware
//! validated at launch, so its answers are trustworthy — unlike most CPUID
//! results in a confidential VM.
//!
//! What CPUID cannot tell you is whether encryption is *active* for this guest;
//! that lives in `MSR_AMD64_SEV`, which is ring 0 only. Use
//! [`is_snp_guest`] instead, which pairs the capability bits with the presence
//! of a working kernel guest interface.

use std::fmt;

/// What the processor reports about its memory encryption features.
///
/// Wraps the four registers of `CPUID(0x8000_001F)`. Feature bits are exposed
/// as accessors rather than fields so that a value read on newer silicon keeps
/// everything this crate does not yet name; [`Self::registers`] always returns
/// the untouched result.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Capabilities {
    eax: u32,
    ebx: u32,
    ecx: u32,
    edx: u32,
}

impl Capabilities {
    /// Secure Memory Encryption.
    ///
    /// A host feature; guests normally see this clear even when SEV is active.
    #[must_use]
    pub const fn sme(self) -> bool {
        self.feature(0)
    }

    /// Secure Encrypted Virtualization.
    #[must_use]
    pub const fn sev(self) -> bool {
        self.feature(1)
    }

    /// The page flush MSR is available.
    #[must_use]
    pub const fn page_flush_msr(self) -> bool {
        self.feature(2)
    }

    /// SEV Encrypted State: register state is encrypted too.
    #[must_use]
    pub const fn sev_es(self) -> bool {
        self.feature(3)
    }

    /// SEV Secure Nested Paging: memory integrity protection.
    #[must_use]
    pub const fn sev_snp(self) -> bool {
        self.feature(4)
    }

    /// Virtual Machine Privilege Levels are supported.
    #[must_use]
    pub const fn vmpl(self) -> bool {
        self.feature(5)
    }

    /// The `RMPQUERY` instruction is available.
    #[must_use]
    pub const fn rmpquery(self) -> bool {
        self.feature(6)
    }

    /// Secure TSC is supported.
    #[must_use]
    pub const fn secure_tsc(self) -> bool {
        self.feature(8)
    }

    /// Virtual Transparent Encryption.
    #[must_use]
    pub const fn vte(self) -> bool {
        self.feature(16)
    }

    /// Bit position of the C-bit in a page table entry.
    #[must_use]
    pub const fn c_bit_position(self) -> u8 {
        low_byte(self.ebx & 0x3F)
    }

    /// Physical address bits lost to encryption metadata.
    #[must_use]
    pub const fn phys_addr_reduction(self) -> u8 {
        low_byte(self.ebx.wrapping_shr(6) & 0x3F)
    }

    /// Number of VMPLs the processor supports.
    ///
    /// Reads as zero when the hypervisor did not populate the field in the
    /// guest CPUID table, which does not imply VMPLs are unavailable.
    #[must_use]
    pub const fn num_vmpls(self) -> u8 {
        low_byte(self.ebx.wrapping_shr(12) & 0xF)
    }

    /// Maximum number of simultaneously encrypted guests.
    #[must_use]
    pub const fn max_encrypted_guests(self) -> u32 {
        self.ecx
    }

    /// Minimum ASID usable by a SEV-enabled, SEV-ES-disabled guest.
    #[must_use]
    pub const fn min_sev_no_es_asid(self) -> u32 {
        self.edx
    }

    /// The raw `EAX`, `EBX`, `ECX` and `EDX` values, in that order.
    #[must_use]
    pub const fn registers(self) -> [u32; 4] {
        [self.eax, self.ebx, self.ecx, self.edx]
    }

    const fn feature(self, bit: u32) -> bool {
        self.eax.wrapping_shr(bit) & 1 == 1
    }
}

impl fmt::Debug for Capabilities {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Capabilities")
            .field("sme", &self.sme())
            .field("sev", &self.sev())
            .field("sev_es", &self.sev_es())
            .field("sev_snp", &self.sev_snp())
            .field("vmpl", &self.vmpl())
            .field("secure_tsc", &self.secure_tsc())
            .field("c_bit_position", &self.c_bit_position())
            .field("phys_addr_reduction", &self.phys_addr_reduction())
            .field("num_vmpls", &self.num_vmpls())
            .finish_non_exhaustive()
    }
}

/// Narrows a value already masked to eight bits or fewer.
const fn low_byte(masked: u32) -> u8 {
    // `u8::try_from` is not callable in a const fn, and the callers have all
    // masked their input to at most eight bits, so the low byte is the value.
    let [byte, _, _, _] = masked.to_le_bytes();
    byte
}

/// Reads `CPUID(0x8000_001F)`.
///
/// Returns `None` when the leaf is not implemented, which is the case on every
/// non-AMD processor and on AMD parts predating SME.
#[cfg(target_arch = "x86_64")]
#[must_use]
pub fn capabilities() -> Option<Capabilities> {
    // `cpuid` is unconditionally available on x86_64, but the extended leaf is
    // only meaningful once 0x8000_0000 confirms the processor implements it.
    use std::arch::x86_64::__cpuid;
    if __cpuid(0x8000_0000).eax < 0x8000_001F {
        return None;
    }
    let leaf = __cpuid(0x8000_001F);
    Some(Capabilities {
        eax: leaf.eax,
        ebx: leaf.ebx,
        ecx: leaf.ecx,
        edx: leaf.edx,
    })
}

/// Reads `CPUID(0x8000_001F)`.
///
/// Always `None` off x86-64.
#[cfg(not(target_arch = "x86_64"))]
#[must_use]
pub fn capabilities() -> Option<Capabilities> {
    None
}

/// Whether this process is running inside an SEV-SNP guest.
///
/// True when the processor advertises SEV-SNP *and* the kernel exposes a guest
/// interface this crate can use. Both halves matter: the capability bit alone
/// is also set on a bare-metal host that merely supports SNP, and a kernel
/// interface can be present but unusable.
#[must_use]
pub fn is_snp_guest() -> bool {
    capabilities().is_some_and(Capabilities::sev_snp) && crate::backend::any_available()
}
