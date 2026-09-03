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

/// What the processor reports about its memory encryption features.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Capabilities {
    /// Secure Memory Encryption.
    pub sme: bool,
    /// Secure Encrypted Virtualization.
    pub sev: bool,
    /// The page flush MSR is available.
    pub page_flush_msr: bool,
    /// SEV Encrypted State: register state is encrypted too.
    pub sev_es: bool,
    /// SEV Secure Nested Paging: memory integrity protection.
    pub sev_snp: bool,
    /// Virtual Machine Privilege Levels are supported.
    pub vmpl: bool,
    /// The `RMPQUERY` instruction is available.
    pub rmpquery: bool,
    /// Secure TSC is supported.
    pub secure_tsc: bool,
    /// Virtual Transparent Encryption.
    pub vte: bool,
    /// Bit position of the C-bit in a page table entry.
    pub c_bit_position: u8,
    /// Physical address bits lost to encryption metadata.
    pub phys_addr_reduction: u8,
    /// Number of VMPLs the processor supports.
    pub num_vmpls: u8,
    /// Maximum number of simultaneously encrypted guests.
    pub max_encrypted_guests: u32,
    /// Minimum ASID usable by a SEV-enabled, SEV-ES-disabled guest.
    pub min_sev_no_es_asid: u32,
    /// The raw register values, for anything this struct does not name.
    pub raw: [u32; 4],
}

/// Reads `CPUID(0x8000_001F)`.
///
/// Returns `None` when the leaf is not implemented, which is the case on every
/// non-AMD processor and on AMD parts predating SME.
#[cfg(target_arch = "x86_64")]
pub fn capabilities() -> Option<Capabilities> {
    // `cpuid` is unconditionally available on x86_64, but the extended leaf is
    // only meaningful once 0x8000_0000 confirms the processor implements it.
    use std::arch::x86_64::__cpuid;
    if __cpuid(0x8000_0000).eax < 0x8000_001F {
        return None;
    }
    let leaf = __cpuid(0x8000_001F);

    let (eax, ebx, ecx, edx) = (leaf.eax, leaf.ebx, leaf.ecx, leaf.edx);
    let bit = |n: u32| eax & (1 << n) != 0;

    Some(Capabilities {
        sme: bit(0),
        sev: bit(1),
        page_flush_msr: bit(2),
        sev_es: bit(3),
        sev_snp: bit(4),
        vmpl: bit(5),
        rmpquery: bit(6),
        secure_tsc: bit(8),
        vte: bit(16),
        c_bit_position: (ebx & 0x3F) as u8,
        phys_addr_reduction: ((ebx >> 6) & 0x3F) as u8,
        num_vmpls: ((ebx >> 12) & 0xF) as u8,
        max_encrypted_guests: ecx,
        min_sev_no_es_asid: edx,
        raw: [eax, ebx, ecx, edx],
    })
}

/// Reads `CPUID(0x8000_001F)`.
///
/// Always `None` off x86_64.
#[cfg(not(target_arch = "x86_64"))]
pub fn capabilities() -> Option<Capabilities> {
    None
}

/// Whether this process is running inside an SEV-SNP guest.
///
/// True when the processor advertises SEV-SNP *and* the kernel exposes a guest
/// interface this crate can use. Both halves matter: the capability bit alone
/// is also set on a bare-metal host that merely supports SNP, and a kernel
/// interface can be present but unusable.
pub fn is_snp_guest() -> bool {
    capabilities().is_some_and(|c| c.sev_snp) && crate::backend::any_available()
}
