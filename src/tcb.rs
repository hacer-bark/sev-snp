//! Processor identification and TCB version decoding.
//!
//! `TCB_VERSION` is the one field in the SEV-SNP ABI whose *layout* depends on
//! the processor generation, so decoding it requires knowing the product. Zen 3
//! (Milan) and Zen 4 (Genoa, Bergamo, Siena) use the legacy layout; Zen 5
//! (Turin) and later insert an FMC security version number and shift the rest.

use std::fmt;

/// A processor family/model/stepping triple as reported by `CPUID(1).EAX`.
///
/// Attestation reports from version 3 onwards carry this directly, which is why
/// [`AttestationReport`](crate::AttestationReport) can decode its own TCB fields
/// without asking the caller which machine produced them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Fms {
    /// Combined base and extended family.
    pub family: u8,
    /// Combined base and extended model.
    pub model: u8,
    /// Stepping.
    pub stepping: u8,
}

impl Fms {
    /// Builds an `Fms` from its parts.
    pub const fn new(family: u8, model: u8, stepping: u8) -> Self {
        Self {
            family,
            model,
            stepping,
        }
    }

    /// Re-encodes into the `CPUID(1).EAX` representation.
    pub const fn to_cpuid_1_eax(self) -> u32 {
        let (family, model, stepping) =
            (self.family as u32, self.model as u32, self.stepping as u32);
        let (base_family, ext_family) = if family >= 0xF {
            (0xF, family - 0xF)
        } else {
            (family, 0)
        };
        (ext_family << 20)
            | ((model >> 4) << 16)
            | (base_family << 8)
            | ((model & 0xF) << 4)
            | (stepping & 0xF)
    }

    /// Decodes a `CPUID(1).EAX` value.
    pub const fn from_cpuid_1_eax(eax: u32) -> Self {
        let base_family = ((eax >> 8) & 0xF) as u8;
        let ext_family = ((eax >> 20) & 0xFF) as u8;
        let family = if base_family == 0xF {
            base_family.wrapping_add(ext_family)
        } else {
            base_family
        };
        let model = (((eax >> 12) & 0xF0) | ((eax >> 4) & 0xF)) as u8;
        Self::new(family, model, (eax & 0xF) as u8)
    }
}

impl fmt::Display for Fms {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "family {:#04x} model {:#04x} stepping {}",
            self.family, self.model, self.stepping
        )
    }
}

/// An AMD EPYC generation, as far as the SEV-SNP ABI cares about it.
///
/// Only the distinction that changes wire layouts is load-bearing; the named
/// variants exist so callers can log something readable and so certificate
/// lookups can name the right product line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Product {
    /// Zen 3, family 19h models 00h-0Fh.
    Milan,
    /// Zen 4, family 19h models 10h-1Fh.
    Genoa,
    /// Zen 4c, family 19h models A0h-AFh (Bergamo and Siena).
    Bergamo,
    /// Zen 5, family 1Ah.
    Turin,
    /// A part this crate does not have a name for.
    ///
    /// TCB decoding still works: the layout is chosen by family, so anything
    /// newer than Zen 5 is handled with the Turin layout.
    Unknown(Fms),
}

impl Product {
    /// Identifies a product from its family/model/stepping.
    pub const fn from_fms(fms: Fms) -> Self {
        match (fms.family, fms.model) {
            (0x19, 0x00..=0x0F) => Self::Milan,
            (0x19, 0x10..=0x1F) => Self::Genoa,
            (0x19, 0xA0..=0xAF) => Self::Bergamo,
            (0x1A, _) => Self::Turin,
            _ => Self::Unknown(fms),
        }
    }

    /// The `TCB_VERSION` layout used by this product.
    pub const fn tcb_layout(self) -> TcbLayout {
        match self {
            Self::Milan | Self::Genoa | Self::Bergamo => TcbLayout::Legacy,
            Self::Turin => TcbLayout::Turin,
            // Anything on family 1Ah or later uses the Turin layout; older
            // families are Zen 3/4 era and use the legacy one.
            Self::Unknown(fms) => {
                if fms.family >= 0x1A {
                    TcbLayout::Turin
                } else {
                    TcbLayout::Legacy
                }
            }
        }
    }

    /// The name AMD's Key Distribution Service uses for this product line.
    ///
    /// Returns `None` for parts this crate cannot name, since guessing a KDS
    /// path would produce a silently wrong certificate lookup.
    pub const fn kds_name(self) -> Option<&'static str> {
        match self {
            Self::Milan => Some("Milan"),
            Self::Genoa => Some("Genoa"),
            Self::Bergamo => Some("Bergamo"),
            Self::Turin => Some("Turin"),
            Self::Unknown(_) => None,
        }
    }
}

impl fmt::Display for Product {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown(fms) => write!(f, "unknown product ({fms})"),
            other => write!(f, "{other:?}"),
        }
    }
}

/// Which byte order a `TCB_VERSION` uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TcbLayout {
    /// Zen 3 and Zen 4: `{bootloader, tee, _, _, _, _, snp, microcode}`.
    Legacy,
    /// Zen 5 and later: `{fmc, bootloader, tee, snp, _, _, _, microcode}`.
    Turin,
}

/// A raw 64-bit `TCB_VERSION`.
///
/// Kept opaque because the same 64 bits mean different things on different
/// processors. Call [`decode`](Self::decode) with the product that produced it
/// to get named fields, or [`raw`](Self::raw) to pass it back to the firmware
/// unchanged — which is what key derivation wants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct TcbVersion(u64);

impl TcbVersion {
    /// Wraps a raw `TCB_VERSION`.
    pub const fn from_raw(raw: u64) -> Self {
        Self(raw)
    }

    /// The underlying 64-bit value.
    pub const fn raw(self) -> u64 {
        self.0
    }

    /// Splits the value into named security version numbers.
    pub const fn decode(self, product: Product) -> TcbParts {
        let b = self.0.to_le_bytes();
        match product.tcb_layout() {
            TcbLayout::Legacy => TcbParts {
                fmc: None,
                bootloader: b[0],
                tee: b[1],
                snp: b[6],
                microcode: b[7],
            },
            TcbLayout::Turin => TcbParts {
                fmc: Some(b[0]),
                bootloader: b[1],
                tee: b[2],
                snp: b[3],
                microcode: b[7],
            },
        }
    }
}

impl fmt::Display for TcbVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#018x}", self.0)
    }
}

/// The named security version numbers inside a `TCB_VERSION`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TcbParts {
    /// FMC security version number. Only present on Zen 5 and later.
    pub fmc: Option<u8>,
    /// PSP bootloader security version number.
    pub bootloader: u8,
    /// PSP operating system security version number.
    pub tee: u8,
    /// SNP firmware security version number.
    pub snp: u8,
    /// Lowest microcode patch level across all cores.
    pub microcode: u8,
}

impl TcbParts {
    /// Re-encodes these fields into a raw `TCB_VERSION` for the given product.
    ///
    /// `fmc` is written only when the layout has a slot for it, so a value set
    /// on a legacy part is dropped rather than corrupting the bootloader field.
    pub const fn encode(self, product: Product) -> TcbVersion {
        let bytes = match product.tcb_layout() {
            TcbLayout::Legacy => [
                self.bootloader,
                self.tee,
                0,
                0,
                0,
                0,
                self.snp,
                self.microcode,
            ],
            TcbLayout::Turin => {
                let fmc = match self.fmc {
                    Some(v) => v,
                    None => 0,
                };
                [
                    fmc,
                    self.bootloader,
                    self.tee,
                    self.snp,
                    0,
                    0,
                    0,
                    self.microcode,
                ]
            }
        };
        TcbVersion(u64::from_le_bytes(bytes))
    }
}

impl fmt::Display for TcbParts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(fmc) = self.fmc {
            write!(f, "fmc={fmc} ")?;
        }
        write!(
            f,
            "bootloader={} tee={} snp={} microcode={}",
            self.bootloader, self.tee, self.snp, self.microcode
        )
    }
}
