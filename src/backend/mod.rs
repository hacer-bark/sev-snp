//! The two kernel interfaces to the SEV-SNP guest firmware.
//!
//! Linux exposes guest requests twice. [`configfs`] is the newer, generic
//! confidential-computing interface added in 6.7; [`ioctl`] is the original
//! `/dev/sev-guest` character device from 5.19. They are not equivalent, and
//! neither one is a superset:
//!
//! | | [`Transport::Ioctl`] | [`Transport::ConfigFs`] |
//! |---|---|---|
//! | Minimum kernel | 5.19 | 6.7 |
//! | Attestation report | yes | yes |
//! | Certificate chain | yes | yes |
//! | Derived key | **yes** | no |
//! | Firmware error codes | **yes** | collapsed to `errno` |
//! | Concurrent-writer detection | no | **yes** |
//!
//! [`crate::Firmware::open`] prefers configfs, because its generation counter
//! catches another process overwriting the request between the write and the
//! read, and falls back to the ioctl device. Key derivation always needs the
//! ioctl device, so `Firmware` opens both when it can.

#[cfg(feature = "configfs")]
#[cfg_attr(docsrs, doc(cfg(feature = "configfs")))]
pub mod configfs;

#[cfg(feature = "sev-guest")]
#[cfg_attr(docsrs, doc(cfg(feature = "sev-guest")))]
pub mod ioctl;

use crate::certs::ExtendedReport;
use crate::error::Result;
#[cfg(feature = "sev-guest")]
use crate::key::{DerivedKey, KeyRequest};
use crate::report::AttestationReport;

/// Which kernel interface a backend speaks.
///
/// A variant exists only when its feature is enabled, so naming a transport
/// this build cannot speak is a compile error rather than a runtime one.
///
/// Marked `#[non_exhaustive]` because of that: cargo unifies features across a
/// dependency graph, so another crate switching one on would otherwise break an
/// exhaustive `match` written here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Transport {
    /// The `/dev/sev-guest` character device.
    #[cfg(feature = "sev-guest")]
    #[cfg_attr(docsrs, doc(cfg(feature = "sev-guest")))]
    Ioctl,
    /// The configfs-TSM interface under `/sys/kernel/config/tsm/report`.
    #[cfg(feature = "configfs")]
    #[cfg_attr(docsrs, doc(cfg(feature = "configfs")))]
    ConfigFs,
}

/// A request for an attestation report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReportRequest {
    pub(crate) data: [u8; 64],
    pub(crate) vmpl: Option<u32>,
}

impl ReportRequest {
    /// A request with all-zero report data at the guest's own VMPL.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            data: [0u8; 64],
            vmpl: None,
        }
    }

    /// Sets the 64 bytes bound into the report.
    #[must_use]
    pub const fn data(mut self, data: [u8; 64]) -> Self {
        self.data = data;
        self
    }

    /// Requests the report at a specific VMPL.
    ///
    /// Must be at or above the caller's own privilege level. Leaving this unset
    /// lets the kernel use its default, which is the level the guest runs at.
    #[must_use]
    pub const fn vmpl(mut self, vmpl: u32) -> Self {
        self.vmpl = Some(vmpl);
        self
    }

    /// The report data this request carries.
    #[must_use]
    pub const fn report_data(&self) -> &[u8; 64] {
        &self.data
    }

    /// The VMPL this request targets, if one was set explicitly.
    #[must_use]
    pub const fn requested_vmpl(&self) -> Option<u32> {
        self.vmpl
    }
}

impl Default for ReportRequest {
    fn default() -> Self {
        Self::new()
    }
}

impl From<[u8; 64]> for ReportRequest {
    fn from(data: [u8; 64]) -> Self {
        Self::new().data(data)
    }
}

impl From<&[u8; 64]> for ReportRequest {
    fn from(data: &[u8; 64]) -> Self {
        Self::new().data(*data)
    }
}

/// A kernel interface capable of issuing SEV-SNP guest requests.
///
/// Implemented by [`configfs::ConfigFs`] and [`ioctl::SevGuest`]. Operations a
/// transport does not implement return [`Error::Unsupported`](crate::Error::Unsupported)
/// rather than panicking or silently degrading.
pub trait GuestBackend: std::fmt::Debug + Send + Sync {
    /// Which interface this backend speaks.
    fn transport(&self) -> Transport;

    /// Requests a signed attestation report.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Firmware`](crate::Error::Firmware) or
    /// [`Error::Vmm`](crate::Error::Vmm) if the request was rejected,
    /// [`Error::Io`](crate::Error::Io) if the kernel call failed, or
    /// [`Error::Parse`](crate::Error::Parse) if the response was malformed.
    fn report(&self, request: &ReportRequest) -> Result<AttestationReport>;

    /// Requests a report together with the host-provisioned certificate chain.
    ///
    /// # Errors
    ///
    /// As [`report`](Self::report), and additionally
    /// [`Error::Parse`](crate::Error::Parse) if the certificate table does not
    /// describe bodies that lie within the blob the host returned.
    fn extended_report(&self, request: &ReportRequest) -> Result<ExtendedReport>;

    /// Derives a key from a chip-held root secret.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Unsupported`](crate::Error::Unsupported) on a transport
    /// without a key derivation interface,
    /// [`Error::InvalidArgument`](crate::Error::InvalidArgument) for a VMPL
    /// outside `0..=3`, or [`Error::Firmware`](crate::Error::Firmware) if the
    /// secure processor rejected the binding.
    #[cfg(feature = "sev-guest")]
    #[cfg_attr(docsrs, doc(cfg(feature = "sev-guest")))]
    fn derive_key(&self, request: &KeyRequest) -> Result<DerivedKey>;
}

/// Whether any usable guest interface exists on this system.
///
/// Only transports compiled into this build are considered.
#[must_use]
pub fn any_available() -> bool {
    #[cfg(feature = "configfs")]
    if configfs::available() {
        return true;
    }
    #[cfg(feature = "sev-guest")]
    if ioctl::available() {
        return true;
    }
    false
}
