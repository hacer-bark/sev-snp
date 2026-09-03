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

pub mod configfs;
pub mod ioctl;

use crate::certs::ExtendedReport;
use crate::error::Result;
use crate::key::{DerivedKey, KeyRequest};
use crate::report::AttestationReport;

/// Which kernel interface a backend speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Transport {
    /// The `/dev/sev-guest` character device.
    Ioctl,
    /// The configfs-TSM interface under `/sys/kernel/config/tsm/report`.
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
    pub const fn new() -> Self {
        Self {
            data: [0u8; 64],
            vmpl: None,
        }
    }

    /// Sets the 64 bytes bound into the report.
    pub const fn data(mut self, data: [u8; 64]) -> Self {
        self.data = data;
        self
    }

    /// Requests the report at a specific VMPL.
    ///
    /// Must be at or above the caller's own privilege level. Leaving this unset
    /// lets the kernel use its default, which is the level the guest runs at.
    pub const fn vmpl(mut self, vmpl: u32) -> Self {
        self.vmpl = Some(vmpl);
        self
    }

    /// The report data this request carries.
    pub const fn report_data(&self) -> &[u8; 64] {
        &self.data
    }

    /// The VMPL this request targets, if one was set explicitly.
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
    fn report(&self, request: &ReportRequest) -> Result<AttestationReport>;

    /// Requests a report together with the host-provisioned certificate chain.
    fn extended_report(&self, request: &ReportRequest) -> Result<ExtendedReport>;

    /// Derives a key from a chip-held root secret.
    fn derive_key(&self, request: &KeyRequest) -> Result<DerivedKey>;
}

/// Whether any usable guest interface exists on this system.
pub fn any_available() -> bool {
    configfs::available() || ioctl::available()
}
