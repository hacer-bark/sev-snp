//! Safe Rust bindings for the Linux AMD SEV-SNP guest API.
//!
//! Inside an SEV-SNP virtual machine, the AMD secure processor will sign
//! statements about the VM and derive keys that never leave the chip. This
//! crate exposes everything the Linux guest interface offers, over both kernel
//! transports, with no `unsafe` required of the caller.
//!
//! # Getting started
//!
//! ```no_run
//! use sev_snp::Firmware;
//!
//! let fw = Firmware::open()?;
//! let report = fw.report(&[0u8; 64])?;
//!
//! println!("measurement: {:x?}", report.measurement());
//! println!("running on {}", report.product().unwrap());
//! # Ok::<_, sev_snp::Error>(())
//! ```
//!
//! # What the guest can ask for
//!
//! - **[Attestation reports](AttestationReport)** — a signed statement covering
//!   the launch measurement, the guest policy, the platform's firmware versions
//!   and 64 bytes of caller-supplied data. Fetch one with [`Firmware::report`].
//! - **[Endorsement certificates](CertTable)** — the chain that verifies the
//!   report's signature, when the host provisioned one. See
//!   [`Firmware::extended_report`].
//! - **[Derived keys](DerivedKey)** — reproducible key material bound to any
//!   combination of the chip, the firmware version, and the guest image. See
//!   [`Firmware::derive_key`] and the [`key`] module.
//! - **[Capability detection](detect)** — what the processor supports, and
//!   whether this process is in fact running inside an SNP guest.
//!
//! # Portability across Zen 3, Zen 4 and Zen 5
//!
//! The guest request protocol is identical on every SEV-SNP part, so the calls
//! in this crate need no per-generation branching. Two things do vary, and both
//! are handled without asking the caller which machine they are on:
//!
//! - **Report version.** Reports are always [`AttestationReport::SIZE`] bytes;
//!   newer revisions only claim space older ones reserved. Fields introduced
//!   later — [`cpuid_fms`](AttestationReport::cpuid_fms) in version 3,
//!   [`launch_mit_vector`](AttestationReport::launch_mit_vector) in version 5 —
//!   return `Option`. Report version tracks *firmware* level, not silicon, so a
//!   Zen 3 machine on current firmware emits version 5 reports.
//! - **TCB version layout.** [`TcbVersion`] means different things on different
//!   processors: Zen 5 inserts an FMC security version number that Zen 3 and
//!   Zen 4 do not have. The raw value is always preserved, and
//!   [`TcbVersion::decode`] splits it correctly for a given [`Product`] —
//!   which reports from version 3 onwards carry themselves.
//!
//! Bitfields such as [`GuestPolicy`] and [`PlatformInfo`] name the bits this
//! crate knows and expose the rest through `unknown_bits`, so a report from
//! firmware newer than this crate parses rather than fails.
//!
//! # Transports
//!
//! Linux exposes guest requests through both `/dev/sev-guest` (5.19 and later)
//! and configfs-TSM (6.7 and later). [`Firmware::open`] uses whichever are
//! present, preferring configfs for reports because it can detect a concurrent
//! writer, and requiring `/dev/sev-guest` for key derivation because configfs
//! does not implement it. See the [`backend`] module for the full comparison.
//!
//! # Trust boundary
//!
//! A report is only evidence once its signature has been checked against AMD's
//! certificate chain, and the freshness of
//! [`report_data`](AttestationReport::report_data) confirmed. This crate
//! obtains and parses reports; it deliberately performs no cryptographic
//! verification and fetches nothing from the network, so that the verifying
//! party can be a different machine running code of its own choosing. Treat
//! everything a report says as unverified until you have done that.

#![cfg_attr(docsrs, feature(doc_cfg))]

#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;

pub mod backend;
pub mod certs;
pub mod detect;
pub mod error;
pub mod key;
pub mod policy;
pub mod report;
pub mod tcb;

pub use backend::{GuestBackend, ReportRequest, Transport};
pub use certs::{CertKind, CertTable, Certificate, ExtendedReport};
pub use error::{Error, FirmwareError, ParseError, Result, VmmError};
pub use key::{DerivedKey, KeyFields, KeyRequest, RootKey};
pub use policy::{GuestPolicy, PlatformInfo, SignatureAlgo, SignerInfo, SigningKey};
pub use report::{AttestationReport, EcdsaP384Signature, FirmwareVersion};
pub use tcb::{Fms, Product, TcbLayout, TcbParts, TcbVersion};

use backend::configfs::ConfigFs;
use backend::ioctl::SevGuest;

/// A handle to the SEV-SNP guest firmware.
///
/// Opens whichever kernel transports are available and routes each request to
/// one that implements it. Cheap to keep around and safe to share between
/// threads; the kernel serialises guest requests internally.
#[derive(Debug)]
pub struct Firmware {
    configfs: Option<ConfigFs>,
    ioctl: Option<SevGuest>,
}

impl Firmware {
    /// Opens every available guest transport.
    ///
    /// Fails with [`Error::NoBackend`] if the kernel exposes neither, which
    /// normally means this is not an SEV-SNP guest. Opening `/dev/sev-guest`
    /// requires root; if that fails but configfs works, this still succeeds and
    /// only [`derive_key`](Self::derive_key) is unavailable.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NoBackend`] if neither transport could be opened.
    pub fn open() -> Result<Self> {
        let configfs = ConfigFs::open().ok();
        let ioctl = SevGuest::open().ok();
        if configfs.is_none() && ioctl.is_none() {
            return Err(Error::NoBackend);
        }
        Ok(Self { configfs, ioctl })
    }

    /// Opens exactly one transport, failing if it is unavailable.
    ///
    /// Use this when a specific interface is required — for instance to insist
    /// on [`Transport::Ioctl`] so that firmware status codes survive, rather
    /// than being collapsed into an `errno` by configfs.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NoBackend`] or [`Error::Io`] if the requested transport
    /// is absent or cannot be opened.
    pub fn open_with(transport: Transport) -> Result<Self> {
        match transport {
            Transport::ConfigFs => Ok(Self {
                configfs: Some(ConfigFs::open()?),
                ioctl: None,
            }),
            Transport::Ioctl => Ok(Self {
                configfs: None,
                ioctl: Some(SevGuest::open()?),
            }),
        }
    }

    /// Which transport reports will be fetched from.
    #[must_use]
    pub fn transport(&self) -> Transport {
        self.report_backend().transport()
    }

    /// Whether key derivation is available on this handle.
    ///
    /// False when only configfs could be opened, which usually means the
    /// process lacks the privileges for `/dev/sev-guest`.
    #[must_use]
    pub const fn can_derive_keys(&self) -> bool {
        self.ioctl.is_some()
    }

    /// Requests a signed attestation report over the given 64 bytes.
    ///
    /// The bytes land in [`AttestationReport::report_data`] and are what binds
    /// the report to a challenge: put a verifier-supplied nonce there, or a
    /// hash of a public key you want the report to endorse. All-zero data
    /// produces a valid but replayable report.
    ///
    /// # Errors
    ///
    /// See [`GuestBackend::report`].
    pub fn report(&self, report_data: &[u8; 64]) -> Result<AttestationReport> {
        self.report_with(&ReportRequest::from(report_data))
    }

    /// Requests a report with full control over the request.
    ///
    /// # Errors
    ///
    /// See [`GuestBackend::report`].
    pub fn report_with(&self, request: &ReportRequest) -> Result<AttestationReport> {
        self.report_backend().report(request)
    }

    /// Requests a report together with the host-provisioned certificate chain.
    ///
    /// The chain is frequently empty: hosts are not required to provision one,
    /// in which case it must be fetched from AMD's Key Distribution Service
    /// instead. [`CertTable::is_empty`] tells you which case you are in.
    ///
    /// # Errors
    ///
    /// See [`GuestBackend::extended_report`].
    pub fn extended_report(&self, report_data: &[u8; 64]) -> Result<ExtendedReport> {
        self.extended_report_with(&ReportRequest::from(report_data))
    }

    /// Requests an extended report with full control over the request.
    ///
    /// # Errors
    ///
    /// See [`GuestBackend::extended_report`].
    pub fn extended_report_with(&self, request: &ReportRequest) -> Result<ExtendedReport> {
        self.report_backend().extended_report(request)
    }

    /// Derives a key from a secret held inside the processor.
    ///
    /// Requires the `/dev/sev-guest` transport; see [`can_derive_keys`](Self::can_derive_keys).
    /// The [`key`] module explains what the request can bind the key to.
    ///
    /// # Errors
    ///
    /// See [`GuestBackend::derive_key`].
    pub fn derive_key(&self, request: &KeyRequest) -> Result<DerivedKey> {
        let ioctl = self.ioctl.as_ref().ok_or(Error::Unsupported(
            "key derivation needs /dev/sev-guest, which is not open",
        ))?;
        ioctl.derive_key(request)
    }

    /// configfs is preferred: it is the only transport that can tell us whether
    /// another process overwrote our request before we read the answer.
    fn report_backend(&self) -> &dyn GuestBackend {
        match (&self.configfs, &self.ioctl) {
            (Some(c), _) => c,
            (None, Some(i)) => i,
            (None, None) => unreachable!("Firmware is never constructed without a backend"),
        }
    }
}

// Small total helpers for reading fixed-width fields out of firmware buffers.
// They live at the crate root, private, so every module can reach them without
// a visibility qualifier: nothing here is part of the public API. All are free
// of panicking operations — no indexing, no unchecked arithmetic, no `unwrap`.

/// Narrows a value that the caller has already masked to eight bits or fewer.
///
/// `u8::try_from` is not callable from a `const fn`, and taking the low byte of
/// an already-masked value is exact.
const fn low_byte(masked: u32) -> u8 {
    let [byte, _, _, _] = masked.to_le_bytes();
    byte
}

/// Widens a byte to `u32` without an `as` cast, callable from a `const fn`.
const fn widen(byte: u8) -> u32 {
    u32::from_le_bytes([byte, 0, 0, 0])
}

/// Copies `N` bytes starting at `offset`, or `None` if the buffer is too short.
fn bytes_at<const N: usize>(buf: &[u8], offset: usize) -> Option<[u8; N]> {
    buf.get(offset..)?.first_chunk::<N>().copied()
}

/// Reads a little-endian `u32` at `offset`.
fn u32_at(buf: &[u8], offset: usize) -> Option<u32> {
    bytes_at::<4>(buf, offset).map(u32::from_le_bytes)
}
