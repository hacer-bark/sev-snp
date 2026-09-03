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
#![cfg_attr(
    feature = "sev-guest",
    doc = "- **[Derived keys](DerivedKey)** — reproducible key material bound to any"
)]
#![cfg_attr(
    feature = "sev-guest",
    doc = "  combination of the chip, the firmware version, and the guest image. See"
)]
#![cfg_attr(
    feature = "sev-guest",
    doc = "  [`Firmware::derive_key`] and the [`key`] module."
)]
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
//! # Transports and features
//!
//! Linux exposes guest requests through both `/dev/sev-guest` (5.19 and later)
//! and configfs-TSM (6.7 and later). [`Firmware::open`] uses whichever are
//! present, preferring configfs for reports because it can detect a concurrent
//! writer, and requiring `/dev/sev-guest` for key derivation because configfs
//! does not implement it. See the [`backend`] module for the full comparison.
//!
//! Each transport is a cargo feature, both on by default. Turning one off
//! compiles it out entirely, along with anything only it needed:
//!
//! - `configfs` — the configfs-TSM transport. Reports only.
//! - `sev-guest` — the `/dev/sev-guest` transport. Adds key derivation and
//!   firmware status codes, and pulls in `libc`.
//!
//! Selecting neither is a compile error. Selecting only `configfs` leaves a
//! crate with no dependencies at all, compiled under `forbid(unsafe_code)` —
//! useful for a verifier or a report-only agent that wants no `unsafe`
//! anywhere in what it builds.
//!
//! Anything a build cannot do is absent rather than failing at run time:
//! without `sev-guest` there is no `Firmware::derive_key`, no `key` module and
//! no `Transport::Ioctl`, so code that needs them fails to compile instead of
//! reaching production and returning an error. Write against both feature sets
//! the way `examples/attest.rs` does, with a `#[cfg]` around the parts that
//! need a particular transport.
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
//!
//! What this crate does check, because a guest can do it without any
//! cryptography and a caller who skips it has no way to notice:
//!
//! - The response answers *this* request. `REPORT_DATA` and the privilege
//!   level are echoed by the firmware, so both are compared against what was
//!   asked for and a mismatch is [`Error::Mismatch`], never a returned report.
//! - The interface is really SEV-SNP. configfs-TSM is shared with TDX and
//!   others, so the provider name is checked once at open; anything else is
//!   [`Error::WrongProvider`] rather than a foreign quote parsed as a report.
//! - The response is shaped like a report. The version is bounded above as
//!   well as below, and a host-supplied certificate blob is bounded in size
//!   and entry count before any of it is decoded.

#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(not(feature = "sev-guest"), forbid(unsafe_code))]

#[cfg(not(any(feature = "configfs", feature = "sev-guest")))]
compile_error!(
    "sev-snp needs at least one backend: enable the `configfs` feature, the \
     `sev-guest` feature, or both (both are on by default)."
);

// The README example covers key derivation, so it is compiled only where that
// API exists. The default feature set includes it, so CI still checks it.
#[cfg(all(doctest, feature = "sev-guest"))]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;

pub mod backend;
pub mod certs;
pub mod detect;
pub mod error;
#[cfg(feature = "sev-guest")]
#[cfg_attr(docsrs, doc(cfg(feature = "sev-guest")))]
pub mod key;
pub mod policy;
pub mod report;
pub mod tcb;

pub use backend::{GuestBackend, ReportRequest, Transport};
pub use certs::{CertKind, CertTable, Certificate, ExtendedReport};
pub use error::{Error, FirmwareError, ParseError, Result, VmmError};
#[cfg(feature = "sev-guest")]
pub use key::{DerivedKey, KeyFields, KeyRequest, RootKey};
pub use policy::{GuestPolicy, PlatformInfo, SignatureAlgo, SignerInfo, SigningKey};
pub use report::{AttestationReport, EcdsaP384Signature, FirmwareVersion};
pub use tcb::{Fms, Product, TcbLayout, TcbParts, TcbVersion};

#[cfg(feature = "configfs")]
use backend::configfs::ConfigFs;
#[cfg(feature = "sev-guest")]
use backend::ioctl::SevGuest;

/// Backoff before each retry of a transient failure.
///
/// One entry per retry, so a request is attempted `len() + 1` times in all.
/// The sum is the entire wall-clock cost of exhausting a request, and it is
/// deliberately a fraction of a second: a call that can be made to block for
/// seconds is a call that can be used to pin a caller's threads, and on the
/// ioctl transport every attempt also consumes a VMPCK sequence number that
/// the guest can never get back.
const RETRY_BACKOFF: [std::time::Duration; 2] = [
    std::time::Duration::from_millis(20),
    std::time::Duration::from_millis(80),
];

/// Whether an error is one the kernel expects the guest to try again on.
///
/// [`Error::Raced`] is transient by definition, and the hypervisor raises
/// [`VmmError::Busy`] — surfacing as `EBUSY` or `EAGAIN` through configfs —
/// while it services another guest's request. Nothing else is retried: a
/// [`Error::Mismatch`] in particular is a signal that something is wrong, not
/// an invitation to ask again.
fn is_transient(error: &Error) -> bool {
    use std::io::ErrorKind::{Interrupted, ResourceBusy, WouldBlock};
    match error {
        Error::Raced | Error::Vmm(VmmError::Busy) => true,
        Error::Io(e) => matches!(e.kind(), ResourceBusy | WouldBlock | Interrupted),
        _ => false,
    }
}

/// Runs `attempt`, retrying transient failures on a fixed, bounded schedule.
fn retrying<T>(mut attempt: impl FnMut() -> Result<T>) -> Result<T> {
    let mut backoff = RETRY_BACKOFF.iter();
    loop {
        match attempt() {
            Err(error) if is_transient(&error) => match backoff.next() {
                Some(delay) => std::thread::sleep(*delay),
                None => return Err(error),
            },
            settled => return settled,
        }
    }
}

/// A handle to the SEV-SNP guest firmware.
///
/// Opens whichever kernel transports are compiled in and available, and routes
/// each request to one that implements it. Cheap to keep around and safe to
/// share between threads; the kernel serialises guest requests internally.
#[derive(Debug)]
pub struct Firmware {
    /// Which backend serves reports. Fixed at open time, and always backed by
    /// a live handle, so no request has to guess.
    transport: Transport,
    #[cfg(feature = "configfs")]
    configfs: Option<ConfigFs>,
    #[cfg(feature = "sev-guest")]
    ioctl: Option<SevGuest>,
}

impl Firmware {
    /// Opens every guest transport that is compiled in and available.
    ///
    /// Opening `/dev/sev-guest` requires root; if that fails but configfs
    /// works, this still succeeds and only key derivation is unavailable.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NoBackend`] if no transport could be opened, which
    /// normally means this is not an SEV-SNP guest.
    pub fn open() -> Result<Self> {
        #[cfg(feature = "configfs")]
        let configfs = ConfigFs::open().ok();
        #[cfg(feature = "sev-guest")]
        let ioctl = SevGuest::open().ok();

        // configfs is preferred for reports: it is the only transport that can
        // tell us whether another process overwrote our request before we read
        // the answer.
        #[cfg(feature = "configfs")]
        let transport = if configfs.is_some() {
            Some(Transport::ConfigFs)
        } else {
            None
        };
        #[cfg(not(feature = "configfs"))]
        let transport = None;

        #[cfg(feature = "sev-guest")]
        let transport = transport.or_else(|| ioctl.as_ref().map(|_| Transport::Ioctl));

        Ok(Self {
            transport: transport.ok_or(Error::NoBackend)?,
            #[cfg(feature = "configfs")]
            configfs,
            #[cfg(feature = "sev-guest")]
            ioctl,
        })
    }

    /// Opens exactly one transport, failing if it is unavailable.
    ///
    /// Use this when a specific interface is required — for instance to insist
    /// on [`Transport::Ioctl`] so that firmware status codes survive, rather
    /// than being collapsed into an `errno` by configfs.
    ///
    /// A transport whose feature is off has no [`Transport`] variant, so
    /// asking for one this build cannot speak does not compile.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NoBackend`] or [`Error::Io`] if the transport is absent
    /// from this system or cannot be opened.
    pub fn open_with(transport: Transport) -> Result<Self> {
        match transport {
            #[cfg(feature = "configfs")]
            Transport::ConfigFs => Ok(Self {
                transport,
                configfs: Some(ConfigFs::open()?),
                #[cfg(feature = "sev-guest")]
                ioctl: None,
            }),
            #[cfg(feature = "sev-guest")]
            Transport::Ioctl => Ok(Self {
                transport,
                #[cfg(feature = "configfs")]
                configfs: None,
                ioctl: Some(SevGuest::open()?),
            }),
        }
    }

    /// Which transport reports will be fetched from.
    #[must_use]
    pub const fn transport(&self) -> Transport {
        self.transport
    }

    /// Whether key derivation is available on this handle.
    ///
    /// False when the device could not be opened, which usually means the
    /// process lacks the privileges for `/dev/sev-guest`.
    #[cfg(feature = "sev-guest")]
    #[cfg_attr(docsrs, doc(cfg(feature = "sev-guest")))]
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
    /// The returned report is guaranteed to carry exactly these bytes: a
    /// response whose `REPORT_DATA` differs is rejected as
    /// [`Error::Mismatch`] rather than returned.
    ///
    /// # Errors
    ///
    /// See [`GuestBackend::report`].
    pub fn report(&self, report_data: &[u8; 64]) -> Result<AttestationReport> {
        self.report_with(&ReportRequest::from(report_data))
    }

    /// Requests a report with full control over the request.
    ///
    /// Transient failures — a busy hypervisor, a detected race — are retried
    /// twice, with a total backoff well under a second, before the error is
    /// returned. Call [`GuestBackend::report`] on a backend directly to issue
    /// exactly one request with no retry.
    ///
    /// # Errors
    ///
    /// See [`GuestBackend::report`].
    pub fn report_with(&self, request: &ReportRequest) -> Result<AttestationReport> {
        retrying(|| self.report_backend()?.report(request))
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
    /// Retried on transient failures exactly as [`report_with`](Self::report_with).
    ///
    /// # Errors
    ///
    /// See [`GuestBackend::extended_report`].
    pub fn extended_report_with(&self, request: &ReportRequest) -> Result<ExtendedReport> {
        retrying(|| self.report_backend()?.extended_report(request))
    }

    /// Derives a key from a secret held inside the processor.
    ///
    /// Requires the `/dev/sev-guest` transport; see
    /// [`can_derive_keys`](Self::can_derive_keys). The [`key`] module explains
    /// what the request can bind the key to.
    ///
    /// # Errors
    ///
    /// See [`GuestBackend::derive_key`].
    #[cfg(feature = "sev-guest")]
    #[cfg_attr(docsrs, doc(cfg(feature = "sev-guest")))]
    pub fn derive_key(&self, request: &KeyRequest) -> Result<DerivedKey> {
        let ioctl = self.ioctl.as_ref().ok_or(Error::Unsupported(
            "key derivation needs /dev/sev-guest, which is not open",
        ))?;
        ioctl.derive_key(request)
    }

    /// The live backend serving reports, selected once at open time.
    fn report_backend(&self) -> Result<&dyn GuestBackend> {
        match self.transport {
            #[cfg(feature = "configfs")]
            Transport::ConfigFs => self
                .configfs
                .as_ref()
                .map(|backend| -> &dyn GuestBackend { backend })
                .ok_or(Error::NoBackend),
            #[cfg(feature = "sev-guest")]
            Transport::Ioctl => self
                .ioctl
                .as_ref()
                .map(|backend| -> &dyn GuestBackend { backend })
                .ok_or(Error::NoBackend),
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
