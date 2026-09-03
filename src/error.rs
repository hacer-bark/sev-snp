//! Errors returned by this crate.

use std::fmt;

/// Result alias used throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Anything that can go wrong talking to the SEV-SNP firmware.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// No usable guest interface was found.
    ///
    /// Either this is not an SEV-SNP guest, or the kernel exposes neither
    /// `/dev/sev-guest` nor configfs-TSM.
    NoBackend,

    /// The selected backend exists but cannot serve this request.
    ///
    /// The most common case is asking configfs-TSM for a derived key: that
    /// interface only implements attestation reports.
    Unsupported(&'static str),

    /// The request was rejected before it reached the firmware.
    InvalidArgument(&'static str),

    /// The PSP firmware rejected the request.
    Firmware(FirmwareError),

    /// The hypervisor rejected the request before the firmware saw it.
    Vmm(VmmError),

    /// A response could not be interpreted.
    Parse(ParseError),

    /// Another process wrote to the same configfs report entry concurrently.
    ///
    /// The response cannot be trusted to correspond to our request, so it is
    /// discarded rather than returned.
    Raced,

    /// An underlying I/O operation failed.
    Io(std::io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoBackend => f.write_str(
                "no SEV-SNP guest interface available (need /dev/sev-guest or configfs-TSM)",
            ),
            Self::Unsupported(what) => write!(f, "unsupported by this backend: {what}"),
            Self::InvalidArgument(what) => write!(f, "invalid argument: {what}"),
            Self::Firmware(e) => write!(f, "firmware error: {e}"),
            Self::Vmm(e) => write!(f, "hypervisor error: {e}"),
            Self::Parse(e) => write!(f, "malformed response: {e}"),
            Self::Raced => f.write_str("concurrent writer detected on configfs report entry"),
            Self::Io(e) => write!(f, "io error: {e}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Parse(e) => Some(e),
            Self::Firmware(e) => Some(e),
            Self::Vmm(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<ParseError> for Error {
    fn from(e: ParseError) -> Self {
        Self::Parse(e)
    }
}

/// Status codes returned by the AMD secure processor.
///
/// Mirrors `sev_ret_code` in `<linux/psp-sev.h>`. Codes the running firmware
/// invents that this crate does not know are preserved in [`Self::Unknown`]
/// rather than being flattened, so a guest on newer firmware never loses
/// information.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FirmwareError {
    /// The platform is not in a state that allows this command.
    InvalidPlatformState,
    /// The guest is not in a state that allows this command.
    InvalidGuestState,
    /// The platform configuration is invalid.
    InvalidConfig,
    /// A supplied buffer was the wrong length.
    InvalidLen,
    /// The platform already has an owner.
    AlreadyOwned,
    /// A supplied certificate could not be validated.
    InvalidCertificate,
    /// The request violates the guest policy.
    PolicyFailure,
    /// The guest is not active.
    Inactive,
    /// A supplied address is invalid or not mapped as expected.
    InvalidAddress,
    /// A signature check failed.
    BadSignature,
    /// A measurement check failed.
    BadMeasurement,
    /// The ASID is already owned by another guest.
    AsidOwned,
    /// The ASID is out of range or not usable.
    InvalidAsid,
    /// Caches must be written back and invalidated before retrying.
    WbinvdRequired,
    /// A data fabric flush is required before retrying.
    DfFlushRequired,
    /// The guest handle does not refer to a valid guest.
    InvalidGuest,
    /// The command is not recognised by this firmware.
    InvalidCommand,
    /// The guest is active and the command requires it not to be.
    Active,
    /// A hardware error occurred that is not attributable to the guest.
    HwPlatformError,
    /// A hardware condition makes it unsafe to continue.
    HwUnsafe,
    /// The firmware does not support this operation.
    Unsupported,
    /// A request parameter is out of range or malformed.
    InvalidParam,
    /// A firmware resource limit was reached.
    ResourceLimit,
    /// Persistent secure data failed its integrity check.
    SecureDataInvalid,
    /// A page size in the request is invalid.
    InvalidPageSize,
    /// A page is not in the RMP state the command requires.
    InvalidPageState,
    /// An RMP metadata entry is invalid.
    InvalidMetadataEntry,
    /// A page is owned by a different guest.
    InvalidPageOwner,
    /// The message sequence number space for the VMPCK is exhausted.
    AeadOverflow,
    /// The command must be reissued outside the ring buffer.
    ExitRingBuffer,
    /// The reverse map table has not been initialised.
    RmpInitRequired,
    /// A security version number is lower than the firmware allows.
    BadSvn,
    /// A structure version in the request is not supported.
    BadVersion,
    /// The platform must be shut down before retrying.
    ShutdownRequired,
    /// A firmware update failed.
    UpdateFailed,
    /// State must be restored before retrying.
    RestoreRequired,
    /// Initialising the reverse map table failed.
    RmpInitFailed,
    /// The requested key is unavailable or invalid.
    InvalidKey,
    /// A previous shutdown did not complete.
    ShutdownIncomplete,
    /// A supplied buffer length does not match what the command needs.
    IncorrectBufferLength,
    /// The buffer must be enlarged and the command reissued.
    ExpandBufferLengthRequest,
    /// An SPDM exchange with a device is required to proceed.
    SpdmRequest,
    /// An SPDM exchange with a device failed.
    SpdmError,
    /// An error occurred on a trusted device connection.
    ErrInDevConn,
    /// The device context is invalid.
    InvalidDevCtx,
    /// The trusted device interface context is invalid.
    InvalidTdiCtx,
    /// The trusted device interface is invalid.
    InvalidTdi,
    /// A resource must be reclaimed before retrying.
    ReclaimRequired,
    /// The resource is in use.
    InUse,
    /// The device is not in a state that allows this command.
    InvalidDevState,
    /// The trusted device interface is not in a state that allows this command.
    InvalidTdiState,
    /// The device certificate changed since it was last validated.
    DevCertChanged,
    /// The device state must be resynchronised.
    ResyncRequired,
    /// The response does not fit in the buffer provided.
    ResponseTooLarge,
    /// A status code not known to this crate, preserved verbatim.
    Unknown(u32),
}

impl FirmwareError {
    /// Interprets a raw firmware status code.
    pub const fn from_raw(code: u32) -> Self {
        match code {
            0x01 => Self::InvalidPlatformState,
            0x02 => Self::InvalidGuestState,
            0x03 => Self::InvalidConfig,
            0x04 => Self::InvalidLen,
            0x05 => Self::AlreadyOwned,
            0x06 => Self::InvalidCertificate,
            0x07 => Self::PolicyFailure,
            0x08 => Self::Inactive,
            0x09 => Self::InvalidAddress,
            0x0A => Self::BadSignature,
            0x0B => Self::BadMeasurement,
            0x0C => Self::AsidOwned,
            0x0D => Self::InvalidAsid,
            0x0E => Self::WbinvdRequired,
            0x0F => Self::DfFlushRequired,
            0x10 => Self::InvalidGuest,
            0x11 => Self::InvalidCommand,
            0x12 => Self::Active,
            0x13 => Self::HwPlatformError,
            0x14 => Self::HwUnsafe,
            0x15 => Self::Unsupported,
            0x16 => Self::InvalidParam,
            0x17 => Self::ResourceLimit,
            0x18 => Self::SecureDataInvalid,
            0x19 => Self::InvalidPageSize,
            0x1A => Self::InvalidPageState,
            0x1B => Self::InvalidMetadataEntry,
            0x1C => Self::InvalidPageOwner,
            0x1D => Self::AeadOverflow,
            0x1F => Self::ExitRingBuffer,
            0x20 => Self::RmpInitRequired,
            0x21 => Self::BadSvn,
            0x22 => Self::BadVersion,
            0x23 => Self::ShutdownRequired,
            0x24 => Self::UpdateFailed,
            0x25 => Self::RestoreRequired,
            0x26 => Self::RmpInitFailed,
            0x27 => Self::InvalidKey,
            0x28 => Self::ShutdownIncomplete,
            0x30 => Self::IncorrectBufferLength,
            0x31 => Self::ExpandBufferLengthRequest,
            0x32 => Self::SpdmRequest,
            0x33 => Self::SpdmError,
            0x35 => Self::ErrInDevConn,
            0x36 => Self::InvalidDevCtx,
            0x37 => Self::InvalidTdiCtx,
            0x38 => Self::InvalidTdi,
            0x39 => Self::ReclaimRequired,
            0x3A => Self::InUse,
            0x3B => Self::InvalidDevState,
            0x3C => Self::InvalidTdiState,
            0x3D => Self::DevCertChanged,
            0x3E => Self::ResyncRequired,
            0x3F => Self::ResponseTooLarge,
            other => Self::Unknown(other),
        }
    }
}

impl fmt::Display for FirmwareError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown(c) => write!(f, "unknown firmware status 0x{c:02X}"),
            other => write!(f, "{other:?}"),
        }
    }
}

impl std::error::Error for FirmwareError {}

/// Errors raised by the hypervisor rather than the firmware.
///
/// Encoded in bits 63:32 of `EXITINFO2`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum VmmError {
    /// The certificate buffer supplied was too small; retry with a larger one.
    /// A supplied buffer was the wrong length.
    InvalidLen,
    /// The hypervisor is busy servicing another guest request; retry later.
    Busy,
    /// A code not known to this crate, preserved verbatim.
    Unknown(u32),
}

impl VmmError {
    /// Interprets a raw VMM status code.
    pub const fn from_raw(code: u32) -> Self {
        match code {
            1 => Self::InvalidLen,
            2 => Self::Busy,
            other => Self::Unknown(other),
        }
    }
}

impl fmt::Display for VmmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLen => f.write_str("certificate buffer too small"),
            Self::Busy => f.write_str("hypervisor busy, retry"),
            Self::Unknown(c) => write!(f, "unknown VMM status {c}"),
        }
    }
}

impl std::error::Error for VmmError {}

/// A response did not match the layout this crate expects.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ParseError {
    /// A buffer was shorter than the structure it should contain.
    TooShort {
        /// What was being parsed.
        what: &'static str,
        /// Bytes required.
        need: usize,
        /// Bytes available.
        got: usize,
    },
    /// The attestation report announced a version this crate cannot parse.
    UnsupportedReportVersion(u32),
    /// A certificate table entry pointed outside the blob that contains it.
    CertTableOutOfBounds,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort { what, need, got } => {
                write!(f, "{what} needs {need} bytes, got {got}")
            }
            Self::UnsupportedReportVersion(v) => {
                write!(f, "attestation report version {v} is not supported")
            }
            Self::CertTableOutOfBounds => {
                f.write_str("certificate table entry points outside the blob")
            }
        }
    }
}

impl std::error::Error for ParseError {}

/// Splits a raw `EXITINFO2` value into its VMM and firmware halves.
pub(crate) fn from_exitinfo2(exitinfo2: u64) -> Option<Error> {
    let fw = (exitinfo2 & 0xFFFF_FFFF) as u32;
    let vmm = (exitinfo2 >> 32) as u32;
    match (vmm, fw) {
        (0, 0) => None,
        (0, fw) => Some(Error::Firmware(FirmwareError::from_raw(fw))),
        (vmm, _) => Some(Error::Vmm(VmmError::from_raw(vmm))),
    }
}
