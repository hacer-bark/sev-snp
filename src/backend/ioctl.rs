//! The `/dev/sev-guest` transport.
//!
//! The original guest interface, available from Linux 5.19. It is the only one
//! that implements key derivation, and the only one that reports the firmware's
//! own status codes instead of collapsing them into an `errno`.
//!
//! The device is mode 0600, so this transport normally requires root.

use super::{GuestBackend, ReportRequest, Transport};
use crate::certs::{CertTable, ExtendedReport};
use crate::error::{Error, FirmwareError, ParseError, Result, VmmError, from_exitinfo2};
use crate::key::{DerivedKey, KeyRequest};
use crate::report::AttestationReport;
use crate::{u32_at, widen};
use std::fs::{File, OpenOptions};
use std::os::fd::{AsRawFd, RawFd};
use std::path::Path;

/// The guest device node.
pub const DEVICE: &str = "/dev/sev-guest";

/// Whether the guest device exists.
#[must_use]
pub fn available() -> bool {
    Path::new(DEVICE).exists()
}

/// Size of `struct snp_guest_request_ioctl`, which the request code encodes.
const IOCTL_ARG_SIZE: u32 = 32;
const _: () = assert!(size_of::<GuestRequestIoctl>() == 32);

/// Builds an `_IOWR('S', nr, struct snp_guest_request_ioctl)` request code.
const fn iowr(nr: u32) -> u32 {
    const DIR_READ_WRITE: u32 = 3;
    DIR_READ_WRITE.wrapping_shl(30)
        | IOCTL_ARG_SIZE.wrapping_shl(16)
        | widen(b'S').wrapping_shl(8)
        | nr
}

const SNP_GET_REPORT: u32 = iowr(0x0);
const SNP_GET_DERIVED_KEY: u32 = iowr(0x1);
const SNP_GET_EXT_REPORT: u32 = iowr(0x2);

/// Size of the fixed response buffer the kernel writes a report into.
const REPORT_RESP_LEN: usize = 4000;
/// Offset of the payload in a firmware response message.
const RESP_PAYLOAD: usize = 0x20;
/// Size of `struct snp_report_req`.
const REPORT_REQ_LEN: usize = 96;
/// Size of `struct snp_ext_report_req`, including its tail padding.
const EXT_REPORT_REQ_LEN: usize = 112;
/// Offset of `certs_len` within `struct snp_ext_report_req`.
const EXT_CERTS_LEN_FIELD: usize = 104;
/// Certificate buffers must be a whole number of pages.
const CERT_GRANULARITY: usize = 4096;
/// The kernel refuses certificate buffers larger than this.
const CERT_MAX: usize = 0x4000;

/// `struct snp_guest_request_ioctl` from `<linux/sev-guest.h>`.
///
/// The explicit padding reproduces the alignment the C compiler inserts between
/// the `__u8` version and the following `__u64`.
#[repr(C)]
#[derive(Debug, Default)]
struct GuestRequestIoctl {
    msg_version: u8,
    _pad: [u8; 7],
    req_data: u64,
    resp_data: u64,
    exitinfo2: u64,
}

/// The `/dev/sev-guest` transport.
#[derive(Debug)]
pub struct SevGuest {
    device: File,
    msg_version: u8,
}

impl SevGuest {
    /// Opens the guest device at its standard location.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] if the device is missing or cannot be opened,
    /// which for a mode 0600 node usually means the process is not root.
    pub fn open() -> Result<Self> {
        Self::open_at(DEVICE)
    }

    /// Opens a guest device at a non-standard path.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] if the path cannot be opened for reading and
    /// writing.
    pub fn open_at(path: impl AsRef<Path>) -> Result<Self> {
        let device = OpenOptions::new().read(true).write(true).open(path)?;
        Ok(Self {
            device,
            msg_version: 1,
        })
    }

    /// Overrides the guest message protocol version.
    ///
    /// Version 1 is what every shipping firmware accepts and is the default.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] for a zero version, which the
    /// firmware rejects.
    pub fn with_msg_version(mut self, version: u8) -> Result<Self> {
        if version == 0 {
            return Err(Error::InvalidArgument("message version must be non-zero"));
        }
        self.msg_version = version;
        Ok(self)
    }

    fn fd(&self) -> RawFd {
        self.device.as_raw_fd()
    }

    /// Issues one guest request.
    ///
    /// Errors reported through `EXITINFO2` take precedence over the `errno`,
    /// because the kernel returns a generic `-EIO` for anything the firmware or
    /// hypervisor rejected and only the former says why.
    #[expect(
        unsafe_code,
        reason = "the whole crate's only FFI call: an ioctl cannot be made safe \
                  by any wrapper, because the obligation being discharged is \
                  that this opcode matches this driver's struct and that the \
                  two buffers stay live for the call. Keeping it here, in one \
                  statement, is what lets every other module forbid unsafe."
    )]
    fn issue(&self, code: u32, request: &mut [u8], response: &mut [u8]) -> Result<()> {
        let bad_address = || Error::InvalidArgument("buffer address does not fit in a u64");
        let mut arg = GuestRequestIoctl {
            msg_version: self.msg_version,
            _pad: [0; 7],
            req_data: u64::try_from(request.as_mut_ptr().expose_provenance())
                .map_err(|_| bad_address())?,
            resp_data: u64::try_from(response.as_mut_ptr().expose_provenance())
                .map_err(|_| bad_address())?,
            exitinfo2: 0,
        };

        // `libc::ioctl` takes the request as `c_ulong` on glibc; the widening
        // is infallible there. A target whose libc declares it differently
        // fails to compile here rather than silently truncating.
        let code = code.into();

        // SAFETY: `code` is one of the three request codes this driver defines,
        // built from the size of the struct we pass, whose layout is pinned by
        // the assertion above. `arg` is a live, correctly sized
        // `snp_guest_request_ioctl`, and the two buffers it points at are
        // exclusively borrowed for the duration of the call.
        let rc = unsafe { libc::ioctl(self.fd(), code, &raw mut arg) };

        if let Some(err) = from_exitinfo2(arg.exitinfo2) {
            return Err(err);
        }
        if rc < 0 {
            return Err(Error::Io(std::io::Error::last_os_error()));
        }
        Ok(())
    }

    /// Builds `struct snp_report_req`: the report data then the VMPL.
    fn report_req(request: &ReportRequest) -> [u8; REPORT_REQ_LEN] {
        let fields = request
            .data
            .into_iter()
            .chain(request.vmpl.unwrap_or(0).to_le_bytes());
        fill(fields)
    }

    /// Builds `struct snp_ext_report_req`: a report request, then the address
    /// and page-aligned length of the certificate buffer.
    fn ext_report_req(
        request: &ReportRequest,
        certs_address: u64,
        certs_len: u32,
    ) -> [u8; EXT_REPORT_REQ_LEN] {
        let fields = Self::report_req(request)
            .into_iter()
            .chain(certs_address.to_le_bytes())
            .chain(certs_len.to_le_bytes());
        fill(fields)
    }

    /// Extracts the report from a firmware response message.
    fn parse_response(response: &[u8]) -> Result<AttestationReport> {
        let status = u32_at(response, 0).ok_or(ParseError::TooShort {
            what: "report response",
            need: 4,
            got: response.len(),
        })?;
        if status != 0 {
            return Err(Error::Firmware(FirmwareError::from_raw(status)));
        }
        let payload = response.get(RESP_PAYLOAD..).ok_or(ParseError::TooShort {
            what: "report response",
            need: RESP_PAYLOAD,
            got: response.len(),
        })?;
        AttestationReport::parse(payload)
    }

    /// Reads the buffer size the kernel asked for after an `INVALID_LEN`.
    fn requested_cert_len(req: &[u8]) -> Result<usize> {
        let needed = u32_at(req, EXT_CERTS_LEN_FIELD)
            .and_then(|len| usize::try_from(len).ok())
            .ok_or(Error::InvalidArgument(
                "kernel did not report a certificate buffer size",
            ))?;
        if needed == 0 || needed > CERT_MAX || !needed.is_multiple_of(CERT_GRANULARITY) {
            return Err(Error::InvalidArgument(
                "kernel asked for an implausible certificate buffer size",
            ));
        }
        Ok(needed)
    }
}

/// Writes an iterator of bytes into a fixed-size buffer, zero-padding the rest.
fn fill<const N: usize>(bytes: impl IntoIterator<Item = u8>) -> [u8; N] {
    let mut out = [0u8; N];
    for (dst, byte) in out.iter_mut().zip(bytes) {
        *dst = byte;
    }
    out
}

impl GuestBackend for SevGuest {
    fn transport(&self) -> Transport {
        Transport::Ioctl
    }

    fn report(&self, request: &ReportRequest) -> Result<AttestationReport> {
        let mut req = Self::report_req(request);
        let mut resp = vec![0u8; REPORT_RESP_LEN];
        self.issue(SNP_GET_REPORT, &mut req, &mut resp)?;
        Self::parse_response(&resp)
    }

    fn extended_report(&self, request: &ReportRequest) -> Result<ExtendedReport> {
        let mut req = Self::ext_report_req(request, 0, 0);
        let mut resp = vec![0u8; REPORT_RESP_LEN];
        let mut certs: Vec<u8> = Vec::new();

        // Ask with an empty buffer first. A host that provisioned certificates
        // answers with the size it needs; one that provisioned none succeeds
        // immediately, which is the common case on public clouds.
        match self.issue(SNP_GET_EXT_REPORT, &mut req, &mut resp) {
            Ok(()) => {}
            Err(Error::Vmm(VmmError::InvalidLen)) => {
                let needed = Self::requested_cert_len(&req)?;
                certs = vec![0u8; needed];
                let address = u64::try_from(certs.as_mut_ptr().expose_provenance())
                    .map_err(|_| Error::InvalidArgument("certificate buffer address too large"))?;
                let len = u32::try_from(needed)
                    .map_err(|_| Error::InvalidArgument("certificate buffer too large"))?;
                req = Self::ext_report_req(request, address, len);
                self.issue(SNP_GET_EXT_REPORT, &mut req, &mut resp)?;
            }
            Err(e) => return Err(e),
        }

        Ok(ExtendedReport {
            report: Self::parse_response(&resp)?,
            certificates: CertTable::parse(&certs)?,
        })
    }

    fn derive_key(&self, request: &KeyRequest) -> Result<DerivedKey> {
        request.validate()?;

        let mut req = request.to_wire();
        let mut resp = [0u8; 64];
        self.issue(SNP_GET_DERIVED_KEY, &mut req, &mut resp)?;

        let status = u32_at(&resp, 0).unwrap_or(u32::MAX);
        if status != 0 {
            return Err(Error::Firmware(FirmwareError::from_raw(status)));
        }

        let key = crate::bytes_at::<{ DerivedKey::LEN }>(&resp, RESP_PAYLOAD)
            .ok_or(Error::InvalidArgument("derived key response was truncated"))?;
        // The response buffer holds a copy of the key; wipe it before it goes
        // back to the allocator.
        zeroize::Zeroize::zeroize(&mut resp[..]);
        Ok(DerivedKey::from_bytes(key))
    }
}
