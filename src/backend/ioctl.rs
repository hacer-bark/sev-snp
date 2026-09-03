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
use std::fs::{File, OpenOptions};
use std::os::fd::{AsRawFd, RawFd};
use std::path::Path;

/// The guest device node.
pub const DEVICE: &str = "/dev/sev-guest";

/// Whether the guest device exists.
pub fn available() -> bool {
    Path::new(DEVICE).exists()
}

/// Builds an `_IOWR('S', nr, struct snp_guest_request_ioctl)` request code.
const fn iowr(nr: u32) -> u64 {
    const DIR_READ_WRITE: u32 = 3;
    const TYPE: u32 = b'S' as u32;
    const SIZE: u32 = size_of::<GuestRequestIoctl>() as u32;
    ((DIR_READ_WRITE << 30) | (SIZE << 16) | (TYPE << 8) | nr) as u64
}

const SNP_GET_REPORT: u64 = iowr(0x0);
const SNP_GET_DERIVED_KEY: u64 = iowr(0x1);
const SNP_GET_EXT_REPORT: u64 = iowr(0x2);

/// Size of the fixed response buffer the kernel writes a report into.
const REPORT_RESP_LEN: usize = 4000;
/// Offset of the payload in a firmware response message.
const RESP_PAYLOAD: usize = 0x20;
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
    pub fn open() -> Result<Self> {
        Self::open_at(DEVICE)
    }

    /// Opens a guest device at a non-standard path.
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
    /// The firmware rejects zero, so this returns an error rather than letting
    /// the kernel do it.
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
    fn issue(&self, code: u64, request: &mut [u8], response: &mut [u8]) -> Result<()> {
        let mut arg = GuestRequestIoctl {
            msg_version: self.msg_version,
            _pad: [0; 7],
            req_data: request.as_mut_ptr() as u64,
            resp_data: response.as_mut_ptr() as u64,
            exitinfo2: 0,
        };

        // SAFETY: `code` is one of the three request codes this driver defines,
        // built from the size of the struct we pass. `arg` is a live, correctly
        // sized `snp_guest_request_ioctl`, and the two buffers it points at are
        // exclusively borrowed for the duration of the call.
        let rc = unsafe { libc::ioctl(self.fd(), code as _, &raw mut arg) };

        if let Some(err) = from_exitinfo2(arg.exitinfo2) {
            return Err(err);
        }
        if rc < 0 {
            return Err(Error::Io(std::io::Error::last_os_error()));
        }
        Ok(())
    }

    /// Builds the 96-byte `struct snp_report_req`.
    fn report_req(request: &ReportRequest) -> [u8; 96] {
        let mut req = [0u8; 96];
        req[..64].copy_from_slice(&request.data);
        req[64..68].copy_from_slice(&request.vmpl.unwrap_or(0).to_le_bytes());
        req
    }

    /// Extracts the report from a firmware response message.
    fn parse_response(response: &[u8]) -> Result<AttestationReport> {
        let status = u32::from_le_bytes(
            response
                .get(..4)
                .ok_or(ParseError::TooShort {
                    what: "report response",
                    need: 4,
                    got: response.len(),
                })?
                .try_into()
                .expect("4 bytes"),
        );
        if status != 0 {
            return Err(Error::Firmware(FirmwareError::from_raw(status)));
        }
        AttestationReport::parse(&response[RESP_PAYLOAD..])
    }
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
        // `struct snp_ext_report_req`: the 96-byte report request, then the
        // certificate buffer address and its page-aligned length.
        let mut req = [0u8; 112];
        req[..96].copy_from_slice(&Self::report_req(request));

        let mut resp = vec![0u8; REPORT_RESP_LEN];
        let mut certs: Vec<u8> = Vec::new();

        // Ask with an empty buffer first. A host that provisioned certificates
        // answers with the size it needs; one that provisioned none succeeds
        // immediately, which is the common case on public clouds.
        match self.issue(SNP_GET_EXT_REPORT, &mut req, &mut resp) {
            Ok(()) => {}
            Err(Error::Vmm(VmmError::InvalidLen)) => {
                let needed =
                    u32::from_le_bytes(req[104..108].try_into().expect("4 bytes")) as usize;
                if needed == 0 || needed > CERT_MAX || !needed.is_multiple_of(CERT_GRANULARITY) {
                    return Err(Error::InvalidArgument(
                        "kernel asked for an implausible certificate buffer size",
                    ));
                }
                certs = vec![0u8; needed];
                req[96..104].copy_from_slice(&(certs.as_mut_ptr() as u64).to_le_bytes());
                req[104..108].copy_from_slice(&(needed as u32).to_le_bytes());
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

        let status = u32::from_le_bytes(resp[..4].try_into().expect("4 bytes"));
        if status != 0 {
            return Err(Error::Firmware(FirmwareError::from_raw(status)));
        }

        let key: [u8; DerivedKey::LEN] = resp[RESP_PAYLOAD..RESP_PAYLOAD + DerivedKey::LEN]
            .try_into()
            .expect("response is 64 bytes");
        // The response buffer holds a copy of the key; wipe it before it goes
        // back to the allocator.
        zeroize::Zeroize::zeroize(&mut resp[..]);
        Ok(DerivedKey::from_bytes(key))
    }
}
