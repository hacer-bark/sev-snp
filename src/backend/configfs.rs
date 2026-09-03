//! The configfs-TSM transport.
//!
//! Present from Linux 6.7 as a generic interface shared by SEV-SNP, TDX and
//! others. A request is a directory: write the nonce to `inblob`, read the
//! signed report back from `outblob`, and read the certificate chain from
//! `auxblob`.
//!
//! Its advantage over the ioctl device is the `generation` counter. configfs
//! entries are ordinary filesystem objects, so a second process can write to
//! the same one between our write and our read, and we would return a report
//! bound to somebody else's nonce. `generation` counts writes, so a value that
//! does not match what we performed means exactly that happened — and the
//! response is discarded as [`Error::Raced`] rather than returned.
//!
//! Each request gets a fresh directory, removed when the call returns, so no
//! state carries between calls.

use super::{GuestBackend, ReportRequest, Transport};
use crate::certs::{CertTable, ExtendedReport};
use crate::error::{Error, Result};
#[cfg(feature = "sev-guest")]
use crate::key::{DerivedKey, KeyRequest};
use crate::report::AttestationReport;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Where the kernel mounts the TSM report interface.
pub const REPORT_ROOT: &str = "/sys/kernel/config/tsm/report";

/// Whether the configfs-TSM report interface is present.
#[must_use]
pub fn available() -> bool {
    Path::new(REPORT_ROOT).is_dir()
}

/// The configfs-TSM transport.
#[derive(Debug, Clone)]
pub struct ConfigFs {
    root: PathBuf,
}

impl ConfigFs {
    /// Opens the interface at its standard location.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NoBackend`] if the kernel does not expose the
    /// configfs-TSM report directory.
    pub fn open() -> Result<Self> {
        Self::open_at(REPORT_ROOT)
    }

    /// Opens the interface at a non-standard mount point.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NoBackend`] if `root` is not a directory.
    pub fn open_at(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        if !root.is_dir() {
            return Err(Error::NoBackend);
        }
        Ok(Self { root })
    }

    /// The provider name the kernel reports, such as `sev_guest`.
    ///
    /// Worth checking before trusting a report: configfs-TSM is shared with
    /// other confidential-computing architectures, and on a TDX guest the same
    /// path yields a TDX quote rather than an SEV-SNP report.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] if a report entry cannot be created or its
    /// `provider` attribute cannot be read.
    pub fn provider(&self) -> Result<String> {
        let entry = Entry::create(&self.root)?;
        let provider = fs::read_to_string(entry.path.join("provider"))?;
        Ok(provider.trim().to_owned())
    }

    /// The lowest VMPL this guest may request a report at.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] if the attribute cannot be read, or
    /// [`Error::InvalidArgument`] if the kernel reports a non-numeric value.
    pub fn privlevel_floor(&self) -> Result<u32> {
        let entry = Entry::create(&self.root)?;
        let text = fs::read_to_string(entry.path.join("privlevel_floor"))?;
        text.trim().parse().map_err(|_| {
            Error::Parse(crate::error::ParseError::TooShort {
                what: "privlevel_floor",
                need: 1,
                got: 0,
            })
        })
    }

    /// Runs one request, returning the report and certificate blobs.
    fn run(&self, request: &ReportRequest) -> Result<(Vec<u8>, Vec<u8>)> {
        let entry = Entry::create(&self.root)?;

        // Every attribute write bumps `generation`; count ours so we can tell
        // our writes apart from somebody else's.
        let mut writes = 0u64;

        if let Some(vmpl) = request.vmpl {
            write_attr(&entry.path.join("privlevel"), vmpl.to_string().as_bytes())?;
            writes = writes.saturating_add(1);
        }

        write_attr(&entry.path.join("inblob"), &request.data)?;
        writes = writes.saturating_add(1);

        // Reading outblob is what actually issues the guest request.
        let outblob = fs::read(entry.path.join("outblob"))?;
        // A provider with no certificates returns an empty auxblob, which is
        // normal rather than an error.
        let auxblob = fs::read(entry.path.join("auxblob")).unwrap_or_default();

        let generation: u64 = fs::read_to_string(entry.path.join("generation"))?
            .trim()
            .parse()
            .unwrap_or(u64::MAX);

        if generation != writes {
            return Err(Error::Raced);
        }

        Ok((outblob, auxblob))
    }
}

impl GuestBackend for ConfigFs {
    fn transport(&self) -> Transport {
        Transport::ConfigFs
    }

    fn report(&self, request: &ReportRequest) -> Result<AttestationReport> {
        let (outblob, _) = self.run(request)?;
        AttestationReport::parse(&outblob)
    }

    fn extended_report(&self, request: &ReportRequest) -> Result<ExtendedReport> {
        let (outblob, auxblob) = self.run(request)?;
        Ok(ExtendedReport {
            report: AttestationReport::parse(&outblob)?,
            certificates: CertTable::parse(&auxblob)?,
        })
    }

    #[cfg(feature = "sev-guest")]
    fn derive_key(&self, _request: &KeyRequest) -> Result<DerivedKey> {
        Err(Error::Unsupported(
            "configfs-TSM has no key derivation interface; enable the \
             `sev-guest` feature and use /dev/sev-guest",
        ))
    }
}

/// Writes a configfs attribute in a single `write` call.
///
/// configfs hands the whole buffer to the provider as one operation; a partial
/// write would be interpreted as a truncated nonce, so anything short is an
/// error rather than something to retry.
fn write_attr(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = fs::OpenOptions::new().write(true).open(path)?;
    let n = file.write(bytes)?;
    if n != bytes.len() {
        return Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::WriteZero,
            "configfs accepted a partial attribute write",
        )));
    }
    Ok(())
}

/// A configfs report directory, removed when dropped.
struct Entry {
    path: PathBuf,
}

impl Entry {
    fn create(root: &Path) -> Result<Self> {
        // configfs entry names only need to be unique within the directory.
        // Pairing the pid with a counter keeps concurrent callers in one
        // process from colliding with each other.
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = root.join(format!("sev-snp-rs-{}-{}", std::process::id(), n));
        fs::create_dir(&path)?;
        Ok(Self { path })
    }
}

impl Drop for Entry {
    fn drop(&mut self) {
        // Nothing useful to do on failure; a leftover directory is inert and
        // will be reclaimed when configfs is unmounted.
        let _ = fs::remove_dir(&self.path);
    }
}
