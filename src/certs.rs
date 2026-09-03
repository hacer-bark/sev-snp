//! The certificate table returned alongside an extended attestation report.
//!
//! When the host has provisioned an endorsement chain, the guest can fetch it
//! with the report in one call. The blob is a table of 24-byte entries — a GUID
//! plus an offset and length — terminated by an all-zero entry, followed by the
//! certificate bodies themselves.
//!
//! Many hosts provision nothing, in which case the blob is empty and the chain
//! has to come from AMD's Key Distribution Service instead. That is a network
//! operation, so this crate does not do it for you; [`Certificate::kind`] and
//! [`crate::Product::kds_name`] give you what a KDS query needs.

use crate::error::{ParseError, Result};
use crate::report::AttestationReport;
use std::fmt;

/// Size of one certificate table entry.
const ENTRY_SIZE: usize = 24;

/// Which certificate in the endorsement chain an entry holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CertKind {
    /// Versioned Chip Endorsement Key, leaf for chip-unique signing.
    Vcek,
    /// Versioned Loaded Endorsement Key, leaf for provider-provisioned signing.
    Vlek,
    /// AMD SEV Signing Key, intermediate above the VCEK.
    Ask,
    /// AMD Root Key.
    Ark,
    /// AMD SEV VLEK signing key, intermediate above the VLEK.
    Asvk,
    /// Extra host-supplied platform information, not a certificate.
    ExtraPlatformInfo,
    /// A GUID this crate does not recognise.
    Unknown,
}

/// GUIDs defined by the GHCB specification for `MSG_REPORT_REQ`.
const VCEK_GUID: [u8; 16] = uuid(0x63da758d, 0xe664, 0x4564, 0xadc5, 0xf4b93be8accd);
const VLEK_GUID: [u8; 16] = uuid(0xa8074bc2, 0xa25a, 0x483e, 0xaae6, 0x39c045a0b8a1);
const ASK_GUID: [u8; 16] = uuid(0x4ab7b379, 0xbbac, 0x4fe4, 0xa02f, 0x05aef327c782);
const ARK_GUID: [u8; 16] = uuid(0xc0b406a4, 0xa803, 0x4952, 0x9743, 0x3fb6014cd0ae);
const ASVK_GUID: [u8; 16] = uuid(0x00000000, 0x0000, 0x0000, 0x0000, 0x000000000000);
const EXTRA_PLATFORM_INFO_GUID: [u8; 16] = uuid(0xecae0c0f, 0x9502, 0x43b1, 0xafa2, 0x0ae2e0d565b6);

/// Assembles a UUID in RFC 4122 binary order, which is what the GHCB uses.
const fn uuid(a: u32, b: u16, c: u16, d: u16, e: u64) -> [u8; 16] {
    let (a, b, c, d, e) = (
        a.to_be_bytes(),
        b.to_be_bytes(),
        c.to_be_bytes(),
        d.to_be_bytes(),
        e.to_be_bytes(),
    );
    [
        a[0], a[1], a[2], a[3], b[0], b[1], c[0], c[1], d[0], d[1], e[2], e[3], e[4], e[5], e[6],
        e[7],
    ]
}

impl CertKind {
    fn from_guid(guid: &[u8; 16]) -> Self {
        match *guid {
            VCEK_GUID => Self::Vcek,
            VLEK_GUID => Self::Vlek,
            ASK_GUID => Self::Ask,
            ARK_GUID => Self::Ark,
            ASVK_GUID => Self::Asvk,
            EXTRA_PLATFORM_INFO_GUID => Self::ExtraPlatformInfo,
            _ => Self::Unknown,
        }
    }
}

/// One entry from the certificate table.
#[derive(Clone, PartialEq, Eq)]
pub struct Certificate {
    kind: CertKind,
    guid: [u8; 16],
    data: Vec<u8>,
}

impl Certificate {
    /// Which certificate this is.
    pub fn kind(&self) -> CertKind {
        self.kind
    }

    /// The raw GUID, useful when [`kind`](Self::kind) is [`CertKind::Unknown`].
    pub fn guid(&self) -> &[u8; 16] {
        &self.guid
    }

    /// The certificate body, DER-encoded X.509 for every AMD-defined kind
    /// except [`CertKind::ExtraPlatformInfo`].
    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

impl fmt::Debug for Certificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Certificate")
            .field("kind", &self.kind)
            .field("len", &self.data.len())
            .finish()
    }
}

/// The endorsement chain accompanying an extended report.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CertTable(Vec<Certificate>);

impl CertTable {
    /// Parses a certificate table blob.
    ///
    /// An empty blob yields an empty table rather than an error: hosts are not
    /// required to provision certificates.
    pub fn parse(blob: &[u8]) -> Result<Self> {
        if blob.is_empty() {
            return Ok(Self::default());
        }

        let mut certs = Vec::new();
        let mut cursor = 0usize;

        loop {
            let entry = blob
                .get(cursor..cursor + ENTRY_SIZE)
                .ok_or(ParseError::TooShort {
                    what: "certificate table entry",
                    need: cursor + ENTRY_SIZE,
                    got: blob.len(),
                })?;

            let guid: [u8; 16] = entry[..16].try_into().expect("16 of 24 bytes");
            let offset = u32::from_le_bytes(entry[16..20].try_into().expect("4 of 24 bytes"));
            let length = u32::from_le_bytes(entry[20..24].try_into().expect("4 of 24 bytes"));

            // An all-zero entry terminates the table.
            if guid == [0u8; 16] && offset == 0 && length == 0 {
                break;
            }

            let start = offset as usize;
            let end = start
                .checked_add(length as usize)
                .ok_or(ParseError::CertTableOutOfBounds)?;
            let data = blob
                .get(start..end)
                .ok_or(ParseError::CertTableOutOfBounds)?;

            certs.push(Certificate {
                kind: CertKind::from_guid(&guid),
                guid,
                data: data.to_vec(),
            });

            cursor += ENTRY_SIZE;
        }

        Ok(Self(certs))
    }

    /// All entries, in table order.
    pub fn entries(&self) -> &[Certificate] {
        &self.0
    }

    /// The first entry of the given kind, if present.
    pub fn get(&self, kind: CertKind) -> Option<&Certificate> {
        self.0.iter().find(|c| c.kind == kind)
    }

    /// Whether the table is empty, which means the host provisioned nothing.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// An attestation report together with the endorsement chain that verifies it.
#[derive(Debug, Clone)]
pub struct ExtendedReport {
    /// The attestation report.
    pub report: AttestationReport,
    /// The certificate chain the host provisioned, possibly empty.
    pub certificates: CertTable,
}
