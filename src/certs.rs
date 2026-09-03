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
use crate::{bytes_at, u32_at};
use std::fmt;

/// Size of one certificate table entry.
const ENTRY_SIZE: usize = 24;
/// Offset of the body offset within an entry.
const ENTRY_OFFSET_FIELD: usize = 16;
/// Offset of the body length within an entry.
const ENTRY_LENGTH_FIELD: usize = 20;

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

// GUIDs defined by the GHCB specification for `MSG_REPORT_REQ`, in RFC 4122
// binary order. The dashed form is given so each can be checked by eye against
// the specification.

/// `63da758d-e664-4564-adc5-f4b93be8accd`
const VCEK_GUID: [u8; 16] = [
    0x63, 0xda, 0x75, 0x8d, 0xe6, 0x64, 0x45, 0x64, 0xad, 0xc5, 0xf4, 0xb9, 0x3b, 0xe8, 0xac, 0xcd,
];
/// `a8074bc2-a25a-483e-aae6-39c045a0b8a1`
const VLEK_GUID: [u8; 16] = [
    0xa8, 0x07, 0x4b, 0xc2, 0xa2, 0x5a, 0x48, 0x3e, 0xaa, 0xe6, 0x39, 0xc0, 0x45, 0xa0, 0xb8, 0xa1,
];
/// `4ab7b379-bbac-4fe4-a02f-05aef327c782`
const ASK_GUID: [u8; 16] = [
    0x4a, 0xb7, 0xb3, 0x79, 0xbb, 0xac, 0x4f, 0xe4, 0xa0, 0x2f, 0x05, 0xae, 0xf3, 0x27, 0xc7, 0x82,
];
/// `c0b406a4-a803-4952-9743-3fb6014cd0ae`
const ARK_GUID: [u8; 16] = [
    0xc0, 0xb4, 0x06, 0xa4, 0xa8, 0x03, 0x49, 0x52, 0x97, 0x43, 0x3f, 0xb6, 0x01, 0x4c, 0xd0, 0xae,
];
/// `ecae0c0f-9502-43b1-afa2-0ae2e0d565b6`
const EXTRA_PLATFORM_INFO_GUID: [u8; 16] = [
    0xec, 0xae, 0x0c, 0x0f, 0x95, 0x02, 0x43, 0xb1, 0xaf, 0xa2, 0x0a, 0xe2, 0xe0, 0xd5, 0x65, 0xb6,
];

impl CertKind {
    /// Identifies an entry by its GUID.
    ///
    /// The all-zero GUID would be the ASVK, but it is also the table
    /// terminator, so it never reaches here: [`CertTable::parse`] stops first.
    const fn from_guid(guid: [u8; 16]) -> Self {
        match guid {
            VCEK_GUID => Self::Vcek,
            VLEK_GUID => Self::Vlek,
            ASK_GUID => Self::Ask,
            ARK_GUID => Self::Ark,
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
    #[must_use]
    pub const fn kind(&self) -> CertKind {
        self.kind
    }

    /// The raw GUID, useful when [`kind`](Self::kind) is [`CertKind::Unknown`].
    #[must_use]
    pub const fn guid(&self) -> &[u8; 16] {
        &self.guid
    }

    /// The certificate body, DER-encoded X.509 for every AMD-defined kind
    /// except [`CertKind::ExtraPlatformInfo`].
    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

impl fmt::Debug for Certificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Certificate")
            .field("kind", &self.kind)
            .field("len", &self.data.len())
            .finish_non_exhaustive()
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
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::TooShort`] if the table runs off the end of the
    /// blob without a terminator, or [`ParseError::CertTableOutOfBounds`] if an
    /// entry describes a body that does not lie within the blob.
    pub fn parse(blob: &[u8]) -> Result<Self> {
        if blob.is_empty() {
            return Ok(Self::default());
        }

        let mut certs = Vec::new();
        let mut cursor = 0usize;

        loop {
            let short = || ParseError::TooShort {
                what: "certificate table entry",
                need: cursor.saturating_add(ENTRY_SIZE),
                got: blob.len(),
            };

            let guid = bytes_at::<16>(blob, cursor).ok_or_else(short)?;
            let offset =
                u32_at(blob, cursor.saturating_add(ENTRY_OFFSET_FIELD)).ok_or_else(short)?;
            let length =
                u32_at(blob, cursor.saturating_add(ENTRY_LENGTH_FIELD)).ok_or_else(short)?;

            // An all-zero entry terminates the table.
            if guid == [0u8; 16] && offset == 0 && length == 0 {
                break;
            }

            let start = usize::try_from(offset).map_err(|_| ParseError::CertTableOutOfBounds)?;
            let len = usize::try_from(length).map_err(|_| ParseError::CertTableOutOfBounds)?;
            let end = start
                .checked_add(len)
                .ok_or(ParseError::CertTableOutOfBounds)?;
            let data = blob
                .get(start..end)
                .ok_or(ParseError::CertTableOutOfBounds)?;

            certs.push(Certificate {
                kind: CertKind::from_guid(guid),
                guid,
                data: data.to_vec(),
            });

            cursor = cursor.saturating_add(ENTRY_SIZE);
        }

        Ok(Self(certs))
    }

    /// All entries, in table order.
    #[must_use]
    pub const fn entries(&self) -> &[Certificate] {
        self.0.as_slice()
    }

    /// The first entry of the given kind, if present.
    #[must_use]
    pub fn get(&self, kind: CertKind) -> Option<&Certificate> {
        self.0.iter().find(|c| c.kind == kind)
    }

    /// Whether the table is empty, which means the host provisioned nothing.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// How many entries the table holds.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.0.len()
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
