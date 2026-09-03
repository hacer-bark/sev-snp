//! Hardware-bound key derivation.
//!
//! The secure processor can derive a 32-byte key from a root secret that never
//! leaves the chip, mixed with any combination of facts about the running VM.
//! Nothing is stored: the same request on the same machine, under the same
//! firmware, running the same guest image, reproduces the same key — and any
//! change to a bound fact silently produces a different one.
//!
//! That is what makes it useful for sealing. Bind
//! [`measurement`](KeyRequest::bind_measurement) and a disk encryption key
//! becomes unreadable if the guest image is tampered with; add
//! [`bind_tcb`](KeyRequest::bind_tcb) and it also becomes unreadable after a
//! firmware rollback. Because the root secret is chip-unique (with
//! [`RootKey::Vcek`]), the sealed data is bound to that physical processor too.
//!
//! ```no_run
//! use sev_snp::{Firmware, KeyRequest};
//!
//! let fw = Firmware::open()?;
//! let report = fw.report(&[0u8; 64])?;
//!
//! // A key that exists only for this image, on this chip, at this TCB.
//! let key = fw.derive_key(
//!     &KeyRequest::new()
//!         .bind_measurement()
//!         .bind_guest_policy()
//!         .bind_tcb(report.reported_tcb()),
//! )?;
//! # let _ = key.as_bytes();
//! # Ok::<_, sev_snp::Error>(())
//! ```

use crate::error::{Error, Result};
use crate::tcb::TcbVersion;
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Which chip-held secret to derive from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum RootKey {
    /// The Versioned Chip Endorsement Key, unique to this physical processor.
    ///
    /// Keys derived from it cannot be reproduced on any other machine, which
    /// is what you want for sealing data to this host.
    #[default]
    Vcek,
    /// The VM Root Key, installed by a migration agent.
    ///
    /// Survives migration to another host, so a key derived from it follows
    /// the VM. Only available when the guest was launched with a migration
    /// agent; otherwise the firmware rejects the request.
    Vmrk,
}

impl RootKey {
    const fn as_raw(self) -> u32 {
        match self {
            Self::Vcek => 0,
            Self::Vmrk => 1,
        }
    }
}

/// The facts mixed into a derived key.
///
/// Each bit names a property of the running guest. A bit that is set makes the
/// derived key depend on that property; a bit that is clear leaves the key
/// insensitive to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct KeyFields(u64);

impl KeyFields {
    /// No fields mixed in.
    pub const NONE: Self = Self(0);

    /// The raw `GUEST_FIELD_SELECT` value.
    #[must_use]
    pub const fn raw(self) -> u64 {
        self.0
    }

    /// The guest launch policy is mixed in.
    #[must_use]
    pub const fn guest_policy(self) -> bool {
        self.bit(0)
    }
    /// The guest image ID is mixed in.
    #[must_use]
    pub const fn image_id(self) -> bool {
        self.bit(1)
    }
    /// The guest family ID is mixed in.
    #[must_use]
    pub const fn family_id(self) -> bool {
        self.bit(2)
    }
    /// The launch measurement is mixed in.
    #[must_use]
    pub const fn measurement(self) -> bool {
        self.bit(3)
    }
    /// The guest security version number is mixed in.
    #[must_use]
    pub const fn guest_svn(self) -> bool {
        self.bit(4)
    }
    /// The TCB version is mixed in.
    #[must_use]
    pub const fn tcb_version(self) -> bool {
        self.bit(5)
    }
    /// The launch mitigation vector is mixed in.
    #[must_use]
    pub const fn launch_mit_vector(self) -> bool {
        self.bit(6)
    }

    const fn bit(self, index: u32) -> bool {
        self.0.wrapping_shr(index) & 1 == 1
    }

    const fn with(self, index: u32) -> Self {
        Self(self.0 | 1_u64.wrapping_shl(index))
    }
}

/// A request for a hardware-derived key.
///
/// Build one with [`KeyRequest::new`] and the `bind_*` methods, then pass it to
/// [`Firmware::derive_key`](crate::Firmware::derive_key). An unmodified request
/// derives a key bound to nothing but the root secret and the VMPL, which is
/// reproducible by any guest on the same chip at the same privilege level — so
/// bind at least [`bind_measurement`](Self::bind_measurement) unless you know
/// you want that.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct KeyRequest {
    root_key: RootKey,
    fields: KeyFields,
    vmpl: u32,
    guest_svn: u32,
    tcb_version: u64,
    launch_mit_vector: u64,
}

impl KeyRequest {
    /// Highest VMPL the SEV-SNP architecture defines.
    pub const MAX_VMPL: u32 = 3;

    /// A request deriving from the chip-unique VCEK with nothing mixed in.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            root_key: RootKey::Vcek,
            fields: KeyFields::NONE,
            vmpl: 0,
            guest_svn: 0,
            tcb_version: 0,
            launch_mit_vector: 0,
        }
    }

    /// Selects the root secret. Defaults to [`RootKey::Vcek`].
    #[must_use]
    pub const fn root_key(mut self, root: RootKey) -> Self {
        self.root_key = root;
        self
    }

    /// Sets the VMPL mixed into the key. Defaults to 0.
    ///
    /// Must be at or below the caller's own privilege level; a guest running at
    /// VMPL 2 cannot derive the key a VMPL 0 component would get. Values above
    /// [`Self::MAX_VMPL`] are rejected when the request is issued.
    #[must_use]
    pub const fn vmpl(mut self, vmpl: u32) -> Self {
        self.vmpl = vmpl;
        self
    }

    /// Binds the key to the guest launch policy.
    #[must_use]
    pub const fn bind_guest_policy(mut self) -> Self {
        self.fields = self.fields.with(0);
        self
    }

    /// Binds the key to the guest image ID from the ID block.
    #[must_use]
    pub const fn bind_image_id(mut self) -> Self {
        self.fields = self.fields.with(1);
        self
    }

    /// Binds the key to the guest family ID from the ID block.
    #[must_use]
    pub const fn bind_family_id(mut self) -> Self {
        self.fields = self.fields.with(2);
        self
    }

    /// Binds the key to the SHA-384 launch measurement of the guest image.
    ///
    /// The single most useful binding: the key changes if anything in the
    /// initial memory image changes.
    #[must_use]
    pub const fn bind_measurement(mut self) -> Self {
        self.fields = self.fields.with(3);
        self
    }

    /// Binds the key to a guest security version number.
    ///
    /// Must not exceed the SVN in the ID block the guest launched with, which
    /// is how it works as an anti-rollback ratchet.
    #[must_use]
    pub const fn bind_guest_svn(mut self, svn: u32) -> Self {
        self.fields = self.fields.with(4);
        self.guest_svn = svn;
        self
    }

    /// Binds the key to a platform TCB version.
    ///
    /// Must not exceed [`AttestationReport::committed_tcb`](crate::AttestationReport::committed_tcb).
    /// Passing [`AttestationReport::reported_tcb`](crate::AttestationReport::reported_tcb)
    /// makes the key invalid after any firmware downgrade.
    #[must_use]
    pub const fn bind_tcb(mut self, tcb: TcbVersion) -> Self {
        self.fields = self.fields.with(5);
        self.tcb_version = tcb.raw();
        self
    }

    /// Binds the key to the launch mitigation vector.
    ///
    /// Requires SEV-SNP firmware 1.58 or later, and a kernel whose
    /// `snp_derived_key_req` includes the field. On an older kernel the value
    /// is dropped before it reaches the firmware and a key derived against a
    /// zero vector comes back instead — with no error. Use
    /// [`AttestationReport::launch_mit_vector`](crate::AttestationReport::launch_mit_vector)
    /// to confirm the platform reports one at all before relying on this.
    #[must_use]
    pub const fn bind_launch_mit_vector(mut self, vector: u64) -> Self {
        self.fields = self.fields.with(6);
        self.launch_mit_vector = vector;
        self
    }

    /// The fields this request binds.
    #[must_use]
    pub const fn fields(&self) -> KeyFields {
        self.fields
    }

    /// The root secret this request derives from.
    #[must_use]
    pub const fn selected_root_key(&self) -> RootKey {
        self.root_key
    }

    pub(crate) const fn validate(&self) -> Result<()> {
        if self.vmpl > Self::MAX_VMPL {
            return Err(Error::InvalidArgument("vmpl must be 0..=3"));
        }
        Ok(())
    }

    /// Serialises to the layout the kernel's `snp_derived_key_req` expects.
    ///
    /// 40 bytes are produced: the 32 the original ABI defined, plus the
    /// mitigation vector appended in firmware 1.58. Kernels predating that
    /// field copy only the first 32 bytes and ignore the rest.
    pub(crate) fn to_wire(self) -> [u8; 40] {
        // Field order per `struct snp_derived_key_req`, with the reserved word
        // after the root key selector.
        let fields = self
            .root_key
            .as_raw()
            .to_le_bytes()
            .into_iter()
            .chain([0u8; 4])
            .chain(self.fields.raw().to_le_bytes())
            .chain(self.vmpl.to_le_bytes())
            .chain(self.guest_svn.to_le_bytes())
            .chain(self.tcb_version.to_le_bytes())
            .chain(self.launch_mit_vector.to_le_bytes());

        let mut out = [0u8; 40];
        for (dst, byte) in out.iter_mut().zip(fields) {
            *dst = byte;
        }
        out
    }
}

/// A 32-byte key derived by the secure processor.
///
/// The bytes are wiped when this value is dropped, and neither `Debug` nor any
/// other formatting impl reveals them. Copy them out with
/// [`as_bytes`](Self::as_bytes) only for as long as you need them.
#[derive(Clone)]
pub struct DerivedKey([u8; Self::LEN]);

impl DerivedKey {
    /// Length of a derived key in bytes.
    pub const LEN: usize = 32;

    pub(crate) const fn from_bytes(bytes: [u8; Self::LEN]) -> Self {
        Self(bytes)
    }

    /// The key material.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }

    /// Wipes the key immediately rather than waiting for the drop.
    pub fn zeroize_now(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for DerivedKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl ZeroizeOnDrop for DerivedKey {}

impl fmt::Debug for DerivedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DerivedKey(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytes_at;
    use rand::RngExt;

    fn le32(buf: &[u8], offset: usize) -> Option<u32> {
        crate::u32_at(buf, offset)
    }

    fn le64(buf: &[u8], offset: usize) -> Option<u64> {
        bytes_at::<8>(buf, offset).map(u64::from_le_bytes)
    }

    #[test]
    fn bindings_serialise_to_the_firmware_layout() {
        let mut rng = rand::rng();
        let (svn, tcb, mit): (u32, u64, u64) = (rng.random(), rng.random(), rng.random());

        let request = KeyRequest::new()
            .root_key(RootKey::Vmrk)
            .vmpl(2)
            .bind_measurement()
            .bind_guest_policy()
            .bind_guest_svn(svn)
            .bind_tcb(TcbVersion::from_raw(tcb))
            .bind_launch_mit_vector(mit);

        let selected = request.fields();
        assert!(selected.measurement() && selected.guest_policy());
        assert!(selected.guest_svn() && selected.tcb_version());
        assert!(selected.launch_mit_vector());
        assert!(!selected.image_id() && !selected.family_id());

        let wire = request.to_wire();
        assert_eq!(le32(&wire, 0), Some(1), "VMRK selector");
        assert_eq!(le32(&wire, 4), Some(0), "reserved word");
        assert_eq!(le64(&wire, 8), Some(selected.raw()));
        assert_eq!(le32(&wire, 16), Some(2), "vmpl");
        assert_eq!(le32(&wire, 20), Some(svn));
        assert_eq!(le64(&wire, 24), Some(tcb));
        assert_eq!(le64(&wire, 32), Some(mit));
    }

    #[test]
    fn vmpls_outside_the_architected_range_never_reach_the_firmware() {
        assert!(KeyRequest::new().vmpl(3).validate().is_ok());
        assert!(KeyRequest::new().vmpl(4).validate().is_err());
    }

    #[test]
    fn key_material_is_wiped_on_drop() {
        let mut key = DerivedKey::from_bytes(rand::rng().random());
        assert_ne!(*key.as_bytes(), [0u8; DerivedKey::LEN]);
        key.zeroize_now();
        assert_eq!(*key.as_bytes(), [0u8; DerivedKey::LEN]);
    }
}
