# Changelog

Notable changes to this crate, newest first. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

A minimum supported Rust version bump is a minor release before 1.0 and a major
one after; it never happens in a patch release.

## [0.1.0] - 2026-09-08

Initial release.

### Added

- `Firmware`, the handle over both Linux guest transports. `open` takes
  whichever are available and prefers configfs-TSM for reports, because it is
  the only one that can detect a concurrent writer; `open_with` pins a single
  transport when firmware status codes or key derivation are required.
- Attestation reports and extended reports (`report`, `extended_report`, and
  the `_with` variants taking a `ReportRequest`). Transient failures — a busy
  hypervisor, a detected race — are retried on a bounded schedule totalling
  under a second, because every ioctl attempt spends a VMPCK sequence number
  the guest cannot get back.
- Hardware key derivation through `/dev/sev-guest`: `KeyRequest` binds a key to
  any combination of measurement, policy, image and family ID, guest SVN, TCB
  version and launch mitigation vector. `DerivedKey` is zeroized on drop and
  redacted in `Debug`.
- `AttestationReport` parsing for report versions 2 through 5 over one code
  path, with fields introduced later returning `Option`. `TcbVersion` keeps its
  raw value and decodes per `Product`, so Zen 5's FMC field does not corrupt a
  Zen 3 reading.
- `CertTable` for the host-provisioned endorsement chain, with the blob size
  and entry count bounded before anything is decoded.
- `GuestPolicy` and `PlatformInfo`, which name the bits this crate knows and
  expose the rest through `unknown_bits` rather than failing on a bit from
  newer firmware.
- `detect` for SEV, SEV-ES and SEV-SNP capabilities via `CPUID(0x8000_001F)`,
  plus `is_snp_guest`.
- Both transports as cargo features, on by default. Selecting neither is a
  compile error; selecting only `configfs` leaves a crate with no dependencies,
  built under `forbid(unsafe_code)`.

### Security

- Every report is checked against the request that produced it. The firmware
  echoes `REPORT_DATA` and the privilege level, so a response answering
  somebody else's request is `Error::Mismatch` rather than a returned report.
- configfs-TSM is shared with TDX and other architectures, so the provider is
  verified once at open and anything but `sev_guest` is `Error::WrongProvider`.
- Report versions are bounded above as well as below, so a TDX quote — whose
  header reads as version 131076 — cannot parse as an SEV-SNP report.
- This crate performs no cryptographic verification and no network access. A
  report is evidence only once a verifier has checked its signature against
  AMD's certificate chain and confirmed the freshness of `report_data`.

[0.1.0]: https://github.com/hacer-bark/sev-snp/releases/tag/v0.1.0
