# sev-snp

[![CI](https://github.com/hacer-bark/sev-snp/actions/workflows/ci.yml/badge.svg)](https://github.com/hacer-bark/sev-snp/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/sev-snp.svg)](https://crates.io/crates/sev-snp)
[![docs.rs](https://img.shields.io/docsrs/sev-snp)](https://docs.rs/sev-snp)
[![license](https://img.shields.io/crates/l/sev-snp.svg)](https://github.com/hacer-bark/sev-snp/blob/main/LICENSE)
[![msrv](https://img.shields.io/badge/msrv-1.87-blue.svg)](https://releases.rs/docs/1.87.0/)

Safe Rust bindings for the Linux AMD SEV-SNP guest API.

Inside an SEV-SNP virtual machine, the AMD secure processor will sign statements
about the VM and derive keys that never leave the chip. This crate exposes
everything the Linux guest interface offers, over both kernel transports, with
no `unsafe` required of the caller.

```rust,no_run
use sev_snp::{Firmware, KeyRequest};

fn main() -> Result<(), sev_snp::Error> {
    let fw = Firmware::open()?;
    let report = fw.report(&[0u8; 64])?;
    println!("measurement: {:x?}", report.measurement());

    // A key that exists only for this image, on this chip, at this TCB.
    let key = fw.derive_key(
        &KeyRequest::new()
            .bind_measurement()
            .bind_guest_policy()
            .bind_tcb(report.reported_tcb()),
    )?;
    println!("sealed key: {} bytes", key.as_bytes().len());
    Ok(())
}
```

## What is covered

| Operation | `/dev/sev-guest` | configfs-TSM |
|---|---|---|
| Attestation report | yes | yes |
| Extended report (certificate chain) | yes | yes |
| Derived key | yes | not implemented by the kernel |
| Firmware status codes | yes | collapsed into `errno` |
| Concurrent-writer detection | no | yes |

Every report is checked against the request that produced it — the firmware
echoes `REPORT_DATA` and the privilege level, so a response that answers
somebody else's request is rejected rather than returned. configfs-TSM is shared
with TDX and other architectures, so the provider is verified at open time and
this crate will not attach to anything but `sev_guest`.

Plus SEV, SEV-ES and SEV-SNP capability detection through
`CPUID(0x8000_001F)`, which is the whole of the guest-visible API for the first
two.

## Features

Each transport is a cargo feature, both on by default. Turning one off compiles
it out entirely, along with anything only it needed.

| Feature | Transport | Adds | Cost |
|---|---|---|---|
| `configfs` | configfs-TSM | reports, concurrent-writer detection | no dependencies |
| `sev-guest` | `/dev/sev-guest` | key derivation, firmware status codes | `libc`, `zeroize` |

Selecting neither is a compile error.

Anything a build cannot do is absent rather than failing at run time. Without
`sev-guest` there is no `Firmware::derive_key`, no `key` module and no
`Transport::Ioctl`, so code that needs them fails to compile rather than
reaching production and returning an error. `Transport` is `#[non_exhaustive]`
so that a sibling crate enabling a feature cannot break an exhaustive `match`.
See `examples/attest.rs` for the `#[cfg]` pattern that works under any feature
selection.

## Unsafe code

The crate builds under `unsafe_code = "deny"`. There is exactly one permitted
exception, carrying an `#[expect(unsafe_code, reason = "...")]` that explains
itself: the `libc::ioctl` call in `backend::ioctl`. An ioctl cannot be made safe
by any wrapper — the obligation being discharged is that the opcode matches the
driver's struct and that the buffers stay live for the call, which only the
caller can know.

With `--no-default-features --features configfs` that block is not compiled, all
dependencies disappear, and the crate is built under
`forbid(unsafe_code)`, which an `expect` cannot lift. "This build contains no
unsafe code" is therefore checked by the compiler rather than asserted here.
That build cannot derive keys: the kernel exposes key derivation only through
the ioctl.

## License

Licensed under the [0BSD license](https://github.com/hacer-bark/sev-snp/blob/main/LICENSE).

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in
this crate shall be licensed as above, without any additional terms or conditions.
