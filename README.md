# sev-snp

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

Plus SEV, SEV-ES and SEV-SNP capability detection through
`CPUID(0x8000_001F)`, which is the whole of the guest-visible API for the first
two.

## Portability

One code path covers Zen 3 through Zen 5. Report versions 2 to 5 parse
identically; fields introduced later return `Option`. `TcbVersion` keeps its raw
value and decodes per product, so Zen 5's FMC field does not corrupt a Zen 3
reading. Policy and platform bitfields expose `unknown_bits()` rather than
failing on a bit from newer firmware.

## Trust boundary

A report is evidence only once its signature has been checked against AMD's
certificate chain and the freshness of `report_data` confirmed. This crate
obtains and parses reports; it performs no cryptographic verification and
fetches nothing from the network, so the verifying party can be a different
machine running code of its own choosing.

## License

Licensed under the [0BSD license](https://github.com/hacer-bark/sev-snp/blob/main/LICENSE).

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in
this crate shall be licensed as above, without any additional terms or conditions.
