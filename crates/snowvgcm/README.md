# snowv-gcm

[![Docs][docs-img]][docs-link]

This crate implements the [SNOW-V-GCM] AEAD construction.

## Installation

```bash
[dependencies]
snowv-gcm = "0.1"
```

## Performance

The ARMv8 and x86-64 assembly backends run at about 0.65 cycles
per byte. The x86-64 implementation requires SSE2 and PCLMULQDQ
instructions. The ARMv8 implementation requires NEON and PMULL.

The defualt Rust implementation will be selected if the CPU does
not support either assembly implementation. (This implementation
can also be selected with the `soft` feature.) It is much
slower at around 9 cycles per byte.

## Security

### Disclosure

This project uses full disclosure. If you find a security bug in
an implementation, please e-mail me or create a GitHub issue.

### Disclaimer

You should only use cryptography libraries that have been
reviewed by cryptographers or cryptography engineers. While I am
a cryptography engineer, I'm not your cryptography engineer, and
I have not had this project reviewed by any other cryptographers.

[//]: # (badges)

[docs-img]: https://docs.rs/snowv-gcm/badge.svg
[docs-link]: https://docs.rs/snowv-gcm
[SNOW-V-GCM]: https://tosc.iacr.org/index.php/ToSC/article/view/8356
