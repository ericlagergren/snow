//! The [SNOW-V-GCM] AEAD cipher.
//!
//! [SNOW-V-GCM]: https://tosc.iacr.org/index.php/ToSC/article/view/8356

#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(not(any(test, doctest, feature = "std")), no_std)]

mod gcm;

pub use gcm::*;
