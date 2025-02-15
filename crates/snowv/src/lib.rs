//! The [SNOW-V] stream cipher.
//!
//! [SNOW-V]: https://tosc.iacr.org/index.php/ToSC/article/view/8356

#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(not(any(test, doctest, feature = "std")), no_std)]

mod backend;
pub mod rust_crypto;
mod stream;

pub use stream::*;
