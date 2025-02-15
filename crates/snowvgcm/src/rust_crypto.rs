//! RustCrypto bindings.
//!
//! [RustCrypto]: https://github.com/rustcrypto

#![cfg(feature = "rust-crypto")]
#![cfg_attr(docsrs, doc(cfg(feature = "rust-crypto")))]

use core::fmt;

use aead::{
    generic_array::typenum::{U16, U32},
    AeadCore, AeadInPlace, Key, KeyInit, KeySizeUser,
};
use cipher::AlgorithmName;

use crate::SnowVGcm;

impl AlgorithmName for SnowVGcm {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SNOW-V-GCM")
    }
}

impl KeySizeUser for SnowVGcm {
    type KeySize = U32;
}

impl KeyInit for SnowVGcm {
    #[inline]
    fn new(key: &Key<Self>) -> Self {
        Self::new(key.as_ref())
    }
}

impl AeadCore for SnowVGcm {
    type NonceSize = U16;
    type TagSize = U16;
    type CiphertextOverhead = U16;
}

impl AeadInPlace for SnowVGcm {
    #[inline]
    fn encrypt_in_place_detached(
        &self,
        nonce: &aead::Nonce<Self>,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> aead::Result<aead::Tag<Self>> {
        let tag = self
            .seal(nonce.as_ref(), buffer.into(), associated_data)
            .map_err(|_| aead::Error)?;
        Ok(tag.into())
    }

    #[inline]
    fn decrypt_in_place_detached(
        &self,
        nonce: &aead::Nonce<Self>,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &aead::Tag<Self>,
    ) -> aead::Result<()> {
        self.open(nonce.as_ref(), buffer.into(), tag.as_ref(), associated_data)
            .map_err(|_| aead::Error)
    }
}
