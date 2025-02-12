//! RustCrypto bindings.
//!
//! [RustCrypto]: https://github.com/rustcrypto

#![cfg(feature = "rust-crypto")]
#![cfg_attr(docsrs, doc(cfg(feature = "rust-crypto")))]

use aead::{
    generic_array::typenum::{U16, U32},
    AeadCore, AeadInPlace,
};

use crate::{Error, SnowVGcm};

/// The size in bytes of a SNOW-V-GCM key.
pub type KeySize = U32;

/// The size in bytes of a SNOW-V-GCM nonce.
pub type NonceSize = U16;

/// The size in bytes of a SNOW-V-GCM authentication tag.
pub type TagSize = U16;

impl From<Error> for aead::Error {
    #[inline]
    fn from(_err: Error) -> Self {
        aead::Error
    }
}

impl AeadCore for SnowVGcm {
    type NonceSize = NonceSize;
    type TagSize = TagSize;
    type CiphertextOverhead = TagSize;
}

impl AeadInPlace for SnowVGcm {
    #[inline]
    #[allow(
        clippy::unwrap_used,
        reason = "The compiler can prove that `try_into` always succeeds"
    )]
    fn encrypt_in_place_detached(
        &self,
        nonce: &aead::Nonce<Self>,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> aead::Result<aead::Tag<Self>> {
        let nonce = nonce.as_slice().try_into().unwrap();
        let tag = self.seal(nonce, buffer.into(), associated_data)?;
        Ok(tag.into())
    }

    #[inline]
    #[allow(
        clippy::unwrap_used,
        reason = "The compiler can prove that `try_into` always succeeds"
    )]
    fn decrypt_in_place_detached(
        &self,
        nonce: &aead::Nonce<Self>,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &aead::Tag<Self>,
    ) -> aead::Result<()> {
        let nonce = nonce.as_slice().try_into().unwrap();
        let tag = tag.as_slice().try_into().unwrap();
        self.open(nonce, buffer.into(), tag, associated_data)
            .map_err(Into::into)
    }
}
