use core::{error, fmt, hash::Hash};

use cipher::KeyInit;
use ghash::{universal_hash::UniversalHash, GHash};

use crate::{stream::SnowV, KEY_SIZE};

/// An eror returned by [`SnowVGcm`].
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct Error;

impl error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SNOW-V-GCM error")
    }
}

/// The size in bytes of a SNOV-V-GCM nonce.
pub const NONCE_SIZE: usize = 16;

/// A SNOW-V-GCM authentication tag.
pub type Tag = [u8; 16];

/// The SNOW-V stream cipher.
#[derive(Clone)]
pub struct SnowVGcm {
    key: [u8; 32],
}

impl SnowVGcm {
    /// TODO
    #[inline]
    pub fn new(key: &[u8; KEY_SIZE]) -> Self {
        Self { key: *key }
    }

    /// Encrypts and authenticates `plaintext`, authenticates
    /// `additional_data`, and writes the result to `dst`.
    ///
    /// # Requirements
    ///
    /// - `dst` must be at least as long as `plaintext`.
    #[inline]
    pub fn seal_in_place(
        &self,
        nonce: &[u8; NONCE_SIZE],
        data: &mut [u8],
        additional_data: &[u8],
    ) -> Result<Tag, Error> {
        let mut cipher = SnowV::new(&self.key, nonce);
        let mut ghash_key = [0; 16];
        cipher.write_keystream_block(&mut ghash_key);
        let mut end_pad = [0; 16];
        cipher.write_keystream_block(&mut end_pad);
        cipher.apply_keystream(data);
        let mut ghash = GHash::new(&self.key);
        todo!()
    }
}

impl fmt::Debug for SnowVGcm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SnowVGcm").finish_non_exhaustive()
    }
}
