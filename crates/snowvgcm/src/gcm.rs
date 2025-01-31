use core::{error, fmt, hash::Hash};

use cipher::KeyInit;
use ghash::{universal_hash::UniversalHash, GHash};
use snowv::SnowV;

/// An eror returned by [`SnowVGcm`].
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct Error;

impl error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SNOW-V-GCM error")
    }
}

/// The size in bytes of a SNOW-V-GCM key.
pub const KEY_SIZE: usize = 32;

/// The size in bytes of a SNOV-V-GCM nonce.
pub const NONCE_SIZE: usize = 16;

/// A SNOW-V-GCM authentication tag.
pub type Tag = [u8; 16];

/// The SNOW-V stream cipher.
#[derive(Clone)]
pub struct SnowVGcm {
    key: [u8; 32],
    // ghash: GHash,
}

impl SnowVGcm {
    /// Creates a new instance of SNOW-V-GCM.
    #[inline]
    pub fn new(key: &[u8; KEY_SIZE]) -> Self {
        Self {
            key: *key,
            // ghash: todo!(),
        }
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
        cipher.write_keystream_block(&mut ghash_key).unwrap(); // TODO

        let mut mask = [0; 16];
        cipher.write_keystream_block(&mut mask).unwrap(); // TODO

        cipher.try_apply_keystream(data.into()).unwrap(); // TODO

        let tag = self.compute_tag(&ghash_key, &mask, data, additional_data);

        Ok(tag)
    }

    fn compute_tag(&self, ghash_key: &[u8; 16], mask: &[u8; 16], ct: &[u8], ad: &[u8]) -> Tag {
        // let mut ghash = self.ghash.clone();
        let mut ghash = GHash::new(ghash_key.into());
        ghash.update_padded(ct);
        ghash.update_padded(ad);

        // Let L = LE64(len(ct)) || LE64(len(A))
        let lengths = {
            #[allow(
                clippy::arithmetic_side_effects,
                reason = "`encrypt` and `decrypt` check the length of `ct` and `ad`"
            )]
            let chunk = ((ct.len() as u128) * 8) | ((ad.len() as u128) * 8) << 64;
            chunk.to_le_bytes()
        };
        ghash.update(&[lengths.into()]);

        let mut tag = ghash.finalize();
        for (z, x) in tag.iter_mut().zip(mask.iter()) {
            *z ^= *x;
        }
        tag.into()
    }
}

impl fmt::Debug for SnowVGcm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SnowVGcm").finish_non_exhaustive()
    }
}

// TODO
// #[cfg(test)]
// mod tests {
//     use super::*;

//     #[test]
//     fn test_seal() {}
// }
