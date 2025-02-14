use core::{error, fmt, hash::Hash};

use inout::InOutBuf;
use polyhash::ghash::GHash;
use snowv::SnowV;
use subtle::ConstantTimeEq;

cfg_if::cfg_if! {
    if #[cfg(feature = "zeroize")] {
        use zeroize::Zeroizing;
    } else {
        struct Zeroizing<T>(T);
        impl<T> Zeroizing<T> {
            #[inline(always)]
            #[allow(clippy::new_ret_no_self)]
            fn new(t: T) -> T {
                t
            }
        }
    }
}

/// An eror returned by [`SnowVGcm`].
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct Error;

impl error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SNOW-V-GCM error")
    }
}

impl From<snowv::Error> for Error {
    #[inline]
    fn from(_err: snowv::Error) -> Self {
        Self
    }
}

/// The size in bytes of a SNOW-V-GCM key.
pub const KEY_SIZE: usize = 32;

/// The size in bytes of a SNOV-V-GCM nonce.
pub const NONCE_SIZE: usize = 16;

/// The size in bytes of a SNOW-V-GCM authentication tag.
pub const TAG_SIZE: usize = 16;

// Because we need to convert bytes to bits.
const P_MAX: u64 = u64::MAX / 8;
const C_MAX: u64 = u64::MAX / 8;
const A_MAX: u64 = u64::MAX / 8;

/// A SNOW-V-GCM authentication tag.
pub type Tag = [u8; TAG_SIZE];

/// The SNOW-V-GCM AEAD.
#[derive(Clone)]
pub struct SnowVGcm {
    key: [u8; KEY_SIZE],
}

impl SnowVGcm {
    /// Creates an instance of SNOW-V-GCM.
    #[inline]
    pub fn new(key: &[u8; KEY_SIZE]) -> Self {
        Self { key: *key }
    }

    /// Encrypts and authenticates `data`, authenticates
    /// `additional_data`, and writes the result to `data`.
    #[inline]
    pub fn seal(
        &self,
        nonce: &[u8; NONCE_SIZE],
        mut data: InOutBuf<'_, '_, u8>,
        additional_data: &[u8],
    ) -> Result<Tag, Error> {
        if !less_or_equal(data.len(), P_MAX) || !less_or_equal(additional_data.len(), A_MAX) {
            return Err(Error);
        }

        let mut cipher = SnowV::new_for_aead(&self.key, nonce);

        let mut ghash_key = Zeroizing::new([0; 16]); // aka H
        cipher.write_keystream_block(&mut ghash_key)?;

        let mut mask = Zeroizing::new([0; 16]); // aka endPad
        cipher.write_keystream_block(&mut mask)?;

        cipher.apply_keystream(data.reborrow())?;

        let tag = self.compute_tag(&ghash_key, &mask, data.get_out(), additional_data);

        Ok(tag)
    }

    /// Decrypts and authenticates `data`, authenticates
    /// `additional_data`, and writes the result to `data`.
    #[inline]
    pub fn open(
        &self,
        nonce: &[u8; NONCE_SIZE],
        data: InOutBuf<'_, '_, u8>,
        tag: &Tag,
        additional_data: &[u8],
    ) -> Result<(), Error> {
        if !less_or_equal(data.len(), C_MAX) || !less_or_equal(additional_data.len(), A_MAX) {
            return Err(Error);
        }

        let mut cipher = SnowV::new_for_aead(&self.key, nonce);

        let mut ghash_key = Zeroizing::new([0; 16]); // aka H
        cipher.write_keystream_block(&mut ghash_key)?;

        let mut mask = Zeroizing::new([0; 16]); // aka endPad
        cipher.write_keystream_block(&mut mask)?;

        let expected_tag = self.compute_tag(&ghash_key, &mask, data.get_in(), additional_data);
        if !bool::from(expected_tag.ct_eq(tag)) {
            return Err(Error);
        }

        cipher.apply_keystream(data)?;

        Ok(())
    }

    #[allow(
        clippy::arithmetic_side_effects,
        reason = "We checked the lengths of `ct` and `at`"
    )]
    fn compute_tag(&self, ghash_key: &[u8; 16], mask: &[u8; 16], ct: &[u8], ad: &[u8]) -> Tag {
        let mut ghash = GHash::new_unchecked(ghash_key);
        ghash.update_padded(ad);
        ghash.update_padded(ct);

        let ad_bits = (ad.len() as u64) * 8;
        let ct_bits = (ct.len() as u64) * 8;

        let mut lengths = [0u8; 16];
        lengths[..8].copy_from_slice(&ad_bits.to_be_bytes());
        lengths[8..].copy_from_slice(&ct_bits.to_be_bytes());
        ghash.update_block(&lengths);

        let mut tag: [u8; 16] = ghash.tag().into();
        for (t, m) in tag.iter_mut().zip(mask) {
            *t ^= *m;
        }
        tag
    }
}

impl fmt::Debug for SnowVGcm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SnowVGcm").finish_non_exhaustive()
    }
}

/// Reports whether `x <= y`.
#[inline(always)]
fn less_or_equal(x: usize, y: u64) -> bool {
    u64::try_from(x).is_ok_and(|n| n <= y)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_round_trip() {
        const PLAINTEXT: &[u8] = b"hello, world!";

        let aead = SnowVGcm::new(&[0; KEY_SIZE]);
        let nonce = [0; NONCE_SIZE];
        let ad = b"additional data";
        let mut data = PLAINTEXT.to_vec();
        let tag = aead.seal(&nonce, data.as_mut_slice().into(), ad).unwrap();
        aead.open(&nonce, data.as_mut_slice().into(), &tag, ad)
            .unwrap();
        assert_eq!(data, PLAINTEXT);
    }

    #[test]
    fn test_vectors() {
        type Test<'a> = (
            &'a [u8; KEY_SIZE],   // key
            &'a [u8; NONCE_SIZE], // nonce
            &'a [u8],             // ad
            &'a [u8],             // pt
            &'a [u8],             // ct
            &'a [u8; 16],         // tag
        );
        const TESTS: &[Test<'_>] = &[
            (
                &[0; KEY_SIZE],
                &[0; NONCE_SIZE],
                &[],
                &[],
                &[],
                &[
                    0x02, 0x9a, 0x62, 0x4c, 0xda, 0xa4, 0xd4, 0x6c, 0xb9, 0xa0, 0xef, 0x40, 0x46,
                    0x95, 0x6c, 0x9f,
                ],
            ),
            (
                &[
                    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c,
                    0x5d, 0x5e, 0x5f, 0x0a, 0x1a, 0x2a, 0x3a, 0x4a, 0x5a, 0x6a, 0x7a, 0x8a, 0x9a,
                    0xaa, 0xba, 0xca, 0xda, 0xea, 0xfa,
                ],
                &[
                    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76,
                    0x54, 0x32, 0x10,
                ],
                &[],
                &[],
                &[],
                &[
                    0xfc, 0x7c, 0xac, 0x57, 0x4c, 0x49, 0xfe, 0xae, 0x61, 0x50, 0x31, 0x5b, 0x96,
                    0x85, 0x42, 0x4c,
                ],
            ),
        ];
        for (i, &(key, nonce, ad, pt, ct, tag)) in TESTS.iter().enumerate() {
            let aead = SnowVGcm::new(key);
            let mut data = pt.to_vec();
            let got_tag = aead.seal(nonce, data.as_mut_slice().into(), ad).unwrap();
            assert_eq!(&got_tag, tag, "#{i}");
            assert_eq!(data, ct, "#{i}");
            aead.open(nonce, data.as_mut_slice().into(), tag, ad)
                .unwrap();
            assert_eq!(data, pt, "#{i}");
        }
    }
}
