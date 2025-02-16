//! The [SNOW-V-GCM] AEAD cipher.
//!
//! [SNOW-V-GCM]: https://tosc.iacr.org/index.php/ToSC/article/view/8356

#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(not(any(test, doctest, feature = "std")), no_std)]

pub mod rust_crypto;

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

/// The error returned by [`SnowVGcm`].
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

/// A SNOW-V-GCM key.
pub type Key = [u8; KEY_SIZE];

/// A SNOW-V-GCM nonce.
pub type Nonce = [u8; NONCE_SIZE];

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
        nonce: &Nonce,
        mut data: InOutBuf<'_, '_, u8>,
        additional_data: &[u8],
    ) -> Result<Tag, Error> {
        if !less_or_equal(data.len(), P_MAX) || !less_or_equal(additional_data.len(), A_MAX) {
            return Err(Error);
        }

        let mut cipher = SnowV::new_for_aead(&self.key, nonce);

        let mut ghash_key = Zeroizing::new([0; 16]); // aka H
        cipher.write_keystream_block(&mut ghash_key)?;

        #[cfg(test)]
        {
            println!(" want: [a5, 78, c7, e6, c9, dd, e7, 7f, af, b7, ae, 37, fa, 56, 95, 4a]");
            println!("ghash: {:x?}", ghash_key);
        }

        let mut mask = Zeroizing::new([0; 16]); // aka endPad
        cipher.write_keystream_block(&mut mask)?;

        #[cfg(test)]
        {
            println!("want: [fc, 7c, ac, 57, 4c, 49, fe, ae, 61, 50, 31, 5b, 96, 85, 42, 4c]");
            println!("mask: {:x?}", mask);
        }

        cipher.apply_keystream(data.reborrow())?;

        let tag = self.compute_tag(&ghash_key, &mask, data.get_out(), additional_data);

        Ok(tag)
    }

    /// Decrypts and authenticates `data`, authenticates
    /// `additional_data`, and writes the result to `data`.
    #[inline]
    pub fn open(
        &self,
        nonce: &Nonce,
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

    macro_rules! hex {
        ($($s:literal)*) => {
            &hex_literal::hex!($($s)*)
        };
    }

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
            &'a Key,   // key
            &'a Nonce, // nonce
            &'a [u8],  // ad
            &'a [u8],  // pt
            &'a [u8],  // ct
            &'a Tag,   // tag
        );
        const TESTS: &[Test<'_>] = &[
            (
                hex!(
                    "00000000000000000000000000000000"
                    "00000000000000000000000000000000"
                ),
                hex!("00000000000000000000000000000000"),
                &[],
                &[],
                &[],
                hex!("029a624cdaa4d46cb9a0ef4046956c9f"),
            ),
            (
                hex!(
                    "505152535455565758595a5b5c5d5e5f"
                    "0a1a2a3a4a5a6a7a8a9aaabacadaeafa"
                ),
                hex!("0123456789abcdeffedcba9876543210"),
                &[],
                &[],
                &[],
                hex!("fc7cac574c49feae6150315b9685424c"),
            ),
            (
                hex!(
                    "00000000000000000000000000000000"
                    "00000000000000000000000000000000"
                ),
                hex!("00000000000000000000000000000000"),
                hex!("30313233343536373839616263646566"),
                &[],
                &[],
                hex!("5a5aa5fbd635ef1ae129614203e10384"),
            ),
            (
                hex!(
                    "505152535455565758595a5b5c5d5e5f"
                    "0a1a2a3a4a5a6a7a8a9aaabacadaeafa"
                ),
                hex!("0123456789abcdeffedcba9876543210"),
                hex!("30313233343536373839616263646566"),
                &[],
                &[],
                hex!("250ec8d77a022c087adf08b65adcbb1a"),
            ),
            (
                hex!(
                    "505152535455565758595a5b5c5d5e5f"
                    "0a1a2a3a4a5a6a7a8a9aaabacadaeafa"
                ),
                hex!("0123456789abcdeffedcba9876543210"),
                &[],
                hex!("30313233343536373839"),
                hex!("dd7e01b2b424a2ef8250"),
                hex!("ddfe4e31e7bfe6902331ec5ce319d90d"),
            ),
            (
                hex!(
                    "505152535455565758595a5b5c5d5e5f"
                    "0a1a2a3a4a5a6a7a8a9aaabacadaeafa"
                ),
                hex!("0123456789abcdeffedcba9876543210"),
                hex!("41414420746573742076616c756521"),
                hex!(
                    "30313233343536373839616263646566"
                    "20536e6f77562d41454144206d6f6465"
                    "21"
                ),
                hex!(
                    "dd7e01b2b424a2ef82502707e87a32c1"
                    "52b0d01818fd7f12243eb5a15659e91b"
                    "4c"
                ),
                hex!("907ea6a5b73a51de747c3e9ad9ee029b"),
            ),
        ];
        for (i, &(key, nonce, ad, pt, ct, tag)) in TESTS.iter().enumerate() {
            let mut data = pt.to_vec();
            println!("data = {:x?}", data);

            let aead = SnowVGcm::new(key);
            let got_tag = aead.seal(nonce, data.as_mut_slice().into(), ad).unwrap();
            println!("ct: {:x?}", data);
            assert_eq!(&got_tag, tag, "#{i}: incorrect tag");
            assert_eq!(data, ct, "#{i}: incorrect ciphertext");
            aead.open(nonce, data.as_mut_slice().into(), tag, ad)
                .unwrap();
            assert_eq!(data, pt, "#{i}: incorrect plaintext");

            #[cfg(feature = "rust-crypto")]
            {
                use aead::{AeadInPlace, KeyInit};

                let aead = <SnowVGcm as KeyInit>::new(key.into());
                let got_tag = aead
                    .encrypt_in_place_detached(nonce.into(), ad, &mut data)
                    .unwrap();
                assert_eq!(got_tag.as_slice(), tag, "#{i}: incorrect tag");
                assert_eq!(data, ct, "#{i}: incorrect ciphertext");
                aead.decrypt_in_place_detached(nonce.into(), ad, data.as_mut_slice(), tag.into())
                    .unwrap();
                assert_eq!(data, pt, "#{i}: incorrect plaintext");
            }
        }
    }
}
