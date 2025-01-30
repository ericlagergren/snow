use core::{fmt, slice};

use crate::backend::State;

/// The size in bytes of a SNOW-V stream cipher key.
pub const KEY_SIZE: usize = 32;

/// The size in bytes of a SNOW-V stream cipher IV.
pub const IV_SIZE: usize = 16;

/// The size in bytes of a SNOW-V block.
pub const BLOCK_SIZE: usize = 16;

/// The maximum number of blocks that can be encrypted.
pub const MAX_BLOCKS: u64 = u64::MAX;

/// The SNOW-V stream cipher.
#[derive(Clone)]
pub struct SnowV(State);

impl SnowV {
    /// TODO
    #[inline]
    pub fn new(key: &[u8; KEY_SIZE], iv: &[u8; IV_SIZE]) -> Self {
        Self(State::new(key, iv, false))
    }

    /// TODO
    #[inline]
    pub fn new_for_aead(key: &[u8; KEY_SIZE], iv: &[u8; IV_SIZE]) -> Self {
        Self(State::new(key, iv, true))
    }

    /// TODO
    #[inline]
    pub fn apply_keystream(&mut self, data: &mut [u8]) {
        let (blocks, tail) = as_blocks_mut(data);
        self.0.apply_keystream_blocks(blocks);
        if !tail.is_empty() {
            let mut tmp = [0; 16];
            self.0.write_keystream_block(&mut tmp);
            for (z, x) in tail.iter_mut().zip(tmp.iter()) {
                *z ^= *x;
            }
        }
    }

    /// TODO
    #[inline]
    pub fn apply_keystream_block(&mut self, block: &mut [u8; BLOCK_SIZE]) {
        self.0.apply_keystream_block(block)
    }

    /// TODO
    #[inline]
    pub fn write_keystream_block(&mut self, block: &mut [u8; BLOCK_SIZE]) {
        self.0.write_keystream_block(block)
    }
}

impl fmt::Debug for SnowV {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SnowV").finish_non_exhaustive()
    }
}

// See https://doc.rust-lang.org/std/primitive.slice.html#method.as_chunks
#[inline(always)]
const fn as_blocks_mut(blocks: &mut [u8]) -> (&mut [[u8; BLOCK_SIZE]], &mut [u8]) {
    #[allow(clippy::arithmetic_side_effects)]
    let len_rounded_down = (blocks.len() / BLOCK_SIZE) * BLOCK_SIZE;
    // SAFETY: The rounded-down value is always the same or
    // smaller than the original length, and thus must be
    // in-bounds of the slice.
    let (head, tail) = unsafe { blocks.split_at_mut_unchecked(len_rounded_down) };
    let new_len = head.len() / BLOCK_SIZE;
    // SAFETY: We cast a slice of `new_len * N` elements into
    // a slice of `new_len` many `N` elements chunks.
    let head = unsafe { slice::from_raw_parts_mut(head.as_mut_ptr().cast(), new_len) };
    (head, tail)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_write_keystream_block() {
        let mut cipher = SnowV::new(&[0; KEY_SIZE], &[0; IV_SIZE]);

        let want: [u128; 8] = [
            0x69ca6daf9ae3b72db134a85a837e419d,
            0xec08aad39d7b0f009b60b28c534300ed,
            0x84abf594fb08a7f1f3a2df18e617683b,
            0x481fa378079dcf04db53b5d629a9eb9d,
            0x031c159dccd0a50c4d5dbf5115d87039,
            0xc0d03ca1370c19400347a0b4d2e9dbe5,
            0xcbca608214a26582cf680916b3451321,
            0x954fdf3084af02f6a8e2481de6bf8279,
        ];
        for (i, want) in want.iter().enumerate() {
            let mut got = [0; BLOCK_SIZE];
            cipher.write_keystream_block(&mut got);
            let want = want.to_le_bytes();
            assert_eq!(got, want, "#{i}");
        }
    }
}
