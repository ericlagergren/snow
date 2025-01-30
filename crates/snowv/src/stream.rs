use core::{fmt, slice};

use crate::backend::State;

/// The size in bytes of a SNOW-V stream cipher key.
pub const KEY_SIZE: usize = 32;

/// The size in bytes of a SNOW-V stream cipher IV.
pub const IV_SIZE: usize = 16;

/// The size in bytes of a SNOW-V block.
pub const BLOCK_SIZE: usize = 16;

/// The SNOW-V stream cipher.
#[derive(Clone)]
pub struct SnowV(State);

impl SnowV {
    /// TODO
    #[inline]
    pub fn new(key: &[u8; KEY_SIZE], iv: &[u8; IV_SIZE]) -> Self {
        Self(State::new(key, iv))
    }

    /// TODO
    #[inline]
    pub fn apply_keystream(&mut self, data: &mut [u8]) {
        let (blocks, tail) = as_blocks_mut(data);
        for block in blocks {
            self.0.apply_keystream_block(block);
        }
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
