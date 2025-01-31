use core::{error, fmt};

use inout::{InOut, InOutBuf};

use crate::backend::State;

/// The size in bytes of a SNOW-V stream cipher key.
pub const KEY_SIZE: usize = 32;

/// The size in bytes of a SNOW-V stream cipher IV.
pub const IV_SIZE: usize = 16;

/// The size in bytes of a SNOW-V block.
pub const BLOCK_SIZE: usize = 16;

/// The maximum number of blocks that can be encrypted.
pub const MAX_BLOCKS: u64 = 1 << 60;

/// An eror returned by [`SnowV`] when it's reached the end of
/// its keystream.
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct Error;

impl error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "end of SNOW-V keystream")
    }
}

/// The SNOW-V stream cipher.
#[derive(Clone)]
pub struct SnowV {
    state: State,
    /// Number of remaining blocks.
    blocks: u64,
}

impl SnowV {
    /// Crates an instance of the SNOW-V stream cipher.
    #[inline]
    pub fn new(key: &[u8; KEY_SIZE], iv: &[u8; IV_SIZE]) -> Self {
        Self {
            state: State::new(key, iv, false),
            blocks: u64::MAX,
        }
    }

    /// Crates an instance of the SNOW-V stream cipher for use
    /// with SNOW-V-GCM.
    #[inline]
    pub fn new_for_aead(key: &[u8; KEY_SIZE], iv: &[u8; IV_SIZE]) -> Self {
        Self {
            state: State::new(key, iv, true),
            blocks: u64::MAX,
        }
    }

    /// XORs each byte in the remainder of the keystream with the
    /// corresponding byte in `data`.
    //#[inline]
    pub fn try_apply_keystream(mut self, data: InOutBuf<'_, '_, u8>) -> Result<(), Error> {
        let nblocks = u64::try_from(data.len())
            .map_err(|_| Error)?
            .div_ceil(BLOCK_SIZE as u64);
        self.blocks = self.blocks.checked_sub(nblocks).ok_or(Error)?;

        let (blocks, mut tail) = as_blocks_mut(data);
        self.state.apply_keystream_blocks(blocks);
        if !tail.is_empty() {
            let mut block = [0; BLOCK_SIZE];
            self.state.write_keystream_block(&mut block);
            tail.xor_in2out(&block[..tail.len()]);
        }
        Ok(())
    }

    /// XORs each byte in the remainder of the keystream with the
    /// corresponding byte in `data`.
    //#[inline]
    pub fn try_apply_keystream2(mut self, data: &mut [u8]) -> Result<(), Error> {
        let nblocks = u64::try_from(data.len())
            .map_err(|_| Error)?
            .div_ceil(BLOCK_SIZE as u64);
        self.blocks = self.blocks.checked_sub(nblocks).ok_or(Error)?;

        let (blocks, tail) = as_blocks_mut2(data);
        self.state.apply_keystream_blocks2(blocks);
        if !tail.is_empty() {
            let mut block = [0; BLOCK_SIZE];
            self.state.write_keystream_block(&mut block);
            for (z, b) in tail.iter_mut().zip(&block) {
                *z ^= *b;
            }
        }
        Ok(())
    }

    /// XORs each byte in `data` with the corresponding byte in
    /// the keystream.
    #[inline]
    pub fn apply_keystream_block(
        &mut self,
        block: InOut<'_, '_, [u8; BLOCK_SIZE]>,
    ) -> Result<(), Error> {
        self.blocks = self.blocks.checked_sub(1).ok_or(Error)?;
        self.state.apply_keystream_block(block);
        Ok(())
    }

    /// Writes the next keystream block to `block`.
    #[inline]
    pub fn write_keystream_block(&mut self, block: &mut [u8; BLOCK_SIZE]) -> Result<(), Error> {
        self.blocks = self.blocks.checked_sub(1).ok_or(Error)?;
        self.state.write_keystream_block(block);
        Ok(())
    }
}

impl fmt::Debug for SnowV {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SnowV").finish_non_exhaustive()
    }
}

#[cfg(feature = "zeroize")]
impl zeroize::ZeroizeOnDrop for SnowV {}

#[inline(always)]
fn as_blocks_mut<'inp, 'out>(
    data: InOutBuf<'inp, 'out, u8>,
) -> (
    InOutBuf<'inp, 'out, [u8; BLOCK_SIZE]>,
    InOutBuf<'inp, 'out, u8>,
) {
    let chunks = data.len() / BLOCK_SIZE;
    let tail_len = data.len() - (chunks * BLOCK_SIZE);

    let (src, dst) = data.into_raw();

    let head = unsafe { InOutBuf::from_raw(src.cast(), dst.cast(), chunks) };
    let tail = unsafe {
        InOutBuf::from_raw(
            src.add(chunks * BLOCK_SIZE),
            dst.add(chunks * BLOCK_SIZE),
            tail_len,
        )
    };
    (head, tail)
}

// See https://doc.rust-lang.org/std/primitive.slice.html#method.as_chunks
#[inline(always)]
const fn as_blocks_mut2(blocks: &mut [u8]) -> (&mut [[u8; BLOCK_SIZE]], &mut [u8]) {
    #[allow(clippy::arithmetic_side_effects)]
    let len_rounded_down = (blocks.len() / BLOCK_SIZE) * BLOCK_SIZE;
    // SAFETY: The rounded-down value is always the same or
    // smaller than the original length, and thus must be
    // in-bounds of the slice.
    let (head, tail) = unsafe { blocks.split_at_mut_unchecked(len_rounded_down) };
    let new_len = head.len() / BLOCK_SIZE;
    // SAFETY: We cast a slice of `new_len * N` elements into
    // a slice of `new_len` many `N` elements chunks.
    let head = unsafe { core::slice::from_raw_parts_mut(head.as_mut_ptr().cast(), new_len) };
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
            cipher.write_keystream_block(&mut got).unwrap();
            let want = want.to_be_bytes();
            assert_eq!(got, want, "#{i}");
        }
    }
}
