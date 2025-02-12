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
    /// Creates an instance of the SNOW-V stream cipher.
    #[inline]
    pub fn new(key: &[u8; KEY_SIZE], iv: &[u8; IV_SIZE]) -> Self {
        Self {
            state: State::new(key, iv, false),
            blocks: u64::MAX,
        }
    }

    /// Creates an instance of the SNOW-V stream cipher for use
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
    #[inline]
    pub fn apply_keystream(mut self, data: InOutBuf<'_, '_, u8>) -> Result<(), Error> {
        let nblocks = u64::try_from(data.len())
            .map_err(|_| Error)?
            .div_ceil(BLOCK_SIZE as u64);
        self.blocks = self.blocks.checked_sub(nblocks).ok_or(Error)?;

        let (blocks, mut tail) = as_blocks_mut(data);
        self.state.apply_keystream_blocks(blocks);
        if !tail.is_empty() {
            let mut block = [0; BLOCK_SIZE];
            self.state.write_keystream_block(&mut block);
            #[allow(
                clippy::indexing_slicing,
                reason = "The compiler can prove the lengths of `block` and `tail`."
            )]
            tail.xor_in2out(&block[..tail.len()]);
        }
        Ok(())
    }

    /// XORs each byte in `block` with the corresponding byte in
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

    /// XORs each byte in `blocks` with the corresponding byte in
    /// the keystream.
    #[inline]
    pub fn apply_keystream_blocks(
        &mut self,
        blocks: InOutBuf<'_, '_, [u8; BLOCK_SIZE]>,
    ) -> Result<(), Error> {
        let nblocks = u64::try_from(blocks.len()).map_err(|_| Error)?;
        self.blocks = self.blocks.checked_sub(nblocks).ok_or(Error)?;
        self.state.apply_keystream_blocks(blocks);
        Ok(())
    }

    /// Writes the next keystream block to `block`.
    #[inline]
    pub fn write_keystream_block(&mut self, block: &mut [u8; BLOCK_SIZE]) -> Result<(), Error> {
        self.blocks = self.blocks.checked_sub(1).ok_or(Error)?;
        self.state.write_keystream_block(block);
        Ok(())
    }

    /// Writes the next keystream blocks to `blocks`.
    #[inline]
    pub fn write_keystream_blocks(&mut self, blocks: &mut [[u8; BLOCK_SIZE]]) -> Result<(), Error> {
        let nblocks = u64::try_from(blocks.len()).map_err(|_| Error)?;
        self.blocks = self.blocks.checked_sub(nblocks).ok_or(Error)?;
        self.state.write_keystream_blocks(blocks);
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
    // The size in bytes of `head`.
    //
    // Cannot overflow, but avoids a lint.
    let head_len = chunks.wrapping_mul(BLOCK_SIZE);
    // The size in bytes of `tail`.
    //
    // Cannot overflow, but avoids a lint.
    let tail_len = data.len().wrapping_sub(head_len);

    let (src, dst) = data.into_raw();

    // SAFETY:
    // - `in_ptr` is initialized and valid to read up to `chunks`
    //    blocks since `chunks` is the length of `data` divided
    //    by the size of a block.
    // - Ditto for writes to `out_ptr`.
    // - All the other safety conditions hold because both
    //   pointers come from the same `InOutBuf`.
    let head = unsafe { InOutBuf::from_raw(src.cast(), dst.cast(), chunks) };

    // SAFETY:
    // - `in_ptr` is initialized and valid to read up to
    //    `tail_len` bytes because `tail_len` is the remainder of
    //    length of `data` divided by the size of a block.
    // - Ditto for writes to `out_ptr`.
    // - All the other safety conditions hold because both
    //   pointers come from the same `InOutBuf`.
    // - The call to `add` is safe because of the aforementioned
    //   safety conditions.
    let tail = unsafe { InOutBuf::from_raw(src.add(head_len), dst.add(head_len), tail_len) };
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
