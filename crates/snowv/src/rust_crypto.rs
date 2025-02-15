//! RustCrypto bindings.
//!
//! [RustCrypto]: https://github.com/rustcrypto

#![cfg(feature = "rust-crypto")]
#![cfg_attr(docsrs, doc(cfg(feature = "rust-crypto")))]

use core::fmt;

use cipher::{
    typenum::{U1, U16, U32},
    AlgorithmName, Block, BlockSizeUser, Iv, IvSizeUser, Key, KeyIvInit, KeySizeUser,
    ParBlocksSizeUser, StreamBackend, StreamCipherCore, StreamCipherError, StreamClosure,
};
use inout::{InOut, InOutBuf};

use crate::SnowV;

impl AlgorithmName for SnowV {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SNOW-V")
    }
}

impl KeySizeUser for SnowV {
    type KeySize = U32;
}

impl IvSizeUser for SnowV {
    type IvSize = U16;
}

impl KeyIvInit for SnowV {
    #[inline]
    fn new(key: &Key<Self>, iv: &Iv<Self>) -> Self {
        Self::new(key.as_ref(), iv.as_ref())
    }
}

impl StreamCipherCore for SnowV {
    #[inline]
    fn remaining_blocks(&self) -> Option<usize> {
        let blocks = usize::try_from(self.remaining_blocks()).unwrap_or(usize::MAX);
        Some(blocks)
    }

    #[inline(always)]
    fn process_with_backend(&mut self, f: impl StreamClosure<BlockSize = Self::BlockSize>) {
        f.call(&mut Backend { state: self });
    }

    #[inline]
    fn apply_keystream_block_inout(&mut self, block: InOut<'_, '_, Block<Self>>) {
        // The default impl essentially just calls
        //     write_keystream_block(tmp);
        //     block.xor_in2out(tmp);
        // which is exactly the same thing as
        // `self.apply_keystream_block`, but with extra steps and
        // possibly worse performance.
        let block = {
            let (in_ptr, out_ptr) = block.into_raw();
            // SAFETY: `cipher::Block<Self>` and `crate::Block`
            // have the same layout in memory.
            unsafe { InOut::from_raw(in_ptr.cast(), out_ptr.cast()) }
        };
        let _ = self.apply_keystream_block(block);
    }

    #[inline]
    fn apply_keystream_blocks(&mut self, blocks: &mut [Block<Self>]) {
        <Self as StreamCipherCore>::apply_keystream_blocks_inout(self, blocks.into());
    }

    #[inline]
    fn apply_keystream_blocks_inout(&mut self, blocks: InOutBuf<'_, '_, Block<Self>>) {
        // The default impl essentially just calls
        //     write_keystream_blocks(tmp);
        //     block.xor_in2out(tmp);
        // which is exactly the same thing as
        // `self.apply_keystream_block`, but with extra steps and
        // possibly worse performance.
        let len = blocks.len();
        let blocks = {
            let (in_ptr, out_ptr) = blocks.into_raw();
            // SAFETY: `cipher::Block<Self>` and `crate::Block`
            // have the same layout in memory.
            unsafe { InOutBuf::from_raw(in_ptr.cast(), out_ptr.cast(), len) }
        };
        let _ = self.apply_keystream_blocks(blocks);
    }

    #[inline]
    fn try_apply_keystream_partial(
        self,
        buf: InOutBuf<'_, '_, u8>,
    ) -> Result<(), StreamCipherError> {
        // This is up to ~2% faster than the default impl.
        self.apply_keystream(buf).map_err(|_| StreamCipherError)
    }
}

impl BlockSizeUser for SnowV {
    type BlockSize = U16;
}

struct Backend<'a> {
    state: &'a mut SnowV,
}

impl BlockSizeUser for Backend<'_> {
    type BlockSize = U16;
}

impl ParBlocksSizeUser for Backend<'_> {
    // None of the backends support more than one block at
    // a time.
    type ParBlocksSize = U1;
}

impl StreamBackend for Backend<'_> {
    #[inline(always)]
    fn gen_ks_block(&mut self, block: &mut Block<Self>) {
        let _ = self.state.write_keystream_block(block.as_mut());
    }

    // We have a stride of 1, so the default impls are fine.
}
