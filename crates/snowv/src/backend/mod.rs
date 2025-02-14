#![allow(clippy::needless_borrow, reason = "false positive")]

use core::{fmt, mem::ManuallyDrop};

use inout::{InOut, InOutBuf};

use crate::Block;

mod aarch64;
mod soft;
mod x86;

cfg_if::cfg_if! {
    if #[cfg(feature = "soft")] {
        use soft as imp;
    } else if #[cfg(all(target_arch = "aarch64", target_feature = "neon"))] {
        use aarch64 as imp;
    } else if #[cfg(all(
        any(target_arch = "x86", target_arch="x86_64"),
        target_feature = "avx2",
    ))] {
        use x86 as imp;
    } else {
        use soft as imp;
    }
}

union Inner {
    asm: ManuallyDrop<imp::State>,
    soft: ManuallyDrop<soft::State>,
}

/// SNOW-V state.
pub(crate) struct State {
    inner: Inner,
    token: imp::Token,
}

impl State {
    #[inline]
    fn have_asm(&self) -> bool {
        self.token.supported()
    }

    /// Initializes the SNOW-V state.
    #[inline]
    pub fn new(key: &[u8; 32], iv: &[u8; 16], aead: bool) -> Self {
        let (token, supported) = imp::Token::new();
        let inner = if supported {
            // SAFETY: `have_asm` is true, so we can call this
            // function.
            #[allow(unused_unsafe)]
            let state = unsafe { imp::State::new(key, iv, aead) };
            Inner {
                asm: ManuallyDrop::new(state),
            }
        } else {
            let state = soft::State::new(key, iv, aead);
            Inner {
                soft: ManuallyDrop::new(state),
            }
        };
        Self { inner, token }
    }

    /// XORs each byte in `block` with the corresponding byte in
    /// the keystream.
    #[inline]
    pub fn apply_keystream_block(&mut self, block: InOut<'_, '_, Block>) {
        if self.have_asm() {
            // SAFETY: `have_asm` is true, so `asm` is
            // initialized.
            unsafe { (&mut self.inner.asm).apply_keystream_block(block) }
        } else {
            // SAFETY: `have_asm` is true, so `soft` is
            // initialized.
            unsafe { (&mut self.inner.soft).apply_keystream_block(block) }
        }
    }

    /// XORs each byte in `blocks` with the corresponding byte in
    /// the keystream.
    #[inline]
    pub fn apply_keystream_blocks(&mut self, blocks: InOutBuf<'_, '_, Block>) {
        if self.have_asm() {
            // SAFETY: `have_asm` is true, so `asm` is
            // initialized.
            unsafe { (&mut self.inner.asm).apply_keystream_blocks(blocks) }
        } else {
            // SAFETY: `have_asm` is true, so `soft` is
            // initialized.
            unsafe { (&mut self.inner.soft).apply_keystream_blocks(blocks) }
        }
    }

    /// Writes the next keystream block to `dst`.
    #[inline]
    pub fn write_keystream_block(&mut self, dst: &mut Block) {
        if self.have_asm() {
            // SAFETY: `have_asm` is true, so `asm` is
            // initialized.
            unsafe { (&mut self.inner).asm.write_keystream_block(dst) }
        } else {
            // SAFETY: `have_asm` is true, so `soft` is
            // initialized.
            unsafe { (&mut self.inner.soft).write_keystream_block(dst) }
        }
    }

    /// Writes the next keystream blocks to `dst`.
    #[inline]
    pub fn write_keystream_blocks(&mut self, dst: &mut [Block]) {
        if self.have_asm() {
            // SAFETY: `have_asm` is true, so `asm` is
            // initialized.
            unsafe { (&mut self.inner).asm.write_keystream_blocks(dst) }
        } else {
            // SAFETY: `have_asm` is true, so `soft` is
            // initialized.
            unsafe { (&mut self.inner.soft).write_keystream_blocks(dst) }
        }
    }
}

impl Clone for State {
    #[inline]
    fn clone(&self) -> Self {
        let inner = if self.have_asm() {
            Inner {
                // SAFETY: `have_asm` is true, so `asm` is
                // initialized.
                asm: unsafe { &self.inner.asm }.clone(),
            }
        } else {
            Inner {
                // SAFETY: `have_asm` is false, so `soft` is
                // initialized.
                soft: unsafe { &self.inner.soft }.clone(),
            }
        };
        Self {
            inner,
            token: self.token,
        }
    }

    #[inline]
    fn clone_from(&mut self, other: &Self) {
        if self.have_asm() {
            // SAFETY: `have_asm` is true, so `asm` is
            // initialized.
            unsafe { (&mut self.inner.asm).clone_from(&other.inner.asm) }
        } else {
            // SAFETY: `have_asm` is false, so `soft` is
            // initialized.
            unsafe { (&mut self.inner.soft).clone_from(&other.inner.soft) }
        }
        self.token = other.token;
    }
}

impl Drop for State {
    #[inline]
    fn drop(&mut self) {
        if self.have_asm() {
            // SAFETY: `have_asm` is true, so `asm` is
            // initialized.
            unsafe { ManuallyDrop::drop(&mut self.inner.asm) }
        } else {
            // SAFETY: `have_asm` is false, so `soft` is
            // initialized.
            unsafe { ManuallyDrop::drop(&mut self.inner.soft) }
        }
    }
}

#[cfg(feature = "zeroize")]
impl zeroize::ZeroizeOnDrop for State {}

impl fmt::Debug for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.have_asm() {
            // SAFETY: `have_asm` is true, so `asm` is
            // initialized.
            unsafe { fmt::Debug::fmt(&self.inner.asm, f) }
        } else {
            // SAFETY: `have_asm` is false, so `soft` is
            // initialized.
            unsafe { fmt::Debug::fmt(&self.inner.soft, f) }
        }
    }
}
