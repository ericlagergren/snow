#![allow(clippy::needless_borrow, reason = "false positive")]

use core::{fmt, mem::ManuallyDrop};

use inout::{InOut, InOutBuf};

mod aarch64;
mod generic;
mod soft;
mod x86;

cfg_if::cfg_if! {
    if #[cfg(feature = "soft")] {
        use soft as imp;
    } else if #[cfg(target_arch = "aarch64")] {
        use aarch64 as imp;
    } else if #[cfg(any(target_arch = "x86", target_arch="x86_64"))] {
        use x86 as imp;
    } else {
        use soft as imp;
    }
}

union Inner {
    asm: ManuallyDrop<imp::State>,
    soft: ManuallyDrop<generic::State>,
}

/// SNOW-V state.
pub(crate) struct State(Inner);

impl State {
    /// Initializes the SNOW-V state.
    #[inline]
    pub fn new(key: &[u8; 32], iv: &[u8; 16], aead: bool) -> Self {
        let inner = if imp::supported() {
            // SAFETY: `supported` is true, so we can call this
            // function.
            #[allow(unused_unsafe)]
            let state = unsafe { imp::State::new(key, iv, aead) };
            Inner {
                asm: ManuallyDrop::new(state),
            }
        } else {
            let state = generic::State::new(key, iv, aead);
            Inner {
                soft: ManuallyDrop::new(state),
            }
        };
        Self(inner)
    }

    /// XORs each byte in `block` with the corresponding byte in
    /// the keystream.
    #[inline]
    pub fn apply_keystream_block(&mut self, block: InOut<'_, '_, [u8; 16]>) {
        if imp::supported() {
            // SAFETY: `supported` is true, so `asm` is
            // initialized.
            unsafe { (&mut self.0.asm).apply_keystream_block(block) }
        } else {
            // SAFETY: `supported` is true, so `soft` is
            // initialized.
            unsafe { (&mut self.0.soft).apply_keystream_block(block) }
        }
    }

    /// XORs each byte in `blocks` with the corresponding byte in
    /// the keystream.
    #[inline]
    pub fn apply_keystream_blocks(&mut self, blocks: InOutBuf<'_, '_, [u8; 16]>) {
        if imp::supported() {
            // SAFETY: `supported` is true, so `asm` is
            // initialized.
            unsafe { (&mut self.0.asm).apply_keystream_blocks(blocks) }
        } else {
            // SAFETY: `supported` is true, so `soft` is
            // initialized.
            unsafe { (&mut self.0.soft).apply_keystream_blocks(blocks) }
        }
    }

    /// Writes the next keystream block to `dst`.
    #[inline]
    pub fn write_keystream_block(&mut self, dst: &mut [u8; 16]) {
        if imp::supported() {
            // SAFETY: `supported` is true, so `asm` is
            // initialized.
            unsafe { (&mut self.0).asm.write_keystream_block(dst) }
        } else {
            // SAFETY: `supported` is true, so `soft` is
            // initialized.
            unsafe { (&mut self.0.soft).write_keystream_block(dst) }
        }
    }
}

impl Clone for State {
    #[inline]
    fn clone(&self) -> Self {
        let inner = if imp::supported() {
            Inner {
                // SAFETY: `supported` is true, so `asm` is
                // initialized.
                asm: unsafe { &self.0.asm }.clone(),
            }
        } else {
            Inner {
                // SAFETY: `supported` is false, so `soft` is
                // initialized.
                soft: unsafe { &self.0.soft }.clone(),
            }
        };
        Self(inner)
    }
}

impl Drop for State {
    #[inline]
    fn drop(&mut self) {
        if imp::supported() {
            // SAFETY: `supported` is true, so `asm` is
            // initialized.
            unsafe { ManuallyDrop::drop(&mut self.0.asm) }
        } else {
            // SAFETY: `supported` is false, so `soft` is
            // initialized.
            unsafe { ManuallyDrop::drop(&mut self.0.soft) }
        }
    }
}

#[cfg(feature = "zeroize")]
impl zeroize::ZeroizeOnDrop for State {}

impl fmt::Debug for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if imp::supported() {
            // SAFETY: `supported` is true, so `asm` is
            // initialized.
            unsafe { fmt::Debug::fmt(&self.0.asm, f) }
        } else {
            // SAFETY: `supported` is false, so `soft` is
            // initialized.
            unsafe { fmt::Debug::fmt(&self.0.soft, f) }
        }
    }
}
