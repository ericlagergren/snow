//! Software implementation.

#![deny(unsafe_code)]

mod aes32;
mod aes64;

use core::ptr;

use inout::{InOut, InOutBuf};

#[derive(Clone, Debug)]
pub(super) struct State {
    a_lo: [u16; 8],
    a_hi: [u16; 8],
    b_lo: [u16; 8],
    b_hi: [u16; 8],

    r1: [u32; 4],
    r2: [u32; 4],
    r3: [u32; 4],
}

impl State {
    /// Initializes the SNOW-V state.
    ///
    /// ```text
    /// (a15, a14, ..., a8) ← (k7, k6, ..., k0)
    /// (a7, a6, ..., a0) ← (iv7, iv6, ..., iv0)
    /// (b15, b14, ..., b8) ← (k15, k14, ..., k8)
    /// (b7, b6, ..., b0) ← (0, 0, ..., 0)
    /// R1, R2, R3 ← 0, 0, 0
    /// for t = 1...16 do
    ///     T1 ← (b₁₅, b₁₄, ..., b₈)
    ///     z ← (R1 +₃₂ T1) ⊕ R2
    ///     FSMUpdate()
    ///     LSFRUpdate()
    ///     (a15, a14, ..., a8) ← (a15, a14, ..., a8) ⊕ z
    ///     if t == 15 then
    ///         R1 ← R1 ⊕ (k7, k6, ... k0)
    ///     if t == 16 then
    ///         R1 ← R1 ⊕ (k15, k14, ..., k8)
    /// ```
    #[allow(
        clippy::unwrap_used,
        reason = "The compiler can prove lengths of slices."
    )]
    #[inline]
    pub fn new(key: &[u8; 32], iv: &[u8; 16], aead: bool) -> Self {
        let (k0, k1) = key.split_at(key.len() / 2);

        let a_lo = {
            let mut tmp = [0u16; 8];
            for (v, iv) in tmp.iter_mut().zip(iv.chunks_exact(2)) {
                *v = u16::from_le_bytes(iv.try_into().unwrap());
            }
            tmp
        };

        let a_hi = {
            let mut tmp = [0u16; 8];
            for (v, k) in tmp.iter_mut().zip(k0.chunks_exact(2)) {
                *v = u16::from_le_bytes(k.try_into().unwrap());
            }
            tmp
        };

        let b_lo = if aead {
            [
                0x6C41, 0x7865, 0x6B45, 0x2064, 0x694A, 0x676E, 0x6854, 0x6D6F,
            ]
        } else {
            [0; 8]
        };

        let b_hi = {
            let mut tmp = [0u16; 8];
            for (v, k) in tmp.iter_mut().zip(k1.chunks_exact(2)) {
                *v = u16::from_le_bytes(k.try_into().unwrap());
            }
            tmp
        };

        let mut z = [0; 16];

        let mut state = State {
            a_lo,
            a_hi,
            b_lo,
            b_hi,
            r1: [0; 4],
            r2: [0; 4],
            r3: [0; 4],
        };
        for _ in 0..15 {
            state.keystream(&mut z);
            for (a, z) in state.a_hi.iter_mut().zip(z.chunks_exact(2)) {
                *a ^= u16::from_le_bytes(z.try_into().unwrap());
            }
        }

        // R1 ← R1 ⊕ (k7, k6, ... k0)
        for (r, k) in state.r1.iter_mut().zip(k0.chunks_exact(4)) {
            *r ^= u32::from_le_bytes(k.try_into().unwrap());
        }

        state.keystream(&mut z);
        for (a, z) in state.a_hi.iter_mut().zip(z.chunks_exact(2)) {
            *a ^= u16::from_le_bytes(z.try_into().unwrap());
        }

        // R1 ← R1 ⊕ (k15, k14, ..., k8)
        for (r, k) in state.r1.iter_mut().zip(k1.chunks_exact(4)) {
            *r ^= u32::from_le_bytes(k.try_into().unwrap());
        }

        state
    }

    #[inline]
    pub fn apply_keystream_block(&mut self, block: InOut<'_, '_, [u8; 16]>) {
        let mut z = [0u8; 16];
        self.keystream(&mut z);
        xor_in2out(block, &z);
    }

    #[inline]
    pub fn apply_keystream_blocks(&mut self, blocks: InOutBuf<'_, '_, [u8; 16]>) {
        for block in blocks {
            self.apply_keystream_block(block);
        }
    }

    #[inline]
    pub fn write_keystream_block(&mut self, z: &mut [u8; 16]) {
        self.keystream(z);
    }

    #[inline]
    pub fn write_keystream_blocks(&mut self, block: &mut [[u8; 16]]) {
        for block in block {
            self.write_keystream_block(block)
        }
    }

    /// Returns the next keystream block.
    ///
    /// ```text
    /// T1 ← (b₁₅, b₁₄, ..., b₈)
    /// z ← (R1 +₃₂ T1) ⊕ R2
    /// FSMUpdate()
    /// LSFRUpdate()
    /// Output keystream symbol z
    /// ```
    #[inline]
    fn keystream(&mut self, z: &mut [u8; 16]) {
        let t1 = self.t1();
        for (((z, &t1), &r1), &r2) in z.chunks_exact_mut(4).zip(&t1).zip(&self.r1).zip(&self.r2) {
            let v = r1.wrapping_add(t1) ^ r2;
            z.copy_from_slice(&v.to_le_bytes());
        }

        self.update_fsm();
        self.update_lsfr();
    }

    /// Updates the FSM.
    ///
    /// ```text
    /// T2 ← (a₇, a₆, ..., a₀)
    /// tmp ← R2 +₃₂ (R3 ⊕ T2)
    /// R3 ← AESᴿ(R2)
    /// R2 ← AESᴿ(R1)
    /// R1 ← σ(tmp)
    /// ```
    #[inline(always)]
    fn update_fsm(&mut self) {
        let (r2, r3) = aes_ct_enc_round(&self.r1, &self.r2);

        let t2 = self.t2();
        for (((r1, &r2), &r3), &t2) in self.r1.iter_mut().zip(&self.r2).zip(&self.r3).zip(&t2) {
            *r1 = r2.wrapping_add(r3 ^ t2);
        }

        permute_sigma(&mut self.r1);
        self.r2 = r2;
        self.r3 = r3;
    }

    /// Updates the LSFR.
    ///
    /// ```text
    /// for i = 0..7 do
    ///     tmpₐ ← b₀ + (α * a₀) + a₁ + (α⁻¹ * a₈) mod gᴬ(α)
    ///     tmp₆ ← a₀ + (β * b₀) + b₃ + (β⁻¹ * b₈) mod gᴮ(β)
    ///     (a₁₅, a₁₄, ..., a₀) ← (tmpₐ, a₁₅, ..., a₁)
    ///     (b₁₅, b₁₄, ..., b₀) ← (tmp₆, b₁₅, ..., b₁)
    /// ```
    #[inline(always)]
    fn update_lsfr(&mut self) {
        // Tap offset 1 (a₈, a₇, ..., a₁).
        let mut tap1 = [0; 8];
        tap1[0..7].copy_from_slice(&self.a_lo[1..]);
        tap1[7] = self.a_hi[0];

        // a_hi' = b_lo ^ tap1 ^ mulx_a ^ inv_mulx_a
        let mut a_hi = [0u16; 8];
        for ((((dst, &b_lo), tap), &a_lo), &a_hi) in a_hi
            .iter_mut()
            .zip(&self.b_lo)
            .zip(&tap1)
            .zip(&self.a_lo)
            .zip(&self.a_hi)
        {
            *dst = b_lo ^ tap ^ mulx(a_lo, 0x990f) ^ inv_mulx(a_hi, 0xcc87);
        }

        // Tap offset 3 (b₁₀, b₉, ..., b₃).
        let mut tap3 = [0; 8];
        tap3[0..5].copy_from_slice(&self.b_lo[3..8]);
        tap3[5..8].copy_from_slice(&self.b_hi[0..3]);

        // b_hi' = a_lo ^ tap3 ^ mulx_b ^ inv_mulx_b
        let mut b_hi = [0u16; 8];
        for ((((dst, &a_lo), tap), &b_lo), &b_hi) in b_hi
            .iter_mut()
            .zip(&self.a_lo)
            .zip(&tap3)
            .zip(&self.b_lo)
            .zip(&self.b_hi)
        {
            *dst = a_lo ^ tap ^ mulx(b_lo, 0xc963) ^ inv_mulx(b_hi, 0xe4b1);
        }

        self.a_lo = self.a_hi;
        self.b_lo = self.b_hi;

        self.a_hi = a_hi;
        self.b_hi = b_hi;
    }

    #[inline(always)]
    #[allow(unsafe_code, reason = "Much better performance")]
    fn t1(&self) -> [u32; 4] {
        // SAFETY: `[u16; 8]` has the same size in memory as
        // `[u8; 16]`. Refs to those types have different
        // alignments, but `u8` has less strict alignment than
        // `u16`.
        let b_hi = unsafe { &*(&self.b_hi as *const [u16; 8]).cast::<[u8; 16]>() };

        let mut t = [0u32; 4];
        for (v, b) in t.iter_mut().zip(b_hi.chunks_exact(4)) {
            *v = u32::from_le_bytes(
                #[allow(clippy::unwrap_used, reason = "The compiler can prove length of `b`")]
                b.try_into().unwrap(),
            );
        }
        t
    }

    #[inline(always)]
    #[allow(unsafe_code, reason = "Much better performance")]
    fn t2(&self) -> [u32; 4] {
        // SAFETY: `[u16; 8]` has the same size in memory as
        // `[u8; 16]`. Refs to those types have different
        // alignments, but `u8` has less strict alignment than
        // `u16`.
        let a_lo = unsafe { &*(&self.a_lo as *const [u16; 8]).cast::<[u8; 16]>() };

        let mut t = [0u32; 4];
        for (v, a) in t.iter_mut().zip(a_lo.chunks_exact(4)) {
            *v = u32::from_le_bytes(
                #[allow(clippy::unwrap_used, reason = "The compiler can prove length of `a`")]
                a.try_into().unwrap(),
            );
        }
        t
    }
}

#[inline(always)]
const fn mulx(x: u16, c: u16) -> u16 {
    if x & 0x8000 != 0 {
        (x << 1) ^ c
    } else {
        x << 1
    }
}

#[inline(always)]
const fn inv_mulx(x: u16, d: u16) -> u16 {
    if x & 0x0001 != 0 {
        (x >> 1) ^ d
    } else {
        x >> 1
    }
}

#[inline(always)]
#[allow(
    clippy::indexing_slicing,
    reason = "The compiler can prove `state[sigma >> 2]` is in bounds."
)]
fn permute_sigma(state: &mut [u32; 4]) {
    const SIGMA: [u8; 16] = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15];

    let mut tmp = [0; 16];
    for (t, &sigma) in tmp.iter_mut().zip(&SIGMA) {
        // The max value in `sigma` is 15, and `15>>2 = 3`, so
        // indexing `state` cannot panic.
        let s = state[(sigma >> 2) as usize];
        *t = (s >> ((sigma & 3) << 3)) as u8;
    }
    for (dst, src) in state.iter_mut().zip(tmp.chunks_exact_mut(4)) {
        *dst = u32::from_le_bytes(
            #[allow(clippy::unwrap_used, reason = "The compiler can prove length of `src`")]
            src.try_into().unwrap(),
        );
    }
}

#[inline(always)]
fn aes_ct_enc_round(block1: &[u32; 4], block2: &[u32; 4]) -> ([u32; 4], [u32; 4]) {
    if cfg!(any(
        target_pointer_width = "16",
        target_pointer_width = "32"
    )) {
        aes32::aes_ct_enc_round(block1, block2)
    } else {
        aes64::aes_ct_enc_round(block1, block2)
    }
}

#[inline(always)]
#[allow(unsafe_code, reason = "Much better performance")]
fn xor_in2out(block: InOut<'_, '_, [u8; 16]>, z: &[u8; 16]) {
    let (in_ptr, out_ptr) = block.into_raw();

    // SAFETY:
    // - `in_ptr` is valid for reads.
    // - `in_ptr` is properly aligned.
    // - `in_ptr` points to an initialized `[u8; 16]`
    let block = unsafe { ptr::read(in_ptr) };

    let mut tmp = [0u8; 16];
    for ((dst, block), &z) in tmp.iter_mut().zip(block).zip(z) {
        *dst = block ^ z;
    }

    // SAFETY:
    // - `out_ptr` is valid for writes.
    // - `out_ptr` is properly aligned.
    unsafe { ptr::write(out_ptr, tmp) }
}
