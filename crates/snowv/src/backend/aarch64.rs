//! AArch64 implementation.

#![cfg(all(
    not(feature = "soft"),
    target_arch = "aarch64",
    target_feature = "neon",
))]
#![allow(clippy::undocumented_unsafe_blocks, reason = "Too many unsafe blocks.")]
#![allow(non_camel_case_types)]

use core::{
    arch::aarch64::{
        uint16x8_t, uint16x8x4_t, uint8x16_t, uint8x16x2_t, vaddq_u32, vaeseq_u8, vaesmcq_u8,
        vandq_u16, vandq_u8, vdupq_n_u8, veorq_u16, veorq_u8, vextq_u8, vld1q_u16_x4, vld1q_u8,
        vld1q_u8_x2, vqtbl1q_s8, vreinterpretq_s16_u16, vreinterpretq_s8_u8, vreinterpretq_u16_s16,
        vreinterpretq_u16_u8, vreinterpretq_u32_u16, vreinterpretq_u32_u8, vreinterpretq_u8_s8,
        vreinterpretq_u8_u16, vreinterpretq_u8_u32, vshlq_n_u16, vshrq_n_s16, vshrq_n_u16,
        vst1q_u8,
    },
    ptr,
};

use inout::{InOut, InOutBuf};

// NB: `aes` implies `neon`.
cpufeatures::new!(have_aes, "aes");

pub fn supported() -> bool {
    have_aes::get()
}

#[derive(Clone, Debug)]
pub(super) struct State {
    lsfr: Lsfr,
    fsm: Fsm,
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
    ///
    /// # Safety
    ///
    /// The NEON and AES architectural features must be enabled.
    #[inline]
    #[target_feature(enable = "neon,aes")]
    pub unsafe fn new(key: &[u8; 32], iv: &[u8; 16], aead: bool) -> Self {
        debug_assert!(supported());

        let uint8x16x2_t(k0, k1) = unsafe { vld1q_u8_x2(key.as_ptr()) };

        let iv0 = if aead {
            const NAMES: &[u8; 16] = b"AlexEkd JingThom";
            unsafe { vld1q_u8(NAMES.as_ptr()) }
        } else {
            unsafe { vdupq_n_u8(0) }
        };
        let iv1 = unsafe { vld1q_u8(iv.as_ptr()) };

        let mut state = State {
            lsfr: unsafe { Lsfr::new(k0, k1, iv0, iv1) },
            fsm: unsafe { Fsm::new() },
        };
        for _ in 0..15 {
            state.lsfr.a_hi = unsafe {
                let z = vreinterpretq_u16_u8(state.keystream());
                veorq_u16(state.lsfr.a_hi, z)
            };
        }
        state.fsm.r1 = unsafe { veorq_u8(state.fsm.r1, k0) };
        state.lsfr.a_hi = unsafe {
            let z = vreinterpretq_u16_u8(state.keystream());
            veorq_u16(state.lsfr.a_hi, z)
        };
        state.fsm.r1 = unsafe { veorq_u8(state.fsm.r1, k1) };

        state
    }

    /// # Safety
    ///
    /// The NEON and AES architectural features must be enabled.
    #[inline]
    #[target_feature(enable = "neon,aes")]
    pub unsafe fn apply_keystream_block(&mut self, mut block: InOut<'_, '_, [u8; 16]>) {
        debug_assert!(supported());

        let data = unsafe { vld1q_u8(ptr::from_ref(block.get_in()).cast()) };
        let z = unsafe { self.keystream() };
        unsafe { vst1q_u8(ptr::from_mut(block.get_out()).cast(), veorq_u8(data, z)) }
    }

    /// # Safety
    ///
    /// The NEON and AES architectural features must be enabled.
    #[inline]
    #[target_feature(enable = "neon,aes")]
    pub unsafe fn apply_keystream_blocks2(&mut self, blocks: &mut [[u8; 16]]) {
        debug_assert!(supported());

        for block in blocks {
            let data = unsafe { vld1q_u8(block.as_ptr()) };
            let z = unsafe { self.keystream() };
            unsafe { vst1q_u8(block.as_mut_ptr(), veorq_u8(data, z)) }
        }
    }

    /// # Safety
    ///
    /// The NEON and AES architectural features must be enabled.
    #[inline]
    #[target_feature(enable = "neon,aes")]
    pub unsafe fn apply_keystream_blocks(&mut self, blocks: InOutBuf<'_, '_, [u8; 16]>) {
        debug_assert!(supported());

        for block in blocks {
            unsafe { self.apply_keystream_block(block) }
        }

        // let mut chunks = blocks.chunks_exact_mut(4);
        // for chunk in chunks.by_ref() {
        //     let (lhs, rhs) = chunk.split_at_mut(chunk.len() / 2);
        //     unsafe {
        //         let uint8x16x4_t(mut b0, mut b1, mut b2, mut b3) =
        //             vld1q_u8_x4(lhs.as_ptr().cast());
        //         let uint8x16x4_t(mut b4, mut b5, mut b6, mut b7) =
        //             vld1q_u8_x4(rhs.as_ptr().cast());

        //         b0 = veorq_u8(b0, self.keystream());
        //         b1 = veorq_u8(b1, self.keystream());
        //         b2 = veorq_u8(b2, self.keystream());
        //         b3 = veorq_u8(b3, self.keystream());
        //         b4 = veorq_u8(b4, self.keystream());
        //         b5 = veorq_u8(b5, self.keystream());
        //         b6 = veorq_u8(b6, self.keystream());
        //         b7 = veorq_u8(b7, self.keystream());

        //         vst1q_u8_x4(lhs.as_mut_ptr().cast(), uint8x16x4_t(b0, b1, b2, b3));
        //         vst1q_u8_x4(rhs.as_mut_ptr().cast(), uint8x16x4_t(b4, b5, b6, b7));
        //     }
        // }
        // for block in chunks.into_remainder() {
        //     unsafe { self.apply_keystream_block(block) }
        // }
    }

    /// # Safety
    ///
    /// The NEON and AES architectural features must be enabled.
    #[inline]
    #[target_feature(enable = "neon,aes")]
    pub unsafe fn write_keystream_block(&mut self, block: &mut [u8; 16]) {
        debug_assert!(supported());

        unsafe { vst1q_u8(block.as_mut_ptr(), self.keystream()) }
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
    ///
    /// # Safety
    ///
    /// The NEON and AES architectural features must be enabled.
    #[inline]
    #[target_feature(enable = "neon,aes")]
    unsafe fn keystream(&mut self) -> uint8x16_t {
        let z = unsafe {
            let sum = vreinterpretq_u8_u32(vaddq_u32(
                vreinterpretq_u32_u8(self.fsm.r1),
                vreinterpretq_u32_u16(self.lsfr.t1()),
            ));
            veorq_u8(sum, self.fsm.r2)
        };
        unsafe {
            self.fsm.update(self.lsfr.t2());
            self.lsfr.update();
        }
        z
    }
}

impl Drop for State {
    #[inline]
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        unsafe {
            zeroize::zeroize_flat_type(self)
        }

        #[cfg(not(feature = "zeroize"))]
        // SAFETY: These require the NEON architectural feature,
        // which we have.
        unsafe {
            self.lsfr.a_lo = veorq_u8(self.lsfr.a_lo, self.lsfr.a_lo);
            self.lsfr.a_hi = veorq_u8(self.lsfr.a_hi, self.lsfr.a_hi);
            self.lsfr.b_lo = veorq_u8(self.lsfr.b_lo, self.lsfr.b_lo);
            self.lsfr.b_hi = veorq_u8(self.lsfr.b_hi, self.lsfr.b_hi);

            self.fsm.r1 = veorq_u8(self.fsm.r1, self.fsm.r1);
            self.fsm.r2 = veorq_u8(self.fsm.r2, self.fsm.r2);
            self.fsm.r3 = veorq_u8(self.fsm.r3, self.fsm.r3);
        }
    }
}

#[cfg(feature = "zeroize")]
impl zeroize::ZeroizeOnDrop for State {}

/// LSFR-A and LSFR-B.
///
/// Both LSFRs are arrays of sixteen 16-bit cells
///
/// ```text
/// LSFR-A = (a₁₅, a₁₄, ..., a₀)
/// LSFR-B = (b₁₅, b₁₄, ..., b₀)
/// ```
///
/// LSFR-A is generated by the polynomial
///
/// ```text
/// gᴬ(x) = x¹⁶ + x¹⁵ + x¹² + x¹¹ + x⁸ + x³ + x² + x + 1 ∈ F₂[x]
/// ```
///
/// LSFR-B is generated by the polynomial
///
/// ```text
/// gᴮ(x) = x¹⁶ + x¹⁵ + x¹⁴ + x¹¹ + x⁸ + x⁶ + x⁵ + x + 1 ∈ F₂[x]
/// ```
#[derive(Clone, Debug)]
struct Lsfr {
    /// The low bits of both A and B.
    ///
    /// lo = [a₇ ... a₀, b₇ ... b₀]
    // lo: u256,
    /// The high bits of both A and B.
    ///
    /// hi = [a₁₅ ... a₈, b₁₅ ... b₈]
    // hi: u256,

    /// (a₇ ... a₀)
    a_lo: uint16x8_t,
    /// (a₁₅ ... a₈)
    a_hi: uint16x8_t,
    /// (b₇ ... b₀)
    b_lo: uint16x8_t,
    /// (b₁₅ ... b₈)
    b_hi: uint16x8_t,
}

impl Lsfr {
    /// Initializes the LSFRs.
    ///
    /// # Safety
    ///
    /// The NEON architectural feature must be enabled.
    #[inline]
    #[target_feature(enable = "neon")]
    unsafe fn new(k0: uint8x16_t, k1: uint8x16_t, iv0: uint8x16_t, iv1: uint8x16_t) -> Self {
        Self {
            a_lo: unsafe { vreinterpretq_u16_u8(k0) },
            a_hi: unsafe { vreinterpretq_u16_u8(k1) },
            b_lo: unsafe { vreinterpretq_u16_u8(iv0) },
            b_hi: unsafe { vreinterpretq_u16_u8(iv1) },
        }
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
    ///
    /// # Safety
    ///
    /// The NEON architectural feature must be enabled.
    #[inline]
    #[target_feature(enable = "neon")]
    unsafe fn update(&mut self) {
        const G: [u16; 32] = [
            // gᴬ(α) = 0x990f, less the term α¹⁶.
            0x990f, 0x990f, 0x990f, 0x990f, 0x990f, 0x990f, 0x990f, 0x990f,
            // gᴮ(β) = 0xc963
            0xc963, 0xc963, 0xc963, 0xc963, 0xc963, 0xc963, 0xc963, 0xc963,
            // gᴬ(α)⁻¹ = 0xcc87
            0xcc87, 0xcc87, 0xcc87, 0xcc87, 0xcc87, 0xcc87, 0xcc87, 0xcc87,
            // gᴮ(β)⁻¹ = 0xe4b1
            0xe4b1, 0xe4b1, 0xe4b1, 0xe4b1, 0xe4b1, 0xe4b1, 0xe4b1, 0xe4b1,
        ];
        let uint16x8x4_t(ga, gb, ga_inv, gb_inv) = unsafe { vld1q_u16_x4(G.as_ptr()) };

        // Multiply x*α and x*β.
        let mulx_a = unsafe { mulx(self.a_lo, ga) };
        let mulx_b = unsafe { mulx(self.b_lo, gb) };

        // Multiply x*α⁻¹ and x*β⁻¹.
        let inv_mulx_a = unsafe { inv_mulx(self.a_hi, ga_inv) };
        let inv_mulx_b = unsafe { inv_mulx(self.b_hi, gb_inv) };

        // NB: We could use `veor3q_u16` here, but we'd need to
        // test for SHA3 support. The compiler usually does it
        // for us anyway.

        let a_hi = unsafe {
            // Tap offset 1 of LSFR-A.
            // a = (a8, a7, a6, ..., a1)
            let tap1 = vreinterpretq_u16_u8(vextq_u8(
                vreinterpretq_u8_u16(self.a_lo),
                vreinterpretq_u8_u16(self.a_hi),
                2,
            ));
            let mut a = veorq_u16(self.b_lo, tap1);
            a = veorq_u16(a, mulx_a);
            veorq_u16(a, inv_mulx_a)
        };

        let b_hi = unsafe {
            // Tap offset 3 of LSFR-B.
            // b = (b10, b9, ..., b3)
            let tap3 = vreinterpretq_u16_u8(vextq_u8(
                vreinterpretq_u8_u16(self.b_lo),
                vreinterpretq_u8_u16(self.b_hi),
                6,
            ));
            let mut b = veorq_u16(self.a_lo, tap3);
            b = veorq_u16(b, mulx_b);
            veorq_u16(b, inv_mulx_b)
        };

        self.a_lo = self.a_hi;
        self.b_lo = self.b_hi;

        self.a_hi = a_hi;
        self.b_hi = b_hi;
    }

    /// Returns the tap `T1 = (b₁₅, b₁₄, ..., b₈)`.
    #[inline(always)]
    fn t1(&self) -> uint16x8_t {
        self.b_hi
    }

    /// Returns the tap `T2 = (a₇, a₆, ..., a₀)`.
    #[inline(always)]
    fn t2(&self) -> uint16x8_t {
        self.a_lo
    }
}

/// The 384-bit FSM.
#[derive(Clone, Debug)]
struct Fsm {
    r1: uint8x16_t,
    r2: uint8x16_t,
    r3: uint8x16_t,
}

impl Fsm {
    /// # Safety
    ///
    /// The NEON architectural feature must be enabled.
    #[inline]
    #[target_feature(enable = "neon")]
    unsafe fn new() -> Self {
        Self {
            r1: unsafe { vdupq_n_u8(0) },
            r2: unsafe { vdupq_n_u8(0) },
            r3: unsafe { vdupq_n_u8(0) },
        }
    }

    /// Updates the FSM.
    ///
    /// ```text
    /// T2 ← (a₇, a₆, ..., a₀)
    /// tmp ← R2 +₃₂ (R3 ⊕ T2)
    /// R3 ←  AESᴿ(R2)
    /// R2 ←  AESᴿ(R1)
    /// R1 ← σ(tmp)
    /// ```
    ///
    /// # Safety
    ///
    /// The NEON and AES architectural features must be enabled.
    #[inline]
    #[target_feature(enable = "neon,aes")]
    unsafe fn update(&mut self, t2: uint16x8_t) {
        let t2 = unsafe { vreinterpretq_u8_u16(t2) };

        let r3 = unsafe { aes(self.r2) };
        let r2 = unsafe { aes(self.r1) };

        self.r1 = unsafe {
            let tmp = vreinterpretq_u8_u32(vaddq_u32(
                vreinterpretq_u32_u8(self.r2),
                vreinterpretq_u32_u8(veorq_u8(self.r3, t2)),
            ));

            let sigma = {
                const SIGMA: [u8; 16] = [
                    0,  // 0 -> 0
                    4,  // 4 -> 1
                    8,  // 8 -> 2
                    12, // 12 -> 3
                    1,  // 1 -> 4
                    5,  // 5 -> 5
                    9,  // 9 -> 6
                    13, // 13 -> 7
                    2,  // 2 -> 8
                    6,  // 6 -> 9
                    10, // 10 -> 10
                    14, // 14 -> 11
                    3,  // 3 -> 12
                    7,  // 7 -> 13
                    11, // 11 -> 14
                    15, // 15 -> 15
                ];
                vld1q_u8(SIGMA.as_ptr())
            };
            shuffle8(tmp, sigma)
        };
        self.r2 = r2;
        self.r3 = r3;
    }
}

/// Performs one AES encrption round with an all-zero round key.
///
/// # Safety
///
/// The NEON and AES architectural features must be enabled.
#[inline]
#[target_feature(enable = "neon,aes")]
unsafe fn aes(v: uint8x16_t) -> uint8x16_t {
    unsafe { vaesmcq_u8(vaeseq_u8(v, vdupq_n_u8(0))) }
}

/// Returns `x*poly`.
///
/// # Safety
///
/// The NEON architectural feature must be enabled.
#[inline]
#[target_feature(enable = "neon")]
unsafe fn mulx(x: uint16x8_t, poly: uint16x8_t) -> uint16x8_t {
    let x̂ = unsafe { vshlq_n_u16(x, 1) };
    // If the high bit of each field element is set, XOR in the
    // polynomial.
    let mask = unsafe { vreinterpretq_u16_s16(vshrq_n_s16(vreinterpretq_s16_u16(x), 15)) };
    unsafe { veorq_u16(x̂, vandq_u16(poly, mask)) }
}

/// Returns `x*poly⁻¹`.
///
/// # Safety
///
/// The NEON architectural feature must be enabled.
#[inline]
#[target_feature(enable = "neon")]
unsafe fn inv_mulx(x: uint16x8_t, poly: uint16x8_t) -> uint16x8_t {
    let x̂ = unsafe { vshrq_n_u16(x, 1) };
    // If the low bit of each field element is set, XOR in the
    // polynomial.
    let mask = unsafe {
        let t = vshlq_n_u16(x, 15);
        vreinterpretq_u16_s16(vshrq_n_s16(vreinterpretq_s16_u16(t), 15))
    };
    unsafe { veorq_u16(x̂, vandq_u16(poly, mask)) }
}

/// Shuffles 8-bit elements in `a` according to the masks in the
/// corresponding 8-bit elements in `b`.
///
/// See [_mm_shuffle_epi8].
///
/// # Safety
///
/// The NEON architectural feature must be enabled.
///
/// [_mm_shuffle_epi8]: https://www.intel.com/content/www/us/en/docs/cpp-compiler/developer-guide-reference/2021-10/shuffle-intrinsics.html
#[inline]
#[target_feature(enable = "neon")]
unsafe fn shuffle8(a: uint8x16_t, b: uint8x16_t) -> uint8x16_t {
    let table = unsafe { vreinterpretq_s8_u8(a) };
    let idx = unsafe { vandq_u8(b, vdupq_n_u8(0x8f)) };
    let res = unsafe { vqtbl1q_s8(table, idx) };
    unsafe { vreinterpretq_u8_s8(res) }
}
