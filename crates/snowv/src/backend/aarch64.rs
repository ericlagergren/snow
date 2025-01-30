//! AArch64 implementation.

#![cfg(all(
    not(feature = "soft"),
    target_arch = "aarch64",
    target_feature = "neon",
))]
#![allow(clippy::undocumented_unsafe_blocks, reason = "Too many unsafe blocks.")]
#![allow(non_camel_case_types)]

use core::arch::aarch64::{
    int16x8_t, uint32x4_t, uint8x16_t, uint8x16x2_t, uint8x16x4_t, vaddq_u32, vaeseq_u8,
    vaesmcq_u8, vandq_u8, vbicq_s16, vbslq_s16, vbslq_u32, vceqzq_s16, vdupq_n_s16, vdupq_n_u8,
    veorq_u8, vextq_u8, vld1q_u32, vld1q_u8, vld1q_u8_x2, vld1q_u8_x4, vnegq_s16, vqtbl1q_s8,
    vqtbl2q_u8, vreinterpretq_s16_u16, vreinterpretq_s16_u8, vreinterpretq_s8_u8,
    vreinterpretq_u16_s16, vreinterpretq_u16_u8, vreinterpretq_u32_u8, vreinterpretq_u64_u8,
    vreinterpretq_u8_s16, vreinterpretq_u8_s8, vreinterpretq_u8_u16, vreinterpretq_u8_u32,
    vreinterpretq_u8_u64, vshlq_n_u16, vshlq_s16, vshrq_n_s16, vshrq_n_u16, vst1q_u8, vst1q_u8_x4,
};

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
        for t in 0..15 {
            state.lsfr.hi.a = unsafe {
                let z = state.keystream();
                {
                    let mut got = [0; 16];
                    vst1q_u8(got.as_mut_ptr(), z);
                    println!("g = {got:x?}");
                    println!("w = {:x?}", INIT[t].to_le_bytes());
                    println!();
                }
                veorq_u8(state.lsfr.hi.a, z)
            };
        }
        state.fsm.r1 = unsafe { veorq_u8(state.fsm.r1, k0) };
        state.lsfr.hi.a = unsafe {
            let z = state.keystream();
            let mut got = [0; 16];
            vst1q_u8(got.as_mut_ptr(), z);
            println!("g = {got:x?}");
            println!("w = {:x?}", INIT[15].to_le_bytes());
            println!();
            veorq_u8(state.lsfr.hi.a, z)
        };
        state.fsm.r1 = unsafe { veorq_u8(state.fsm.r1, k1) };

        state
    }

    /// # Safety
    ///
    /// The NEON and AES architectural features must be enabled.
    #[inline]
    #[target_feature(enable = "neon,aes")]
    pub unsafe fn apply_keystream_block(&mut self, block: &mut [u8; 16]) {
        debug_assert!(supported());

        let data = unsafe { vld1q_u8(block.as_mut_ptr()) };
        let z = unsafe { self.keystream() };
        unsafe { vst1q_u8(block.as_mut_ptr(), veorq_u8(data, z)) }
    }

    /// # Safety
    ///
    /// The NEON and AES architectural features must be enabled.
    #[inline]
    #[target_feature(enable = "neon,aes")]
    pub unsafe fn apply_keystream_blocks(&mut self, blocks: &mut [[u8; 16]]) {
        debug_assert!(supported());

        if true {
            for block in blocks {
                unsafe { self.apply_keystream_block(block) }
            }
        } else {
            let mut chunks = blocks.chunks_exact_mut(4);
            for chunk in chunks.by_ref() {
                let (lhs, rhs) = chunk.split_at_mut(chunk.len() / 2);
                unsafe {
                    let uint8x16x4_t(mut b0, mut b1, mut b2, mut b3) =
                        vld1q_u8_x4(lhs.as_ptr().cast());
                    let uint8x16x4_t(mut b4, mut b5, mut b6, mut b7) =
                        vld1q_u8_x4(rhs.as_ptr().cast());

                    b0 = veorq_u8(b0, self.keystream());
                    b1 = veorq_u8(b1, self.keystream());
                    b2 = veorq_u8(b2, self.keystream());
                    b3 = veorq_u8(b3, self.keystream());
                    b4 = veorq_u8(b4, self.keystream());
                    b5 = veorq_u8(b5, self.keystream());
                    b6 = veorq_u8(b6, self.keystream());
                    b7 = veorq_u8(b7, self.keystream());

                    vst1q_u8_x4(lhs.as_mut_ptr().cast(), uint8x16x4_t(b0, b1, b2, b3));
                    vst1q_u8_x4(rhs.as_mut_ptr().cast(), uint8x16x4_t(b4, b5, b6, b7));
                }
            }
            for block in chunks.into_remainder() {
                unsafe { self.apply_keystream_block(block) }
            }
        }
    }

    /// # Safety
    ///
    /// The NEON and AES architectural features must be enabled.
    //#[inline]
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
                vreinterpretq_u32_u8(self.lsfr.t1()),
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

const INIT: [u128; 16] = [
    0x00000000000000000000000000000000,
    0x63636363636363636363636363636363,
    0xa5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5,
    0xeaeaeaeaebebebebebebebebebebebeb,
    0x55f7f7c2e8e8dd4ae8dd4ae8dd4ae8e8,
    0xc72a23bfe893733023bc66ec94d2ebb2,
    0xa7ddcaf3138761026eadf42b54e3efcf,
    0x6a67623e6f8af9791ecd8183c5868e3a,
    0x45101e83a2c6ddeb4086382dacfb3b65,
    0x3cc4df56ecbfc1066dac02c50a683cfe,
    0x0ccbe1de2e41afda7098d56019200698,
    0x53cd9869c778caded7db459b6f458b10,
    0x8d940be59fbdb161c121fc297a3d0a15,
    0x26132c149eaf12ccd32f3576f6436894,
    0x0e75be0954181ef58a60a9a9543a05ff,
    0xdc77a49723eb656ae18f282cf1de1d00,
];

/// LSFR-A and LSFR-B.
///
/// Both LSFRs are arrays of sixteen 16-bit cells
///
/// ```text
/// LSFR-A = {a₀, a₁, ..., a₁₅}
/// LSFR-B = {b₀, b₁, ..., b₁₅}
/// ```
///
/// LSFR-A is generated by the polynomial
///
/// ```text
/// gᴬ(x) = x¹⁶ + x¹⁵ + x¹² + x¹¹ + x⁸ + x³ + x² + x + 1 ∈ F₂ [x]
/// ```
///
/// LSFR-B is generated by the polynomial
///
/// ```text
/// gᴮ(x) = x¹⁶ + x¹⁵ + x¹⁴ + x¹¹ + x⁸ + x⁶ + x⁵ + x + 1 ∈ F₂ [x]
/// ```
#[derive(Clone, Debug)]
struct Lsfr {
    /// The low bits of both A and B.
    ///
    /// lo = [a₇ ... a₀, b₇ ... b₀]
    lo: u256,
    /// The high bits of both A and B.
    ///
    /// hi = [a₁₅ ... a₈, b₁₅ ... b₈]
    hi: u256,
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
            lo: u256 { a: k0, b: iv0 },
            hi: u256 { a: k1, b: iv1 },
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
    /// The NEON and AES architectural features must be enabled.
    #[inline]
    #[target_feature(enable = "neon")]
    unsafe fn update(&mut self) {
        // Multiply x*α.
        let mulx = unsafe {
            let poly = {
                const G: [u16; 16] = [
                    // gᴬ(α) = 0x990f, less the term α¹⁶.
                    0x990f, 0x990f, 0x990f, 0x990f, 0x990f, 0x990f, 0x990f, 0x990f,
                    // gᴮ(β) = 0xc963
                    0xc963, 0xc963, 0xc963, 0xc963, 0xc963, 0xc963, 0xc963, 0xc963,
                ];
                let uint8x16x2_t(a, b) = vld1q_u8_x2(G.as_ptr().cast());
                u256::new(a, b)
            };
            let x̂ = shl16::<1>(self.lo);
            // If the 15th bit of `x` is set, XOR in the
            // polynomial.
            let mask = ashr16::<15>(self.lo);
            bitxor(x̂, bitand(poly, mask))
        };

        // Multiply x*α⁻¹.
        let invx = unsafe {
            let poly = {
                const G: [i16; 16] = [
                    // gᴬ(α)⁻¹
                    13177, 13177, 13177, 13177, 13177, 13177, 13177, 13177,
                    // gᴮ(β)⁻¹
                    6991, 6991, 6991, 6991, 6991, 6991, 6991, 6991,
                ];
                let uint8x16x2_t(a, b) = vld1q_u8_x2(G.as_ptr().cast());
                u256::new(a, b)
            };
            let x̂ = shr16::<1>(self.hi);
            let mask = shl16::<15>(self.hi);
            bitxor(x̂, sign16(poly, mask))
        };

        let old_hi = self.hi;
        self.hi = unsafe {
            bitxor(
                bitxor(
                    blend32(
                        alignr8::<{ 1 * 2 }>(self.hi, self.lo),
                        alignr8::<{ 3 * 2 }>(self.hi, self.lo),
                        0xf0,
                    ),
                    permute4x64(self.lo, 0x4e),
                ),
                bitxor(invx, mulx),
            )
        };
        self.lo = old_hi;
    }

    /// Returns the tap `T1 = (b₁₅, b₁₄, ..., b₈)`.
    #[inline(always)]
    fn t1(&self) -> uint8x16_t {
        self.hi.b
    }

    /// Returns the tap `T2 = (a₇, a₆, ..., a₀)`.
    #[inline(always)]
    fn t2(&self) -> uint8x16_t {
        self.lo.a
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
    unsafe fn update(&mut self, t2: uint8x16_t) {
        let r3 = unsafe { aes(self.r2) };
        let r2 = unsafe { aes(self.r1) };

        self.r1 = unsafe {
            let tmp = vreinterpretq_u8_u32(vaddq_u32(
                vreinterpretq_u32_u8(self.r2),
                vreinterpretq_u32_u8(veorq_u8(self.r3, t2)),
            ));
            let sigma = {
                const SIGMA: [u8; 16] = [15, 11, 7, 3, 14, 10, 6, 2, 13, 9, 5, 1, 12, 8, 4, 0];
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

/// A 256-bit vector.
#[derive(Copy, Clone, Debug)]
#[repr(C)]
struct u256 {
    a: uint8x16_t,
    b: uint8x16_t,
}

impl u256 {
    #[inline(always)]
    const fn new(a: uint8x16_t, b: uint8x16_t) -> Self {
        Self { a, b }
    }

    #[inline(always)]
    const fn lo(&self) -> uint8x16_t {
        self.a
    }

    #[inline(always)]
    const fn hi(&self) -> uint8x16_t {
        self.b
    }
}

/// Packs 32-bit elements in `a` and `b` depending the
/// corresponding bits in `MASK`.
///
/// If bit `i` is 1, element `b[i]` is chosen. Otherwise, element
/// `a[i]` is chosen.
///
/// See [_mm256_blend_epi32].
///
/// # Safety
///
/// The NEON architectural feature must be enabled.
///
/// [_mm256_blend_epi32]: https://www.intel.com/content/www/us/en/docs/cpp-compiler/developer-guide-reference/2021-10/mm-blend-epi32-mm256-blend-epi16-32.html
#[inline]
#[target_feature(enable = "neon")]
unsafe fn blend32(a: u256, b: u256, mask: u8) -> u256 {
    #[inline]
    #[target_feature(enable = "neon")]
    unsafe fn blend(a: uint32x4_t, b: uint32x4_t, mask: u8) -> uint32x4_t {
        let mask = {
            let mut tmp = [0u32; 4];
            for (i, v) in tmp.iter_mut().enumerate() {
                if (mask & (1 << i)) != 0 {
                    *v = u32::MAX;
                }
            }
            unsafe { vld1q_u32(tmp.as_ptr()) }
        };
        unsafe { vbslq_u32(mask, b, a) }
    }

    let t0 = unsafe {
        let a0 = vreinterpretq_u32_u8(a.lo());
        let b0 = vreinterpretq_u32_u8(b.lo());
        vreinterpretq_u8_u32(blend(a0, b0, mask & 0xf))
    };
    let t1 = unsafe {
        let b1 = vreinterpretq_u32_u8(b.hi());
        let a1 = vreinterpretq_u32_u8(a.hi());
        vreinterpretq_u8_u32(blend(a1, b1, mask >> 4))
    };
    u256::new(t0, t1)
}

/// Concatenates pairs of 128-bit elements in `a` and `b`, shifts
/// the concatenated pairs right by `N` bytes, and places the low
/// 128 bits from each pair in a new vector.
///
/// ```text
/// let t0 = ((low(a) << 128) | low(b)) >> (N*8);
/// let t1 = ((high(a) << 128) | high(b)) >> (N*8);
/// let result = (t1 << 128) | t0;
/// ```
///
/// See [_mm256_alignr_epi8].
///
/// # Safety
///
/// The NEON architectural feature must be enabled.
///
/// [_mm256_alignr_epi8]: https://www.intel.com/content/www/us/en/docs/cpp-compiler/developer-guide-reference/2021-10/mm256-alignr-epi8.html
#[inline]
#[target_feature(enable = "neon")]
unsafe fn alignr8<const N: i32>(a: u256, b: u256) -> u256 {
    let t0 = unsafe { vextq_u8(b.lo(), a.lo(), N) };
    let t1 = unsafe { vextq_u8(b.hi(), a.hi(), N) };
    u256::new(t0, t1)
}

/// Shuffles 64-bit elements in `a` using the control mask
/// `CTRL`.
///
/// See [_mm256_permute4x64_epi64].
///
/// # Safety
///
/// The NEON architectural feature must be enabled.
///
/// [_mm256_permute4x64_epi64]: https://www.intel.com/content/www/us/en/docs/cpp-compiler/developer-guide-reference/2021-10/mm256-permute4x64-epi64.html
#[inline]
#[target_feature(enable = "neon")]
unsafe fn permute4x64(a: u256, ctrl: u8) -> u256 {
    // 2,3,0,1, so swap halves.
    if ctrl == 0x4e {
        return u256::new(a.hi(), a.lo());
    }

    let a0 = unsafe { vreinterpretq_u64_u8(a.lo()) };
    let a1 = unsafe { vreinterpretq_u64_u8(a.hi()) };
    let table = unsafe { uint8x16x2_t(vreinterpretq_u8_u64(a0), vreinterpretq_u8_u64(a1)) };

    let mut indices = [0; 4];
    for (i, v) in indices.iter_mut().enumerate() {
        *v = ((ctrl >> (i * 2)) & 0x3) as usize;
    }

    macro_rules! index {
        ($idx:expr) => {{
            let mut idx = [0u8; 16];
            let (lhs, rhs) = idx.split_at_mut(8);
            for (i, v) in lhs.iter_mut().enumerate() {
                *v = (indices[$idx] + i) as u8;
            }
            for (i, v) in rhs.iter_mut().enumerate() {
                *v = (indices[$idx + 1] + i) as u8;
            }
            vld1q_u8(idx.as_ptr())
        }};
    }

    let lo = unsafe { vqtbl2q_u8(table, index!(0)) };
    let hi = unsafe { vqtbl2q_u8(table, index!(2)) };
    u256::new(lo, hi)
}

/// Bitwise XOR.
///
/// # Safety
///
/// The NEON architectural feature must be enabled.
#[inline]
#[target_feature(enable = "neon")]
unsafe fn bitxor(a: u256, b: u256) -> u256 {
    let lo = unsafe { veorq_u8(a.lo(), b.lo()) };
    let hi = unsafe { veorq_u8(a.hi(), b.hi()) };
    u256::new(lo, hi)
}

/// Bitwise AND.
///
/// # Safety
///
/// The NEON architectural feature must be enabled.
#[inline]
#[target_feature(enable = "neon")]
unsafe fn bitand(a: u256, b: u256) -> u256 {
    let lo = unsafe { vandq_u8(a.lo(), b.lo()) };
    let hi = unsafe { vandq_u8(a.hi(), b.hi()) };
    u256::new(lo, hi)
}

/// Logical right shift on 16-bit elements.
///
/// # Safety
///
/// The NEON architectural feature must be enabled.
#[inline]
#[target_feature(enable = "neon")]
unsafe fn shl16<const N: i32>(a: u256) -> u256 {
    let lo = unsafe { vreinterpretq_u8_u16(vshlq_n_u16::<N>(vreinterpretq_u16_u8(a.lo()))) };
    let hi = unsafe { vreinterpretq_u8_u16(vshlq_n_u16::<N>(vreinterpretq_u16_u8(a.hi()))) };
    u256::new(lo, hi)
}

/// Logical right shift on 16-bit elements.
///
/// # Safety
///
/// The NEON architectural feature must be enabled.
#[inline]
#[target_feature(enable = "neon")]
unsafe fn shr16<const N: i32>(a: u256) -> u256 {
    let lo = unsafe { vreinterpretq_u8_u16(vshrq_n_u16::<N>(vreinterpretq_u16_u8(a.lo()))) };
    let hi = unsafe { vreinterpretq_u8_u16(vshrq_n_u16::<N>(vreinterpretq_u16_u8(a.hi()))) };
    u256::new(lo, hi)
}

/// Arithmetic right shift on 16-bit elements.
///
/// # Safety
///
/// The NEON architectural feature must be enabled.
#[inline]
#[target_feature(enable = "neon")]
unsafe fn ashr16<const N: i32>(a: u256) -> u256 {
    // #[inline]
    // #[target_feature(enable = "neon")]
    // unsafe fn ashr(a: int16x8_t, n: i16) -> int16x8_t {
    //     let n = if n > 15 { 15 } else { n };
    //     unsafe { vshlq_s16(a, vdupq_n_s16(-n)) }
    // }
    // // let lo = unsafe { vreinterpretq_u8_s16(ashr(vreinterpretq_s16_u8(a.lo()), N)) };
    // // let hi = unsafe { vreinterpretq_u8_s16(ashr(vreinterpretq_s16_u8(a.hi()), N)) };
    let lo = unsafe { vreinterpretq_u8_s16(vshrq_n_s16::<N>(vreinterpretq_s16_u8(a.lo()))) };
    let hi = unsafe { vreinterpretq_u8_s16(vshrq_n_s16::<N>(vreinterpretq_s16_u8(a.hi()))) };
    u256::new(lo, hi)
}

/// Changes the signs of 16-bit elements in `a` depending on the
/// sign of 16-bit elements in `b`.
///
/// - If the element in `b` is negative, the corresponding
///   element in `a` is negated.
/// - If the element in `b` is zero, the corresponding element in
///   `a` is zeroed.
/// - Otherwise, the corresponding element in `a` is left
///   unchanged.
///
/// See [_mm256_sign_epi16].
///
/// # Safety
///
/// The NEON architectural feature must be enabled.
///
/// [_mm256_sign_epi16]: https://www.intel.com/content/www/us/en/docs/cpp-compiler/developer-guide-reference/2021-10/mm256-sign-epi8-16-32.html
#[inline]
#[target_feature(enable = "neon")]
unsafe fn sign16(a: u256, b: u256) -> u256 {
    #[inline]
    #[target_feature(enable = "neon")]
    unsafe fn sign(a: int16x8_t, b: int16x8_t) -> int16x8_t {
        // let neg_mask = if b < 0 { 0xffff } else { 0 };
        let neg_mask = unsafe { vreinterpretq_u16_s16(vshrq_n_s16(b, 15)) };

        // let zero_mask = if b == 0 { 0xffff } else { 0 };
        let zero_mask = unsafe { vreinterpretq_s16_u16(vceqzq_s16(b)) };

        // let v = if neg_mask { -a } else { a };
        let v = unsafe { vbslq_s16(neg_mask, vnegq_s16(a), a) };

        // v & !zero_mask
        unsafe { vbicq_s16(v, zero_mask) }
    }
    let lo = unsafe {
        vreinterpretq_u8_s16(sign(
            vreinterpretq_s16_u8(a.lo()),
            vreinterpretq_s16_u8(b.lo()),
        ))
    };
    let hi = unsafe {
        vreinterpretq_u8_s16(sign(
            vreinterpretq_s16_u8(a.hi()),
            vreinterpretq_s16_u8(b.hi()),
        ))
    };
    u256::new(lo, hi)
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
