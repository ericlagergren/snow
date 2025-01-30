//! AArch64 implementation.

#![cfg(all(
    not(feature = "soft"),
    target_arch = "aarch64",
    target_feature = "neon",
))]
#![allow(clippy::undocumented_unsafe_blocks, reason = "Too many unsafe blocks.")]
#![allow(non_camel_case_types)]

use core::arch::aarch64::{
    int16x8_t, uint32x4x2_t, uint64x2x2_t, uint8x16_t, uint8x16x2_t, vaddq_u8, vaeseq_u8,
    vaesmcq_u8, vandq_u8, vbicq_s16, vbslq_s16, vbslq_u32, vceqzq_s16, vdupq_n_u8, veorq_u8,
    vextq_u8, vld1q_u32, vld1q_u8, vld1q_u8_x2, vnegq_s16, vqtbl1q_s8, vqtbl2q_u8,
    vreinterpretq_s16_u16, vreinterpretq_s16_u8, vreinterpretq_s8_u8, vreinterpretq_u16_s16,
    vreinterpretq_u16_u8, vreinterpretq_u32_u8, vreinterpretq_u64_u8, vreinterpretq_u8_s16,
    vreinterpretq_u8_s8, vreinterpretq_u8_u16, vreinterpretq_u8_u32, vreinterpretq_u8_u64,
    vshlq_n_u16, vshrq_n_s16, vshrq_n_u16, vst1q_u8,
};

// NB: `aes` implies `neon`.
cpufeatures::new!(have_aes, "aes");

pub fn supported() -> bool {
    have_aes::get()
}

#[derive(Copy, Clone, Debug)]
#[repr(transparent)]
pub(crate) struct Block(uint8x16_t);

impl Default for Block {
    #[inline]
    fn default() -> Self {
        // SAFETY: This intrinsic requires the `neon` target
        // feature, which we have.
        let fe = unsafe { vdupq_n_u8(0) };
        Self(fe)
    }
}

#[derive(Clone, Debug)]
pub(super) struct State {
    lo: u256,
    hi: u256,
    r1: uint8x16_t,
    r2: uint8x16_t,
    r3: uint8x16_t,
}

impl State {
    #[inline]
    #[target_feature(enable = "neon,aes")]
    pub unsafe fn apply_keystream_block(&mut self, block: &mut [u8; 16]) {
        let data = unsafe { vld1q_u8(block.as_mut_ptr()) };
        let z = unsafe { self.keystream() };
        unsafe { vst1q_u8(block.as_mut_ptr(), veorq_u8(data, z)) }
    }

    #[inline]
    #[target_feature(enable = "neon,aes")]
    pub unsafe fn write_keystream_block(&mut self, block: &mut [u8; 16]) {
        let z = unsafe { self.keystream() };
        unsafe { vst1q_u8(block.as_mut_ptr(), z) }
    }

    #[inline]
    #[target_feature(enable = "neon,aes")]
    unsafe fn keystream(&mut self) -> uint8x16_t {
        // Extract tags.
        let t1 = (self.hi.0).1;
        let t2 = (self.lo.0).0;

        // LFSR update.
        const SNOWV: [u16; 16] = [
            0x990f, 0x990f, 0x990f, 0x990f, 0x990f, 0x990f, 0x990f, 0x990f, 0xc963, 0xc963, 0xc963,
            0xc963, 0xc963, 0xc963, 0xc963, 0xc963,
        ];
        let snowv_mul = u256(unsafe { vld1q_u8_x2(SNOWV.as_ptr().cast()) });
        let mulx = unsafe {
            xor256(
                shl16::<1>(self.lo),
                and256(snowv_mul, ashr16::<15>(self.lo)),
            )
        };

        const SNOWV_INV: [i16; 16] = [
            13177, 13177, 13177, 13177, 13177, 13177, 13177, 13177, 6991, 6991, 6991, 6991, 6991,
            6991, 6991, 6991,
        ];
        let snowv_inv = u256(unsafe { vld1q_u8_x2(SNOWV_INV.as_ptr().cast()) });
        let invx = unsafe { xor256(shr16::<1>(self.hi), sign16(snowv_inv, shl16::<15>(self.hi))) };

        let old_hi = self.hi;
        self.hi = unsafe {
            xor256(
                xor256(
                    blend32::<0xf0>(
                        alignr8::<{ 1 * 3 }>(self.hi, self.lo),
                        alignr8::<{ 3 * 2 }>(self.hi, self.lo),
                    ),
                    permute4x64::<0x4e>(self.lo),
                ),
                xor256(invx, mulx),
            )
        };
        self.lo = old_hi;

        // Apply keystream.
        let z = unsafe { veorq_u8(self.r2, vaddq_u8(self.r1, t1)) };

        // FSM update.
        let r3 = unsafe { vaesmcq_u8(vaeseq_u8(self.r2, vdupq_n_u8(0))) };
        let r2 = unsafe { vaesmcq_u8(vaeseq_u8(self.r1, vdupq_n_u8(0))) };

        const SNOWV_SIGMA: [u8; 16] = [15, 11, 7, 3, 14, 10, 6, 2, 13, 9, 5, 1, 12, 8, 4, 0];
        let sigma = unsafe { vld1q_u8(SNOWV_SIGMA.as_ptr()) };

        self.r1 = unsafe { shuffle8(vaddq_u8(self.r2, veorq_u8(self.r3, t2)), sigma) };
        self.r2 = r2;
        self.r3 = r3;

        z
    }
}

#[derive(Copy, Clone, Debug)]
#[repr(transparent)]
struct u256(uint8x16x2_t);

// _mm256_blend_epi32
#[inline]
#[target_feature(enable = "neon")]
unsafe fn blend32<const MASK: i32>(a: u256, b: u256) -> u256 {
    let a = unsafe { uint32x4x2_t(vreinterpretq_u32_u8((a.0).0), vreinterpretq_u32_u8((a.0).1)) };
    let b = unsafe { uint32x4x2_t(vreinterpretq_u32_u8((b.0).0), vreinterpretq_u32_u8((b.0).1)) };

    let mut mask = [0u32; 4];
    for (i, v) in mask.iter_mut().enumerate() {
        if (MASK & (1 << i)) != 0 {
            *v = u32::MAX;
        }
    }
    let mask = unsafe { vld1q_u32(mask.as_ptr()) };
    let t0 = unsafe { vreinterpretq_u8_u32(vbslq_u32(mask, b.0, a.0)) };
    let t1 = unsafe { vreinterpretq_u8_u32(vbslq_u32(mask, b.1, a.1)) };
    u256(uint8x16x2_t(t0, t1))
}

// _mm256_alignr_epi8
#[inline]
#[target_feature(enable = "neon")]
unsafe fn alignr8<const N: i32>(a: u256, b: u256) -> u256 {
    let t0 = unsafe { vextq_u8((b.0).0, (a.0).0, N) };
    let t1 = unsafe { vextq_u8((b.0).1, (a.0).1, N) };
    u256(uint8x16x2_t(t0, t1))
}

// _mm256_permute4x64_epi64
#[inline]
#[target_feature(enable = "neon")]
unsafe fn permute4x64<const CTRL: i32>(a: u256) -> u256 {
    // 2,3,0,1
    if CTRL == 0x4e {
        return u256(uint8x16x2_t((a.0).1, (a.0).0));
    }

    let a = unsafe { uint64x2x2_t(vreinterpretq_u64_u8((a.0).0), vreinterpretq_u64_u8((a.0).1)) };
    let table = unsafe { uint8x16x2_t(vreinterpretq_u8_u64(a.0), vreinterpretq_u8_u64(a.1)) };

    let mut indices = [0; 4];
    for (i, v) in indices.iter_mut().enumerate() {
        *v = ((CTRL >> (i * 2)) & 0x3) as usize;
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
    u256(uint8x16x2_t(lo, hi))
}

// _mm256_xor_si256
#[inline]
#[target_feature(enable = "neon")]
unsafe fn xor256(a: u256, b: u256) -> u256 {
    let lo = unsafe { veorq_u8((a.0).0, (b.0).0) };
    let hi = unsafe { veorq_u8((a.0).1, (b.0).1) };
    u256(uint8x16x2_t(lo, hi))
}

// _mm256_and_si256
#[inline]
#[target_feature(enable = "neon")]
unsafe fn and256(a: u256, b: u256) -> u256 {
    let lo = unsafe { vandq_u8((a.0).0, (b.0).0) };
    let hi = unsafe { vandq_u8((a.0).1, (b.0).1) };
    u256(uint8x16x2_t(lo, hi))
}

// _mm256_slli_epi16
#[inline]
#[target_feature(enable = "neon")]
unsafe fn shl16<const N: i32>(a: u256) -> u256 {
    let lo = unsafe { vreinterpretq_u8_u16(vshlq_n_u16::<N>(vreinterpretq_u16_u8((a.0).0))) };
    let hi = unsafe { vreinterpretq_u8_u16(vshlq_n_u16::<N>(vreinterpretq_u16_u8((a.0).1))) };
    u256(uint8x16x2_t(lo, hi))
}

// _mm256_srli_epi16
#[inline]
#[target_feature(enable = "neon")]
unsafe fn shr16<const N: i32>(a: u256) -> u256 {
    let lo = unsafe { vreinterpretq_u8_u16(vshrq_n_u16::<N>(vreinterpretq_u16_u8((a.0).0))) };
    let hi = unsafe { vreinterpretq_u8_u16(vshrq_n_u16::<N>(vreinterpretq_u16_u8((a.0).1))) };
    u256(uint8x16x2_t(lo, hi))
}

// _mm256_srai_epi16
#[inline]
#[target_feature(enable = "neon")]
unsafe fn ashr16<const N: i32>(a: u256) -> u256 {
    let lo = unsafe { vreinterpretq_u8_s16(vshrq_n_s16::<N>(vreinterpretq_s16_u8((a.0).0))) };
    let hi = unsafe { vreinterpretq_u8_s16(vshrq_n_s16::<N>(vreinterpretq_s16_u8((a.0).1))) };
    u256(uint8x16x2_t(lo, hi))
}

// _mm256_sign_epi16
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
            vreinterpretq_s16_u8((a.0).0),
            vreinterpretq_s16_u8((b.0).0),
        ))
    };
    let hi = unsafe {
        vreinterpretq_u8_s16(sign(
            vreinterpretq_s16_u8((a.0).1),
            vreinterpretq_s16_u8((b.0).1),
        ))
    };
    u256(uint8x16x2_t(lo, hi))
}

// _mm_shuffle_epi8
#[inline]
#[target_feature(enable = "neon")]
unsafe fn shuffle8(a: uint8x16_t, b: uint8x16_t) -> uint8x16_t {
    let table = unsafe { vreinterpretq_s8_u8(a) };
    let idx = unsafe { vandq_u8(b, vdupq_n_u8(0x8f)) };
    let res = unsafe { vqtbl1q_s8(table, idx) };
    unsafe { vreinterpretq_u8_s8(res) }
}
