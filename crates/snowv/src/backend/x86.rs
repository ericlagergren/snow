//! x86/x86_64 implementation.

#![cfg(all(
    not(feature = "soft"),
    any(target_arch = "x86", target_arch = "x86_64"),
    target_feature = "avx2",
))]
#![allow(clippy::undocumented_unsafe_blocks, reason = "Too many unsafe blocks.")]

cfg_if::cfg_if! {
    if #[cfg(target_arch = "x86_64")] {
        use core::arch::x86_64::*;
    } else {
        use core::arch::x86::*;
    }
}

use inout::{InOut, InOutBuf};

use crate::Block;

cpufeatures::new!(have_asm, "aes", "avx2");

#[derive(Copy, Clone, Debug)]
pub(super) struct Token {
    token: have_pclmulqdq::InitToken,
}

impl Token {
    #[inline]
    pub fn new() -> (Self, bool) {
        let (token, supported) = have_pclmulqdq::init_get();
        (Self { token }, supported)
    }

    #[inline]
    pub fn supported(&self) -> bool {
        self.token.get()
    }
}

#[derive(Clone, Debug)]
pub(super) struct State {
    lsfr: Lsfr,
    fsm: Fsm,
}

impl State {
    /// # Safety
    ///
    /// The AES and AVX2 architectural features must be enabled.
    #[inline]
    #[target_feature(enable = "avx2,aes")]
    pub unsafe fn new(key: &[u8; 32], iv: &[u8; 16], aead: bool) -> Self {
        let key = unsafe { _mm256_loadu_si256(key.as_ptr().cast()) };
        let iv = unsafe { _mm_loadu_si128(iv.as_ptr().cast()) };

        let mut state = State {
            lsfr: unsafe { Lsfr::new(key, iv) },
            fsm: unsafe { Fsm::new() },
        };

        if aead {
            state.lsfr.lo = unsafe {
                let aead = _mm_lddqu_si128(b"AlexEkd JingThom".as_ptr().cast());
                _mm256_insertf128_si256(state.lsfr.lo, aead, 1)
            };
        }

        for _ in 0..15 {
            state.lsfr.hi = unsafe {
                let z = state.keystream();
                _mm256_xor_si256(state.lsfr.hi, _mm256_zextsi128_si256(z))
            };
        }

        state.fsm.r1 = unsafe { _mm_xor_si128(state.fsm.r1, _mm256_extracti128_si256(key, 0)) };
        state.lsfr.hi = unsafe {
            let z = state.keystream();
            _mm256_xor_si256(state.lsfr.hi, _mm256_zextsi128_si256(z))
        };
        state.fsm.r1 = unsafe { _mm_xor_si128(state.fsm.r1, _mm256_extracti128_si256(key, 1)) };

        state
    }

    /// # Safety
    ///
    /// The AES and AVX2 architectural features must be enabled.
    #[inline]
    #[target_feature(enable = "avx2,aes")]
    pub unsafe fn apply_keystream_block(&mut self, block: InOut<'_, '_, Block>) {
        let (in_ptr, out_ptr) = block.into_raw();
        let data = unsafe { _mm_lddqu_si128(in_ptr.cast()) };
        let z = unsafe { self.keystream() };
        unsafe { _mm_storeu_si128(out_ptr.cast(), _mm_xor_si128(data, z)) }
    }

    /// # Safety
    ///
    /// The AES and AVX2 architectural features must be enabled.
    #[inline]
    #[target_feature(enable = "avx2,aes")]
    pub unsafe fn apply_keystream_blocks(&mut self, blocks: InOutBuf<'_, '_, Block>) {
        for block in blocks {
            unsafe { self.apply_keystream_block(block) }
        }
    }

    /// # Safety
    ///
    /// The AES and AVX2 architectural features must be enabled.
    #[inline]
    #[target_feature(enable = "avx2,aes")]
    pub unsafe fn write_keystream_block(&mut self, block: &mut Block) {
        unsafe { _mm_storeu_si128(block.as_mut_ptr().cast(), self.keystream()) }
    }

    /// # Safety
    ///
    /// The AES and AVX2 architectural features must be enabled.
    #[inline]
    #[target_feature(enable = "avx2,aes")]
    pub unsafe fn write_keystream_blocks(&mut self, block: &mut [Block]) {
        for block in block {
            unsafe { self.write_keystream_block(block) }
        }
    }

    /// # Safety
    ///
    /// The AES and AVX2 architectural features must be enabled.
    #[inline]
    #[target_feature(enable = "avx2,aes")]
    unsafe fn keystream(&mut self) -> __m128i {
        let t1 = unsafe { _mm256_extracti128_si256(self.lsfr.hi, 1) };
        let t2 = unsafe { _mm256_castsi256_si128(self.lsfr.lo) };

        unsafe { self.lsfr.update() }
        let z = unsafe { _mm_xor_si128(self.fsm.r2, _mm_add_epi32(self.fsm.r1, t1)) };
        unsafe { self.fsm.update(t2) }

        z
    }
}

#[derive(Clone, Debug)]
struct Lsfr {
    lo: __m256i,
    hi: __m256i,
}

impl Lsfr {
    /// # Safety
    ///
    /// The AVX2 architectural feature must be enabled.
    #[inline]
    #[target_feature(enable = "avx2")]
    unsafe fn new(key: __m256i, iv: __m128i) -> Self {
        Self {
            lo: unsafe { _mm256_zextsi128_si256(iv) },
            hi: key,
        }
    }

    /// # Safety
    ///
    /// The AVX2 architectural feature must be enabled.
    #[inline]
    #[target_feature(enable = "avx2")]
    unsafe fn update(&mut self) {
        let mulx = unsafe {
            let poly = _mm256_blend_epi32(
                vpset16(-26353), // vpset16(0x990f),
                vpset16(-13981), // vpset16(0xc963),
                0xf0,
            );
            _mm256_xor_si256(
                _mm256_slli_epi16(self.lo, 1),
                _mm256_and_si256(poly, _mm256_srai_epi16(self.lo, 15)),
            )
        };

        let invx = unsafe {
            let poly = _mm256_blend_epi32(
                vpset16(13177), // vpset16(-0xcc87),
                vpset16(6991),  // vpset16(-0xe4b1),
                0xf0,
            );
            _mm256_xor_si256(
                _mm256_srli_epi16(self.hi, 1),
                _mm256_sign_epi16(poly, _mm256_slli_epi16(self.hi, 15)),
            )
        };

        let hi_old = self.hi;
        self.hi = unsafe {
            _mm256_xor_si256(
                _mm256_xor_si256(
                    _mm256_blend_epi32(
                        _mm256_alignr_epi8(self.hi, self.lo, 1 * 2),
                        _mm256_alignr_epi8(self.hi, self.lo, 3 * 2),
                        0xf0,
                    ),
                    _mm256_permute4x64_epi64(self.lo, 0x4e),
                ),
                _mm256_xor_si256(invx, mulx),
            )
        };
        self.lo = hi_old;
    }
}

#[derive(Clone, Debug)]
struct Fsm {
    r1: __m128i,
    r2: __m128i,
    r3: __m128i,
}

impl Fsm {
    /// # Safety
    ///
    /// The SSE2 architectural feature must be enabled.
    #[inline]
    #[target_feature(enable = "sse2")]
    unsafe fn new() -> Self {
        Self {
            r1: unsafe { _mm_setzero_si128() },
            r2: unsafe { _mm_setzero_si128() },
            r3: unsafe { _mm_setzero_si128() },
        }
    }

    /// # Safety
    ///
    /// The AES and AVX2 architectural features must be enabled.
    #[inline]
    #[target_feature(enable = "avx2,aes")]
    unsafe fn update(&mut self, t2: __m128i) {
        let r3_new = unsafe { _mm_aesenc_si128(self.r2, _mm_setzero_si128()) };
        let r2_new = unsafe { _mm_aesenc_si128(self.r1, _mm_setzero_si128()) };
        self.r1 = unsafe {
            let sigma = _mm_set_epi8(15, 11, 7, 3, 14, 10, 6, 2, 13, 9, 5, 1, 12, 8, 4, 0);
            _mm_shuffle_epi8(_mm_add_epi32(self.r2, _mm_xor_si128(self.r3, t2)), sigma)
        };
        self.r3 = r3_new;
        self.r2 = r2_new;
    }
}

/// # Safety
///
/// The AVX2 architectural feature must be enabled.
#[inline]
#[target_feature(enable = "avx2")]
unsafe fn vpset16(value: i16) -> __m256i {
    unsafe { _mm256_set1_epi16(value) }
}
