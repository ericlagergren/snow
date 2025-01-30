//! x86/x86_64 implementation.

#![cfg(all(
    not(feature = "soft"),
    any(target_arch = "x86", target_arch = "x86_64"),
    target_feature = "avx2",
))]

pub(crate) struct State {
    lo: __m256i,
    hi: __m256i,
    r1: __m128i,
    r2: __m128i,
    r3: __m128i,
}

#[inline]
#[target_feature(enable = "avx2")]
unsafe fn vpset16(value: i16) -> __m256i {
    _mm256_set1_epi16(value)
}

const _snowv_mul: __m256i = _mm256_blend_epi32(vpset16(0x990f), vpset16(0xc963), 0xf0);
const _snowv_inv: __m256i = _mm256_blend_epi32(vpset16(-0xcc87), vpset16(-0xe4b1), 0xf0);
const _snowv_aead: __m128i = _mm_lddqu_si128(b"AlexEkd JingThom".as_ptr());
const _snowv_sigma: __m128i = _mm_set_epi8(15, 11, 7, 3, 14, 10, 6, 2, 13, 9, 5, 1, 12, 8, 4, 0);
const _snowv_zero: __m128i = _mm_setzero_si128();

impl State {
    #[target_feature(enable = "avx2,aes")]
    pub fn keystream(&mut self) -> __m128i {
        // Extract the tags T1 and T2
        let T1 = _mm256_extracti128_si256(hi, 1);
        let T2 = _mm256_castsi256_si128(lo);
        // LFSR Update
        let mulx = _mm256_xor_si256(
            _mm256_slli_epi16(self.lo, 1),
            _mm256_and_si256(_snowv_mul, _mm256_srai_epi16(self.lo, 15)),
        );
        let invx = _mm256_xor_si256(
            _mm256_srli_epi16(self.hi, 1),
            _mm256_sign_epi16(_snowv_inv, _mm256_slli_epi16(self.hi, 15)),
        );
        let hi_old = hi;
        self.hi = _mm256_xor_si256(
            _mm256_xor_si256(
                _mm256_blend_epi32(
                    _mm256_alignr_epi8(self.hi, self.lo, 1 * 2),
                    _mm256_alignr_epi8(self.hi, self.lo, 3 * 2),
                    0xf0,
                ),
                _mm256_permute4x64_epi64(lo, 0x4e),
            ),
            _mm256_xor_si256(invx, mulx),
        );
        self.lo = hi_old;
        // Keystream word
        let z = _mm_xor_si128(self.r2, _mm_add_epi32(self.r1, T1));

        // FSM Update
        let r3_new = _mm_aesenc_si128(self.r2, _snowv_zero);
        let r2_new = _mm_aesenc_si128(self.r1, _snowv_zero);
        self.r1 = _mm_shuffle_epi8(
            _mm_add_epi32(self.r2, _mm_xor_si128(self.r3, T2)),
            _snowv_sigma,
        );
        self.r3 = R3new;
        self.r2 = R2new;

        z
    }
}
