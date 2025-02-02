//! Software implementation.

//#![forbid(unsafe_code)] TODO

use core::{mem, ptr};

use inout::{InOut, InOutBuf};

#[derive(Clone, Debug)]
pub(super) struct State {
    a: [u16; 16],
    b: [u16; 16],
    r1: [u32; 4],
    r2: [u32; 4],
    r3: [u32; 4],
}

impl State {
    pub fn new(key: &[u8; 32], iv: &[u8; 16], aead: bool) -> Self {
        let (k0, k1) = key.split_at(key.len() / 2);

        let a = {
            let mut tmp = [0u16; 16];
            let (lhs, rhs) = tmp.split_at_mut(8);
            for (v, iv) in lhs.iter_mut().zip(iv.chunks_exact(2)) {
                *v = u16::from_le_bytes([iv[0], iv[1]]);
            }
            for (v, k) in rhs.iter_mut().zip(k0.chunks_exact(2)) {
                *v = u16::from_le_bytes([k[0], k[1]]);
            }
            tmp
        };

        let b = {
            let mut tmp = [0u16; 16];
            let (lhs, rhs) = tmp.split_at_mut(8);
            if aead {
                lhs.copy_from_slice(&[
                    0x6C41, 0x7865, 0x6B45, 0x2064, 0x694A, 0x676E, 0x6854, 0x6D6F,
                ]);
            }
            for (v, k) in rhs.iter_mut().zip(k1.chunks_exact(2)) {
                *v = u16::from_le_bytes([k[0], k[1]]);
            }
            tmp
        };

        let mut z = [0; 16];

        let mut state = State {
            a,
            b,
            r1: [0; 4],
            r2: [0; 4],
            r3: [0; 4],
        };
        for _ in 0..15 {
            state.keystream(&mut z);
            for (a, z) in state.a_hi_mut().iter_mut().zip(z.chunks_exact(2)) {
                *a ^= u16::from_le_bytes([z[0], z[1]]);
            }
        }

        for (r, k) in state.r1.iter_mut().zip(k0.chunks_exact(4)) {
            *r ^= u32::from_le_bytes([k[0], k[1], k[2], k[3]]);
        }

        state.keystream(&mut z);
        for (a, z) in state.a_hi_mut().iter_mut().zip(z.chunks_exact(2)) {
            *a ^= u16::from_le_bytes([z[0], z[1]]);
        }

        for (r, k) in state.r1.iter_mut().zip(k0.chunks_exact(4)) {
            *r ^= u32::from_le_bytes([k[0], k[1], k[2], k[3]]);
        }

        state
    }

    #[inline]
    #[no_mangle]
    pub fn apply_keystream_block(&mut self, mut block: InOut<'_, '_, [u8; 16]>) {
        let mut z = [0u8; 16];
        self.keystream(&mut z);
        let src = *block.get_in();
        for ((dst, src), z) in block.get_out().iter_mut().zip(src.iter()).zip(z) {
            *dst = *src ^ z;
        }
    }

    #[inline]
    #[no_mangle]
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
    fn keystream(&mut self, z: &mut [u8; 16]) {
        for (i, z) in z.chunks_exact_mut(4).enumerate() {
            let t1 = {
                let hi = self.b[2 * i + 9];
                let lo = self.b[2 * i + 8];
                ((hi as u32) << 16) | (lo as u32)
            };
            let v = t1.wrapping_add(self.r1[i]) ^ self.r2[i];
            z.copy_from_slice(&v.to_le_bytes());
        }

        self.update_fsm();
        self.update_lsfr();
    }

    #[inline]
    fn update_fsm(&mut self) {
        let r1temp = self.r1;

        for i in 0..4 {
            let t2 = {
                let hi = self.a[2 * i + 1];
                let lo = self.a[2 * i];
                ((hi as u32) << 16) | (lo as u32)
            };
            self.r1[i] = (t2 ^ self.r3[i]).wrapping_add(self.r2[i]);
        }
        permute_sigma(&mut self.r1);
        aes_enc_round(&mut self.r3, &self.r2);
        aes_enc_round(&mut self.r2, &r1temp);
    }

    #[inline]
    fn update_lsfr(&mut self) {
        for _ in 0..8 {
            let u = mul_x(self.a[0], 0x990f) ^ self.a[1] ^ mul_x_inv(self.a[8], 0xcc87) ^ self.b[0];
            let v = mul_x(self.b[0], 0xc963) ^ self.b[3] ^ mul_x_inv(self.b[8], 0xe4b1) ^ self.a[0];

            for j in 0..15 {
                self.a[j] = self.a[j + 1];
                self.b[j] = self.b[j + 1];
            }

            self.a[15] = u;
            self.b[15] = v;
        }
    }

    #[inline(always)]
    fn a_hi_mut(&mut self) -> &mut [u16] {
        let n = self.a.len() / 2;
        self.a.split_at_mut(n).1
    }
}

const fn mul_x(v: u16, c: u16) -> u16 {
    if v & 0x8000 != 0 {
        (v << 1) ^ c
    } else {
        v << 1
    }
}

const fn mul_x_inv(v: u16, d: u16) -> u16 {
    if v & 0x0001 != 0 {
        (v >> 1) ^ d
    } else {
        v >> 1
    }
}

fn permute_sigma(state: &mut [u32; 4]) {
    const SIGMA: [u8; 16] = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15];

    let mut tmp = [0; 16];
    for (i, t) in tmp.iter_mut().enumerate() {
        *t = (state[(SIGMA[i] >> 2) as usize] >> ((SIGMA[i] & 3) << 3)) as u8;
    }
    for (dst, src) in state.iter_mut().zip(tmp.chunks_exact_mut(4)) {
        *dst = u32::from_le_bytes([src[0], src[1], src[2], src[3]]);
    }
}

#[inline(always)]
fn aes_enc_round(dst: &mut [u32; 4], src: &[u32; 4]) {
    use aes::{hazmat::cipher_round, Block};

    *dst = *src;
    let block: &mut Block = unsafe { mem::transmute(dst) };
    cipher_round(block, &Block::default());
}
