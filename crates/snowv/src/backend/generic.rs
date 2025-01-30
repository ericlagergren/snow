//! Software implementation.

#![forbid(unsafe_code)]

#[derive(Clone, Debug)]
pub(super) struct State {
    a: [u16; 16],
    b: [u16; 16],
    r1: [u32; 4],
    r2: [u32; 4],
    r3: [u32; 4],
}

impl State {
    pub fn new(_key: &[u8; 32], _iv: &[u8; 16], _aead: bool) -> Self {
        todo!()
    }

    pub fn apply_keystream_block(&mut self, data: &mut [u8; 16]) {
        for i in 0..4 {
            let t1 = {
                let hi = self.b[2 * i + 9];
                let lo = self.b[2 * i + 8];
                ((hi as u32) << 16) | (lo as u32)
            };
            let v = (t1 + self.r1[i]) ^ self.r2[i];
            // data[i * 4 + 0] = (v >> 0) & 0xff;
            // data[i * 4 + 1] = (v >> 8) & 0xff;
            // data[i * 4 + 2] = (v >> 16) & 0xff;
            // data[i * 4 + 3] = (v >> 24) & 0xff;
            data[i * 4..(i + 1) * 4].copy_from_slice(&v.to_le_bytes());
        }

        self.update_fsm();
        self.update_lsfr();
    }

    pub fn apply_keystream_blocks(&mut self, blocks: &mut [[u8; 16]]) {
        for block in blocks {
            self.apply_keystream_block(block);
        }
    }

    pub fn write_keystream_block(&mut self, data: &mut [u8; 16]) {
        for i in 0..4 {
            let t1 = {
                let hi = self.b[2 * i + 9];
                let lo = self.b[2 * i + 8];
                ((hi as u32) << 16) | (lo as u32)
            };
            let v = (t1 + self.r1[i]) ^ self.r2[i];
            // data[i * 4 + 0] = (v >> 0) & 0xff;
            // data[i * 4 + 1] = (v >> 8) & 0xff;
            // data[i * 4 + 2] = (v >> 16) & 0xff;
            // data[i * 4 + 3] = (v >> 24) & 0xff;
            data[i * 4..(i + 1) * 4].copy_from_slice(&v.to_le_bytes());
        }

        self.update_fsm();
        self.update_lsfr();
    }
}

pub type Block = [u32; 4];

impl State {
    fn update_fsm(&mut self) {
        let r1temp = self.r1;

        for i in 0..4 {
            let t2 = {
                let hi = self.a[2 * i + 1];
                let lo = self.a[2 * i];
                ((hi as u32) << 16) | (lo as u32)
            };
            self.r1[i] = (t2 ^ self.r3[i]) + self.r2[i];
        }
        permute_sigma(&mut self.r1);
        aes_enc_round(&mut self.r3, &self.r2);
        aes_enc_round(&mut self.r2, &r1temp);
    }

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
        *dst = u32::from_le_bytes(src.try_into().unwrap());
    }
}

fn aes_enc_round(_dst: &mut Block, _src: &Block) {
    todo!()
}
