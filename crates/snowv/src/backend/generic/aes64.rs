/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org>
 * Copyright (c) 2025 Eric Lagergren
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

//! Constant time 64-bit bitsliced AES from [BearSSL].
//!
//! [BearSSL]: https://www.bearssl.org/gitweb/?p=BearSSL;a=tree;h=7d854167e69c8fe84add518ee0ddc672bbe2b2d7;hb=HEAD

/// Perform one AES round on two blocks with an all-zero round
/// key.
///
/// - `SubBytes`
/// - `ShiftRows
/// - `MixColumns`
///
/// `AddRoundKey` is elided because SNOW-V uses an all-zero round
/// key.
#[inline(always)]
pub(super) fn aes_ct_enc_round(block1: &[u32; 4], block2: &[u32; 4]) -> ([u32; 4], [u32; 4]) {
    let mut q = [0u64; 8];
    (q[0], q[4]) = aes_ct_interleave_in(block1);
    (q[1], q[5]) = aes_ct_interleave_in(block2);
    // No need to interleave blocks 3 and 4 since they're all
    // zero.
    // (q[2], q[6]) = aes_ct_interleave_in(&[0u32; 4]);
    // (q[3], q[7]) = aes_ct_interleave_in(&[0u32; 4]);

    aes_ct_ortho(&mut q);
    aes_ct_sbox(&mut q);
    aes_ct_shift_rows(&mut q);
    aes_ct_mix_columns(&mut q);
    aes_ct_ortho(&mut q);

    let r1 = aes_ct_interleave_out(q[0], q[4]);
    let r2 = aes_ct_interleave_out(q[1], q[5]);

    (r1, r2)
}

/// Interleave bytes for an AES input block. If input bytes are
/// denoted 0123456789ABCDEF, and have been decoded with
/// little-endian convention (w[0] contains 0123, with '3' being
/// most significant; w[1] contains 4567, and so on), then output
/// word q0 will be set to 08192A3B (again little-endian
/// convention) and q1 will be set to 4C5D6E7F.
#[inline(always)]
fn aes_ct_interleave_in(w: &[u32; 4]) -> (u64, u64) {
    let mut x0 = u64::from(w[0]);
    let mut x1 = u64::from(w[1]);
    let mut x2 = u64::from(w[2]);
    let mut x3 = u64::from(w[3]);
    x0 |= x0 << 16;
    x1 |= x1 << 16;
    x2 |= x2 << 16;
    x3 |= x3 << 16;
    x0 &= 0x0000FFFF0000FFFF;
    x1 &= 0x0000FFFF0000FFFF;
    x2 &= 0x0000FFFF0000FFFF;
    x3 &= 0x0000FFFF0000FFFF;
    x0 |= x0 << 8;
    x1 |= x1 << 8;
    x2 |= x2 << 8;
    x3 |= x3 << 8;
    x0 &= 0x00FF00FF00FF00FF;
    x1 &= 0x00FF00FF00FF00FF;
    x2 &= 0x00FF00FF00FF00FF;
    x3 &= 0x00FF00FF00FF00FF;
    let q0 = x0 | (x2 << 8);
    let q1 = x1 | (x3 << 8);
    (q0, q1)
}

#[inline(always)]
fn aes_ct_interleave_out(q0: u64, q1: u64) -> [u32; 4] {
    let mut w = [0u32; 4];
    let mut x0 = q0 & 0x00FF00FF00FF00FF;
    let mut x1 = q1 & 0x00FF00FF00FF00FF;
    let mut x2 = (q0 >> 8) & 0x00FF00FF00FF00FF;
    let mut x3 = (q1 >> 8) & 0x00FF00FF00FF00FF;
    x0 |= x0 >> 8;
    x1 |= x1 >> 8;
    x2 |= x2 >> 8;
    x3 |= x3 >> 8;
    x0 &= 0x0000FFFF0000FFFF;
    x1 &= 0x0000FFFF0000FFFF;
    x2 &= 0x0000FFFF0000FFFF;
    x3 &= 0x0000FFFF0000FFFF;
    w[0] = (x0 as u32) | ((x0 >> 16) as u32);
    w[1] = (x1 as u32) | ((x1 >> 16) as u32);
    w[2] = (x2 as u32) | ((x2 >> 16) as u32);
    w[3] = (x3 as u32) | ((x3 >> 16) as u32);
    w
}

/// Perform bytewise orthogonalization of eight 64-bit words.
/// Bytes of q0..q7 are spread over all words: for a byte x that
/// occurs at rank i in q[j] (byte x uses bits 8*i to 8*i+7 in
/// q[j]), the bit of rank k in x (0 <= k <= 7) goes to q[k] at
/// rank 8*i+j.
///
/// This operation is an involution.
#[inline(always)]
fn aes_ct_ortho(q: &mut [u64; 8]) {
    macro_rules! swap {
        (2; $x:expr, $y:expr) => {
            swap!(0x5555555555555555, 0xAAAAAAAAAAAAAAAA, 1, $x, $y)
        };
        (4; $x:expr, $y:expr) => {
            swap!(0x3333333333333333, 0xCCCCCCCCCCCCCCCC, 2, $x, $y)
        };
        (8; $x:expr, $y:expr) => {
            swap!(0x0F0F0F0F0F0F0F0F, 0xF0F0F0F0F0F0F0F0, 4, $x, $y)
        };
        ($cl:literal, $ch:literal, $s:literal, $x:expr, $y:expr) => {
            let a = $x;
            let b = $y;
            $x = (a & $cl) | ((b & $cl) << $s);
            $y = ((a & $ch) >> $s) | (b & $ch);
        };
    }

    swap!(2; q[0], q[1]);
    swap!(2; q[2], q[3]);
    swap!(2; q[4], q[5]);
    swap!(2; q[6], q[7]);

    swap!(4; q[0], q[2]);
    swap!(4; q[1], q[3]);
    swap!(4; q[4], q[6]);
    swap!(4; q[5], q[7]);

    swap!(8; q[0], q[4]);
    swap!(8; q[1], q[5]);
    swap!(8; q[2], q[6]);
    swap!(8; q[3], q[7]);
}

#[inline(always)]
fn aes_ct_shift_rows(q: &mut [u64; 8]) {
    for x in q {
        *x = (*x & 0x000000000000FFFF)
            | ((*x & 0x00000000FFF00000) >> 4)
            | ((*x & 0x00000000000F0000) << 12)
            | ((*x & 0x0000FF0000000000) >> 8)
            | ((*x & 0x000000FF00000000) << 8)
            | ((*x & 0xF000000000000000) >> 12)
            | ((*x & 0x0FFF000000000000) << 4);
    }
}

#[inline(always)]
fn aes_ct_mix_columns(q: &mut [u64; 8]) {
    let q0 = q[0];
    let q1 = q[1];
    let q2 = q[2];
    let q3 = q[3];
    let q4 = q[4];
    let q5 = q[5];
    let q6 = q[6];
    let q7 = q[7];

    let r0 = q0.rotate_left(48);
    let r1 = q1.rotate_left(48);
    let r2 = q2.rotate_left(48);
    let r3 = q3.rotate_left(48);
    let r4 = q4.rotate_left(48);
    let r5 = q5.rotate_left(48);
    let r6 = q6.rotate_left(48);
    let r7 = q7.rotate_left(48);

    q[0] = q7 ^ r7 ^ r0 ^ (q0 ^ r0).rotate_right(32);
    q[1] = q0 ^ r0 ^ q7 ^ r7 ^ r1 ^ (q1 ^ r1).rotate_right(32);
    q[2] = q1 ^ r1 ^ r2 ^ (q2 ^ r2).rotate_right(32);
    q[3] = q2 ^ r2 ^ q7 ^ r7 ^ r3 ^ (q3 ^ r3).rotate_right(32);
    q[4] = q3 ^ r3 ^ q7 ^ r7 ^ r4 ^ (q4 ^ r4).rotate_right(32);
    q[5] = q4 ^ r4 ^ r5 ^ (q5 ^ r5).rotate_right(32);
    q[6] = q5 ^ r5 ^ r6 ^ (q6 ^ r6).rotate_right(32);
    q[7] = q6 ^ r6 ^ r7 ^ (q7 ^ r7).rotate_right(32);
}

/// The AES S-box, as a bitsliced constant-time version. The
/// input array consists in eight 64-bit words; 64 S-box
/// instances are computed in parallel. Bits 0 to 7 of each S-box
/// input (bit 0 is least significant) are spread over the words
/// 0 to 7, at the same rank.
#[inline(always)]
fn aes_ct_sbox(q: &mut [u64; 8]) {
    let x0 = q[7];
    let x1 = q[6];
    let x2 = q[5];
    let x3 = q[4];
    let x4 = q[3];
    let x5 = q[2];
    let x6 = q[1];
    let x7 = q[0];

    // Top linear transformation.
    let y14 = x3 ^ x5;
    let y13 = x0 ^ x6;
    let y9 = x0 ^ x3;
    let y8 = x0 ^ x5;
    let t0 = x1 ^ x2;
    let y1 = t0 ^ x7;
    let y4 = y1 ^ x3;
    let y12 = y13 ^ y14;
    let y2 = y1 ^ x0;
    let y5 = y1 ^ x6;
    let y3 = y5 ^ y8;
    let t1 = x4 ^ y12;
    let y15 = t1 ^ x5;
    let y20 = t1 ^ x1;
    let y6 = y15 ^ x7;
    let y10 = y15 ^ t0;
    let y11 = y20 ^ y9;
    let y7 = x7 ^ y11;
    let y17 = y10 ^ y11;
    let y19 = y10 ^ y8;
    let y16 = t0 ^ y11;
    let y21 = y13 ^ y16;
    let y18 = x0 ^ y16;

    // Non-linear section.
    let t2 = y12 & y15;
    let t3 = y3 & y6;
    let t4 = t3 ^ t2;
    let t5 = y4 & x7;
    let t6 = t5 ^ t2;
    let t7 = y13 & y16;
    let t8 = y5 & y1;
    let t9 = t8 ^ t7;
    let t10 = y2 & y7;
    let t11 = t10 ^ t7;
    let t12 = y9 & y11;
    let t13 = y14 & y17;
    let t14 = t13 ^ t12;
    let t15 = y8 & y10;
    let t16 = t15 ^ t12;
    let t17 = t4 ^ t14;
    let t18 = t6 ^ t16;
    let t19 = t9 ^ t14;
    let t20 = t11 ^ t16;
    let t21 = t17 ^ y20;
    let t22 = t18 ^ y19;
    let t23 = t19 ^ y21;
    let t24 = t20 ^ y18;

    let t25 = t21 ^ t22;
    let t26 = t21 & t23;
    let t27 = t24 ^ t26;
    let t28 = t25 & t27;
    let t29 = t28 ^ t22;
    let t30 = t23 ^ t24;
    let t31 = t22 ^ t26;
    let t32 = t31 & t30;
    let t33 = t32 ^ t24;
    let t34 = t23 ^ t33;
    let t35 = t27 ^ t33;
    let t36 = t24 & t35;
    let t37 = t36 ^ t34;
    let t38 = t27 ^ t36;
    let t39 = t29 & t38;
    let t40 = t25 ^ t39;

    let t41 = t40 ^ t37;
    let t42 = t29 ^ t33;
    let t43 = t29 ^ t40;
    let t44 = t33 ^ t37;
    let t45 = t42 ^ t41;
    let z0 = t44 & y15;
    let z1 = t37 & y6;
    let z2 = t33 & x7;
    let z3 = t43 & y16;
    let z4 = t40 & y1;
    let z5 = t29 & y7;
    let z6 = t42 & y11;
    let z7 = t45 & y17;
    let z8 = t41 & y10;
    let z9 = t44 & y12;
    let z10 = t37 & y3;
    let z11 = t33 & y4;
    let z12 = t43 & y13;
    let z13 = t40 & y5;
    let z14 = t29 & y2;
    let z15 = t42 & y9;
    let z16 = t45 & y14;
    let z17 = t41 & y8;

    // Bottom linear transformation.
    let t46 = z15 ^ z16;
    let t47 = z10 ^ z11;
    let t48 = z5 ^ z13;
    let t49 = z9 ^ z10;
    let t50 = z2 ^ z12;
    let t51 = z2 ^ z5;
    let t52 = z7 ^ z8;
    let t53 = z0 ^ z3;
    let t54 = z6 ^ z7;
    let t55 = z16 ^ z17;
    let t56 = z12 ^ t48;
    let t57 = t50 ^ t53;
    let t58 = z4 ^ t46;
    let t59 = z3 ^ t54;
    let t60 = t46 ^ t57;
    let t61 = z14 ^ t57;
    let t62 = t52 ^ t58;
    let t63 = t49 ^ t58;
    let t64 = z4 ^ t59;
    let t65 = t61 ^ t62;
    let t66 = z1 ^ t63;
    let s0 = t59 ^ t63;
    let s6 = t56 ^ !t62;
    let s7 = t48 ^ !t60;
    let t67 = t64 ^ t65;
    let s3 = t53 ^ t66;
    let s4 = t51 ^ t66;
    let s5 = t47 ^ t65;
    let s1 = t64 ^ !s3;
    let s2 = t55 ^ !t67;

    q[7] = s0;
    q[6] = s1;
    q[5] = s2;
    q[4] = s3;
    q[3] = s4;
    q[2] = s5;
    q[1] = s6;
    q[0] = s7;
}
