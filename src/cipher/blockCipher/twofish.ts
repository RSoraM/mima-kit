import { createCipher } from '../../core/cipher';
import { KitError, rotateL32, rotateR32, U8, u8 } from '../../core/utils';

// * Constants

const P0 = new Uint8Array([
  0xa9, 0x67, 0xb3, 0xe8, 0x04, 0xfd, 0xa3, 0x76, 0x9a, 0x92, 0x80, 0x78, 0xe4, 0xdd, 0xd1, 0x38,
  0x0d, 0xc6, 0x35, 0x98, 0x18, 0xf7, 0xec, 0x6c, 0x43, 0x75, 0x37, 0x26, 0xfa, 0x13, 0x94, 0x48,
  0xf2, 0xd0, 0x8b, 0x30, 0x84, 0x54, 0xdf, 0x23, 0x19, 0x5b, 0x3d, 0x59, 0xf3, 0xae, 0xa2, 0x82,
  0x63, 0x01, 0x83, 0x2e, 0xd9, 0x51, 0x9b, 0x7c, 0xa6, 0xeb, 0xa5, 0xbe, 0x16, 0x0c, 0xe3, 0x61,
  0xc0, 0x8c, 0x3a, 0xf5, 0x73, 0x2c, 0x25, 0x0b, 0xbb, 0x4e, 0x89, 0x6b, 0x53, 0x6a, 0xb4, 0xf1,
  0xe1, 0xe6, 0xbd, 0x45, 0xe2, 0xf4, 0xb6, 0x66, 0xcc, 0x95, 0x03, 0x56, 0xd4, 0x1c, 0x1e, 0xd7,
  0xfb, 0xc3, 0x8e, 0xb5, 0xe9, 0xcf, 0xbf, 0xba, 0xea, 0x77, 0x39, 0xaf, 0x33, 0xc9, 0x62, 0x71,
  0x81, 0x79, 0x09, 0xad, 0x24, 0xcd, 0xf9, 0xd8, 0xe5, 0xc5, 0xb9, 0x4d, 0x44, 0x08, 0x86, 0xe7,
  0xa1, 0x1d, 0xaa, 0xed, 0x06, 0x70, 0xb2, 0xd2, 0x41, 0x7b, 0xa0, 0x11, 0x31, 0xc2, 0x27, 0x90,
  0x20, 0xf6, 0x60, 0xff, 0x96, 0x5c, 0xb1, 0xab, 0x9e, 0x9c, 0x52, 0x1b, 0x5f, 0x93, 0x0a, 0xef,
  0x91, 0x85, 0x49, 0xee, 0x2d, 0x4f, 0x8f, 0x3b, 0x47, 0x87, 0x6d, 0x46, 0xd6, 0x3e, 0x69, 0x64,
  0x2a, 0xce, 0xcb, 0x2f, 0xfc, 0x97, 0x05, 0x7a, 0xac, 0x7f, 0xd5, 0x1a, 0x4b, 0x0e, 0xa7, 0x5a,
  0x28, 0x14, 0x3f, 0x29, 0x88, 0x3c, 0x4c, 0x02, 0xb8, 0xda, 0xb0, 0x17, 0x55, 0x1f, 0x8a, 0x7d,
  0x57, 0xc7, 0x8d, 0x74, 0xb7, 0xc4, 0x9f, 0x72, 0x7e, 0x15, 0x22, 0x12, 0x58, 0x07, 0x99, 0x34,
  0x6e, 0x50, 0xde, 0x68, 0x65, 0xbc, 0xdb, 0xf8, 0xc8, 0xa8, 0x2b, 0x40, 0xdc, 0xfe, 0x32, 0xa4,
  0xca, 0x10, 0x21, 0xf0, 0xd3, 0x5d, 0x0f, 0x00, 0x6f, 0x9d, 0x36, 0x42, 0x4a, 0x5e, 0xc1, 0xe0,
]);
const P1 = new Uint8Array([
  0x75, 0xf3, 0xc6, 0xf4, 0xdb, 0x7b, 0xfb, 0xc8, 0x4a, 0xd3, 0xe6, 0x6b, 0x45, 0x7d, 0xe8, 0x4b,
  0xd6, 0x32, 0xd8, 0xfd, 0x37, 0x71, 0xf1, 0xe1, 0x30, 0x0f, 0xf8, 0x1b, 0x87, 0xfa, 0x06, 0x3f,
  0x5e, 0xba, 0xae, 0x5b, 0x8a, 0x00, 0xbc, 0x9d, 0x6d, 0xc1, 0xb1, 0x0e, 0x80, 0x5d, 0xd2, 0xd5,
  0xa0, 0x84, 0x07, 0x14, 0xb5, 0x90, 0x2c, 0xa3, 0xb2, 0x73, 0x4c, 0x54, 0x92, 0x74, 0x36, 0x51,
  0x38, 0xb0, 0xbd, 0x5a, 0xfc, 0x60, 0x62, 0x96, 0x6c, 0x42, 0xf7, 0x10, 0x7c, 0x28, 0x27, 0x8c,
  0x13, 0x95, 0x9c, 0xc7, 0x24, 0x46, 0x3b, 0x70, 0xca, 0xe3, 0x85, 0xcb, 0x11, 0xd0, 0x93, 0xb8,
  0xa6, 0x83, 0x20, 0xff, 0x9f, 0x77, 0xc3, 0xcc, 0x03, 0x6f, 0x08, 0xbf, 0x40, 0xe7, 0x2b, 0xe2,
  0x79, 0x0c, 0xaa, 0x82, 0x41, 0x3a, 0xea, 0xb9, 0xe4, 0x9a, 0xa4, 0x97, 0x7e, 0xda, 0x7a, 0x17,
  0x66, 0x94, 0xa1, 0x1d, 0x3d, 0xf0, 0xde, 0xb3, 0x0b, 0x72, 0xa7, 0x1c, 0xef, 0xd1, 0x53, 0x3e,
  0x8f, 0x33, 0x26, 0x5f, 0xec, 0x76, 0x2a, 0x49, 0x81, 0x88, 0xee, 0x21, 0xc4, 0x1a, 0xeb, 0xd9,
  0xc5, 0x39, 0x99, 0xcd, 0xad, 0x31, 0x8b, 0x01, 0x18, 0x23, 0xdd, 0x1f, 0x4e, 0x2d, 0xf9, 0x48,
  0x4f, 0xf2, 0x65, 0x8e, 0x78, 0x5c, 0x58, 0x19, 0x8d, 0xe5, 0x98, 0x57, 0x67, 0x7f, 0x05, 0x64,
  0xaf, 0x63, 0xb6, 0xfe, 0xf5, 0xb7, 0x3c, 0xa5, 0xce, 0xe9, 0x68, 0x44, 0xe0, 0x4d, 0x43, 0x69,
  0x29, 0x2e, 0xac, 0x15, 0x59, 0xa8, 0x0a, 0x9e, 0x6e, 0x47, 0xdf, 0x34, 0x35, 0x6a, 0xcf, 0xdc,
  0x22, 0xc9, 0xc0, 0x9b, 0x89, 0xd4, 0xed, 0xab, 0x12, 0xa2, 0x0d, 0x52, 0xbb, 0x02, 0x2f, 0xa9,
  0xd7, 0x61, 0x1e, 0xb4, 0x50, 0x04, 0xf6, 0xc2, 0x16, 0x25, 0x86, 0x56, 0x55, 0x09, 0xbe, 0x91,
]);
const P = [P0, P1];
const P_00 = 1;
const P_01 = 0;
const P_02 = 0;
const P_03 = P_01 ^ 1;
const P_04 = 1;
const P_10 = 0;
const P_11 = 0;
const P_12 = 1;
const P_13 = P_11 ^ 1;
const P_14 = 0;
const P_20 = 1;
const P_21 = 1;
const P_22 = 0;
const P_23 = P_21 ^ 1;
const P_24 = 0;
const P_30 = 0;
const P_31 = 1;
const P_32 = 1;
const P_33 = P_31 ^ 1;
const P_34 = 1;
const GF256_FDBK_2 = 0x169 >> 1;
const GF256_FDBK_4 = 0x169 >> 2;
const RS_GF_FDBK = 0x14d;
const MDS = [
  new Uint32Array(256),
  new Uint32Array(256),
  new Uint32Array(256),
  new Uint32Array(256),
];

// * Functions

const LFSR1 = (x: number) => (x >> 1) ^ ((x & 0x01) !== 0 ? GF256_FDBK_2 : 0);
const LFSR2 = (x: number) =>
  (x >> 2) ^ ((x & 0x02) !== 0 ? GF256_FDBK_2 : 0) ^ ((x & 0x01) !== 0 ? GF256_FDBK_4 : 0);
const Mx_X = (x: number) => x ^ LFSR2(x);
const Mx_Y = (x: number) => x ^ LFSR1(x) ^ LFSR2(x);
(function initMDS() {
  // precompute the MDS matrix
  const m1 = new Uint32Array(2);
  const mX = new Uint32Array(2);
  const mY = new Uint32Array(2);
  for (let i = 0; i < 256; i++) {
    const j0 = P[0][i] & 0xff;
    m1[0] = j0;
    mX[0] = Mx_X(j0) & 0xff;
    mY[0] = Mx_Y(j0) & 0xff;

    const j1 = P[1][i] & 0xff;
    m1[1] = j1;
    mX[1] = Mx_X(j1) & 0xff;
    mY[1] = Mx_Y(j1) & 0xff;

    MDS[0][i] = (m1[P_00] << 0) | (mX[P_00] << 8) | (mY[P_00] << 16) | (mY[P_00] << 24);
    MDS[1][i] = (mY[P_10] << 0) | (mY[P_10] << 8) | (mX[P_10] << 16) | (m1[P_10] << 24);
    MDS[2][i] = (mX[P_20] << 0) | (mY[P_20] << 8) | (m1[P_20] << 16) | (mY[P_20] << 24);
    MDS[3][i] = (mX[P_30] << 0) | (m1[P_30] << 8) | (mY[P_30] << 16) | (mX[P_30] << 24);
  }
})();

const b0 = (x: number) => x & 0xff;
const b1 = (x: number) => (x >>> 8) & 0xff;
const b2 = (x: number) => (x >>> 16) & 0xff;
const b3 = (x: number) => (x >>> 24) & 0xff;
function chooseB(x: number, N: number) {
  switch (N & 3) {
    case 0:
      return b0(x);
    case 1:
      return b1(x);
    case 2:
      return b2(x);
    case 3:
      return b3(x);
    default:
      return 0;
  }
}
function RS_REM(x: number) {
  const b = (x >>> 24) & 0xff;
  const g2 = ((b << 1) ^ ((b & 0x80) !== 0 ? RS_GF_FDBK : 0)) & 0xff;
  const g3 = (b >>> 1) ^ ((b & 0x01) !== 0 ? RS_GF_FDBK >>> 1 : 0) ^ g2;
  return (x << 8) ^ (g3 << 24) ^ (g2 << 16) ^ (g3 << 8) ^ b;
}
function RS_MDS_Encode(k0: number, k1: number) {
  for (let i = 0; i < 4; i++) {
    k1 = RS_REM(k1);
  }
  k1 ^= k0;
  for (let i = 0; i < 4; i++) {
    k1 = RS_REM(k1);
  }
  return k1;
}
function F32(K64SigByte: number, x: number, k32: Uint32Array) {
  let lB0 = b0(x);
  let lB1 = b1(x);
  let lB2 = b2(x);
  let lB3 = b3(x);
  const k0 = k32[0] || 0;
  const k1 = k32[1] || 0;
  const k2 = k32[2] || 0;
  const k3 = k32[3] || 0;

  let result = 0;
  let K64LSB = K64SigByte & 0x3;
  if (K64LSB === 1) {
    result =
      MDS[0][(P[P_01][lB0] & 0xff) ^ b0(k0)] ^
      MDS[1][(P[P_11][lB1] & 0xff) ^ b1(k0)] ^
      MDS[2][(P[P_21][lB2] & 0xff) ^ b2(k0)] ^
      MDS[3][(P[P_31][lB3] & 0xff) ^ b3(k0)];
    return result;
  }

  if (K64LSB === 0) {
    lB0 = (P[P_04][lB0] & 0xff) ^ b0(k3);
    lB1 = (P[P_14][lB1] & 0xff) ^ b1(k3);
    lB2 = (P[P_24][lB2] & 0xff) ^ b2(k3);
    lB3 = (P[P_34][lB3] & 0xff) ^ b3(k3);
    K64LSB = 3;
  }

  if (K64LSB === 3) {
    lB0 = (P[P_03][lB0] & 0xff) ^ b0(k2);
    lB1 = (P[P_13][lB1] & 0xff) ^ b1(k2);
    lB2 = (P[P_23][lB2] & 0xff) ^ b2(k2);
    lB3 = (P[P_33][lB3] & 0xff) ^ b3(k2);
    K64LSB = 2;
  }

  if (K64LSB === 2) {
    result =
      MDS[0][(P[P_01][(P[P_02][lB0] & 0xff) ^ b0(k1)] & 0xff) ^ b0(k0)] ^
      MDS[1][(P[P_11][(P[P_12][lB1] & 0xff) ^ b1(k1)] & 0xff) ^ b1(k0)] ^
      MDS[2][(P[P_21][(P[P_22][lB2] & 0xff) ^ b2(k1)] & 0xff) ^ b2(k0)] ^
      MDS[3][(P[P_31][(P[P_32][lB3] & 0xff) ^ b3(k1)] & 0xff) ^ b3(k0)];
    return result;
  }

  return 0;
}
function Fe32(SBox: Uint32Array, x: number, R: number) {
  const result =
    SBox[0x000 + 2 * chooseB(x, R + 0) + 0] ^
    SBox[0x000 + 2 * chooseB(x, R + 1) + 1] ^
    SBox[0x200 + 2 * chooseB(x, R + 2) + 0] ^
    SBox[0x200 + 2 * chooseB(x, R + 3) + 1];
  return result;
}

// * Blowfish Algorithm

function initKeySchedule(K: Uint8Array) {
  const K32 = new Uint32Array(K.buffer, K.byteOffset, K.length >> 2);
  const K32e = new Uint32Array([K32[0], K32[2], K32[4], K32[6]]);
  const K32o = new Uint32Array([K32[1], K32[3], K32[5], K32[7]]);
  const K64Count = K32.length >> 1;

  // compute S-box keys using (12, 8) Reed-Solomon code over GF(256)
  const SBoxKeys = new Uint32Array(4);
  for (let i = 0; i < 4; i++) {
    const j = K64Count - 1 - i;
    SBoxKeys[j] = RS_MDS_Encode(K32e[i], K32o[i]);
  }

  // compute the round decryption subkeys for PHT. these same subkeys
  // will be used in encryption but will be applied in reverse order.
  let q = 0;
  const Subkeys = new Uint32Array(40);
  for (let i = 0; i < 20; i++) {
    let A = F32(K64Count, q, K32e);
    let B = F32(K64Count, q + 0x01010101, K32o);
    B = rotateL32(B, 8);
    A += B;
    Subkeys[2 * i] = A;
    A += B;
    Subkeys[2 * i + 1] = rotateL32(A, 9);
    q += 0x02020202;
  }

  // fully expand the table for speed
  const k0 = SBoxKeys[0];
  const k1 = SBoxKeys[1];
  const k2 = SBoxKeys[2];
  const k3 = SBoxKeys[3];
  const SBox = new Uint32Array(4 * 256);
  for (let i = 0; i < 256; i++) {
    let lb0 = i;
    let lb1 = i;
    let lb2 = i;
    let lb3 = i;
    let K64CountLSB = K64Count & 3;

    if (K64CountLSB === 1) {
      SBox[0x000 + 2 * i + 0] = MDS[0][(P[P_01][lb0] & 0xff) ^ b0(k0)];
      SBox[0x000 + 2 * i + 1] = MDS[1][(P[P_11][lb1] & 0xff) ^ b1(k0)];
      SBox[0x200 + 2 * i + 0] = MDS[2][(P[P_21][lb2] & 0xff) ^ b2(k0)];
      SBox[0x200 + 2 * i + 1] = MDS[3][(P[P_31][lb3] & 0xff) ^ b3(k0)];
      continue;
    }

    if (K64CountLSB === 0) {
      lb0 = (P[P_04][lb0] & 0xff) ^ b0(k3);
      lb1 = (P[P_14][lb1] & 0xff) ^ b1(k3);
      lb2 = (P[P_24][lb2] & 0xff) ^ b2(k3);
      lb3 = (P[P_34][lb3] & 0xff) ^ b3(k3);
      K64CountLSB = 3;
    }

    if (K64CountLSB === 3) {
      lb0 = (P[P_03][lb0] & 0xff) ^ b0(k2);
      lb1 = (P[P_13][lb1] & 0xff) ^ b1(k2);
      lb2 = (P[P_23][lb2] & 0xff) ^ b2(k2);
      lb3 = (P[P_33][lb3] & 0xff) ^ b3(k2);
      K64CountLSB = 2;
    }

    if (K64CountLSB === 2) {
      SBox[0x000 + 2 * i + 0] = MDS[0][(P[P_01][(P[P_02][lb0] & 0xff) ^ b0(k1)] & 0xff) ^ b0(k0)];
      SBox[0x000 + 2 * i + 1] = MDS[1][(P[P_11][(P[P_12][lb1] & 0xff) ^ b1(k1)] & 0xff) ^ b1(k0)];
      SBox[0x200 + 2 * i + 0] = MDS[2][(P[P_21][(P[P_22][lb2] & 0xff) ^ b2(k1)] & 0xff) ^ b2(k0)];
      SBox[0x200 + 2 * i + 1] = MDS[3][(P[P_31][(P[P_32][lb3] & 0xff) ^ b3(k1)] & 0xff) ^ b3(k0)];
    }
  }

  return { Subkeys, SBox };
}

function _twofish(K: Uint8Array, b: 128 | 192 | 256) {
  K = u8(K);
  if (K.byteLength !== b >> 3) {
    throw new KitError(`Twofish key must be ${b >> 3} byte`);
  }
  const { Subkeys, SBox } = initKeySchedule(K);

  const encrypt = (M: Uint8Array) => {
    M = u8(M);
    if (M.byteLength !== 16) {
      throw new KitError('Twofish block must be 16 byte');
    }
    const M32 = new Uint32Array(M.buffer, M.byteOffset, M.length >> 2);
    // input whitening
    let x0 = M32[0] ^ Subkeys[0];
    let x1 = M32[1] ^ Subkeys[1];
    let x2 = M32[2] ^ Subkeys[2];
    let x3 = M32[3] ^ Subkeys[3];

    let k = 8;
    // 16 rounds of encryption
    for (let i = 0; i < 16; i += 2) {
      let t0 = Fe32(SBox, x0, 0);
      let t1 = Fe32(SBox, x1, 3);
      x2 ^= t0 + t1 + Subkeys[k++];
      x2 = rotateR32(x2, 1);
      x3 = rotateL32(x3, 1);
      x3 ^= t0 + 2 * t1 + Subkeys[k++];

      t0 = Fe32(SBox, x2, 0);
      t1 = Fe32(SBox, x3, 3);
      x0 ^= t0 + t1 + Subkeys[k++];
      x0 = rotateR32(x0, 1);
      x1 = rotateL32(x1, 1);
      x1 ^= t0 + 2 * t1 + Subkeys[k++];
    }

    // output whitening
    x2 ^= Subkeys[4];
    x3 ^= Subkeys[5];
    x0 ^= Subkeys[6];
    x1 ^= Subkeys[7];

    const _ = new Uint32Array([x2, x3, x0, x1]);
    return new U8(_.buffer, _.byteOffset, _.byteLength);
  };
  const decrypt = (C: Uint8Array) => {
    C = u8(C);
    if (C.byteLength !== 16) {
      throw new KitError('Twofish block must be 16 byte');
    }
    const M32 = new Uint32Array(C.buffer, C.byteOffset, C.length >> 2);
    // input whitening
    let x2 = M32[0] ^ Subkeys[4];
    let x3 = M32[1] ^ Subkeys[5];
    let x0 = M32[2] ^ Subkeys[6];
    let x1 = M32[3] ^ Subkeys[7];

    let k = 39;
    // 16 rounds of decryption
    for (let i = 0; i < 16; i += 2) {
      let t0 = Fe32(SBox, x2, 0);
      let t1 = Fe32(SBox, x3, 3);
      x1 ^= t0 + 2 * t1 + Subkeys[k--];
      x1 = rotateR32(x1, 1);
      x0 = rotateL32(x0, 1);
      x0 ^= t0 + t1 + Subkeys[k--];

      t0 = Fe32(SBox, x0, 0);
      t1 = Fe32(SBox, x1, 3);
      x3 ^= t0 + 2 * t1 + Subkeys[k--];
      x3 = rotateR32(x3, 1);
      x2 = rotateL32(x2, 1);
      x2 ^= t0 + t1 + Subkeys[k--];
    }

    // output whitening
    x0 ^= Subkeys[0];
    x1 ^= Subkeys[1];
    x2 ^= Subkeys[2];
    x3 ^= Subkeys[3];

    const _ = new Uint32Array([x0, x1, x2, x3]);
    return new U8(_.buffer, _.byteOffset, _.byteLength);
  };
  return { encrypt, decrypt };
}

/**
 * Twofish 分组密码算法 / block cipher algorithm
 *
 * @param {128 | 192 | 256} b - 密钥长度 / Key size (bit)
 */
export function twofish(b: 128 | 192 | 256) {
  return createCipher((K: Uint8Array) => _twofish(K, b), {
    ALGORITHM: 'Twofish',
    BLOCK_SIZE: 16,
    KEY_SIZE: b >> 3,
    MIN_KEY_SIZE: b >> 3,
    MAX_KEY_SIZE: b >> 3,
  });
}
