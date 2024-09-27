import { createCipher } from '../../core/cipher'
import { KitError, rotateL32, rotateR32 } from '../../core/utils'

// * Constants

const P0 = new Uint8Array([0xA9, 0x67, 0xB3, 0xE8, 0x04, 0xFD, 0xA3, 0x76, 0x9A, 0x92, 0x80, 0x78, 0xE4, 0xDD, 0xD1, 0x38, 0x0D, 0xC6, 0x35, 0x98, 0x18, 0xF7, 0xEC, 0x6C, 0x43, 0x75, 0x37, 0x26, 0xFA, 0x13, 0x94, 0x48, 0xF2, 0xD0, 0x8B, 0x30, 0x84, 0x54, 0xDF, 0x23, 0x19, 0x5B, 0x3D, 0x59, 0xF3, 0xAE, 0xA2, 0x82, 0x63, 0x01, 0x83, 0x2E, 0xD9, 0x51, 0x9B, 0x7C, 0xA6, 0xEB, 0xA5, 0xBE, 0x16, 0x0C, 0xE3, 0x61, 0xC0, 0x8C, 0x3A, 0xF5, 0x73, 0x2C, 0x25, 0x0B, 0xBB, 0x4E, 0x89, 0x6B, 0x53, 0x6A, 0xB4, 0xF1, 0xE1, 0xE6, 0xBD, 0x45, 0xE2, 0xF4, 0xB6, 0x66, 0xCC, 0x95, 0x03, 0x56, 0xD4, 0x1C, 0x1E, 0xD7, 0xFB, 0xC3, 0x8E, 0xB5, 0xE9, 0xCF, 0xBF, 0xBA, 0xEA, 0x77, 0x39, 0xAF, 0x33, 0xC9, 0x62, 0x71, 0x81, 0x79, 0x09, 0xAD, 0x24, 0xCD, 0xF9, 0xD8, 0xE5, 0xC5, 0xB9, 0x4D, 0x44, 0x08, 0x86, 0xE7, 0xA1, 0x1D, 0xAA, 0xED, 0x06, 0x70, 0xB2, 0xD2, 0x41, 0x7B, 0xA0, 0x11, 0x31, 0xC2, 0x27, 0x90, 0x20, 0xF6, 0x60, 0xFF, 0x96, 0x5C, 0xB1, 0xAB, 0x9E, 0x9C, 0x52, 0x1B, 0x5F, 0x93, 0x0A, 0xEF, 0x91, 0x85, 0x49, 0xEE, 0x2D, 0x4F, 0x8F, 0x3B, 0x47, 0x87, 0x6D, 0x46, 0xD6, 0x3E, 0x69, 0x64, 0x2A, 0xCE, 0xCB, 0x2F, 0xFC, 0x97, 0x05, 0x7A, 0xAC, 0x7F, 0xD5, 0x1A, 0x4B, 0x0E, 0xA7, 0x5A, 0x28, 0x14, 0x3F, 0x29, 0x88, 0x3C, 0x4C, 0x02, 0xB8, 0xDA, 0xB0, 0x17, 0x55, 0x1F, 0x8A, 0x7D, 0x57, 0xC7, 0x8D, 0x74, 0xB7, 0xC4, 0x9F, 0x72, 0x7E, 0x15, 0x22, 0x12, 0x58, 0x07, 0x99, 0x34, 0x6E, 0x50, 0xDE, 0x68, 0x65, 0xBC, 0xDB, 0xF8, 0xC8, 0xA8, 0x2B, 0x40, 0xDC, 0xFE, 0x32, 0xA4, 0xCA, 0x10, 0x21, 0xF0, 0xD3, 0x5D, 0x0F, 0x00, 0x6F, 0x9D, 0x36, 0x42, 0x4A, 0x5E, 0xC1, 0xE0])
const P1 = new Uint8Array([0x75, 0xF3, 0xC6, 0xF4, 0xDB, 0x7B, 0xFB, 0xC8, 0x4A, 0xD3, 0xE6, 0x6B, 0x45, 0x7D, 0xE8, 0x4B, 0xD6, 0x32, 0xD8, 0xFD, 0x37, 0x71, 0xF1, 0xE1, 0x30, 0x0F, 0xF8, 0x1B, 0x87, 0xFA, 0x06, 0x3F, 0x5E, 0xBA, 0xAE, 0x5B, 0x8A, 0x00, 0xBC, 0x9D, 0x6D, 0xC1, 0xB1, 0x0E, 0x80, 0x5D, 0xD2, 0xD5, 0xA0, 0x84, 0x07, 0x14, 0xB5, 0x90, 0x2C, 0xA3, 0xB2, 0x73, 0x4C, 0x54, 0x92, 0x74, 0x36, 0x51, 0x38, 0xB0, 0xBD, 0x5A, 0xFC, 0x60, 0x62, 0x96, 0x6C, 0x42, 0xF7, 0x10, 0x7C, 0x28, 0x27, 0x8C, 0x13, 0x95, 0x9C, 0xC7, 0x24, 0x46, 0x3B, 0x70, 0xCA, 0xE3, 0x85, 0xCB, 0x11, 0xD0, 0x93, 0xB8, 0xA6, 0x83, 0x20, 0xFF, 0x9F, 0x77, 0xC3, 0xCC, 0x03, 0x6F, 0x08, 0xBF, 0x40, 0xE7, 0x2B, 0xE2, 0x79, 0x0C, 0xAA, 0x82, 0x41, 0x3A, 0xEA, 0xB9, 0xE4, 0x9A, 0xA4, 0x97, 0x7E, 0xDA, 0x7A, 0x17, 0x66, 0x94, 0xA1, 0x1D, 0x3D, 0xF0, 0xDE, 0xB3, 0x0B, 0x72, 0xA7, 0x1C, 0xEF, 0xD1, 0x53, 0x3E, 0x8F, 0x33, 0x26, 0x5F, 0xEC, 0x76, 0x2A, 0x49, 0x81, 0x88, 0xEE, 0x21, 0xC4, 0x1A, 0xEB, 0xD9, 0xC5, 0x39, 0x99, 0xCD, 0xAD, 0x31, 0x8B, 0x01, 0x18, 0x23, 0xDD, 0x1F, 0x4E, 0x2D, 0xF9, 0x48, 0x4F, 0xF2, 0x65, 0x8E, 0x78, 0x5C, 0x58, 0x19, 0x8D, 0xE5, 0x98, 0x57, 0x67, 0x7F, 0x05, 0x64, 0xAF, 0x63, 0xB6, 0xFE, 0xF5, 0xB7, 0x3C, 0xA5, 0xCE, 0xE9, 0x68, 0x44, 0xE0, 0x4D, 0x43, 0x69, 0x29, 0x2E, 0xAC, 0x15, 0x59, 0xA8, 0x0A, 0x9E, 0x6E, 0x47, 0xDF, 0x34, 0x35, 0x6A, 0xCF, 0xDC, 0x22, 0xC9, 0xC0, 0x9B, 0x89, 0xD4, 0xED, 0xAB, 0x12, 0xA2, 0x0D, 0x52, 0xBB, 0x02, 0x2F, 0xA9, 0xD7, 0x61, 0x1E, 0xB4, 0x50, 0x04, 0xF6, 0xC2, 0x16, 0x25, 0x86, 0x56, 0x55, 0x09, 0xBE, 0x91])
const P = [P0, P1]
const P_00 = 1
const P_01 = 0
const P_02 = 0
const P_03 = P_01 ^ 1
const P_04 = 1
const P_10 = 0
const P_11 = 0
const P_12 = 1
const P_13 = P_11 ^ 1
const P_14 = 0
const P_20 = 1
const P_21 = 1
const P_22 = 0
const P_23 = P_21 ^ 1
const P_24 = 0
const P_30 = 0
const P_31 = 1
const P_32 = 1
const P_33 = P_31 ^ 1
const P_34 = 1
const GF256_FDBK_2 = 0x169 >> 1
const GF256_FDBK_4 = 0x169 >> 2
const RS_GF_FDBK = 0x14D
const MDS = [
  new Uint32Array(256),
  new Uint32Array(256),
  new Uint32Array(256),
  new Uint32Array(256),
]

// * Functions

const LFSR1 = (x: number) => (x >> 1) ^ ((x & 0x01) !== 0 ? GF256_FDBK_2 : 0)
const LFSR2 = (x: number) => (x >> 2) ^ ((x & 0x02) !== 0 ? GF256_FDBK_2 : 0) ^ ((x & 0x01) !== 0 ? GF256_FDBK_4 : 0)
const Mx_X = (x: number) => x ^ LFSR2(x)
const Mx_Y = (x: number) => x ^ LFSR1(x) ^ LFSR2(x);
(function initMDS() {
  // precompute the MDS matrix
  const m1 = new Uint32Array(2)
  const mX = new Uint32Array(2)
  const mY = new Uint32Array(2)
  for (let i = 0; i < 256; i++) {
    const j0 = P[0][i] & 0xFF
    m1[0] = j0
    mX[0] = Mx_X(j0) & 0xFF
    mY[0] = Mx_Y(j0) & 0xFF

    const j1 = P[1][i] & 0xFF
    m1[1] = j1
    mX[1] = Mx_X(j1) & 0xFF
    mY[1] = Mx_Y(j1) & 0xFF

    MDS[0][i]
      = (m1[P_00] << 0)
      | (mX[P_00] << 8)
      | (mY[P_00] << 16)
      | (mY[P_00] << 24)
    MDS[1][i]
      = (mY[P_10] << 0)
      | (mY[P_10] << 8)
      | (mX[P_10] << 16)
      | (m1[P_10] << 24)
    MDS[2][i]
      = (mX[P_20] << 0)
      | (mY[P_20] << 8)
      | (m1[P_20] << 16)
      | (mY[P_20] << 24)
    MDS[3][i]
      = (mX[P_30] << 0)
      | (m1[P_30] << 8)
      | (mY[P_30] << 16)
      | (mX[P_30] << 24)
  }
})()

const b0 = (x: number) => x & 0xFF
const b1 = (x: number) => (x >>> 8) & 0xFF
const b2 = (x: number) => (x >>> 16) & 0xFF
const b3 = (x: number) => (x >>> 24) & 0xFF
function chooseB(x: number, N: number) {
  switch (N & 3) {
    case 0: return b0(x)
    case 1: return b1(x)
    case 2: return b2(x)
    case 3: return b3(x)
    default: return 0
  }
}
function RS_REM(x: number) {
  const b = (x >>> 24) & 0xFF
  const g2 = ((b << 1) ^ ((b & 0x80) !== 0 ? RS_GF_FDBK : 0)) & 0xFF
  const g3 = (b >>> 1) ^ ((b & 0x01) !== 0 ? (RS_GF_FDBK >>> 1) : 0) ^ g2
  return (x << 8) ^ (g3 << 24) ^ (g2 << 16) ^ (g3 << 8) ^ b
}
function RS_MDS_Encode(k0: number, k1: number) {
  for (let i = 0; i < 4; i++) {
    k1 = RS_REM(k1)
  }
  k1 ^= k0
  for (let i = 0; i < 4; i++) {
    k1 = RS_REM(k1)
  }
  return k1
}
function F32(K64SigByte: number, x: number, k32: Uint32Array) {
  let lB0 = b0(x)
  let lB1 = b1(x)
  let lB2 = b2(x)
  let lB3 = b3(x)
  const k0 = k32[0] || 0
  const k1 = k32[1] || 0
  const k2 = k32[2] || 0
  const k3 = k32[3] || 0

  let result = 0
  let K64LSB = K64SigByte & 0x3
  if (K64LSB === 1) {
    result
      = MDS[0][P[P_01][lB0] & 0xFF ^ b0(k0)]
      ^ MDS[1][P[P_11][lB1] & 0xFF ^ b1(k0)]
      ^ MDS[2][P[P_21][lB2] & 0xFF ^ b2(k0)]
      ^ MDS[3][P[P_31][lB3] & 0xFF ^ b3(k0)]
    return result
  }

  if (K64LSB === 0) {
    lB0 = P[P_04][lB0] & 0xFF ^ b0(k3)
    lB1 = P[P_14][lB1] & 0xFF ^ b1(k3)
    lB2 = P[P_24][lB2] & 0xFF ^ b2(k3)
    lB3 = P[P_34][lB3] & 0xFF ^ b3(k3)
    K64LSB = 3
  }

  if (K64LSB === 3) {
    lB0 = P[P_03][lB0] & 0xFF ^ b0(k2)
    lB1 = P[P_13][lB1] & 0xFF ^ b1(k2)
    lB2 = P[P_23][lB2] & 0xFF ^ b2(k2)
    lB3 = P[P_33][lB3] & 0xFF ^ b3(k2)
    K64LSB = 2
  }

  if (K64LSB === 2) {
    result
      = MDS[0][P[P_01][P[P_02][lB0] & 0xFF ^ b0(k1)] & 0xFF ^ b0(k0)]
      ^ MDS[1][P[P_11][P[P_12][lB1] & 0xFF ^ b1(k1)] & 0xFF ^ b1(k0)]
      ^ MDS[2][P[P_21][P[P_22][lB2] & 0xFF ^ b2(k1)] & 0xFF ^ b2(k0)]
      ^ MDS[3][P[P_31][P[P_32][lB3] & 0xFF ^ b3(k1)] & 0xFF ^ b3(k0)]
    return result
  }

  return 0
}
function Fe32(SBox: Uint32Array, x: number, R: number) {
  const result
    = SBox[0x000 + 2 * chooseB(x, R + 0) + 0]
    ^ SBox[0x000 + 2 * chooseB(x, R + 1) + 1]
    ^ SBox[0x200 + 2 * chooseB(x, R + 2) + 0]
    ^ SBox[0x200 + 2 * chooseB(x, R + 3) + 1]
  return result
}

// * Blowfish Algorithm

function initKeySchedule(K: Uint8Array) {
  const K32 = new Uint32Array(K.buffer, K.byteOffset)
  const K32e = new Uint32Array([K32[0], K32[2], K32[4], K32[6]])
  const K32o = new Uint32Array([K32[1], K32[3], K32[5], K32[7]])
  const K64Count = K32.length >> 1

  // compute S-box keys using (12, 8) Reed-Solomon code over GF(256)
  const SBoxKeys = new Uint32Array(4)
  for (let i = 0; i < 4; i++) {
    const j = K64Count - 1 - i
    SBoxKeys[j] = RS_MDS_Encode(K32e[i], K32o[i])
  }

  // compute the round decryption subkeys for PHT. these same subkeys
  // will be used in encryption but will be applied in reverse order.
  let q = 0
  const Subkeys = new Uint32Array(40)
  for (let i = 0; i < 20; i++) {
    let A = F32(K64Count, q, K32e)
    let B = F32(K64Count, q + 0x01010101, K32o)
    B = rotateL32(B, 8)
    A += B
    Subkeys[2 * i] = A
    A += B
    Subkeys[2 * i + 1] = rotateL32(A, 9)
    q += 0x02020202
  }

  // fully expand the table for speed
  const k0 = SBoxKeys[0]
  const k1 = SBoxKeys[1]
  const k2 = SBoxKeys[2]
  const k3 = SBoxKeys[3]
  const SBox = new Uint32Array(4 * 256)
  for (let i = 0; i < 256; i++) {
    let lb0 = i
    let lb1 = i
    let lb2 = i
    let lb3 = i
    let K64CountLSB = K64Count & 3

    if (K64CountLSB === 1) {
      SBox[0x000 + 2 * i + 0] = MDS[0][P[P_01][lb0] & 0xFF ^ b0(k0)]
      SBox[0x000 + 2 * i + 1] = MDS[1][P[P_11][lb1] & 0xFF ^ b1(k0)]
      SBox[0x200 + 2 * i + 0] = MDS[2][P[P_21][lb2] & 0xFF ^ b2(k0)]
      SBox[0x200 + 2 * i + 1] = MDS[3][P[P_31][lb3] & 0xFF ^ b3(k0)]
      continue
    }

    if (K64CountLSB === 0) {
      lb0 = P[P_04][lb0] & 0xFF ^ b0(k3)
      lb1 = P[P_14][lb1] & 0xFF ^ b1(k3)
      lb2 = P[P_24][lb2] & 0xFF ^ b2(k3)
      lb3 = P[P_34][lb3] & 0xFF ^ b3(k3)
      K64CountLSB = 3
    }

    if (K64CountLSB === 3) {
      lb0 = P[P_03][lb0] & 0xFF ^ b0(k2)
      lb1 = P[P_13][lb1] & 0xFF ^ b1(k2)
      lb2 = P[P_23][lb2] & 0xFF ^ b2(k2)
      lb3 = P[P_33][lb3] & 0xFF ^ b3(k2)
      K64CountLSB = 2
    }

    if (K64CountLSB === 2) {
      SBox[0x000 + 2 * i + 0]
        = MDS[0][P[P_01][P[P_02][lb0] & 0xFF ^ b0(k1)] & 0xFF ^ b0(k0)]
      SBox[0x000 + 2 * i + 1]
        = MDS[1][P[P_11][P[P_12][lb1] & 0xFF ^ b1(k1)] & 0xFF ^ b1(k0)]
      SBox[0x200 + 2 * i + 0]
        = MDS[2][P[P_21][P[P_22][lb2] & 0xFF ^ b2(k1)] & 0xFF ^ b2(k0)]
      SBox[0x200 + 2 * i + 1]
        = MDS[3][P[P_31][P[P_32][lb3] & 0xFF ^ b3(k1)] & 0xFF ^ b3(k0)]
    }
  }

  return { Subkeys, SBox }
}

function _twofish(K: Uint8Array) {
  if (K.byteLength !== 16 && K.byteLength !== 24 && K.byteLength !== 32) {
    throw new KitError(`Twofish requires a key of length 16, 24, or 32 bytes`)
  }
  const { Subkeys, SBox } = initKeySchedule(K)

  const encrypt = (M: Uint8Array) => {
    const M32 = new Uint32Array(M.buffer, M.byteOffset)
    // input whitening
    let x0 = M32[0] ^ Subkeys[0]
    let x1 = M32[1] ^ Subkeys[1]
    let x2 = M32[2] ^ Subkeys[2]
    let x3 = M32[3] ^ Subkeys[3]

    let k = 8
    // 16 rounds of encryption
    for (let i = 0; i < 16; i += 2) {
      let t0 = Fe32(SBox, x0, 0)
      let t1 = Fe32(SBox, x1, 3)
      x2 ^= t0 + t1 + Subkeys[k++]
      x2 = rotateR32(x2, 1)
      x3 = rotateL32(x3, 1)
      x3 ^= t0 + 2 * t1 + Subkeys[k++]

      t0 = Fe32(SBox, x2, 0)
      t1 = Fe32(SBox, x3, 3)
      x0 ^= t0 + t1 + Subkeys[k++]
      x0 = rotateR32(x0, 1)
      x1 = rotateL32(x1, 1)
      x1 ^= t0 + 2 * t1 + Subkeys[k++]
    }

    // output whitening
    x2 ^= Subkeys[4]
    x3 ^= Subkeys[5]
    x0 ^= Subkeys[6]
    x1 ^= Subkeys[7]

    return new Uint8Array(new Uint32Array([x2, x3, x0, x1]).buffer)
  }
  const decrypt = (C: Uint8Array) => {
    const M32 = new Uint32Array(C.buffer, C.byteOffset)
    // input whitening
    let x2 = M32[0] ^ Subkeys[4]
    let x3 = M32[1] ^ Subkeys[5]
    let x0 = M32[2] ^ Subkeys[6]
    let x1 = M32[3] ^ Subkeys[7]

    let k = 39
    // 16 rounds of decryption
    for (let i = 0; i < 16; i += 2) {
      let t0 = Fe32(SBox, x2, 0)
      let t1 = Fe32(SBox, x3, 3)
      x1 ^= t0 + 2 * t1 + Subkeys[k--]
      x1 = rotateR32(x1, 1)
      x0 = rotateL32(x0, 1)
      x0 ^= t0 + t1 + Subkeys[k--]

      t0 = Fe32(SBox, x0, 0)
      t1 = Fe32(SBox, x1, 3)
      x3 ^= t0 + 2 * t1 + Subkeys[k--]
      x3 = rotateR32(x3, 1)
      x2 = rotateL32(x2, 1)
      x2 ^= t0 + t1 + Subkeys[k--]
    }

    // output whitening
    x0 ^= Subkeys[0]
    x1 ^= Subkeys[1]
    x2 ^= Subkeys[2]
    x3 ^= Subkeys[3]

    return new Uint8Array(new Uint32Array([x0, x1, x2, x3]).buffer)
  }
  return { encrypt, decrypt }
}

/**
 * @description
 * Twofish block cipher algorithm.
 *
 * Twofish 分组密码算法.
 */
export const twofish = createCipher(
  _twofish,
  {
    ALGORITHM: 'Blowfish',
    BLOCK_SIZE: 16,
    KEY_SIZE: 56,
  },
)
