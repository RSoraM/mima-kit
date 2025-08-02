import { createCipher } from '../../core/cipher'
import { genBitMask, KitError, resizeBuffer, rotateL, rotateR, U8 } from '../../core/utils'

// const Eul = [0xB7, 0xE1, 0x51, 0x62, 0x8A, 0xED, 0x2A, 0x6A, 0xBF, 0x71, 0x58, 0x80, 0x9C, 0xF4, 0xF3, 0xC7, 0x62, 0xE7, 0x16, 0x0F, 0x38, 0xB4, 0xDA, 0x56, 0xA7, 0x84, 0xD9, 0x04, 0x51, 0x90, 0xCF, 0xEF]
// const Phi = [0x9E, 0x37, 0x79, 0xB9, 0x7F, 0x4A, 0x7C, 0x15, 0xF3, 0x9C, 0xC0, 0x60, 0x5C, 0xED, 0xC8, 0x34, 0x10, 0x82, 0x27, 0x6B, 0xF3, 0xA2, 0x72, 0x51, 0xF8, 0x6C, 0x6A, 0x11, 0xD0, 0xC1, 0x8E, 0x95]
// const P = Eul{0,...,w-1} - 2) | 1
// const Q = Phi{0,...,w-1} - 2) | 1

// * Functions

function _setup(key: Uint8Array, word_size: number, round: number, mask: bigint) {
  const word_bit = BigInt(word_size)
  const word_byte = word_size >> 3
  const P = (0xB7E151628AED2A6ABF7158809CF4F3C7n >> (128n - word_bit)) | 1n
  const Q = (0x9E3779B97F4A7C15F39CC0605CEDC835n >> (128n - word_bit)) | 1n
  // Break the key into w-bit words
  const c = Math.ceil((key.length || 1) / word_byte)
  const L = resizeBuffer(key, c * word_byte)
  const LV = L.view(word_byte)
  // Initialize key-independent pseudorandom S array
  const t = (round + 1) << 1
  const S = new U8(t * word_byte)
  const SV = S.view(word_byte)
  // S[0] = P
  let prv = P
  SV.set(0, prv, true)
  for (let i = 1; i < t; i++) {
    // S[i] = S[i-1] + Q
    prv = (prv + Q) & mask
    SV.set(i, prv, true)
  }
  // The main key scheduling loop
  let i = 0
  let j = 0
  let A = 0n
  let B = 0n
  const v = 3 * Math.max(c, t)
  for (let k = 0; k < v; k++) {
    // A = S[i] = (S[i] + A + B) <<< 3
    const S = SV.get(i, true)
    A = rotateL(word_bit, S + A + B, 3n, mask)
    SV.set(i, A, true)
    // B = L[j] = (L[j] + A + B) <<< (A + B)
    const L = LV.get(j, true)
    B = rotateL(word_bit, L + A + B, A + B, mask)
    LV.set(j, B, true)
    // i = (i + 1) mod t
    i = (i + 1) % t
    // j = (j + 1) mod c
    j = (j + 1) % c
  }
  return S
}
function _encrypt(M: Uint8Array, S: Uint8Array, word_size: number, round: number, mask: bigint) {
  if (M.byteLength !== word_size >> 2) {
    throw new KitError(`ARC5-${word_size}/${round} block must be ${word_size >> 3} byte`)
  }
  const word_bit = BigInt(word_size)
  const word_byte = word_size >> 3
  const MV = U8.from(M).view(word_byte)
  const SV = U8.from(S).view(word_byte)
  // A = M[0] + S[0], B = M[1] + S[1]
  let A = MV.get(0, true) + SV.get(0, true)
  let B = MV.get(1, true) + SV.get(1, true)
  A &= mask
  B &= mask
  for (let i = 1; i <= round; i++) {
    // A = ((A ^ B) <<< B) + S[2 * i]
    A = rotateL(word_bit, A ^ B, B, mask)
    A += SV.get(i << 1, true)
    A &= mask
    // B = ((B ^ A) <<< A) + S[2 * i + 1]
    B = rotateL(word_bit, B ^ A, A, mask)
    B += SV.get((i << 1) + 1, true)
    B &= mask
  }
  return U8.fromBI(B << word_bit | A, word_byte << 1, true)
}
function _decrypt(C: Uint8Array, S: Uint8Array, word_size: number, round: number, mask: bigint) {
  if (C.byteLength !== word_size >> 2) {
    throw new KitError(`ARC5-${word_size}/${round} block must be ${word_size >> 3} byte`)
  }
  const word_bit = BigInt(word_size)
  const word_byte = word_size >> 3
  const CV = U8.from(C).view(word_byte)
  const SV = U8.from(S).view(word_byte)
  // A = C[0], B = C[1]
  let A = CV.get(0, true)
  let B = CV.get(1, true)
  for (let i = round; i > 0; i--) {
    // B = ((B - S[2 * i + 1]) >>> A) ^ A
    const S1 = SV.get((i << 1) + 1, true)
    B = rotateR(word_bit, B - S1, A, mask)
    B = B ^ A
    B &= mask
    // A = ((A - S[2 * i]) >>> B) ^ B
    const S0 = SV.get(i << 1, true)
    A = rotateR(word_bit, A - S0, B, mask)
    A = A ^ B
    A &= mask
  }
  // A = A - S[0], B = B - S[1]
  A = A - SV.get(0, true)
  A &= mask
  B = B - SV.get(1, true)
  B &= mask
  return U8.fromBI(B << word_bit | A, word_byte << 1, true)
}

// * ARC5 Algorithm

function _arc5(K: Uint8Array, WORD_SIZE: 8 | 16 | 32 | 64 | 128, round: number) {
  const mask = genBitMask(WORD_SIZE)
  const S = _setup(K, WORD_SIZE, round, mask)
  const encrypt = (M: Uint8Array) => _encrypt(M, S, WORD_SIZE, round, mask)
  const decrypt = (C: Uint8Array) => _decrypt(C, S, WORD_SIZE, round, mask)
  return { encrypt, decrypt }
}

/**
 * ARC5 分组加密算法 / block cipher algorithm
 *
 * ```ts
 * const spec8 = arc5(8, 8) // ARC5-8/8
 * const spec16 = arc5(16, 12) // ARC5-16/12
 * const spec32 = arc5(32, 16) // ARC5-32/16 (default)
 * const spec64 = arc5(64, 20) // ARC5-64/20
 * const spec128 = arc5(128, 24) // ARC5-128/24
 * ```
 *
 * @param {16 | 32 | 64} WORD_SIZE - 工作字长 / Word size (default: 32 bit)
 * @param {number} round - 轮数 / Rounds (default: 16)
 */
export function arc5(WORD_SIZE: 8 | 16 | 32 | 64 | 128 = 32, round: number = 16) {
  if (round <= 0 || round > 255) {
    throw new KitError('ARC5 round must be between 1 and 255')
  }
  return createCipher(
    (K: Uint8Array) => _arc5(K, WORD_SIZE, round),
    {
      ALGORITHM: `ARC5-${WORD_SIZE}/${round}`,
      BLOCK_SIZE: WORD_SIZE >> 2,
      KEY_SIZE: 16,
      MIN_KEY_SIZE: 1,
      MAX_KEY_SIZE: 255,
    },
  )
}
