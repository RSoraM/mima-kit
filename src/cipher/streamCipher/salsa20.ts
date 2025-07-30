import { createCipher } from '../../core/cipher'
import { Counter, KitError, U8, resizeBuffer, rotateL32 } from '../../core/utils'

// * Functions

// eslint-disable-next-line unused-imports/no-unused-vars
function QR(a: number, b: number, c: number, d: number) {
  b ^= rotateL32(a + d, 7)
  c ^= rotateL32(b + a, 9)
  d ^= rotateL32(c + b, 13)
  a ^= rotateL32(d + c, 18)
  return [a, b, c, d]
}

function hash(x: Uint8Array, rounds: number = 20) {
  // to word
  const X = new Uint32Array(x.buffer)
  const W = X.slice(0)
  // main loop
  for (let i = 0; i < rounds; i += 2) {
    // ODD Rounds
    // [W[0], W[4], W[8], W[12]] = QR(W[0], W[4], W[8], W[12]);
    // [W[5], W[9], W[13], W[1]] = QR(W[5], W[9], W[13], W[1]);
    // [W[10], W[14], W[2], W[6]] = QR(W[10], W[14], W[2], W[6]);
    // [W[15], W[3], W[7], W[11]] = QR(W[15], W[3], W[7], W[11]);
    // EVEN Rounds
    // [W[0], W[1], W[2], W[3]] = QR(W[0], W[1], W[2], W[3]);
    // [W[5], W[6], W[7], W[4]] = QR(W[5], W[6], W[7], W[4]);
    // [W[10], W[11], W[8], W[9]] = QR(W[10], W[11], W[8], W[9]);
    // [W[15], W[12], W[13], W[14]] = QR(W[15], W[12], W[13], W[14])
    W[4] ^= rotateL32(W[0] + W[12], 7)
    W[8] ^= rotateL32(W[4] + W[0], 9)
    W[12] ^= rotateL32(W[8] + W[4], 13)
    W[0] ^= rotateL32(W[12] + W[8], 18)
    W[9] ^= rotateL32(W[5] + W[1], 7)
    W[13] ^= rotateL32(W[9] + W[5], 9)
    W[1] ^= rotateL32(W[13] + W[9], 13)
    W[5] ^= rotateL32(W[1] + W[13], 18)
    W[14] ^= rotateL32(W[10] + W[6], 7)
    W[2] ^= rotateL32(W[14] + W[10], 9)
    W[6] ^= rotateL32(W[2] + W[14], 13)
    W[10] ^= rotateL32(W[6] + W[2], 18)
    W[3] ^= rotateL32(W[15] + W[11], 7)
    W[7] ^= rotateL32(W[3] + W[15], 9)
    W[11] ^= rotateL32(W[7] + W[3], 13)
    W[15] ^= rotateL32(W[11] + W[7], 18)
    W[1] ^= rotateL32(W[0] + W[3], 7)
    W[2] ^= rotateL32(W[1] + W[0], 9)
    W[3] ^= rotateL32(W[2] + W[1], 13)
    W[0] ^= rotateL32(W[3] + W[2], 18)
    W[6] ^= rotateL32(W[5] + W[4], 7)
    W[7] ^= rotateL32(W[6] + W[5], 9)
    W[4] ^= rotateL32(W[7] + W[6], 13)
    W[5] ^= rotateL32(W[4] + W[7], 18)
    W[11] ^= rotateL32(W[10] + W[9], 7)
    W[8] ^= rotateL32(W[11] + W[10], 9)
    W[9] ^= rotateL32(W[8] + W[11], 13)
    W[10] ^= rotateL32(W[9] + W[8], 18)
    W[12] ^= rotateL32(W[15] + W[14], 7)
    W[13] ^= rotateL32(W[12] + W[15], 9)
    W[14] ^= rotateL32(W[13] + W[12], 13)
    W[15] ^= rotateL32(W[14] + W[13], 18)
  }
  // mix
  for (let i = 0; i < 16; i++) {
    W[i] += X[i]
  }
  return new U8(W.buffer)
}

function expand(K: Uint8Array, iv: Uint8Array) {
  if (iv.byteLength !== 8) {
    throw new KitError(`Salsa20 iv must be 8 byte`)
  }

  const S = new Counter(64)
  const S32 = new Uint32Array(S.buffer)
  const K32 = new Uint32Array(K.buffer)
  const N32 = new Uint32Array(iv.buffer)
  switch (K.byteLength) {
    case 16: // use tau
      S32[0] = 0x61707865
      S32[1] = K32[0]
      S32[2] = K32[1]
      S32[3] = K32[2]
      S32[4] = K32[3]
      S32[5] = 0x3120646E
      S32[6] = N32[0]
      S32[7] = N32[1]
      S32[10] = 0x79622D36
      S32[11] = K32[0]
      S32[12] = K32[1]
      S32[13] = K32[2]
      S32[14] = K32[3]
      S32[15] = 0x6B206574
      break
    case 32: // use sigma
      S32[0] = 0x61707865
      S32[1] = K32[0]
      S32[2] = K32[1]
      S32[3] = K32[2]
      S32[4] = K32[3]
      S32[5] = 0x3320646E
      S32[6] = N32[0]
      S32[7] = N32[1]
      S32[10] = 0x79622D32
      S32[11] = K32[4]
      S32[12] = K32[5]
      S32[13] = K32[6]
      S32[14] = K32[7]
      S32[15] = 0x6B206574
      break
    default:
      throw new KitError(`Salsa20 key must be 16 or 32 byte`)
  }

  return S
}

// * Salsa20 Algorithm

function _salsa20(key: Uint8Array, iv: Uint8Array) {
  /** Counter Block */
  const E = expand(key, iv)
  /** Presudo Random Byte Stream */
  let S = hash(E)
  let current = 1

  const cipher = (M: Uint8Array) => {
    const R = U8.from(M)
    const BLOCK_TOTAL = (R.length >> 6) + 1
    if (current > BLOCK_TOTAL) {
      return R.map((byte, i) => byte ^ S[i])
    }
    // Squeeze
    S = resizeBuffer(S, BLOCK_TOTAL << 6)
    while (BLOCK_TOTAL > current) {
      E.inc(32, 8, true)
      S.set(hash(E), current << 6)
      current++
    }
    return R.map((byte, i) => byte ^ S[i])
  }
  return {
    encrypt: (M: Uint8Array) => cipher(M),
    decrypt: (C: Uint8Array) => cipher(C),
  }
}

/**
 * Salsa20 流密码 / Stream Cipher
 */
export const salsa20 = createCipher(
  _salsa20,
  {
    ALGORITHM: 'Salsa20',
    KEY_SIZE: 32,
    MIN_KEY_SIZE: 16,
    MAX_KEY_SIZE: 32,
    IV_SIZE: 8,
    MIN_IV_SIZE: 8,
    MAX_IV_SIZE: 8,
  },
)

export const salsa20Hash = hash
