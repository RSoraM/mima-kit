import { createCipher } from '../core/cipher'
import { KitError, joinBuffer, rotateL128, rotateL16, rotateL32, rotateL64, rotateL8, rotateR128, rotateR16, rotateR32, rotateR64, rotateR8 } from '../core/utils'

// const Eul = [0xB7, 0xE1, 0x51, 0x62, 0x8A, 0xED, 0x2A, 0x6A, 0xBF, 0x71, 0x58, 0x80, 0x9C, 0xF4, 0xF3, 0xC7, 0x62, 0xE7, 0x16, 0x0F, 0x38, 0xB4, 0xDA, 0x56, 0xA7, 0x84, 0xD9, 0x04, 0x51, 0x90, 0xCF, 0xEF]
// const Phi = [0x9E, 0x37, 0x79, 0xB9, 0x7F, 0x4A, 0x7C, 0x15, 0xF3, 0x9C, 0xC0, 0x60, 0x5C, 0xED, 0xC8, 0x34, 0x10, 0x82, 0x27, 0x6B, 0xF3, 0xA2, 0x72, 0x51, 0xF8, 0x6C, 0x6A, 0x11, 0xD0, 0xC1, 0x8E, 0x95]
// const P = Eul{0,...,w-1} - 2) | 1
// const Q = Phi{0,...,w-1} - 2) | 1

// * Functions

function setup8(K: Uint8Array, r: number) {
  const P = 0xB7
  const Q = 0x9F
  // Break the key into 8-bit words
  const L = K.byteLength === 0
    ? new Uint8Array(1)
    : K.slice(0)
  const c = L.length
  // Initialize key-independent pseudorandom S array
  const t = (r + 1) << 1
  const S = new Uint8Array(t)
  S[0] = P
  for (let i = 1; i < t; i++) {
    S[i] = S[i - 1] + Q
  }
  // The main key scheduling loop
  let i = 0
  let j = 0
  let A = 0
  let B = 0
  const v = 3 * Math.max(c, t)
  for (let k = 0; k < v; k++) {
    A = S[i] = rotateL8(S[i] + A + B, 3)
    B = L[j] = rotateL8(L[j] + A + B, A + B)
    i = (i + 1) % t
    j = (j + 1) % c
  }
  return S
}
function encrypt8(M: Uint8Array, S: Uint8Array, r: number) {
  const C = M.slice(0)
  C[0] += S[0]
  C[1] += S[1]
  for (let i = 1; i <= r; i++) {
    C[0] = rotateL8(C[0] ^ C[1], C[1] % 8)
    C[0] += S[(i << 1)]
    C[1] = rotateL8(C[1] ^ C[0], C[0] % 8)
    C[1] += S[(i << 1) + 1]
  }
  return C
}
function decrypt8(C: Uint8Array, S: Uint8Array, r: number) {
  const M = C.slice(0)
  for (let i = r; i > 0; i--) {
    M[1] -= S[(i << 1) + 1]
    M[1] = rotateR8(M[1], M[0] % 8) ^ M[0]
    M[0] -= S[(i << 1)]
    M[0] = rotateR8(M[0], M[1] % 8) ^ M[1]
  }
  M[0] -= S[0]
  M[1] -= S[1]
  return M
}

function setup16(K: Uint8Array, r: number) {
  const P = 0xB7E1
  const Q = 0x9E37
  // Break the key into 16-bit words
  const l = K.byteLength === 0
    ? new Uint8Array(2)
    : joinBuffer(K, new Uint8Array(K.byteLength % 2))
  const L = new Uint16Array(l.buffer)
  const c = L.length
  // Initialize key-independent pseudorandom S array
  const t = (r + 1) << 1
  const S = new Uint16Array(t)
  S[0] = P
  for (let i = 1; i < t; i++) {
    S[i] = S[i - 1] + Q
  }
  // The main key scheduling loop
  let i = 0
  let j = 0
  let A = 0
  let B = 0
  const v = 3 * Math.max(c, t)
  for (let k = 0; k < v; k++) {
    A = S[i] = rotateL16(S[i] + A + B, 3)
    B = L[j] = rotateL16(L[j] + A + B, A + B)
    i = (i + 1) % t
    j = (j + 1) % c
  }
  return new Uint8Array(S.buffer)
}
function encrypt16(M: Uint8Array, S: Uint8Array, r: number) {
  const C = M.slice(0)
  const C16 = new Uint16Array(C.buffer)
  const S16 = new Uint16Array(S.buffer)
  C16[0] += S16[0]
  C16[1] += S16[1]
  for (let i = 1; i <= r; i++) {
    C16[0] = rotateL16(C16[0] ^ C16[1], C16[1] % 16)
    C16[0] += S16[(i << 1)]
    C16[1] = rotateL16(C16[1] ^ C16[0], C16[0] % 16)
    C16[1] += S16[(i << 1) + 1]
  }
  return C
}
function decrypt16(C: Uint8Array, S: Uint8Array, r: number) {
  const M = C.slice(0)
  const M16 = new Uint16Array(M.buffer)
  const S16 = new Uint16Array(S.buffer)
  for (let i = r; i > 0; i--) {
    M16[1] -= S16[(i << 1) + 1]
    M16[1] = rotateR16(M16[1], M16[0] % 16) ^ M16[0]
    M16[0] -= S16[i << 1]
    M16[0] = rotateR16(M16[0], M16[1] % 16) ^ M16[1]
  }
  M16[0] -= S16[0]
  M16[1] -= S16[1]
  return M
}

function setup32(K: Uint8Array, r: number) {
  const P = 0xB7E15163
  const Q = 0x9E3779B9
  // Break the key into 32-bit words
  const l = K.byteLength === 0
    ? new Uint8Array(4)
    : joinBuffer(K, new Uint8Array(K.byteLength % 4))
  const L = new Uint32Array(l.buffer)
  const c = L.length
  // Initialize key-independent pseudorandom S array
  const t = (r + 1) << 1
  const S = new Uint32Array(t)
  S[0] = P
  for (let i = 1; i < t; i++) {
    S[i] = S[i - 1] + Q
  }
  // The main key scheduling loop
  let i = 0
  let j = 0
  let A = 0
  let B = 0
  const v = 3 * Math.max(c, t)
  for (let k = 0; k < v; k++) {
    A = S[i] = rotateL32(S[i] + A + B, 3)
    B = L[j] = rotateL32(L[j] + A + B, A + B)
    i = (i + 1) % t
    j = (j + 1) % c
  }
  return new Uint8Array(S.buffer)
}
function encrypt32(M: Uint8Array, S: Uint8Array, r: number) {
  const C = M.slice(0)
  const C32 = new Uint32Array(C.buffer)
  const S32 = new Uint32Array(S.buffer)
  C32[0] += S32[0]
  C32[1] += S32[1]
  for (let i = 1; i <= r; i++) {
    C32[0] = rotateL32(C32[0] ^ C32[1], C32[1] % 32)
    C32[0] += S32[(i << 1)]
    C32[1] = rotateL32(C32[1] ^ C32[0], C32[0] % 32)
    C32[1] += S32[(i << 1) + 1]
  }
  return C
}
function decrypt32(C: Uint8Array, S: Uint8Array, r: number) {
  const M = C.slice(0)
  const M32 = new Uint32Array(M.buffer)
  const S32 = new Uint32Array(S.buffer)
  for (let i = r; i > 0; i--) {
    M32[1] -= S32[(i << 1) + 1]
    M32[1] = rotateR32(M32[1], M32[0] % 32) ^ M32[0]
    M32[0] -= S32[i << 1]
    M32[0] = rotateR32(M32[0], M32[1] % 32) ^ M32[1]
  }
  M32[0] -= S32[0]
  M32[1] -= S32[1]
  return M
}

function setup64(K: Uint8Array, r: number) {
  const P = 0xB7E151628AED2A6Bn
  const Q = 0x9E3779B97F4A7C15n
  // Break the key into 64-bit words
  const l = K.byteLength === 0
    ? new Uint8Array(8)
    : joinBuffer(K, new Uint8Array(K.byteLength % 8))
  const L = new BigUint64Array(l.buffer)
  const c = L.length
  // Initialize key-independent pseudorandom S array
  const t = (r + 1) << 1
  const S = new BigUint64Array(t)
  S[0] = P
  for (let i = 1; i < t; i++) {
    S[i] = S[i - 1] + Q
  }
  // The main key scheduling loop
  let i = 0
  let j = 0
  let A = 0n
  let B = 0n
  const v = 3 * Math.max(c, t)
  for (let k = 0; k < v; k++) {
    A = S[i] = rotateL64(S[i] + A + B, 3n)
    B = L[j] = rotateL64(L[j] + A + B, A + B)
    i = (i + 1) % t
    j = (j + 1) % c
  }
  return new Uint8Array(S.buffer)
}
function encrypt64(M: Uint8Array, S: Uint8Array, r: number) {
  const C = M.slice(0)
  const C64 = new BigUint64Array(C.buffer)
  const S64 = new BigUint64Array(S.buffer)
  C64[0] += S64[0]
  C64[1] += S64[1]
  for (let i = 1; i <= r; i++) {
    C64[0] = rotateL64(C64[0] ^ C64[1], C64[1] % 64n)
    C64[0] += S64[(i << 1)]
    C64[1] = rotateL64(C64[1] ^ C64[0], C64[0] % 64n)
    C64[1] += S64[(i << 1) + 1]
  }
  return C
}
function decrypt64(C: Uint8Array, S: Uint8Array, r: number) {
  const M = C.slice(0)
  const M64 = new BigUint64Array(M.buffer)
  const S64 = new BigUint64Array(S.buffer)
  for (let i = r; i > 0; i--) {
    M64[1] -= S64[(i << 1) + 1]
    M64[1] = rotateR64(M64[1], M64[0]) ^ M64[0]
    M64[0] -= S64[(i << 1)]
    M64[0] = rotateR64(M64[0], M64[1]) ^ M64[1]
  }
  M64[0] -= S64[0]
  M64[1] -= S64[1]
  return M
}

function setup128(K: Uint8Array, r: number) {
  const P = 0xB7E151628AED2A6ABF7158809CF4F3C7n
  const Q = 0x9E3779B97F4A7C15F39CC0605CEDC835n
  // Break the key into 64-bit words
  const c = K.byteLength === 0
    ? 1
    : (K.byteLength + (K.byteLength % 16)) >> 4
  const L = Array.from<bigint>({ length: c }).fill(0n);
  (function breakKey() {
    const K64 = new BigUint64Array(K.buffer)
    // littel-endian
    for (let i = 0; i < c; i++) {
      L[i] = K64[(i << 1)] | (K64[(i << 1) + 1] << 64n)
    }
  })()
  const t = (r + 1) << 1
  const S = Array.from<bigint>({ length: t }).fill(0n);
  (function initS() {
    S[0] = P
    for (let i = 1; i < t; i++) {
      S[i] = S[i - 1] + Q
      S[i] &= 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFn
    }
  })()
  let i = 0
  let j = 0
  let A = 0n
  let B = 0n
  const v = 3 * Math.max(c, t)
  for (let k = 0; k < v; k++) {
    A = S[i] = rotateL128(S[i] + A + B, 3n)
    B = L[j] = rotateL128(L[j] + A + B, A + B)
    i = (i + 1) % t
    j = (j + 1) % c
  }
  const R = new BigUint64Array(t << 1)
  S.forEach((v, i) => {
    const h = v & 0xFFFFFFFFFFFFFFFFn
    const l = v >> 64n
    R[(i << 1)] = h
    R[(i << 1) + 1] = l
  })
  return new Uint8Array(R.buffer)
}
function encrypt128(M: Uint8Array, S: Uint8Array, r: number) {
  const C = M.slice(0)
  const C64 = new BigUint64Array(C.buffer)
  const S64 = new BigUint64Array(S.buffer)
  let C0 = C64[0] | C64[1] << 64n
  let C1 = C64[2] | C64[3] << 64n
  C0 += S64[0] | S64[1] << 64n
  C0 &= 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFn
  C1 += S64[2] | S64[3] << 64n
  C1 &= 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFn
  for (let i = 1; i <= r; i++) {
    C0 = rotateL128(C0 ^ C1, C1)
    C0 += S64[(i << 2) + 0] | S64[(i << 2) + 1] << 64n
    C0 &= 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFn
    C1 = rotateL128(C1 ^ C0, C0)
    C1 += S64[(i << 2) + 2] | S64[(i << 2) + 3] << 64n
    C1 &= 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFn
  }
  C64[0] = C0 & 0xFFFFFFFFFFFFFFFFn
  C64[1] = C0 >> 64n
  C64[2] = C1 & 0xFFFFFFFFFFFFFFFFn
  C64[3] = C1 >> 64n
  return C
}
function decrypt128(C: Uint8Array, S: Uint8Array, r: number) {
  const M = C.slice(0)
  const M64 = new BigUint64Array(M.buffer)
  const S64 = new BigUint64Array(S.buffer)
  let M0 = M64[0] | M64[1] << 64n
  let M1 = M64[2] | M64[3] << 64n
  for (let i = r; i > 0; i--) {
    M1 -= S64[(i << 2) + 2] | S64[(i << 2) + 3] << 64n
    M1 &= 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFn
    M1 = rotateR128(M1, M0) ^ M0
    M0 -= S64[(i << 2) + 0] | S64[(i << 2) + 1] << 64n
    M0 &= 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFn
    M0 = rotateR128(M0, M1) ^ M1
  }
  M0 -= S64[0] | S64[1] << 64n
  M0 &= 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFn
  M1 -= S64[2] | S64[3] << 64n
  M1 &= 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFn

  M64[0] = M0 & 0xFFFFFFFFFFFFFFFFn
  M64[1] = M0 >> 64n
  M64[2] = M1 & 0xFFFFFFFFFFFFFFFFn
  M64[3] = M1 >> 64n
  return M
}

// * ARC5 Algorithm

/**
 * @description
 * ARC5 Algorithm recommended using a key length of at least 16 bytes
 *
 * ARC5 算法推荐使用长度至少为 16 字节的密钥
 *
 * @example
 * ```ts
 * const spec8 = arc5(8, 8) // ARC5-8/8
 * const spec16 = arc5(16, 12) // ARC5-16/12
 * const spec32 = arc5(32, 16) // ARC5-32/16 (default)
 * const spec64 = arc5(64, 20) // ARC5-64/20
 * const spec128 = arc5(128, 24) // ARC5-128/24
 * ```
 *
 * @param {16 | 32 | 64} WORD_SIZE - default 32 bit
 * @param {number} round - default 16
 */
export function arc5(WORD_SIZE: 8 | 16 | 32 | 64 | 128 = 32, round: number = 16) {
  if (round <= 0 || round > 255) {
    throw new KitError('ARC5 requires a positive number of rounds less than 256')
  }
  return createCipher(
    (K: Uint8Array) => {
      let S: Uint8Array
      let _encrypt: (M: Uint8Array) => Uint8Array
      let _decrypt: (C: Uint8Array) => Uint8Array
      switch (WORD_SIZE) {
        case 8:
          S = setup8(K, round)
          _encrypt = (M: Uint8Array) => encrypt8(M, S, round)
          _decrypt = (C: Uint8Array) => decrypt8(C, S, round)
          break
        case 16:
          S = setup16(K, round)
          _encrypt = (M: Uint8Array) => encrypt16(M, S, round)
          _decrypt = (C: Uint8Array) => decrypt16(C, S, round)
          break
        case 32:
          S = setup32(K, round)
          _encrypt = (M: Uint8Array) => encrypt32(M, S, round)
          _decrypt = (C: Uint8Array) => decrypt32(C, S, round)
          break
        case 64:
          S = setup64(K, round)
          _encrypt = (M: Uint8Array) => encrypt64(M, S, round)
          _decrypt = (C: Uint8Array) => decrypt64(C, S, round)
          break
        case 128:
          S = setup128(K, round)
          _encrypt = (M: Uint8Array) => encrypt128(M, S, round)
          _decrypt = (C: Uint8Array) => decrypt128(C, S, round)
          break
        default:
          throw new KitError('ARC5 requires a word size of 8, 16, 32, 64 or 128')
      }
      return {
        encrypt: (M: Uint8Array) => {
          if (M.byteLength !== WORD_SIZE >> 2) {
            throw new KitError(`ARC5 requires a block of length ${WORD_SIZE >> 2} bytes`)
          }
          return _encrypt(M)
        },
        decrypt: (C: Uint8Array) => {
          if (C.byteLength !== WORD_SIZE >> 2) {
            throw new KitError(`ARC5 requires a block of length ${WORD_SIZE >> 2} bytes`)
          }
          return _decrypt(C)
        },
      }
    },
    {
      ALGORITHM: `ARC5-${WORD_SIZE}/${round}`,
      BLOCK_SIZE: WORD_SIZE >> 1,
      KEY_SIZE: 255,
    },
  )
}
