import { createIVStreamCipher } from '../core/cipher'
import { KitError, rotateL32 } from '../core/utils'

// * Functions

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
    [W[0], W[4], W[8], W[12]] = QR(W[0], W[4], W[8], W[12]);
    [W[5], W[9], W[13], W[1]] = QR(W[5], W[9], W[13], W[1]);
    [W[10], W[14], W[2], W[6]] = QR(W[10], W[14], W[2], W[6]);
    [W[15], W[3], W[7], W[11]] = QR(W[15], W[3], W[7], W[11]);
    // EVEN Rounds
    [W[0], W[1], W[2], W[3]] = QR(W[0], W[1], W[2], W[3]);
    [W[5], W[6], W[7], W[4]] = QR(W[5], W[6], W[7], W[4]);
    [W[10], W[11], W[8], W[9]] = QR(W[10], W[11], W[8], W[9]);
    [W[15], W[12], W[13], W[14]] = QR(W[15], W[12], W[13], W[14])
  }
  // mix
  const Z = new Uint8Array(64)
  const Z32 = new Uint32Array(Z.buffer)
  for (let i = 0; i < 16; i++) {
    Z32[i] = X[i] + W[i]
  }
  return Z
}

function expand(K: Uint8Array, iv: Uint8Array) {
  if (iv.byteLength !== 8) {
    throw new KitError(`Salsa20 requires a nonce of 8 bytes`)
  }

  const S = new Uint8Array(64)
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
      throw new KitError(`Salsa20 requires a key of length 16 or 32 bytes`)
  }

  return S
}

// * Salsa20 Algorithm

export const salsa20 = createIVStreamCipher(
  (K: Uint8Array, iv: Uint8Array) => {
    let E = expand(K, iv)
    let S = hash(E)
    let current = 1

    const inc64 = (E: Uint8Array) => {
      const E64 = new BigUint64Array(E.buffer)
      E64[4] += 1n
      return E
    }
    const cipher = (M: Uint8Array) => {
      const BLOCK_TOTAL = (M.byteLength >> 6) + 1
      if (current > BLOCK_TOTAL) {
        return M.map((byte, i) => byte ^ S[i])
      }
      const _S = new Uint8Array(BLOCK_TOTAL << 6)
      _S.set(S, 0)
      S = _S
      while (BLOCK_TOTAL > current) {
        E = inc64(E)
        S.set(hash(E), current << 6)
        current++
      }
      return M.map((byte, i) => byte ^ S[i])
    }
    return {
      encrypt: (M: Uint8Array) => cipher(M),
      decrypt: (C: Uint8Array) => cipher(C),
    }
  },
  {
    ALGORITHM: 'Salsa20',
    KEY_SIZE: 32,
    IV_SIZE: 8,
  },
)
