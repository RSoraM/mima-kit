import { createIVStreamCipher } from '../core/cipher'
import { rotateL32 } from '../core/utils'

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
  const xView = new DataView(x.buffer)
  const X = Array.from({ length: 16 }, (_, i) => xView.getUint32(i * 4, true))
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
  const z = new Uint8Array(64)
  const zView = new DataView(z.buffer)
  for (let i = 0; i < 16; i++) {
    zView.setUint32(i * 4, X[i] + W[i], true)
  }
  return z
}

function expand(K: Uint8Array, iv: Uint8Array) {
  if (iv.byteLength !== 8) {
    throw new Error(`Salsa20 requires a nonce of 8 bytes`)
  }

  const S = new Uint8Array(64)
  const SView = new DataView(S.buffer)
  const KView = new DataView(K.buffer)
  const NView = new DataView(iv.buffer)
  switch (K.byteLength) {
    case 16: // use tau
      SView.setUint32(0, 0x61707865, true)
      SView.setUint32(4, KView.getUint32(0, true), true)
      SView.setUint32(8, KView.getUint32(4, true), true)
      SView.setUint32(12, KView.getUint32(8, true), true)
      SView.setUint32(16, KView.getUint32(12, true), true)
      SView.setUint32(20, 0x3120646E, true)
      SView.setUint32(24, NView.getUint32(0, true), true)
      SView.setUint32(28, NView.getUint32(4, true), true)
      SView.setUint32(32, 0, true)
      SView.setUint32(36, 0, true)
      SView.setUint32(40, 0x79622D36, true)
      SView.setUint32(44, KView.getUint32(0, true), true)
      SView.setUint32(48, KView.getUint32(4, true), true)
      SView.setUint32(52, KView.getUint32(8, true), true)
      SView.setUint32(56, KView.getUint32(12, true), true)
      SView.setUint32(60, 0x6B206574, true)
      break
    case 32: // use sigma
      SView.setUint32(0, 0x61707865, true)
      SView.setUint32(4, KView.getUint32(0, true), true)
      SView.setUint32(8, KView.getUint32(4, true), true)
      SView.setUint32(12, KView.getUint32(8, true), true)
      SView.setUint32(16, KView.getUint32(12, true), true)
      SView.setUint32(20, 0x3320646E, true)
      SView.setUint32(24, NView.getUint32(0, true), true)
      SView.setUint32(28, NView.getUint32(4, true), true)
      SView.setUint32(32, 0, true)
      SView.setUint32(36, 0, true)
      SView.setUint32(40, 0x79622D32, true)
      SView.setUint32(44, KView.getUint32(16, true), true)
      SView.setUint32(48, KView.getUint32(20, true), true)
      SView.setUint32(52, KView.getUint32(24, true), true)
      SView.setUint32(56, KView.getUint32(28, true), true)
      SView.setUint32(60, 0x6B206574, true)
      break
    default:
      throw new Error(`Salsa20 requires a key of length 16 or 32 bytes`)
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
      const view = new DataView(E.buffer)
      view.setBigUint64(32, view.getBigUint64(32, true) + 1n, true)
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
