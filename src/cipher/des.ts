import { KitError } from '../core/utils'
import { createCipherAlgorithm } from '../core/cipherSuite'

// * Constants

const IP = [58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7].map(value => 64 - value)
const FP = [40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25].map(value => 64 - value)
const E = [32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1].map(value => 32 - value)
const PC1 = [57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4].map(value => 64 - value)
const PC2 = [14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32].map(value => 56 - value)
const P = [16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25].map(value => 32 - value)
const KEY_SHIFT = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

const S1 = [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7, 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8, 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0, 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
const S2 = [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10, 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5, 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15, 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
const S3 = [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8, 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1, 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7, 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
const S4 = [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15, 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9, 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4, 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
const S5 = [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9, 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6, 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14, 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
const S6 = [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11, 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8, 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6, 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
const S7 = [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1, 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6, 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2, 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
const S8 = [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7, 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2, 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8, 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]

// * Functions

function permute(input: bigint, table: number[]) {
  let output = 0n
  for (let i = 0; i < table.length; i++) {
    output = output << 1n
    output |= ((input >> BigInt(table[i])) & 0x1n)
  }

  return output
}

function substitute(input: bigint) {
  const s = [S1, S2, S3, S4, S5, S6, S7, S8]

  let output = 0n
  for (let i = 0; i < 8; i++) {
    const word = Number((input >> BigInt(6 * (7 - i))) & 0x3Fn)
    const x = (word >> 1) & 0xF
    const y = (word >> 4) & 0b10 | (word & 0b1)
    const offset = x + (y << 4)
    output = (output << 4n) | BigInt(s[i][offset])
  }

  return output
}

function generateKeys(key: Uint8Array) {
  const k = permute(key.reduce((acc, cur) => (acc << 8n) | BigInt(cur), 0n), PC1)
  const key_set = new Uint8Array(16 * 6)

  let l = 0xFFFFFFFn & (k >> 28n)
  let r = 0xFFFFFFFn & (k)
  for (let i = 0; i < 16; i++) {
    l = ((l << BigInt(KEY_SHIFT[i])) | (l >> 28n - BigInt(KEY_SHIFT[i]))) & 0xFFFFFFFn
    r = ((r << BigInt(KEY_SHIFT[i])) | (r >> 28n - BigInt(KEY_SHIFT[i]))) & 0xFFFFFFFn
    const kr = permute((l << 28n) | r, PC2)
    const offset = i * 6
    key_set[offset + 0] = Number(0xFFn & (kr >> 40n))
    key_set[offset + 1] = Number(0xFFn & (kr >> 32n))
    key_set[offset + 2] = Number(0xFFn & (kr >> 24n))
    key_set[offset + 3] = Number(0xFFn & (kr >> 16n))
    key_set[offset + 4] = Number(0xFFn & (kr >> 8n))
    key_set[offset + 5] = Number(0xFFn & (kr))
  }

  return key_set
}

function reverseKeys(keys: Uint8Array) {
  const key_set = new Uint8Array(keys.byteLength)
  for (let i = 0; i < 16; i++) {
    const offset = keys.byteLength - i * 6
    key_set.set(keys.subarray(offset - 6, offset), i * 6)
  }
  return key_set
}

function isEqual(a: Uint8Array, b: Uint8Array) {
  if (a.byteLength !== b.byteLength) {
    return false
  }

  for (let i = 0; i < a.byteLength; i++) {
    if (a[i] !== b[i]) {
      return false
    }
  }

  return true
}

// * DES

function Cipher(M: Uint8Array, K: Uint8Array) {
  const m = permute(M.reduce((acc, cur) => acc << 8n | BigInt(cur), 0n), IP)
  let l = 0xFFFFFFFFn & (m >> 32n)
  let r = 0xFFFFFFFFn & (m)

  for (let i = 0; i < 16; i++) {
    const offset = i * 6
    const k = K.subarray(offset, offset + 6).reduce((acc, cur) => (acc << 8n) | BigInt(cur), 0n)
    const l_next = r
    r = permute(r, E) ^ k
    r = substitute(r)
    r = permute(r, P) ^ l
    l = l_next
  }

  return permute((r << 32n) | l, FP)
}

export const des = createCipherAlgorithm(
  (K: Uint8Array) => {
    const key_set = generateKeys(K)
    const inv_key_set = reverseKeys(key_set)
    return {
      encrypt: (M: Uint8Array) => {
        const buffer = new ArrayBuffer(8)
        const view = new DataView(buffer)
        view.setBigUint64(0, Cipher(M, key_set), false)
        return new Uint8Array(buffer)
      },
      decrypt: (C: Uint8Array) => {
        const buffer = new ArrayBuffer(8)
        const view = new DataView(buffer)
        view.setBigUint64(0, Cipher(C, inv_key_set), false)
        return new Uint8Array(buffer)
      },
    }
  },
  {
    ALGORITHM: 'DES',
    BLOCK_SIZE: 8,
    KEY_SIZE: 8,
  },
)

export function t_des(k: 128 | 192) {
  return createCipherAlgorithm(
    (K: Uint8Array) => {
      if (K.byteLength !== k >> 3) {
        throw new KitError(`Key length must be ${k >> 3} bytes`)
      }
      const K1 = K.subarray(0, 8)
      const K2 = K.subarray(8, 16)
      const K3 = k === 128 ? K1 : K.subarray(16, 24)
      if (isEqual(K1, K2) || (k === 192 && (isEqual(K1, K3) || isEqual(K2, K3)))) {
        console.warn('mima-kit: Weak key detected in 3DES')
      }

      const d1 = des(K1)
      const d2 = des(K2)
      const d3 = des(K3)
      return {
        encrypt: (M: Uint8Array) => d3.encrypt(d2.decrypt(d1.encrypt(M))),
        decrypt: (C: Uint8Array) => d1.decrypt(d2.encrypt(d3.decrypt(C))),
      }
    },
    {
      ALGORITHM: '3DES',
      BLOCK_SIZE: 8,
      KEY_SIZE: k >> 3,
    },
  )
}
