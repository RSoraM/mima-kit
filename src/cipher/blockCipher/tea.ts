import { createCipher } from '../../core/cipher'
import { KitError } from '../../core/utils'

// * Constants

const DELTA = 0x9E3779B9

// * Tiny Encryption Algorithm (TEA)

function _tea(K: Uint8Array, round: number) {
  if (K.byteLength !== 16) {
    throw new KitError('TEA requires a key of length 16 bytes')
  }
  const K32 = new Uint32Array(K.buffer)

  const encrypt = (M: Uint8Array) => {
    if (M.byteLength !== 8) {
      throw new KitError('TEA requires a block of length 8 bytes')
    }
    const C = M.slice(0)
    const C32 = new Uint32Array(C.buffer)
    let sum = 0
    for (let i = 0; i < round; i++) {
      sum += DELTA
      C32[0] += ((C32[1] << 4) + K32[0]) ^ (C32[1] + sum) ^ ((C32[1] >>> 5) + K32[1])
      C32[1] += ((C32[0] << 4) + K32[2]) ^ (C32[0] + sum) ^ ((C32[0] >>> 5) + K32[3])
    }
    return C
  }
  const decrypt = (C: Uint8Array) => {
    if (C.byteLength !== 8) {
      throw new KitError('TEA requires a block of length 8 bytes')
    }
    const M = C.slice(0)
    const M32 = new Uint32Array(M.buffer)
    let sum = 0xC6EF3720
    for (let i = 0; i < round; i++) {
      M32[1] -= ((M32[0] << 4) + K32[2]) ^ (M32[0] + sum) ^ ((M32[0] >>> 5) + K32[3])
      M32[0] -= ((M32[1] << 4) + K32[0]) ^ (M32[1] + sum) ^ ((M32[1] >>> 5) + K32[1])
      sum -= DELTA
    }
    return M
  }
  return { encrypt, decrypt }
}

function _xtea(K: Uint8Array, round: number) {
  if (K.byteLength !== 16) {
    throw new KitError('TEA requires a key of length 16 bytes')
  }
  const K32 = new Uint32Array(K.buffer)

  const encrypt = (M: Uint8Array) => {
    if (M.byteLength !== 8) {
      throw new KitError('TEA requires a block of length 8 bytes')
    }
    const C = M.slice(0)
    const C32 = new Uint32Array(C.buffer)
    let sum = 0
    for (let i = 0; i < round; i++) {
      C32[0] += (C32[1] << 4 ^ C32[1] >>> 5) + C32[1] ^ sum + K32[sum & 3]
      sum += DELTA
      C32[1] += (C32[0] << 4 ^ C32[0] >>> 5) + C32[0] ^ sum + K32[(sum >>> 11) & 3]
    }
    return C
  }
  const decrypt = (C: Uint8Array) => {
    if (C.byteLength !== 8) {
      throw new KitError('TEA requires a block of length 8 bytes')
    }
    const M = C.slice(0)
    const M32 = new Uint32Array(M.buffer)
    let sum = DELTA << 5
    for (let i = 0; i < round; i++) {
      M32[1] -= ((M32[0] << 4 ^ M32[0] >>> 5) + M32[0]) ^ (sum + K32[(sum >>> 11) & 3])
      sum -= DELTA
      M32[0] -= ((M32[1] << 4 ^ M32[1] >>> 5) + M32[1]) ^ (sum + K32[sum & 3])
    }
    return M
  }
  return { encrypt, decrypt }
}

/**
 * @description
 * Tiny Encryption Algorithm (TEA) block cipher algorithm.
 *
 * 微型加密算法 (TEA) 分组密码算法.
 *
 * @param {number} round - (default: 32)
 */
export function tea(round: number = 32) {
  if (round <= 0) {
    throw new KitError('TEA requires a positive number of rounds')
  }
  return createCipher(
    (K: Uint8Array) => _tea(K, round),
    {
      ALGORITHM: 'TEA',
      BLOCK_SIZE: 8,
      KEY_SIZE: 16,
    },
  )
}

/**
 * @description
 * eXtended Tiny Encryption Algorithm (XTEA) block cipher algorithm.
 *
 * 扩展微型加密算法 (XTEA) 分组密码算法.
 *
 * @param {number} round - (default: 32)
 */
export function xtea(round: number = 32) {
  if (round <= 0) {
    throw new KitError('XTEA requires a positive number of rounds')
  }
  return createCipher(
    (K: Uint8Array) => _xtea(K, round),
    {
      ALGORITHM: 'XTEA',
      BLOCK_SIZE: 8,
      KEY_SIZE: 16,
    },
  )
}
