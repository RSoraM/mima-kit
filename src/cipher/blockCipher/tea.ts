import type { Padding } from '../../core/cipher.js'
import { PKCS7_PAD, createCipher } from '../../core/cipher.js'
import { KitError, U8 } from '../../core/utils.js'

// * Constants

const DELTA = 0x9E3779B9

// * Tiny Encryption Algorithm (TEA)

function _tea(K: Uint8Array, round: number) {
  if (K.length !== 16) {
    throw new KitError('TEA key must be 16 byte')
  }
  const K32 = new Uint32Array(K.buffer)
  const sum_delta = (DELTA * round) & 0xFFFFFFFF

  const encrypt = (M: Uint8Array) => {
    if (M.length !== 8) {
      throw new KitError('TEA block must be 8 byte')
    }
    const C = U8.from(M.slice(0))
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
    if (C.length !== 8) {
      throw new KitError('TEA block must be 8 byte')
    }
    const M = U8.from(C.slice(0))
    const M32 = new Uint32Array(M.buffer)
    let sum = sum_delta
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
  if (K.length !== 16) {
    throw new KitError('XTEA key must be 16 byte')
  }
  const K32 = new Uint32Array(K.buffer)
  const sum_delta = (DELTA * round) & 0xFFFFFFFF

  const encrypt = (M: Uint8Array) => {
    if (M.length !== 8) {
      throw new KitError('XTEA block must be 8 byte')
    }
    const C = U8.from(M.slice(0))
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
    if (C.length !== 8) {
      throw new KitError('XTEA block must be 8 byte')
    }
    const M = U8.from(C.slice(0))
    const M32 = new Uint32Array(M.buffer)
    let sum = sum_delta
    for (let i = 0; i < round; i++) {
      M32[1] -= ((M32[0] << 4 ^ M32[0] >>> 5) + M32[0]) ^ (sum + K32[(sum >>> 11) & 3])
      sum -= DELTA
      M32[0] -= ((M32[1] << 4 ^ M32[1] >>> 5) + M32[1]) ^ (sum + K32[sum & 3])
    }
    return M
  }
  return { encrypt, decrypt }
}

function _xxtea(K: Uint8Array, padding: Padding, round?: number) {
  if (K.length !== 16) {
    throw new KitError('XXTEA key must be 16 byte')
  }
  const K32 = new Uint32Array(K.buffer)

  const encrypt = (M: Uint8Array) => {
    const C = U8.from(padding(M, 4))
    if (C.length < 8 || C.length % 4 !== 0) {
      throw new KitError('XXTEA block must be a multiple of 4 byte (at least 8 byte)')
    }
    const C32 = new Uint32Array(C.buffer)
    const n = C32.length
    let _round = round || (6 + 52 / n) >>> 0
    let sum = 0
    let y: number
    let z = C32[n - 1]
    let p: number

    while (_round-- > 0) {
      sum += DELTA
      const e = (sum >>> 2) & 3
      for (p = 0; p < n - 1; p++) {
        y = C32[p + 1]
        z = C32[p] += (((z >>> 5 ^ y << 2) + (y >>> 3 ^ z << 4)) ^ ((sum ^ y) + (K32[(p & 3) ^ e] ^ z)))
      }
      y = C32[0]
      z = C32[n - 1] += (((z >>> 5 ^ y << 2) + (y >>> 3 ^ z << 4)) ^ ((sum ^ y) + (K32[(p & 3) ^ e] ^ z)))
    }
    return C
  }
  const decrypt = (C: Uint8Array) => {
    if (C.length % 4 !== 0) {
      throw new KitError('Decryption error')
    }
    const M = U8.from(C.slice(0))
    const M32 = new Uint32Array(M.buffer)
    const n = M32.length
    let _round = round || (6 + 52 / n) >>> 0
    let sum = (DELTA * _round) & 0xFFFFFFFF
    let y = M32[0]
    let z: number
    let p: number
    while (_round-- > 0) {
      const e = (sum >>> 2) & 3
      for (p = n - 1; p > 0; p--) {
        z = M32[p - 1]
        y = M32[p] -= (((z >>> 5 ^ y << 2) + (y >>> 3 ^ z << 4)) ^ ((sum ^ y) + (K32[(p & 3) ^ e] ^ z)))
      }
      z = M32[n - 1]
      y = M32[0] -= (((z >>> 5 ^ y << 2) + (y >>> 3 ^ z << 4)) ^ ((sum ^ y) + (K32[(p & 3) ^ e] ^ z)))
      sum -= DELTA
    }
    return padding(M)
  }
  return { encrypt, decrypt }
}

/**
 * 微型加密算法 (TEA) 分组密码算法
 *
 * Tiny Encryption Algorithm (TEA) block cipher algorithm
 *
 * @param {number} round - 轮数 / Rounds (default: 32)
 */
export function tea(round: number = 32) {
  if (round <= 0) {
    throw new KitError('TEA round must be a positive number')
  }
  return createCipher(
    (K: Uint8Array) => _tea(K, round),
    {
      ALGORITHM: 'TEA',
      BLOCK_SIZE: 8,
      KEY_SIZE: 16,
      MIN_KEY_SIZE: 16,
      MAX_KEY_SIZE: 16,
    },
  )
}

/**
 * 扩展微型加密算法 (XTEA) 分组密码算法
 *
 * eXtended Tiny Encryption Algorithm (XTEA) block cipher algorithm
 *
 * @param {number} round - 轮数 / Rounds (default: 32)
 */
export function xtea(round: number = 32) {
  if (round <= 0) {
    throw new KitError('XTEA round must be a positive number')
  }
  return createCipher(
    (K: Uint8Array) => _xtea(K, round),
    {
      ALGORITHM: 'XTEA',
      BLOCK_SIZE: 8,
      KEY_SIZE: 16,
      MIN_KEY_SIZE: 16,
      MAX_KEY_SIZE: 16,
    },
  )
}

export interface XXTEAConfig {
  /**
   * 分组大小 / Block size (default: 16)
   *
   * `XXTEA` 本身设计用于加密任意数量的数据块。单独使用 `XXTEA` 时，该选项不起作用。
   * 但是，如果需要将 `XXTEA` 用作分组密码和 `工作模式` 一起使用，则可以通过此选项设置分组大小。
   *
   * 注意: 这不是 `XXTEA` 的标准用法且缺乏相关的安全分析。
   *
   * `XXTEA` is natively designed to encrypt arbitrary amounts of data blocks.
   * When used alone, this option does not take effect.
   * However, if you need to use `XXTEA` as a block cipher and use it with `Operation Mode`,
   * you can set the `BLOCK_SIZE` through this option.
   *
   * Note: This is not the standard usage of `XXTEA` and lacks relevant security analysis.
   */
  BLOCK_SIZE?: number
  /**
   * 填充方式 / Padding method (default: PKCS7)
   *
   * 如果要像其他分组密码一样使用 `XXTEA`，例如使用 `CBC` 模式，
   * 应该将 `padding` 设置为 `NO_PAD` 并让 `工作模式` 处理填充。
   *
   * If you want to use `XXTEA` like other block ciphers, such as with `CBC` mode,
   * you should set the `padding` to `NO_PAD` and let the `Operation Mode` handle the padding.
   */
  padding?: Padding
  /**
   * 轮数 / Rounds (default: undefined)
   *
   * `XXTEA` 的轮数可以通过这个选项设置，如果不设置则使用默认的轮数计算方式。
   *
   * The rounds of `XXTEA` can be set through this option,
   * if not set, the default round calculation method will be used.
   */
  round?: number
}

/**
 * 纠正块 TEA (XXTEA) 分组密码算法
 *
 * Corrected Block TEA (XXTEA) block cipher algorithm
 *
 * @param {Padding} [config.padding] - 填充方式 / Padding method (default: PKCS7)
 * @param {number} [config.round] - 轮数 / Rounds (default: undefined)
 * @param {number} [config.BLOCK_SIZE] - 分组大小 / Block size (default: 16)
 */
export function xxtea(config?: XXTEAConfig) {
  const {
    BLOCK_SIZE = 16,
    padding = PKCS7_PAD,
    round,
  } = config ?? {}
  if (BLOCK_SIZE < 8 || BLOCK_SIZE % 4 !== 0) {
    throw new KitError('XXTEA block size must be a multiple of 4 byte (at least 8 byte)')
  }
  return createCipher(
    (K: Uint8Array) => _xxtea(K, padding, round),
    {
      ALGORITHM: 'XXTEA',
      BLOCK_SIZE,
      KEY_SIZE: 16,
      MIN_KEY_SIZE: 16,
      MAX_KEY_SIZE: 16,
    },
  )
}
