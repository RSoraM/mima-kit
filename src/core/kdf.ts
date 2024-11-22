import type { Hash, KeyHash } from './hash'
import type { U8 } from './utils'
import { Counter, joinBuffer } from './utils'

export interface KDF {
  /**
   * @param {number} k_bit - 期望的密钥长度 / output keying material length
   * @param {Uint8Array} ikm - 输入密钥材料 / input keying material
   * @param {Uint8Array} info - 附加信息 / optional context and application specific information
   */
  (k_bit: number, ikm: Uint8Array, info?: Uint8Array): U8
}

/**
 * ANSI-X9.63 Key Derivation Function
 *
 * ANSI-X9.63 密钥派生函数
 */
export function ANSI_X963_KDF(hash: Hash): KDF {
  const d_bit = hash.DIGEST_SIZE << 3
  return (k_bit: number, ikm: Uint8Array, info = new Uint8Array(0)) => {
    /** Output Keying Material */
    const okm: Uint8Array[] = []

    const counter = new Counter([0, 0, 0, 1])
    for (let okm_bit = 0; okm_bit < k_bit; okm_bit += d_bit) {
      const data = joinBuffer(ikm, counter, info)
      okm.push(hash(data))
      counter.inc()
    }

    return joinBuffer(...okm).slice(0, k_bit >> 3)
  }
}

/**
 * HKDF Key Derivation Function
 *
 * HKDF 密钥派生函数
 */
export function hkdf(k_hash: KeyHash, salt = new Uint8Array(k_hash.DIGEST_SIZE)): KDF {
  const d_bit = k_hash.DIGEST_SIZE << 3
  return (k_bit: number, ikm: Uint8Array, info = new Uint8Array(0)) => {
    /** Pseudo-Random Key */
    const prk = k_hash(salt)(ikm)
    /** Output Keying Material */
    const okm: Uint8Array[] = []

    const counter = new Uint8Array([1])
    let prv = new Uint8Array(0)
    for (let okm_bit = 0; okm_bit < k_bit; okm_bit += d_bit) {
      prv = k_hash(prk)(joinBuffer(prv, info, counter))
      okm.push(prv)
      counter[0]++
    }

    return joinBuffer(...okm).slice(0, k_bit >> 3)
  }
}

/**
 * Password-Based Key Derivation Function 2
 *
 * PBKDF2 密码基础密钥派生函数
 */
export function pbkdf2(k_hash: KeyHash, salt = new Uint8Array(k_hash.DIGEST_SIZE), iterations = 1000): KDF {
  const d_bit = k_hash.DIGEST_SIZE << 3
  return (k_bit: number, ikm: Uint8Array, info = new Uint8Array(0)) => {
    ikm = joinBuffer(ikm, info)

    /** Output Keying Material */
    const okm: Uint8Array[] = []

    let T: Uint8Array
    let U: Uint8Array
    const counter = new Counter([0, 0, 0, 1])
    for (let okm_bit = 0; okm_bit < k_bit; okm_bit += d_bit) {
      T = new Uint8Array(k_hash.DIGEST_SIZE)
      U = joinBuffer(salt, counter)
      for (let i = 0; i < iterations; i++) {
        U = k_hash(ikm)(U)
        T.forEach((_, j) => T[j] ^= U[j])
      }
      okm.push(T)
      counter.inc()
    }

    return joinBuffer(...okm).slice(0, k_bit >> 3)
  }
}
