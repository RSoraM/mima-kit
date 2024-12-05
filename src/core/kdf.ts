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
export function x963kdf(hash: Hash): KDF {
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
 * HMAC-based Key Derivation Function (HKDF), please combine `hmac` and `hash` externally to control the behavior of calling `hmac` inside the function.
 *
 * 基于 HMAC 的密钥派生函数 (HKDF), 请在外部组合 `hmac` 和 `hash` 函数, 以控制在函数内部调用 `hmac` 时的行为.
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
 * Password-Based Key Derivation Function 2 (PBKDF2), please combine `hmac` and `hash` externally to control the behavior of calling `hmac` inside the function.
 * Also, PBKDF2 does not use the `info` parameter, if provided, it will be ignored.
 *
 * PBKDF2 密码基础密钥派生函数 (PBKDF2), 请在外部组合 `hmac` 和 `hash` 函数, 以控制在函数内部调用 `hmac` 时的行为.
 * 同时, PBKDF2 不使用 `info` 参数, 如果提供 `info`, 将被忽略.
 */
export function pbkdf2(k_hash: KeyHash, salt = new Uint8Array(k_hash.DIGEST_SIZE), iterations = 1000): KDF {
  const d_bit = k_hash.DIGEST_SIZE << 3
  return (k_bit: number, ikm: Uint8Array) => {
    ikm = joinBuffer(ikm)

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
