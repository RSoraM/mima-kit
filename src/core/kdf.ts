import type { Hash, KeyHash } from './hash'
import type { U8 } from './utils'
import { joinBuffer } from './utils'

function inc32(ctr: Uint8Array) {
  const view = new DataView(ctr.buffer)
  let counter = view.getUint32(0, false)
  counter = (counter + 1) % 0xFFFFFFFF
  view.setUint32(0, counter, false)
  return ctr
}

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
    const counter = new Uint8Array([0, 0, 0, 1])

    for (let bits = 0; bits < k_bit; bits += d_bit) {
      const data = joinBuffer(ikm, counter, info)
      okm.push(hash(data))
      inc32(counter)
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
  return (k_bit: number, ikm: Uint8Array, info = new Uint8Array(0)) => {
    const k_byte = k_bit >> 3
    /** Pseudo-Random Key */
    const prk = k_hash(salt)(ikm)
    /** Output Keying Material */
    const okm: Uint8Array[] = []
    const counter = new Uint8Array([1])

    let prv = new Uint8Array(0)
    for (let bytes = 0; bytes < k_byte; bytes += k_hash.DIGEST_SIZE) {
      prv = k_hash(prk)(joinBuffer(prv, info, counter))
      okm.push(prv)
      counter[0]++
    }

    return joinBuffer(...okm).slice(0, k_byte)
  }
}

/**
 * Password-Based Key Derivation Function 2
 *
 * PBKDF2 密码基础密钥派生函数
 */
export function pbkdf2(k_hash: KeyHash, salt = new Uint8Array(k_hash.DIGEST_SIZE), iterations = 1000): KDF {
  return (k_bit: number, ikm: Uint8Array, info = new Uint8Array(0)) => {
    const k_byte = k_bit >> 3
    /** Output Keying Material */
    const okm: Uint8Array[] = []
    const counter = new Uint8Array([0, 0, 0, 1])

    ikm = joinBuffer(ikm, info)
    for (let bytes = 0; bytes < k_byte; bytes += k_hash.DIGEST_SIZE) {
      const T = new Uint8Array(k_hash.DIGEST_SIZE)

      let U = joinBuffer(salt, counter)
      for (let i = 0; i < iterations; i++) {
        U = k_hash(ikm)(U)
        T.forEach((_, i) => T[i] ^= U[i])
      }
      inc32(counter)
      okm.push(T)
    }

    return joinBuffer(...okm).slice(0, k_byte)
  }
}
