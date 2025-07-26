import { salsa20Hash } from '../cipher/streamCipher/salsa20'
import { hmac } from '../hash/hmac'
import { sha256 } from '../hash/sha256'
import type { Hash, KeyHash } from './hash'
import { Counter, U8, joinBuffer } from './utils'

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
    const prk = k_hash(salt, ikm)
    /** Output Keying Material */
    const okm: Uint8Array[] = []

    const counter = new Uint8Array([1])
    let prv = new Uint8Array(0)
    for (let okm_bit = 0; okm_bit < k_bit; okm_bit += d_bit) {
      prv = k_hash(prk, joinBuffer(prv, info, counter))
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
    ikm = U8.from(ikm)

    /** Output Keying Material */
    const okm: Uint8Array[] = []

    let T: Uint8Array
    let U: Uint8Array
    const counter = new Counter([0, 0, 0, 1])
    for (let okm_bit = 0; okm_bit < k_bit; okm_bit += d_bit) {
      T = new Uint8Array(k_hash.DIGEST_SIZE)
      U = joinBuffer(salt, counter)
      for (let i = 0; i < iterations; i++) {
        U = k_hash(ikm, U)
        T.forEach((_, j) => T[j] ^= U[j])
      }
      okm.push(T)
      counter.inc()
    }

    return joinBuffer(...okm).slice(0, k_bit >> 3)
  }
}

/** Scrypt Key Derivation Function, Block Mix */
function scrypt_bm(r: number, B: Uint8Array) {
  const Y = new U8(B.length)
  let X = B.subarray(B.length - 64)
  for (let i = 0; i < 2 * r; i++) {
    const start = i << 6
    const Bi = B.subarray(start, start + 64)
    const T = X.map((_, j) => Bi[j] ^ X[j])
    X = salsa20Hash(T, 8)
    if (i & 1)
      Y.set(X, ((i >> 1) << 6) + (r << 6))
    else
      Y.set(X, (i >> 1) << 6)
  }
  return Y
}
/** Scrypt Key Derivation Function, ROM Mix */
function scrypt_rm(r: number, B: Uint8Array, N: number) {
  const V = new Uint8Array(N * r << 7)
  let X = U8.from(B)
  for (let i = 0; i < N; i++) {
    V.set(X, i * r << 7)
    X = scrypt_bm(r, X)
  }

  const Nn = BigInt(N)
  const start = X.length - 64
  for (let i = 0; i < N; i++) {
    const j = Number(X.subarray(start).toBI(true) % Nn)
    const Vi = V.subarray(j * r << 7, (j + 1) * r << 7)
    X.forEach((_, k) => X[k] ^= Vi[k])
    X = scrypt_bm(r, X)
  }

  return U8.from(X)
}
export function scrypt(salt: Uint8Array, N = 16384, r = 8, p = 1): KDF {
  const kh = hmac(sha256)
  return (k_bit: number, ikm: Uint8Array) => {
    const B = pbkdf2(kh, salt.slice(), 1)(r * p << 10, ikm)
    const T = []
    for (let i = 0; i < p; i++) {
      const Bi = B.subarray(i * r << 7, (i + 1) * r << 7)
      T.push(scrypt_rm(r, Bi, N))
    }

    return pbkdf2(kh, joinBuffer(...T), 1)(k_bit, ikm)
  }
}
