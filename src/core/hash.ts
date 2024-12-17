import type { U8 } from './utils'
import { wrap } from './utils'

// * 散列函数包装器

export interface Digest {
  /**
   * @param {Uint8Array} M - 消息 / message
   */
  (M: Uint8Array): U8
}
export interface HashDescription {
  /**
   * 算法名称 / Algorithm name
   */
  ALGORITHM: string
  /**
   * 分块大小 / Block size (byte)
   */
  BLOCK_SIZE: number
  /**
   * 摘要大小 / Digest size (byte)
   */
  DIGEST_SIZE: number
  OID?: string
}
export interface Hash extends Digest, HashDescription {
}
/**
 * 散列算法包装器,
 * 提供散列算法描述, 以实现 `HMAC` 等拓展算法.
 *
 * Hash algorithm wrapper,
 * provide hash algorithm description to implement extended algorithms such as `HMAC`.
 *
 * @param {Digest} digest - 摘要函数 / digest function
 * @param {HashDescription} description - 算法描述 / algorithm description
 *
 * ```ts
 * const digest: Digest = (M: Uint8Array): U8 => { ... }
 * const description: HashDescription = { ... }
 * const hash = createHash(digest, description)
 * ```
 */
export const createHash = (digest: Digest, description: HashDescription): Hash => wrap(digest, description)

// * 元组散列函数包装器

export interface TupleDigest {
  /**
   * @param {Uint8Array[]} M - 消息 / message
   */
  (M: Uint8Array[]): U8
}
export interface TupleHashDescription extends HashDescription {
}
export interface TupleHash extends TupleDigest, TupleHashDescription {
}
/**
 * 元组散列算法包装器
 *
 * Tuple hash algorithm wrapper
 *
 * @param {TupleDigest} digest - 元组摘要函数 / tuple digest function
 * @param {TupleHashDescription} description - 算法描述 / algorithm description
 *
 * ```ts
 * const digest: TupleDigest = (M: Uint8Array[]): U8 => { ... }
 * const description: TupleHashDescription = { ... }
 * const hash = createTupleHash(digest, description)
 * ```
 */
export const createTupleHash = (digest: TupleDigest, description: TupleHashDescription): TupleHash => wrap(digest, description)

// * 密钥散列函数

export interface KeyDigest {
  /**
   * @param {Uint8Array} K - 密钥 / key
   * @param {Uint8Array} M - 消息 / message
   */
  (K: Uint8Array, M: Uint8Array): U8
}
export interface KeyHashDescription extends HashDescription {
  /**
   * 推荐的密钥大小 / Recommended key size (byte)
   */
  KEY_SIZE: number
}
/**
 * 密钥散列函数 / Keyed hash function
 */
export interface KeyHash extends KeyDigest, KeyHashDescription {
}
export const createKeyHash = (digest: KeyDigest, description: KeyHashDescription): KeyHash => wrap(digest, description)
