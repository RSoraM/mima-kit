import type { U8 } from './utils'
import { wrap } from './utils'

// * 散列函数包装器

export interface Digest {
  (M: Uint8Array): U8
}
export interface HashDescription {
  /**
   * Algorithm name
   *
   * 算法名称
   */
  ALGORITHM: string
  /**
   * Block size (byte)
   *
   * 分块大小 (byte)
   */
  BLOCK_SIZE: number
  /**
   * Digest size (byte)
   *
   * 摘要大小 (byte)
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
 * @example
 * ```ts
 * const digest: Digest = (M: Uint8Array): U8 => { ... }
 * const description: HashDescription = { ... }
 * const hash = createHash(digest, description)
 * ```
 */
export const createHash = (digest: Digest, description: HashDescription): Hash => wrap(digest, description)

// * 元组散列函数包装器

export interface TupleDigest {
  (M: Uint8Array[]): U8
}
export interface TupleHashDescription extends HashDescription {
}
export interface TupleHash extends TupleDigest, TupleHashDescription {
  digest: TupleDigest
}
/**
 * 元组散列算法包装器
 *
 * Tuple hash algorithm wrapper
 *
 * @param {TupleDigest} digest - 元组摘要函数 / tuple digest function
 * @param {TupleHashDescription} description - 算法描述 / algorithm description
 * @example
 * ```ts
 * const digest: TupleDigest = (M: Uint8Array[]): U8 => { ... }
 * const description: TupleHashDescription = { ... }
 * const hash = createTupleHash(digest, description)
 * ```
 */
export const createTupleHash = (digest: TupleDigest, description: TupleHashDescription): TupleHash => wrap(digest, { digest, ...description })

// * 密钥散列函数

export interface KeyHashDescription extends HashDescription {
  /**
   * Recommended key size (byte)
   *
   * 推荐的密钥大小 (字节)
   */
  KEY_SIZE: number
}
export interface KeyHash extends KeyHashDescription {
  (K: Uint8Array): Hash
}
