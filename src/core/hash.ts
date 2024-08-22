import type { Codec } from './codec'
import { HEX, UTF8 } from './codec'

// * 散列函数包装器

/**
 * @description
 * Digest function interface
 *
 * 散列函数的接口
 */
interface Digest {
  (M: Uint8Array): Uint8Array
}

/**
 * @description
 * Hash algorithm description interface
 *
 * 散列算法的描述接口
 *
 * @property {string} ALGORITHM - 算法名称
 * @property {number} BLOCK_SIZE - 分块大小
 * @property {number} DIGEST_SIZE - 摘要大小
 */
interface HashDescription {
  ALGORITHM: string
  BLOCK_SIZE: number
  DIGEST_SIZE: number
}

/**
 * @description
 * Hash algorithm interface
 *
 * 散列算法的接口
 */
export interface Hash extends HashDescription {
  /**
   * @param {string | Uint8Array} M - 输入
   * @param {Codec} codec - 输出编解码器(default: Hex)
   */
  (M: string | Uint8Array, codec?: Codec): string
  digest: Digest
}

/**
 * @description
 * Create a wrapper for the digest function
 *
 * 为散列函数创建一个包装
 *
 * The wrapper function records the description of the digest function for the implementation of related extended algorithms such as `HMAC`.
 *
 * 包装函数记录了散列函数的描述信息, 以便实现 `HMAC` 等相关拓展算法.
 *
 * @example
 * ```ts
 * const hash = createHash((M: Uint8Array) => Uint8Array, {...})
 * ```
 *
 * @param {Digest} digest - 散列函数
 * @param {HashDescription} description - 算法描述
 */
export function createHash(digest: Digest, description: HashDescription): Hash {
  return Object.assign(
    (M: string | Uint8Array, codec: Codec = HEX) => {
      M = typeof M == 'string' ? UTF8.parse(M) : M
      const status = digest(M)
      return codec.stringify(status)
    },
    {
      ...description,
      digest,
    },
  )
}

// * 元组散列函数包装器

/**
 * @description
 * Digest function interface
 *
 * 元组散列函数的接口
 *
 * @param {Uint8Array} M - 输入
 */
type TupleDigest = (M: Uint8Array[]) => Uint8Array

/**
 * @description
 * Hash algorithm interface
 *
 * 元组散列算法的接口
 */
export interface TupleHash extends HashDescription {
  /**
   * @description
   * Hash function with automatic input conversion and optional output encoding
   *
   * 自动转换输入且可自定义输出编码的元组散列函数
   *
   * @param {Array<string | Uint8Array>} input - 输入
   * @param {Codec} codec - 输出编解码器
   */
  (input: Array<string | Uint8Array>, codec?: Codec): string

  digest: TupleDigest
}

/**
 * @description
 * Create a wrapper for the tuple digest function
 *
 * 为元组散列函数创建一个包装
 *
 * @example
 * ```ts
 * const hash = createTupleHash((M: Uint8Array[]) => Uint8Array, {...})
 * ```
 *
 * @param {TupleDigest} digest - 散列函数
 * @param {HashDescription} description - 算法描述
 */
export function createTupleHash(digest: TupleDigest, description: HashDescription): TupleHash {
  return Object.assign(
    (input: Array<string | Uint8Array>, codec: Codec = HEX) => {
      input = input.map(s => typeof s === 'string' ? UTF8.parse(s) : s)
      const status = digest(input as Uint8Array[])
      return codec.stringify(status)
    },
    {
      ...description,
      digest,
    },
  )
}
