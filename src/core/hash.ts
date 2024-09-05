import type { Codec } from './codec'
import { HEX, UTF8 } from './codec'

export type Digest = (M: Uint8Array) => Uint8Array
export type TupleDigest = (M: Uint8Array[]) => Uint8Array

// * 散列算法包装器

export interface HashScheme {
  digest: Digest
  /**
   * @default UTF8
   */
  INPUT_CODEC?: Codec
  /**
   * @default HEX
   */
  OUTPUT_CODEC?: Codec
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
}

/**
 * @description
 * Hash algorithm
 *
 * 散列算法
 */
export interface Hash extends HashDescription {
  digest: Digest
  (M: string | Uint8Array, codec?: Codec): string
  INPUT_CODEC: Codec
  OUTPUT_CODEC: Codec
}

/**
 * @description
 * Create a hash algorithm based on the scheme
 *
 * 根据方案创建散列算法
 *
 * Request hash algorithm description to implement extended algorithms such as `HMAC`
 *
 * 提供散列算法描述, 以实现 `HMAC` 等拓展算法.
 *
 * @example
 * ```ts
 * const scheme: HashScheme = { ... }
 * const description: HashDescription = { ... }
 * const hash = createHash(scheme, description)
 * ```
 *
 * @param {HashScheme} scheme - 散列方案
 * @param {HashDescription} description - 算法描述
 */
export function createHash(scheme: HashScheme, description: HashDescription): Hash {
  const { digest, INPUT_CODEC = UTF8, OUTPUT_CODEC = HEX } = scheme
  const _description = {
    digest,
    INPUT_CODEC,
    OUTPUT_CODEC,
    ...description,
  }

  return Object.freeze(Object.assign(
    (M: string | Uint8Array, codec?: Codec) => {
      M = typeof M === 'string' ? INPUT_CODEC.parse(M) : M
      const status = digest(M)
      codec = codec || OUTPUT_CODEC
      return codec.stringify(status)
    },
    _description,
  ))
}

// * 元组散列函数包装器

export interface TupleHashScheme {
  digest: TupleDigest
  /**
   * @default UTF8
   */
  INPUT_CODEC?: Codec
  /**
   * @default HEX
   */
  OUTPUT_CODEC?: Codec
}

export interface TupleHashDescription extends HashDescription { }

/**
 * @description
 * Tuple Hash algorithm
 *
 * 元组散列算法
 */
export interface TupleHash extends TupleHashDescription {
  digest: TupleDigest
  (M: Array<string | Uint8Array>, codec?: Codec): string
  INPUT_CODEC: Codec
  OUTPUT_CODEC: Codec
}

/**
 * @description
 * Create a tuple hash algorithm based on the scheme
 *
 * 根据方案创建元组散列算法
 *
 * @example
 * ```ts
 * const scheme: TupleHashScheme = { ... }
 * const description: TupleHashDescription = { ... }
 * const tupleHash = createTupleHash(scheme, description)
 * ```
 *
 * @param {TupleHashScheme} scheme - 元组散列方案
 * @param {TupleHashDescription} description - 算法描述
 */
export function createTupleHash(scheme: TupleHashScheme, description: TupleHashDescription): TupleHash {
  const { digest, INPUT_CODEC = UTF8, OUTPUT_CODEC = HEX } = scheme
  const _description = {
    digest,
    INPUT_CODEC,
    OUTPUT_CODEC,
    ...description,
  }

  return Object.freeze(Object.assign(
    (M: Array<string | Uint8Array>, codec?: Codec) => {
      const status = digest(M.map(s => typeof s === 'string' ? INPUT_CODEC.parse(s) : s))
      codec = codec || OUTPUT_CODEC
      return codec.stringify(status)
    },
    _description,
  ))
}
