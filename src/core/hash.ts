import type { Codec } from './codec'
import { Hex, Utf8 } from './codec'

/**
 * @description
 * Hash algorithm description interface.
 * 散列算法的描述接口
 *
 * @property {string} ALGORITHM - 算法名称
 * @property {number} BLOCK_SIZE - 块大小
 * @property {number} DIGEST_SIZE - 摘要大小
 */
interface AlgorithmDescription {
  ALGORITHM: string
  BLOCK_SIZE: number
  DIGEST_SIZE: number
}

/**
 * @description
 * Digest function interface.
 * 散列函数的接口.
 *
 * @param {Uint8Array} M - 输入
 * @returns {Uint8Array} - 输出
 */
interface Digest {
  (M: Uint8Array): Uint8Array
}

/**
 * @description
 * Hash algorithm interface.
 * 散列算法的接口.
 */
export interface Hash extends AlgorithmDescription {
  /**
   * @description
   * Hash function with automatic input conversion and optional output encoding.
   * 自动转换输入且可自定义输出编码的散列函数.
   *
   * @param {string | Uint8Array} input - 输入
   * @param {Codec} codec - 编解码器
   */
  (input: string | Uint8Array, codec?: Codec): string

  digest: Digest
}

/**
 * @description
 * Create a wrapper for the digest function.
 * 为散列函数创建一个包装.
 *
 * Users usually use `string` as input, but the algorithm is implemented
 * using `ArrayBuffer`. Asking users to convert data types is too verbose.
 * 用户调用时一般使用 `string` 作为输入, 但算法通过 `ArrayBuffer` 实现.
 * 让用户转换数据类型实在过于繁琐.
 *
 * In addition to being user-friendly, the wrapper function can also record
 * the original function and algorithm description information to implement
 * related extended algorithms such as `HMAC`.
 * 除了方便用户使用外, 包装函数还可以记录 原始函数 和 算法描述信息,
 * 以便实现 HMAC 等相关拓展算法.
 *
 * @example
 * ```ts
 * const hash = createHash((M: Uint8Array) => Uint8Array, {...})
 * ```
 *
 * @param {Digest} digest - 散列函数
 * @param {AlgorithmDescription} description - 算法描述
 */
export function createHash(digest: Digest, description: AlgorithmDescription): Hash {
  return Object.assign(
    (input: string | Uint8Array, codec: Codec = Hex) => {
      const M = typeof input == 'string' ? Utf8.parse(input) : input
      const status = digest(M)
      return codec.stringify(status)
    },
    {
      ...description,
      digest,
    },
  )
}
