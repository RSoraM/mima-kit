import type { Codec } from './codec'
import { Hex, Utf8 } from './codec'

/** Hash 描述接口 */
interface AlgorithmDescription {
  ALGORITHM: string
  BLOCK_SIZE: number
  DIGEST_SIZE: number
}

/** Hash 函数接口 */
type Digest = (M: Uint8Array) => Uint8Array

/** Hash 算法接口 */
export interface Hash {
  // 默认调用签名
  (input: string | Uint8Array, codec?: Codec): string
  // 原始函数
  digest: Digest
  // 算法描述
  ALGORITHM: string
  BLOCK_SIZE: number
  DIGEST_SIZE: number
}

/** 创建 Hash 函数 */
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
