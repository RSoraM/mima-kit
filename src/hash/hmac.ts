import type { Hash } from '../core/hash'
import { createHash } from '../core/hash'
import { UTF8 } from '../core/codec'

/**
 * @description
 * FIPS.198-1: The Keyed-Hash Message Authentication Code (HMAC).
 *
 * FIPS.198-1: 散列消息认证码 (HMAC).
 *
 * @example
 * ```ts
 * hmac(sm3, 'key')('hello')
 * hmac(sm3, 'key')('hello', B64)
 * ```
 *
 * @param {Hash} hash - 散列函数
 * @param {string | Uint8Array} key - 密钥
 */
export function hmac(hash: Hash, key: string | Uint8Array) {
  // * 初始化
  const BLOCK_SIZE = hash.BLOCK_SIZE

  // * 密钥处理
  const K0 = new Uint8Array(BLOCK_SIZE)
  const K = typeof key === 'string' ? UTF8.parse(key) : key
  K0.set(K.byteLength > BLOCK_SIZE ? hash.digest(K) : K)

  const iPad = K0.map(byte => (byte ^ 0x36))
  const oPad = K0.map(byte => (byte ^ 0x5C))

  // * 创建 HMAC-HASH 函数
  return createHash(
    (M: Uint8Array) => {
      // 内层
      let innerBuffer = new Uint8Array(iPad.byteLength + M.byteLength)
      innerBuffer.set(iPad)
      innerBuffer.set(M, iPad.byteLength)
      innerBuffer = hash.digest(innerBuffer)
      // 外层
      const outerBuffer = new Uint8Array(oPad.byteLength + innerBuffer.byteLength)
      outerBuffer.set(oPad)
      outerBuffer.set(innerBuffer, oPad.byteLength)
      // 返回
      return hash.digest(outerBuffer)
    },
    {
      ALGORITHM: `HMAC-${hash.ALGORITHM}`,
      BLOCK_SIZE: hash.BLOCK_SIZE,
      DIGEST_SIZE: hash.DIGEST_SIZE,
    },
  )
}
