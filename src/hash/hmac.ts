import type { Codec } from '../core/codec'
import { HEX, UTF8 } from '../core/codec'
import type { Digest, Hash, HashDescription } from '../core/hash'
import { createHash } from '../core/hash'

export interface HMACScheme {
  hash: Hash
  key: string | Uint8Array
  /**
   * @default UTF8
   */
  KEY_CODEC?: Codec
  /**
   * if provided `INPUT_CODEC`, use `INPUT_CODEC`, else use `hash.INPUT_CODEC`
   *
   * 如果提供了 `INPUT_CODEC`，则使用 `INPUT_CODEC`，否则使用 `hash.INPUT_CODEC`
   */
  INPUT_CODEC?: Codec
  /**
   * if provided `OUTPUT_CODEC`, use `OUTPUT_CODEC`, else use `hash.OUTPUT_CODEC`
   *
   * 如果提供了 `OUTPUT_CODEC`，则使用 `OUTPUT_CODEC`，否则使用 `hash.OUTPUT_CODEC`
   */
  OUTPUT_CODEC?: Codec
}

export interface HMACDescription extends HashDescription { }

export interface HMAC extends HMACDescription {
  digest: Digest
  (M: string | Uint8Array): string
  (M: string | Uint8Array, codec: Codec): string
  INPUT_CODEC: Codec
  OUTPUT_CODEC: Codec
}

/**
 * @description
 * FIPS.198-1: The Keyed-Hash Message Authentication Code (HMAC).
 *
 * FIPS.198-1: 散列消息认证码 (HMAC).
 *
 * @example
 * ```ts
 * const scheme: HMACScheme = {
 *   hash: sha256,
 *   key: 'key',
 *   key_codec: HEX,
 *   input_codec: UTF8,
 *   output_codec: HEX,
 * }
 * const hmac_sha256 = hmac(scheme)
 * ```
 *
 * @param {HMACScheme} scheme - HMAC scheme
 */
export function hmac(scheme: HMACScheme): HMAC {
  // * 初始化
  const { hash, key, KEY_CODEC = UTF8 } = scheme
  const { digest, ALGORITHM, BLOCK_SIZE, DIGEST_SIZE } = hash
  const INPUT_CODEC = scheme.INPUT_CODEC || hash.INPUT_CODEC || UTF8
  const OUTPUT_CODEC = scheme.OUTPUT_CODEC || hash.OUTPUT_CODEC || HEX

  // * 密钥处理
  const K0 = new Uint8Array(BLOCK_SIZE)
  const K = typeof key === 'string' ? KEY_CODEC.parse(key) : key
  K0.set(K.byteLength > BLOCK_SIZE ? digest(K) : K)
  const iPad = K0.map(byte => (byte ^ 0x36))
  const oPad = K0.map(byte => (byte ^ 0x5C))

  const hmac = (M: Uint8Array) => {
    // 内层
    let innerBuffer = new Uint8Array(iPad.byteLength + M.byteLength)
    innerBuffer.set(iPad)
    innerBuffer.set(M, iPad.byteLength)
    innerBuffer = digest(innerBuffer)
    // 外层
    const outerBuffer = new Uint8Array(oPad.byteLength + innerBuffer.byteLength)
    outerBuffer.set(oPad)
    outerBuffer.set(innerBuffer, oPad.byteLength)
    // 返回
    return digest(outerBuffer)
  }

  // * 创建 HMAC-HASH 函数
  return createHash(
    {
      digest: hmac,
      INPUT_CODEC,
      OUTPUT_CODEC,
    },
    {
      ALGORITHM: `HMAC-${ALGORITHM}`,
      BLOCK_SIZE,
      DIGEST_SIZE,
    },
  )
}
