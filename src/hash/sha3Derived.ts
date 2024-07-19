import { Utf8 } from '../core/codec'
import { createHash } from '../core/hash'
import { joinBuffer } from '../core/utils'
import { sha3, shake128, shake256 } from './sha3'

// * Encode and Padding Function

/**
 * @description
 * 整数编码
 * Inspired by https://github.com/paulmillr/noble-hashes
 *
 * @example
 * ```ts
 * leftEncode(0) // Uint8Array(2) [ 1, 0 ]
 * leftEncode(18446744073709551615n) // Uint8Array(9) [ 8, 255, 255, 255, 255, 255, 255, 255, 255 ]
 * ```
 *
 * @param {number|bigint} x 输入
 */
function leftEncode(x: number | bigint): Uint8Array {
  const result = []
  do {
    let xi
    if (typeof x === 'bigint') {
      xi = x & 0xFFn
      x = x >> 8n
    }
    else {
      xi = x & 0xFF
      x = x >> 8
    }

    result.unshift(Number(xi))
  } while (x > 0)

  result.unshift(result.length)

  return new Uint8Array(result)
}

/**
 * @description
 * 整数编码
 * Inspired by https://github.com/paulmillr/noble-hashes
 *
 * @example
 * ```ts
 * rightEncode(0) // Uint8Array(2) [ 0, 1 ]
 * rightEncode(18446744073709551615n) // Uint8Array(9) [ 255, 255, 255, 255, 255, 255, 255, 255, 8 ]
 * ```
 *
 * @param {number|bigint} x 输入
 */
// eslint-disable-next-line unused-imports/no-unused-vars
function rightEncode(x: number | bigint): Uint8Array {
  const result = []
  do {
    let xi
    if (typeof x === 'bigint') {
      xi = x & 0xFFn
      x = x >> 8n
    }
    else {
      xi = x & 0xFF
      x = x >> 8
    }

    result.unshift(Number(xi))
  } while (x > 0)

  result.push(result.length)

  return new Uint8Array(result)
}

/**
 * @description
 * SP.800-185 2.3.3:
 *
 * bytepad(N, S, w) = left_encode(w) || N || S || 0^z
 *
 * @param N - function-name
 * @param S - customization
 * @param w
 * @returns
 */
function bytepad(X: Uint8Array[], w: number): Uint8Array {
  if (w <= 0) {
    throw new Error('Invalid w')
  }

  // 使用 leftEncode 函数编码 w
  const encodedW = leftEncode(w)

  // z = left_encode(w)||N||S
  // 计算 z 的有效字节长度总和
  // 用于计算填充零字节的数量
  let zByteLength = encodedW.byteLength
  X.forEach(x => zByteLength += x.byteLength)

  // 计算需要填充的零字节的数量
  const zeroByteLength = w - (zByteLength % w)

  return joinBuffer(encodedW, ...X, new Uint8Array(zeroByteLength))
}

/**
 * @description
 * cSHAKE Padding
 * cSHAKE 填充函数
 *
 * 00 || pad10*1
 *
 * @param {number} rBit 吸收量(bit)
 * @param {number} sigByte 原始消息字节
 */
function cShakePadding(rBit: number, sigByte: number) {
  const rByte = rBit >> 3
  const q = rByte - (sigByte % rByte)
  const p = new Uint8Array(q)

  if (q === 1) {
    p[0] = 0x84
    return p
  }

  p[0] = 0x04
  p[q - 1] = 0x80
  return p
}

// * cSHAKE

/**
 * @description
 * cSHAKE128 is a customizable variant of SHAKE128
 * cSHAKE128 是 SHAKE128 的可定制变体
 *
 * @example
 * ```ts
 * cSHAKE128(256,'','password')('hello') // 'd3ff6985c8016860b2e459d92968e8eee9a3843b5bf0658f5a9a2a7e34894380'
 * cSHAKE128(256,'','password')('hello',B64) // '0/9phcgBaGCy5FnZKWjo7umjhDtb8GWPWpoqfjSJQ4A='
 * ```
 * @param d
 * @param N
 * @param S
 */
export function cShake128(d: number, N: string | Uint8Array = '', S: string | Uint8Array = '') {
  N = typeof N === 'string' ? Utf8.parse(N) : N
  S = typeof S === 'string' ? Utf8.parse(S) : S

  if (N.byteLength === 0 && S.byteLength === 0) {
    return shake128(d)
  }

  return createHash(
    (M: Uint8Array) => {
      const P = joinBuffer(
        bytepad([leftEncode(N.byteLength << 3), N, leftEncode(S.byteLength << 3), S], 168),
        M,
      )
      return sha3(256, d, cShakePadding)(P)
    },
    {
      ALGORITHM: `cSHAKE128/${d}`,
      BLOCK_SIZE: 168,
      DIGEST_SIZE: d >> 3,
    },
  )
}

/**
 * @description
 * cSHAKE256 is a customizable variant of SHAKE256
 * cSHAKE256 是 SHAKE256 的可定制变体
 *
 * @example
 * ```ts
 * cSHAKE256(512,'','password')('hello') // 'bf2fffa507ad934fcf169ec14f478e3b1227058e7154314fbadbf318b71bbf1d01b97559dbd43d80b448a24e4f79c7072806107d2ff59b832fb1b6cd215149f7'
 * cSHAKE256(512,'','password')('hello',B64) // 'vy//pQetk0/PFp7BT0eOOxInBY5xVDFPutvzGLcbvx0BuXVZ29Q9gLRIok5PeccHKAYQfS/1m4MvsbbNIVFJ9w=='
 * ```
 * @param d
 * @param N
 * @param S
 */
export function cShake256(d: number, N: string | Uint8Array = '', S: string | Uint8Array = '') {
  N = typeof N === 'string' ? Utf8.parse(N) : N
  S = typeof S === 'string' ? Utf8.parse(S) : S

  if (N.byteLength === 0 && S.byteLength === 0) {
    return shake256(d)
  }

  return createHash(
    (M: Uint8Array) => {
      const P = joinBuffer(
        bytepad([leftEncode(N.byteLength << 3), N, leftEncode(S.byteLength << 3), S], 136),
        M,
      )
      return sha3(512, d, cShakePadding)(P)
    },
    {
      ALGORITHM: `cSHAKE256/${d}`,
      BLOCK_SIZE: 136,
      DIGEST_SIZE: d >> 3,
    },
  )
}

// * KMAC

// TODO
