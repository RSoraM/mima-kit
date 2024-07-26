import { createHash } from '../core/hash'
import { rotateR64 } from '../core/utils'
import { Utf8 } from '../core/codec'

// * Constants

const K = [0x428A2F98D728AE22n, 0x7137449123EF65CDn, 0xB5C0FBCFEC4D3B2Fn, 0xE9B5DBA58189DBBCn, 0x3956C25BF348B538n, 0x59F111F1B605D019n, 0x923F82A4AF194F9Bn, 0xAB1C5ED5DA6D8118n, 0xD807AA98A3030242n, 0x12835B0145706FBEn, 0x243185BE4EE4B28Cn, 0x550C7DC3D5FFB4E2n, 0x72BE5D74F27B896Fn, 0x80DEB1FE3B1696B1n, 0x9BDC06A725C71235n, 0xC19BF174CF692694n, 0xE49B69C19EF14AD2n, 0xEFBE4786384F25E3n, 0x0FC19DC68B8CD5B5n, 0x240CA1CC77AC9C65n, 0x2DE92C6F592B0275n, 0x4A7484AA6EA6E483n, 0x5CB0A9DCBD41FBD4n, 0x76F988DA831153B5n, 0x983E5152EE66DFABn, 0xA831C66D2DB43210n, 0xB00327C898FB213Fn, 0xBF597FC7BEEF0EE4n, 0xC6E00BF33DA88FC2n, 0xD5A79147930AA725n, 0x06CA6351E003826Fn, 0x142929670A0E6E70n, 0x27B70A8546D22FFCn, 0x2E1B21385C26C926n, 0x4D2C6DFC5AC42AEDn, 0x53380D139D95B3DFn, 0x650A73548BAF63DEn, 0x766A0ABB3C77B2A8n, 0x81C2C92E47EDAEE6n, 0x92722C851482353Bn, 0xA2BFE8A14CF10364n, 0xA81A664BBC423001n, 0xC24B8B70D0F89791n, 0xC76C51A30654BE30n, 0xD192E819D6EF5218n, 0xD69906245565A910n, 0xF40E35855771202An, 0x106AA07032BBD1B8n, 0x19A4C116B8D2D0C8n, 0x1E376C085141AB53n, 0x2748774CDF8EEB99n, 0x34B0BCB5E19B48A8n, 0x391C0CB3C5C95A63n, 0x4ED8AA4AE3418ACBn, 0x5B9CCA4F7763E373n, 0x682E6FF3D6B2B8A3n, 0x748F82EE5DEFB2FCn, 0x78A5636F43172F60n, 0x84C87814A1F0AB72n, 0x8CC702081A6439ECn, 0x90BEFFFA23631E28n, 0xA4506CEBDE82BDE9n, 0xBEF9A3F7B2C67915n, 0xC67178F2E372532Bn, 0xCA273ECEEA26619Cn, 0xD186B8C721C0C207n, 0xEADA7DD6CDE0EB1En, 0xF57D4F7FEE6ED178n, 0x06F067AA72176FBAn, 0x0A637DC5A2C898A6n, 0x113F9804BEF90DAEn, 0x1B710B35131C471Bn, 0x28DB77F523047D84n, 0x32CAAB7B40C72493n, 0x3C9EBE0A15C9BEBCn, 0x431D67C49C100D4Cn, 0x4CC5D4BECB3E42B6n, 0x597F299CFC657E2An, 0x5FCB6FAB3AD6FAECn, 0x6C44198C4A475817n]

// * Function

const Ch = (x: bigint, y: bigint, z: bigint) => (x & y) ^ ((~x) & z)
const Maj = (x: bigint, y: bigint, z: bigint) => (x & y) ^ (x & z) ^ (y & z)
const Sigma0 = (x: bigint) => rotateR64(x, 28n) ^ rotateR64(x, 34n) ^ rotateR64(x, 39n)
const Sigma1 = (x: bigint) => rotateR64(x, 14n) ^ rotateR64(x, 18n) ^ rotateR64(x, 41n)
const sigma0 = (x: bigint) => rotateR64(x, 1n) ^ rotateR64(x, 8n) ^ (x >> 7n)
const sigma1 = (x: bigint) => rotateR64(x, 19n) ^ rotateR64(x, 61n) ^ (x >> 6n)

// * Algorithm

/**
 * @description
 * SHA-384 & SHA-512 & SHA-512/t common function
 * SHA-384 & SHA-512 & SHA-512/t 通用函数
 *
 * @param {Uint8Array} status - 工作变量
 * @param {Uint8Array} M - 消息
 */
function sha384_512(status: Uint8Array, M: Uint8Array) {
  // * 初始化
  const statusView = new DataView(status.buffer)

  const sigBytes = M.byteLength
  const BLOCK_SIZE = 128
  const BLOCK_TOTAL = Math.ceil((sigBytes + 17) / BLOCK_SIZE)
  const BITS_TOTAL = BigInt(sigBytes) << 3n
  if (BITS_TOTAL > 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFn)
    throw new Error('Message is too long')

  // * 填充
  const P = new Uint8Array(BLOCK_TOTAL * BLOCK_SIZE)
  P.set(M)

  // appending the bit '1' to the message
  P[sigBytes] = 0x80

  // appending length
  const dataView = new DataView(P.buffer)
  dataView.setBigUint64(P.byteLength - 16, BITS_TOTAL >> 32n, false)
  dataView.setBigUint64(P.byteLength - 8, BITS_TOTAL & 0xFFFFFFFFFFFFFFFFn, false)

  // * 分块处理
  for (let i = 0; i < BLOCK_TOTAL; i++) {
    // 获取当前块
    const currentBlock = P.slice(i * BLOCK_SIZE, (i + 1) * BLOCK_SIZE)
    const view = new DataView(currentBlock.buffer)

    // 初始化工作变量
    const h0 = statusView.getBigUint64(0, false)
    const h1 = statusView.getBigUint64(8, false)
    const h2 = statusView.getBigUint64(16, false)
    const h3 = statusView.getBigUint64(24, false)
    const h4 = statusView.getBigUint64(32, false)
    const h5 = statusView.getBigUint64(40, false)
    const h6 = statusView.getBigUint64(48, false)
    const h7 = statusView.getBigUint64(56, false)
    let a = h0
    let b = h1
    let c = h2
    let d = h3
    let e = h4
    let f = h5
    let g = h6
    let h = h7

    // 合并执行 扩展 & 压缩
    const W = new BigUint64Array(80)
    for (let i = 0; i < W.length; i++) {
      // 扩展
      if (i < 16)
        W[i] = view.getBigUint64(i << 3, false)
      else
        W[i] = sigma1(W[i - 2]) + W[i - 7] + sigma0(W[i - 15]) + W[i - 16]

      // 压缩
      const T1 = h + Sigma1(e) + Ch(e, f, g) + K[i] + W[i]
      const T2 = Sigma0(a) + Maj(a, b, c)
      h = g
      g = f
      f = e
      e = (d + T1) & 0xFFFFFFFFFFFFFFFFn
      d = c
      c = b
      b = a
      a = (T1 + T2) & 0xFFFFFFFFFFFFFFFFn
    }

    // 更新工作变量
    statusView.setBigUint64(0, h0 + a, false)
    statusView.setBigUint64(8, h1 + b, false)
    statusView.setBigUint64(16, h2 + c, false)
    statusView.setBigUint64(24, h3 + d, false)
    statusView.setBigUint64(32, h4 + e, false)
    statusView.setBigUint64(40, h5 + f, false)
    statusView.setBigUint64(48, h6 + g, false)
    statusView.setBigUint64(56, h7 + h, false)
  }

  // 返回工作变量
  return status
}

/**
 * @description
 * SHA-512/t IV generator
 * SHA-512/t IV 生成函数
 *
 * @example
 * ```
 * (0 < t < 512) && (t !== 384)
 * ```
 *
 * @param {number} t - 截断长度 bit
 */
function IVGen(t: number) {
  if (t <= 0) {
    throw new Error('t must be greater than 0')
  }
  if (t >= 512) {
    throw new Error('t must be less than 512')
  }
  if (t === 384) {
    throw new Error('t must not be 384')
  }

  const status = new Uint8Array(64)
  const statusView = new DataView(status.buffer)
  statusView.setBigUint64(0, 0x6A09E667F3BCC908n ^ 0xA5A5A5A5A5A5A5A5n, false)
  statusView.setBigUint64(8, 0xBB67AE8584CAA73Bn ^ 0xA5A5A5A5A5A5A5A5n, false)
  statusView.setBigUint64(16, 0x3C6EF372FE94F82Bn ^ 0xA5A5A5A5A5A5A5A5n, false)
  statusView.setBigUint64(24, 0xA54FF53A5F1D36F1n ^ 0xA5A5A5A5A5A5A5A5n, false)
  statusView.setBigUint64(32, 0x510E527FADE682D1n ^ 0xA5A5A5A5A5A5A5A5n, false)
  statusView.setBigUint64(40, 0x9B05688C2B3E6C1Fn ^ 0xA5A5A5A5A5A5A5A5n, false)
  statusView.setBigUint64(48, 0x1F83D9ABFB41BD6Bn ^ 0xA5A5A5A5A5A5A5A5n, false)
  statusView.setBigUint64(56, 0x5BE0CD19137E2179n ^ 0xA5A5A5A5A5A5A5A5n, false)

  return sha384_512(status, Utf8.parse(`SHA-512/${t}`))
}

/**
 * @description
 * SHA-384 hash algorithm is truncated versions of SHA-512
 * SHA-384 散列算法 是 SHA-512 的截断版本
 *
 * @example
 * ```ts
 * sha384('hello') // '59e1748777448c69de6b800d7a33bbfb9ff1b463e44354c3553bcdb9c666fa90125a3c79f90397bdf5f6a13de828684f'
 * sha384('hello', B64) // 'WeF0h3dEjGnea4ANejO7+5/xtGPkQ1TDVTvNucZm+pASWjx5+QOXvfX2oT3oKGhP'
 * ```
 */
export const sha384 = createHash(
  (M: Uint8Array) => {
    // * 初始化
    const status = new Uint8Array(64)
    const statusView = new DataView(status.buffer)
    statusView.setBigUint64(0, 0xCBBB9D5DC1059ED8n, false)
    statusView.setBigUint64(8, 0x629A292A367CD507n, false)
    statusView.setBigUint64(16, 0x9159015A3070DD17n, false)
    statusView.setBigUint64(24, 0x152FECD8F70E5939n, false)
    statusView.setBigUint64(32, 0x67332667FFC00B31n, false)
    statusView.setBigUint64(40, 0x8EB44A8768581511n, false)
    statusView.setBigUint64(48, 0xDB0C2E0D64F98FA7n, false)
    statusView.setBigUint64(56, 0x47B5481DBEFA4FA4n, false)

    sha384_512(status, M)

    // * 截断输出
    return status.slice(0, 48)
  },
  {
    ALGORITHM: 'SHA-384',
    BLOCK_SIZE: 128,
    DIGEST_SIZE: 48,
  },
)

/**
 * @description
 * SHA-512 hash algorithm
 * SHA-512 散列算法
 *
 * @example
 * ```ts
 * sha512('hello') // '9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043'
 * sha512('hello', B64) // 'm3HSJL1i83hdltRq0+o9czGb+8KJDKra4t/3JRlnPKcjI8PZm6XBHXx6zG4UuMXaDEZjR1wuXDre9G9zvN7AQw=='
 * ```
 */
export const sha512 = createHash(
  (M: Uint8Array) => {
    // * 初始化
    const status = new Uint8Array(64)
    const statusView = new DataView(status.buffer)
    statusView.setBigUint64(0, 0x6A09E667F3BCC908n, false)
    statusView.setBigUint64(8, 0xBB67AE8584CAA73Bn, false)
    statusView.setBigUint64(16, 0x3C6EF372FE94F82Bn, false)
    statusView.setBigUint64(24, 0xA54FF53A5F1D36F1n, false)
    statusView.setBigUint64(32, 0x510E527FADE682D1n, false)
    statusView.setBigUint64(40, 0x9B05688C2B3E6C1Fn, false)
    statusView.setBigUint64(48, 0x1F83D9ABFB41BD6Bn, false)
    statusView.setBigUint64(56, 0x5BE0CD19137E2179n, false)

    sha384_512(status, M)

    // * 截断输出
    return status
  },
  {
    ALGORITHM: 'SHA-512',
    BLOCK_SIZE: 128,
    DIGEST_SIZE: 64,
  },
)

/**
 * @description
 * SHA-512/t hash algorithm is t-bit hash function base on SHA-512
 * SHA-512/t 散列算法 是基于 SHA-512 的 t 位散列函数
 *
 * @example
 * ```ts
 * sha512t(224)('hello') // 'fe8509ed1fb7dcefc27e6ac1a80eddbec4cb3d2c6fe565244374061c'
 * sha512t(224)('hello', B64) // '/oUJ7R+33O/CfmrBqA7dvsTLPSxv5WUkQ3QGHA=='
 * ```
 *
 * @param {number} t - 截断长度 bit
 */
export function sha512t(t: number) {
  // * 初始化
  const status = IVGen(t)

  // * 返回散列函数
  return createHash(
    (M: Uint8Array) => sha384_512(status.slice(0), M).slice(0, t >> 3),
    {
      ALGORITHM: `SHA-512/${t}`,
      BLOCK_SIZE: 128,
      DIGEST_SIZE: t >> 3,
    },
  )
}
