import { createHash } from '../core/hash'
import { rotateR32 } from '../core/utils'

// * Constants

const K = [0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5, 0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174, 0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA, 0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967, 0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85, 0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070, 0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3, 0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2]

// * Function

const Ch = (x: number, y: number, z: number) => (x & y) ^ ((~x) & z)
const Maj = (x: number, y: number, z: number) => (x & y) ^ (x & z) ^ (y & z)
const Sigma0 = (x: number) => rotateR32(x, 2) ^ rotateR32(x, 13) ^ rotateR32(x, 22)
const Sigma1 = (x: number) => rotateR32(x, 6) ^ rotateR32(x, 11) ^ rotateR32(x, 25)
const sigma0 = (x: number) => rotateR32(x, 7) ^ rotateR32(x, 18) ^ (x >>> 3)
const sigma1 = (x: number) => rotateR32(x, 17) ^ rotateR32(x, 19) ^ (x >>> 10)

// * Algorithm

/**
 * @param {Uint8Array} state - 初始状态
 * @param {Uint8Array} M - 消息
 */
function digest(state: Uint8Array, M: Uint8Array) {
  // * 初始化
  state = state.slice(0)
  const stateView = new DataView(state.buffer)

  const sigBytes = M.byteLength
  const BLOCK_SIZE = 64
  const BLOCK_TOTAL = Math.ceil((sigBytes + 9) / BLOCK_SIZE)
  const BITS_TOTAL = BigInt(sigBytes) << 3n
  if (BITS_TOTAL > 0xFFFFFFFFFFFFFFFFn) {
    throw new Error('Message is too long')
  }

  // * 填充
  const P = new Uint8Array(BLOCK_TOTAL * BLOCK_SIZE)
  P.set(M)

  // appending the bit '1' to the message
  P[sigBytes] = 0x80

  // appending length
  const PView = new DataView(P.buffer)
  PView.setBigUint64(P.byteLength - 8, BITS_TOTAL, false)

  // * 分块处理
  for (let i = 0; i < BLOCK_TOTAL; i++) {
    // 获取当前块
    const currentBlock = P.slice(i * BLOCK_SIZE, (i + 1) * BLOCK_SIZE)
    const view = new DataView(currentBlock.buffer)

    // 准备状态字
    const h0 = stateView.getUint32(0, false)
    const h1 = stateView.getUint32(4, false)
    const h2 = stateView.getUint32(8, false)
    const h3 = stateView.getUint32(12, false)
    const h4 = stateView.getUint32(16, false)
    const h5 = stateView.getUint32(20, false)
    const h6 = stateView.getUint32(24, false)
    const h7 = stateView.getUint32(28, false)
    let a = h0
    let b = h1
    let c = h2
    let d = h3
    let e = h4
    let f = h5
    let g = h6
    let h = h7

    // 合并执行 扩展 & 压缩
    const W = new Uint32Array(64)
    for (let i = 0; i < W.length; i++) {
      // 扩展
      if (i < 16)
        W[i] = view.getUint32(i * 4, false)
      else
        W[i] = sigma1(W[i - 2]) + W[i - 7] + sigma0(W[i - 15]) + W[i - 16]

      // 压缩
      const T1 = h + Sigma1(e) + Ch(e, f, g) + K[i] + W[i]
      const T2 = Sigma0(a) + Maj(a, b, c)
      h = g
      g = f
      f = e
      e = d + T1
      d = c
      c = b
      b = a
      a = T1 + T2
    }

    // 更新状态字
    stateView.setUint32(0, h0 + a, false)
    stateView.setUint32(4, h1 + b, false)
    stateView.setUint32(8, h2 + c, false)
    stateView.setUint32(12, h3 + d, false)
    stateView.setUint32(16, h4 + e, false)
    stateView.setUint32(20, h5 + f, false)
    stateView.setUint32(24, h6 + g, false)
    stateView.setUint32(28, h7 + h, false)
  }

  // * 返回状态
  return state
}

function sha224Digest(M: Uint8Array) {
  // * 初始化 SHA-224 状态
  const state = new Uint8Array(32)
  const stateView = new DataView(state.buffer)
  stateView.setUint32(0, 0xC1059ED8, false)
  stateView.setUint32(4, 0x367CD507, false)
  stateView.setUint32(8, 0x3070DD17, false)
  stateView.setUint32(12, 0xF70E5939, false)
  stateView.setUint32(16, 0xFFC00B31, false)
  stateView.setUint32(20, 0x68581511, false)
  stateView.setUint32(24, 0x64F98FA7, false)
  stateView.setUint32(28, 0xBEFA4FA4, false)

  return digest(state, M).slice(0, 28)
}

function sha256Digest(M: Uint8Array) {
  // * 初始化 SHA-256 状态
  const state = new Uint8Array(32)
  const stateView = new DataView(state.buffer)
  stateView.setUint32(0, 0x6A09E667, false)
  stateView.setUint32(4, 0xBB67AE85, false)
  stateView.setUint32(8, 0x3C6EF372, false)
  stateView.setUint32(12, 0xA54FF53A, false)
  stateView.setUint32(16, 0x510E527F, false)
  stateView.setUint32(20, 0x9B05688C, false)
  stateView.setUint32(24, 0x1F83D9AB, false)
  stateView.setUint32(28, 0x5BE0CD19, false)

  return digest(state, M)
}

/**
 * @description
 * SHA-224 hash algorithm is truncated versions of SHA-256
 *
 * SHA-224 散列算法 是 SHA-256 的截断版本
 *
 * @example
 * ```ts
 * sha224('hello') // 'ea09ae9cc6768c50fcee903ed054556e5bfc8347907f12598aa24193'
 * sha224('hello', B64) // '6gmunMZ2jFD87pA+0FRVblv8g0eQfxJZiqJBkw=='
 * ```
 */
export const sha224 = createHash(
  {
    digest: sha224Digest,
  },
  {
    ALGORITHM: 'SHA-224',
    BLOCK_SIZE: 64,
    DIGEST_SIZE: 28,
  },
)

/**
 * @description
 * SHA-256 hash algorithm
 *
 * SHA-256 散列算法
 *
 * @example
 * ```ts
 * sha256('hello') // '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824'
 * sha256('hello', B64) // 'LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ='
 * ```
 */
export const sha256 = createHash(
  {
    digest: sha256Digest,
  },
  {
    ALGORITHM: 'SHA-256',
    BLOCK_SIZE: 64,
    DIGEST_SIZE: 32,
  },
)
