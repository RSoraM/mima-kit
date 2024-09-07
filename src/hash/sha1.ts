import { createHash } from '../core/hash'
import { KitError, rotateL32 } from '../core/utils'

// * Constants

function K(t: number) {
  if (t < 20)
    return 0x5A827999
  if (t < 40)
    return 0x6ED9EBA1
  if (t < 60)
    return 0x8F1BBCDC
  return 0xCA62C1D6
}

// * Function

const Ch = (x: number, y: number, z: number) => (x & y) ^ ((~x) & z)
const Parity = (x: number, y: number, z: number) => x ^ y ^ z
const Maj = (x: number, y: number, z: number) => (x & y) ^ (x & z) ^ (y & z)
function ft(x: number, y: number, z: number, t: number) {
  if (t < 20)
    return Ch(x, y, z)
  if (t < 40)
    return Parity(x, y, z)
  if (t < 60)
    return Maj(x, y, z)
  return Parity(x, y, z)
}

// * Algorithm

function digest(M: Uint8Array) {
  // * 初始化
  const state = new Uint8Array(20)
  const stateView = new DataView(state.buffer)
  stateView.setUint32(0, 0x67452301, false)
  stateView.setUint32(4, 0xEFCDAB89, false)
  stateView.setUint32(8, 0x98BADCFE, false)
  stateView.setUint32(12, 0x10325476, false)
  stateView.setUint32(16, 0xC3D2E1F0, false)

  const sigBytes = M.byteLength
  const BLOCK_SIZE = 64
  const BLOCK_TOTAL = Math.ceil((sigBytes + 9) / BLOCK_SIZE)
  const BITS_TOTAL = BigInt(sigBytes) << 3n
  if (BITS_TOTAL > 0xFFFFFFFFFFFFFFFFn) {
    throw new KitError('Message is too long')
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
    const H0 = stateView.getUint32(0, false)
    const H1 = stateView.getUint32(4, false)
    const H2 = stateView.getUint32(8, false)
    const H3 = stateView.getUint32(12, false)
    const H4 = stateView.getUint32(16, false)
    let a = H0
    let b = H1
    let c = H2
    let d = H3
    let e = H4

    // 合并执行 扩展 & 压缩
    const W = new Uint32Array(80)
    for (let i = 0; i < 80; i++) {
      // 扩展
      if (i < 16)
        W[i] = view.getUint32(i * 4, false)
      else
        W[i] = rotateL32(W[i - 3] ^ W[i - 8] ^ W[i - 14] ^ W[i - 16], 1)

      // 压缩
      const T = rotateL32(a, 5) + ft(b, c, d, i) + K(i) + e + W[i]
      e = d
      d = c
      c = rotateL32(b, 30)
      b = a
      a = T
    }

    // 更新状态字
    stateView.setUint32(0, H0 + a, false)
    stateView.setUint32(4, H1 + b, false)
    stateView.setUint32(8, H2 + c, false)
    stateView.setUint32(12, H3 + d, false)
    stateView.setUint32(16, H4 + e, false)
  }

  // * 返回状态
  return state
}

/**
 * @description
 * SHA-1 hash algorithm
 *
 * SHA-1 散列算法
 *
 * @example
 * ```ts
 * sha1('hello') // 'aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d'
 * sha1('hello', B64) // 'qvTGHdzF6KLavt4PO0gs2a6pQ00='
 * ```
 */
export const sha1 = createHash(
  {
    digest,
  },
  {
    ALGORITHM: 'SHA-1',
    BLOCK_SIZE: 64,
    DIGEST_SIZE: 20,
  },
)
