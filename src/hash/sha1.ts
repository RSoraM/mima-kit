import { createHash } from '../core/hash'
import { rotateL } from '../core/utils'

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

/**
 * ### SHA-1
 *
 * @description
 * SHA-1 hash algorithm <br>
 * SHA-1 散列算法
 *
 * @example
 * sha1('hello') // 'aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d'
 * sha1('hello', B64) // 'qvTGHdzF6KLavt4PO0gs2a6pQ00='
 *
 * @param {string | Uint8Array} input 输入
 * @param {Codec} codec 输出编解码器
 */
export const sha1 = createHash(
  (M: Uint8Array) => {
    // * 初始化
    const status = new Uint8Array(20)
    const statusView = new DataView(status.buffer)
    statusView.setUint32(0, 0x67452301, false)
    statusView.setUint32(4, 0xEFCDAB89, false)
    statusView.setUint32(8, 0x98BADCFE, false)
    statusView.setUint32(12, 0x10325476, false)
    statusView.setUint32(16, 0xC3D2E1F0, false)

    const sigBytes = M.byteLength
    const BLOCK_SIZE = 64
    const BLOCK_TOTAL = Math.ceil((sigBytes + 9) / BLOCK_SIZE)
    const BITS_TOTAL = BigInt(sigBytes) << 3n
    if (BITS_TOTAL > 0xFFFFFFFFFFFFFFFFn)
      throw new Error('Message is too long')

    // * 填充
    const P = new Uint8Array(BLOCK_TOTAL * BLOCK_SIZE)
    P.set(M)

    // appending the bit '1' to the message
    P[sigBytes] = 0x80

    // appending length
    const dataView = new DataView(P.buffer)
    dataView.setBigUint64(P.byteLength - 8, BITS_TOTAL, false)

    // * 分块处理
    for (let i = 0; i < BLOCK_TOTAL; i++) {
      // 获取当前块
      const currentBlock = P.slice(i * BLOCK_SIZE, (i + 1) * BLOCK_SIZE)
      const view = new DataView(currentBlock.buffer)

      // 初始化工作变量
      const h0 = statusView.getUint32(0, false)
      const h1 = statusView.getUint32(4, false)
      const h2 = statusView.getUint32(8, false)
      const h3 = statusView.getUint32(12, false)
      const h4 = statusView.getUint32(16, false)
      let a = h0
      let b = h1
      let c = h2
      let d = h3
      let e = h4

      // 合并执行 扩展 & 压缩
      const W = new Uint32Array(80)
      for (let i = 0; i < 80; i++) {
        // 扩展
        if (i < 16)
          W[i] = view.getUint32(i * 4, false)
        else
          W[i] = rotateL(W[i - 3] ^ W[i - 8] ^ W[i - 14] ^ W[i - 16], 1)

        // 压缩
        const T = rotateL(a, 5) + ft(b, c, d, i) + K(i) + e + W[i]
        e = d
        d = c
        c = rotateL(b, 30)
        b = a
        a = T
      }

      // 更新工作变量
      statusView.setUint32(0, h0 + a, false)
      statusView.setUint32(4, h1 + b, false)
      statusView.setUint32(8, h2 + c, false)
      statusView.setUint32(12, h3 + d, false)
      statusView.setUint32(16, h4 + e, false)
    }

    // * 截断输出
    return status
  },
  {
    ALGORITHM: 'SHA-1',
    BLOCK_SIZE: 64,
    DIGEST_SIZE: 20,
  },
)
