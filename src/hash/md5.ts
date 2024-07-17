import { createHash } from '../core/hash'
import { rotateL } from '../core/utils'

// * Constants
const K: number[] = []
for (let i = 0; i < 64; i++) {
  K[i] = (Math.abs(Math.sin(i + 1)) * 0x100000000) | 0
}

// * Function
function FF(a: number, b: number, c: number, d: number, m: number, s: number, k: number) {
  const n = a + ((b & c) | (~b & d)) + m + k
  return rotateL(n, s) + b
}

function GG(a: number, b: number, c: number, d: number, m: number, s: number, k: number) {
  const n = a + ((b & d) | (c & ~d)) + m + k
  return rotateL(n, s) + b
}

function HH(a: number, b: number, c: number, d: number, m: number, s: number, k: number) {
  const n = a + (b ^ c ^ d) + m + k
  return rotateL(n, s) + b
}

function II(a: number, b: number, c: number, d: number, m: number, s: number, k: number) {
  const n = a + (c ^ (b | ~d)) + m + k
  return rotateL(n, s) + b
}

// * Algorithm

/**
 * ### MD5
 *
 * @description
 * MD5 hash algorithm <br>
 * MD5 散列算法
 *
 * @example
 * md5.digest('hello') // Uint8Array
 * md5('hello') // '5d41402abc4b2a76b9719d911017c592'
 * md5('hello', B64) // 'XUQQArxLKnbpdJ2REBfFkA=='
 *
 * @param {string | Uint8Array} input 输入
 * @param {Codec} codec 输出编解码器
 */
export const md5 = createHash(
  (M: Uint8Array) => {
    // * 初始化
    const status = new Uint8Array(16)
    const statusView = new DataView(status.buffer)
    statusView.setUint32(0, 0x67452301, true)
    statusView.setUint32(4, 0xEFCDAB89, true)
    statusView.setUint32(8, 0x98BADCFE, true)
    statusView.setUint32(12, 0x10325476, true)

    const sigBytes = M.byteLength
    const BLOCK_SIZE = 64
    const BLOCK_TOTAL = Math.ceil((sigBytes + 9) / BLOCK_SIZE)
    const BITS_TOTAL = BigInt(sigBytes) << 3n

    // * 填充
    const P = new Uint8Array(BLOCK_TOTAL * BLOCK_SIZE)
    P.set(M)

    // appending the bit '1' to the message
    P[sigBytes] = 0x80

    // appending length
    const dataView = new DataView(P.buffer)
    dataView.setBigUint64(P.byteLength - 8, BITS_TOTAL, true)

    // * 分块处理
    for (let i = 0; i < BLOCK_TOTAL; i++) {
      // 获取分块
      const currentBlock = P.slice(i * BLOCK_SIZE, (i + 1) * BLOCK_SIZE)
      const view = new DataView(currentBlock.buffer)

      // 初始化工作变量
      const A = statusView.getUint32(0, true)
      const B = statusView.getUint32(4, true)
      const C = statusView.getUint32(8, true)
      const D = statusView.getUint32(12, true)
      let a = A
      let b = B
      let c = C
      let d = D

      // 划分词典
      const M = []
      for (let i = 0; i < 16; i++) {
        M[i] = view.getUint32(i * 4, true)
      }

      /* Round 1 */
      a = FF(a, b, c, d, M[0], 7, K[0])
      d = FF(d, a, b, c, M[1], 12, K[1])
      c = FF(c, d, a, b, M[2], 17, K[2])
      b = FF(b, c, d, a, M[3], 22, K[3])
      a = FF(a, b, c, d, M[4], 7, K[4])
      d = FF(d, a, b, c, M[5], 12, K[5])
      c = FF(c, d, a, b, M[6], 17, K[6])
      b = FF(b, c, d, a, M[7], 22, K[7])
      a = FF(a, b, c, d, M[8], 7, K[8])
      d = FF(d, a, b, c, M[9], 12, K[9])
      c = FF(c, d, a, b, M[10], 17, K[10])
      b = FF(b, c, d, a, M[11], 22, K[11])
      a = FF(a, b, c, d, M[12], 7, K[12])
      d = FF(d, a, b, c, M[13], 12, K[13])
      c = FF(c, d, a, b, M[14], 17, K[14])
      b = FF(b, c, d, a, M[15], 22, K[15])

      /* Round 2 */
      a = GG(a, b, c, d, M[1], 5, K[16])
      d = GG(d, a, b, c, M[6], 9, K[17])
      c = GG(c, d, a, b, M[11], 14, K[18])
      b = GG(b, c, d, a, M[0], 20, K[19])
      a = GG(a, b, c, d, M[5], 5, K[20])
      d = GG(d, a, b, c, M[10], 9, K[21])
      c = GG(c, d, a, b, M[15], 14, K[22])
      b = GG(b, c, d, a, M[4], 20, K[23])
      a = GG(a, b, c, d, M[9], 5, K[24])
      d = GG(d, a, b, c, M[14], 9, K[25])
      c = GG(c, d, a, b, M[3], 14, K[26])
      b = GG(b, c, d, a, M[8], 20, K[27])
      a = GG(a, b, c, d, M[13], 5, K[28])
      d = GG(d, a, b, c, M[2], 9, K[29])
      c = GG(c, d, a, b, M[7], 14, K[30])
      b = GG(b, c, d, a, M[12], 20, K[31])

      /* Round 3 */
      a = HH(a, b, c, d, M[5], 4, K[32])
      d = HH(d, a, b, c, M[8], 11, K[33])
      c = HH(c, d, a, b, M[11], 16, K[34])
      b = HH(b, c, d, a, M[14], 23, K[35])
      a = HH(a, b, c, d, M[1], 4, K[36])
      d = HH(d, a, b, c, M[4], 11, K[37])
      c = HH(c, d, a, b, M[7], 16, K[38])
      b = HH(b, c, d, a, M[10], 23, K[39])
      a = HH(a, b, c, d, M[13], 4, K[40])
      d = HH(d, a, b, c, M[0], 11, K[41])
      c = HH(c, d, a, b, M[3], 16, K[42])
      b = HH(b, c, d, a, M[6], 23, K[43])
      a = HH(a, b, c, d, M[9], 4, K[44])
      d = HH(d, a, b, c, M[12], 11, K[45])
      c = HH(c, d, a, b, M[15], 16, K[46])
      b = HH(b, c, d, a, M[2], 23, K[47])

      /* Round 4 */
      a = II(a, b, c, d, M[0], 6, K[48])
      d = II(d, a, b, c, M[7], 10, K[49])
      c = II(c, d, a, b, M[14], 15, K[50])
      b = II(b, c, d, a, M[5], 21, K[51])
      a = II(a, b, c, d, M[12], 6, K[52])
      d = II(d, a, b, c, M[3], 10, K[53])
      c = II(c, d, a, b, M[10], 15, K[54])
      b = II(b, c, d, a, M[1], 21, K[55])
      a = II(a, b, c, d, M[8], 6, K[56])
      d = II(d, a, b, c, M[15], 10, K[57])
      c = II(c, d, a, b, M[6], 15, K[58])
      b = II(b, c, d, a, M[13], 21, K[59])
      a = II(a, b, c, d, M[4], 6, K[60])
      d = II(d, a, b, c, M[11], 10, K[61])
      c = II(c, d, a, b, M[2], 15, K[62])
      b = II(b, c, d, a, M[9], 21, K[63])

      // 更新工作变量
      statusView.setUint32(0, A + a, true)
      statusView.setUint32(4, B + b, true)
      statusView.setUint32(8, C + c, true)
      statusView.setUint32(12, D + d, true)
    }

    // * 截断输出
    return status
  },
  {
    ALGORITHM: 'MD5',
    BLOCK_SIZE: 64,
    DIGEST_SIZE: 16,
  },
)
