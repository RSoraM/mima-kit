import { createHash } from '../core/hash'
import { rotateL32 } from '../core/utils'

// * Function
function FF(X: number, Y: number, Z: number, j: number) {
  if (j < 16)
    return X ^ Y ^ Z
  return (X & Y) | (X & Z) | (Y & Z)
}
function GG(X: number, Y: number, Z: number, j: number) {
  if (j < 16)
    return X ^ Y ^ Z
  return (X & Y) | (~X & Z)
}
const P0 = (X: number) => X ^ rotateL32(X, 9) ^ rotateL32(X, 17)
const P1 = (X: number) => X ^ rotateL32(X, 15) ^ rotateL32(X, 23)

// * Algorithm

/**
 * @description
 * SM3 hash algorithm
 *
 * SM3 散列算法
 *
 * @example
 * ```ts
 * sm3('hello') // 'becbbfaae6548b8bf0cfcad5a27183cd1be6093b1cceccc303d9c61d0a645268'
 * sm3('hello', B64) // 'vsu/quZUi4vwz8rVonGDzRvmCTsczszDA9nGHQpkUmg='
 * ```
 */
export const sm3 = createHash(
  (M: Uint8Array) => {
    // * 初始化
    const status = new Uint8Array(32)
    const statusView = new DataView(status.buffer)
    statusView.setUint32(0, 0x7380166F, false)
    statusView.setUint32(4, 0x4914B2B9, false)
    statusView.setUint32(8, 0x172442D7, false)
    statusView.setUint32(12, 0xDA8A0600, false)
    statusView.setUint32(16, 0xA96F30BC, false)
    statusView.setUint32(20, 0x163138AA, false)
    statusView.setUint32(24, 0xE38DEE4D, false)
    statusView.setUint32(28, 0xB0FB0E4E, false)

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

    // * 迭代压缩
    for (let i = 0; i < BLOCK_TOTAL; i++) {
      /** B(n) */
      const currentBlock = P.slice(i * BLOCK_SIZE, (i + 1) * BLOCK_SIZE)
      const view = new DataView(currentBlock.buffer)

      // 初始化工作变量
      const h0 = statusView.getUint32(0, false)
      const h1 = statusView.getUint32(4, false)
      const h2 = statusView.getUint32(8, false)
      const h3 = statusView.getUint32(12, false)
      const h4 = statusView.getUint32(16, false)
      const h5 = statusView.getUint32(20, false)
      const h6 = statusView.getUint32(24, false)
      const h7 = statusView.getUint32(28, false)
      let A = h0
      let B = h1
      let C = h2
      let D = h3
      let E = h4
      let F = h5
      let G = h6
      let H = h7

      // 合并执行 扩展 & 压缩
      const W = new Uint32Array(68)
      const W1 = new Uint32Array(64)
      for (let i = 0; i < 68; i++) {
        // 拓展 W
        if (i < 16) {
          W[i] = view.getUint32(i * 4, false)
        }
        else {
          W[i] = P1(W[i - 16] ^ W[i - 9] ^ rotateL32(W[i - 3], 15)) ^ rotateL32(W[i - 13], 7) ^ W[i - 6]
        }

        // W1 拓展 & 压缩
        if (i > 3) {
          // W1 拓展
          const j = i - 4
          // W1[j] = W[j] ^ W[j + 4]
          W1[j] = W[j] ^ W[i]

          // 压缩
          const T = j < 16 ? 0x79CC4519 : 0x7A879D8A
          const SS1 = rotateL32(rotateL32(A, 12) + E + rotateL32(T, j), 7)
          const SS2 = SS1 ^ rotateL32(A, 12)
          const TT1 = FF(A, B, C, j) + D + SS2 + W1[j]
          const TT2 = GG(E, F, G, j) + H + SS1 + W[j]
          D = C
          C = rotateL32(B, 9)
          B = A
          A = TT1
          H = G
          G = rotateL32(F, 19)
          F = E
          E = P0(TT2)
        }
      }

      // 更新工作变量
      statusView.setUint32(0, h0 ^ A, false)
      statusView.setUint32(4, h1 ^ B, false)
      statusView.setUint32(8, h2 ^ C, false)
      statusView.setUint32(12, h3 ^ D, false)
      statusView.setUint32(16, h4 ^ E, false)
      statusView.setUint32(20, h5 ^ F, false)
      statusView.setUint32(24, h6 ^ G, false)
      statusView.setUint32(28, h7 ^ H, false)
    }

    // * 截断输出
    return status
  },
  {
    ALGORITHM: 'SM3',
    BLOCK_SIZE: 64,
    DIGEST_SIZE: 32,
  },
)
