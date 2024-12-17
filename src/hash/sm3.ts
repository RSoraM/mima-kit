import { createHash } from '../core/hash'
import { KitError, U8, genBitMask, rotateL } from '../core/utils'

// * Function
const mask32 = genBitMask(32)
const rotateL32 = (x: number, n: number) => Number(rotateL(32, x, n, mask32))
const FF = (X: number, Y: number, Z: number, j: number) => j < 16 ? X ^ Y ^ Z : (X & Y) | (X & Z) | (Y & Z)
const GG = (X: number, Y: number, Z: number, j: number) => j < 16 ? X ^ Y ^ Z : (X & Y) | (~X & Z)
const P0 = (X: number) => X ^ rotateL32(X, 9) ^ rotateL32(X, 17)
const P1 = (X: number) => X ^ rotateL32(X, 15) ^ rotateL32(X, 23)

// * Algorithm

function digest(M: Uint8Array) {
  // * 初始化
  const state = new U8(32)
  const state_view = state.view(4)
  state_view.set(0, 0x7380166Fn)
  state_view.set(1, 0x4914B2B9n)
  state_view.set(2, 0x172442D7n)
  state_view.set(3, 0xDA8A0600n)
  state_view.set(4, 0xA96F30BCn)
  state_view.set(5, 0x163138AAn)
  state_view.set(6, 0xE38DEE4Dn)
  state_view.set(7, 0xB0FB0E4En)

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

  // * 迭代压缩
  for (let i = 0; i < BLOCK_TOTAL; i++) {
    /** B(n) */
    const currentBlock = P.slice(i * BLOCK_SIZE, (i + 1) * BLOCK_SIZE)
    const view = new DataView(currentBlock.buffer)

    // 准备状态字
    const H0 = Number(state_view.get(0))
    const H1 = Number(state_view.get(1))
    const H2 = Number(state_view.get(2))
    const H3 = Number(state_view.get(3))
    const H4 = Number(state_view.get(4))
    const H5 = Number(state_view.get(5))
    const H6 = Number(state_view.get(6))
    const H7 = Number(state_view.get(7))
    let A = H0
    let B = H1
    let C = H2
    let D = H3
    let E = H4
    let F = H5
    let G = H6
    let H = H7

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

    // 更新状态字
    state_view.set(0, BigInt(H0 ^ A))
    state_view.set(1, BigInt(H1 ^ B))
    state_view.set(2, BigInt(H2 ^ C))
    state_view.set(3, BigInt(H3 ^ D))
    state_view.set(4, BigInt(H4 ^ E))
    state_view.set(5, BigInt(H5 ^ F))
    state_view.set(6, BigInt(H6 ^ G))
    state_view.set(7, BigInt(H7 ^ H))
  }

  // * 截断输出
  return state
}

export const sm3 = createHash(
  digest,
  {
    ALGORITHM: 'SM3',
    BLOCK_SIZE: 64,
    DIGEST_SIZE: 32,
    OID: '1.2.156.10197.1.401',
  },
)
