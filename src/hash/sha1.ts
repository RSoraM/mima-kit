import { createHash } from '../core/hash'
import { rotateL32, U8 } from '../core/utils'

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

function digest(message: Uint8Array) {
  // * 初始化
  const state = new U8(20)
  const state_view = state.view(4)
  state_view.set(0, 0x67452301n)
  state_view.set(1, 0xEFCDAB89n)
  state_view.set(2, 0x98BADCFEn)
  state_view.set(3, 0x10325476n)
  state_view.set(4, 0xC3D2E1F0n)

  const m_byte = message.length
  const m_bit = BigInt(m_byte) << 3n
  const block_size = 64
  // ceil((M_BYTE + 9) / 64)
  const block_total = (m_byte + 9 + 63) >> 6

  // * 填充
  const p = new U8(block_total * block_size)
  p.set(message)

  // appending the bit '1' to the message
  p[m_byte] = 0x80

  // appending length
  const p_view = new DataView(p.buffer)
  p_view.setBigUint64(p.length - 8, m_bit)

  // * 分块处理
  for (let offset = 0; offset < p.length; offset += block_size) {
    /** B(n) = p[offset:offset + block_size] */

    // 准备状态字
    const H0 = Number(state_view.get(0))
    const H1 = Number(state_view.get(1))
    const H2 = Number(state_view.get(2))
    const H3 = Number(state_view.get(3))
    const H4 = Number(state_view.get(4))
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
        // W[i] = B(n)[i]
        W[i] = p_view.getUint32(offset + (i << 2))
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
    state_view.set(0, BigInt(H0 + a))
    state_view.set(1, BigInt(H1 + b))
    state_view.set(2, BigInt(H2 + c))
    state_view.set(3, BigInt(H3 + d))
    state_view.set(4, BigInt(H4 + e))
  }

  // * 返回状态
  return state
}

export const sha1 = createHash(
  digest,
  {
    ALGORITHM: 'SHA-1',
    BLOCK_SIZE: 64,
    DIGEST_SIZE: 20,
    OID: '1.3.14.3.2.26',
  },
)
