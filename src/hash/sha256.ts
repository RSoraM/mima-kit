import { createHash } from '../core/hash.js'
import { U8, rotateR32 } from '../core/utils.js'

// * Constants

const K = new Uint32Array([0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5, 0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174, 0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA, 0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967, 0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85, 0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070, 0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3, 0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2])

// * Function

const Ch = (x: number, y: number, z: number) => (x & y) ^ ((~x) & z)
const Maj = (x: number, y: number, z: number) => (x & y) ^ (x & z) ^ (y & z)
const Sigma0 = (x: number) => rotateR32(x, 2) ^ rotateR32(x, 13) ^ rotateR32(x, 22)
const Sigma1 = (x: number) => rotateR32(x, 6) ^ rotateR32(x, 11) ^ rotateR32(x, 25)
const sigma0 = (x: number) => rotateR32(x, 7) ^ rotateR32(x, 18) ^ (x >>> 3)
const sigma1 = (x: number) => rotateR32(x, 17) ^ rotateR32(x, 19) ^ (x >>> 10)

// * Algorithm

function digest(state: U8, message: Uint8Array) {
  // * 初始化
  state = state.slice(0)
  const state_view = state.view(4)

  const m_byte = message.length
  const m_bit = BigInt(m_byte) << 3n
  const block_size = 64
  // ceil((m_byte + 9) / 64)
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
    const h0 = Number(state_view.get(0))
    const h1 = Number(state_view.get(1))
    const h2 = Number(state_view.get(2))
    const h3 = Number(state_view.get(3))
    const h4 = Number(state_view.get(4))
    const h5 = Number(state_view.get(5))
    const h6 = Number(state_view.get(6))
    const h7 = Number(state_view.get(7))
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
        // W[i] = B(n)[i]
        W[i] = p_view.getUint32(offset + (i << 2))
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
    state_view.set(0, BigInt(h0 + a))
    state_view.set(1, BigInt(h1 + b))
    state_view.set(2, BigInt(h2 + c))
    state_view.set(3, BigInt(h3 + d))
    state_view.set(4, BigInt(h4 + e))
    state_view.set(5, BigInt(h5 + f))
    state_view.set(6, BigInt(h6 + g))
    state_view.set(7, BigInt(h7 + h))
  }

  // * 返回状态
  return state
}

function sha224Digest(M: Uint8Array) {
  // * 初始化 SHA-224 状态
  const state = new U8(32)
  const state_view = state.view(4)
  state_view.set(0, 0xC1059ED8n)
  state_view.set(1, 0x367CD507n)
  state_view.set(2, 0x3070DD17n)
  state_view.set(3, 0xF70E5939n)
  state_view.set(4, 0xFFC00B31n)
  state_view.set(5, 0x68581511n)
  state_view.set(6, 0x64F98FA7n)
  state_view.set(7, 0xBEFA4FA4n)

  return digest(state, M).slice(0, 28)
}

function sha256Digest(M: Uint8Array) {
  // * 初始化 SHA-256 状态
  const state = new U8(32)
  const state_view = state.view(4)
  state_view.set(0, 0x6A09E667n)
  state_view.set(1, 0xBB67AE85n)
  state_view.set(2, 0x3C6EF372n)
  state_view.set(3, 0xA54FF53An)
  state_view.set(4, 0x510E527Fn)
  state_view.set(5, 0x9B05688Cn)
  state_view.set(6, 0x1F83D9ABn)
  state_view.set(7, 0x5BE0CD19n)

  return digest(state, M)
}

export const sha224 = createHash(
  sha224Digest,
  {
    ALGORITHM: 'SHA-224',
    BLOCK_SIZE: 64,
    DIGEST_SIZE: 28,
    OID: '2.16.840.1.101.3.4.2.4',
  },
)

export const sha256 = createHash(
  sha256Digest,
  {
    ALGORITHM: 'SHA-256',
    BLOCK_SIZE: 64,
    DIGEST_SIZE: 32,
    OID: '2.16.840.1.101.3.4.2.1',
  },
)
