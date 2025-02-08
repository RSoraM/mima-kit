import { createHash } from '../core/hash.js'
import { U8, rotateL32 } from '../core/utils.js'

// * Constants

/**
 * 轮常量列表 K 由 64 个 32 位无符号整数组成, 使用 1 到 64 的正弦函数生成.
 *
 * The round constants K is a list of 64 32-bit unsigned integers,
 * generated by the sine function from 1 to 64.
 *
 * ```ts
 * const K: number[] = []
 * for (let i = 0; i < 64; i++) {
 *   K[i] = (Math.abs(Math.sin(i + 1)) * 0x100000000) >>> 0
 * }
 * ```
 */
const K = new Uint32Array([0xD76AA478, 0xE8C7B756, 0x242070DB, 0xC1BDCEEE, 0xF57C0FAF, 0x4787C62A, 0xA8304613, 0xFD469501, 0x698098D8, 0x8B44F7AF, 0xFFFF5BB1, 0x895CD7BE, 0x6B901122, 0xFD987193, 0xA679438E, 0x49B40821, 0xF61E2562, 0xC040B340, 0x265E5A51, 0xE9B6C7AA, 0xD62F105D, 0x02441453, 0xD8A1E681, 0xE7D3FBC8, 0x21E1CDE6, 0xC33707D6, 0xF4D50D87, 0x455A14ED, 0xA9E3E905, 0xFCEFA3F8, 0x676F02D9, 0x8D2A4C8A, 0xFFFA3942, 0x8771F681, 0x6D9D6122, 0xFDE5380C, 0xA4BEEA44, 0x4BDECFA9, 0xF6BB4B60, 0xBEBFBC70, 0x289B7EC6, 0xEAA127FA, 0xD4EF3085, 0x04881D05, 0xD9D4D039, 0xE6DB99E5, 0x1FA27CF8, 0xC4AC5665, 0xF4292244, 0x432AFF97, 0xAB9423A7, 0xFC93A039, 0x655B59C3, 0x8F0CCC92, 0xFFEFF47D, 0x85845DD1, 0x6FA87E4F, 0xFE2CE6E0, 0xA3014314, 0x4E0811A1, 0xF7537E82, 0xBD3AF235, 0x2AD7D2BB, 0xEB86D391])

// * Function

function FF(a: number, b: number, c: number, d: number, m: number, s: number, k: number) {
  const n = a + ((b & c) | (~b & d)) + m + k
  return rotateL32(n, s) + b
}

function GG(a: number, b: number, c: number, d: number, m: number, s: number, k: number) {
  const n = a + ((b & d) | (c & ~d)) + m + k
  return rotateL32(n, s) + b
}

function HH(a: number, b: number, c: number, d: number, m: number, s: number, k: number) {
  const n = a + (b ^ c ^ d) + m + k
  return rotateL32(n, s) + b
}

function II(a: number, b: number, c: number, d: number, m: number, s: number, k: number) {
  const n = a + (c ^ (b | ~d)) + m + k
  return rotateL32(n, s) + b
}

// * Algorithm

function digest(message: Uint8Array) {
  // * 初始化
  const state = new Uint32Array([0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476])

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
  p_view.setBigUint64(p.length - 8, m_bit, true)

  // * 分块处理
  for (let offset = 0; offset < p.length;) {
    // 获取分块
    const current_buffer = p.subarray(offset, offset += block_size).buffer

    // 准备状态字
    const A = state[0]
    const B = state[1]
    const C = state[2]
    const D = state[3]
    let a = A
    let b = B
    let c = C
    let d = D

    // 划分词典
    const M = new Uint32Array(current_buffer)

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

    // 更新状态字
    state[0] = A + a
    state[1] = B + b
    state[2] = C + c
    state[3] = D + d
  }

  // * 返回状态
  return new U8(state.buffer)
}

export const md5 = createHash(
  digest,
  {
    ALGORITHM: 'MD5',
    BLOCK_SIZE: 64,
    DIGEST_SIZE: 16,
    OID: '1.2.840.113549.2.5',
  },
)
