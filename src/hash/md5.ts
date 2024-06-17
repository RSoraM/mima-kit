import type { Codec } from '../core/codec'
import { Hex, Utf8 } from '../core/codec'
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

export function md5(input: string, codec: Codec = Hex) {
  // * Initialization
  const hashBuffer = new ArrayBuffer(16)
  const hashDV = new DataView(hashBuffer)
  hashDV.setUint32(0, 0x67452301, true)
  hashDV.setUint32(4, 0xEFCDAB89, true)
  hashDV.setUint32(8, 0x98BADCFE, true)
  hashDV.setUint32(12, 0x10325476, true)

  const bytes = new Uint8Array(Utf8.parse(input))
  const sigBytes = bytes.byteLength
  const BLOCK_SIZE = 64
  const BLOCK_TOTAL = Math.ceil((sigBytes + 9) / BLOCK_SIZE)
  const BITS_TOTAL = BigInt(sigBytes * 8)
  if (BITS_TOTAL > 0xFFFFFFFFFFFFFFn)
    throw new Error('Message is too long')

  // * Preprocessing

  const data = new Uint8Array(new ArrayBuffer(BLOCK_TOTAL * BLOCK_SIZE))
  data.set(bytes)

  // appending the bit '1' to the message
  data[sigBytes] = 0x80

  // appending length
  const k = (56 - (sigBytes + 1) % 64) % 64
  const dataDV = new DataView(data.buffer)
  dataDV.setBigUint64(sigBytes + 1 + k, BITS_TOTAL, true)

  // * Processing

  function _doProcess(data: Uint8Array, i: number) {
    // Initialize the five working variables:
    const A = hashDV.getUint32(0, true)
    const B = hashDV.getUint32(4, true)
    const C = hashDV.getUint32(8, true)
    const D = hashDV.getUint32(12, true)
    let a = A
    let b = B
    let c = C
    let d = D

    const currentBlock = data.slice(i * BLOCK_SIZE, (i + 1) * BLOCK_SIZE)
    const dv = new DataView(currentBlock.buffer)

    const M = []
    for (let i = 0; i < 16; i++) {
      M[i] = dv.getUint32(i * 4, true)
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

    // Add this chunk's hash to result so far:
    hashDV.setUint32(0, (A + a) | 0, true)
    hashDV.setUint32(4, (B + b) | 0, true)
    hashDV.setUint32(8, (C + c) | 0, true)
    hashDV.setUint32(12, (D + d) | 0, true)
  }

  for (let i = 0; i < BLOCK_TOTAL; i++)
    _doProcess(data, i)

  // * TRUNCATION

  return codec.stringify(hashBuffer)
}
