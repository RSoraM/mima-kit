import { Hex, Utf8 } from '../core/codec'
import type { Codec } from '../core/codec'
import { rotateR } from '../core/utils'

// * Constants
const K = [0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5, 0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174, 0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA, 0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967, 0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85, 0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070, 0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3, 0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2]

// * Function
const Ch = (x: number, y: number, z: number) => (x & y) ^ ((~x) & z)
const Maj = (x: number, y: number, z: number) => (x & y) ^ (x & z) ^ (y & z)
const Sigma0 = (x: number) => rotateR(x, 2) ^ rotateR(x, 13) ^ rotateR(x, 22)
const Sigma1 = (x: number) => rotateR(x, 6) ^ rotateR(x, 11) ^ rotateR(x, 25)
const sigma0 = (x: number) => rotateR(x, 7) ^ rotateR(x, 18) ^ (x >>> 3)
const sigma1 = (x: number) => rotateR(x, 17) ^ rotateR(x, 19) ^ (x >>> 10)

// * Algorithm
export function sha224(input: string, codec: Codec = Hex) {
  // * Initialization
  const hashBuffer = new ArrayBuffer(32)
  const hashDV = new DataView(hashBuffer)
  hashDV.setUint32(0, 0xC1059ED8, false)
  hashDV.setUint32(4, 0x367CD507, false)
  hashDV.setUint32(8, 0x3070DD17, false)
  hashDV.setUint32(12, 0xF70E5939, false)
  hashDV.setUint32(16, 0xFFC00B31, false)
  hashDV.setUint32(20, 0x68581511, false)
  hashDV.setUint32(24, 0x64F98FA7, false)
  hashDV.setUint32(28, 0xBEFA4FA4, false)

  sha224_256(hashBuffer, input)

  return codec.stringify(hashBuffer.slice(0, 28))
}

export function sha256(input: string, codec: Codec = Hex) {
  // * Initialization
  const hashBuffer = new ArrayBuffer(32)
  const hashDV = new DataView(hashBuffer)
  hashDV.setUint32(0, 0x6A09E667, false)
  hashDV.setUint32(4, 0xBB67AE85, false)
  hashDV.setUint32(8, 0x3C6EF372, false)
  hashDV.setUint32(12, 0xA54FF53A, false)
  hashDV.setUint32(16, 0x510E527F, false)
  hashDV.setUint32(20, 0x9B05688C, false)
  hashDV.setUint32(24, 0x1F83D9AB, false)
  hashDV.setUint32(28, 0x5BE0CD19, false)

  sha224_256(hashBuffer, input)

  return codec.stringify(hashBuffer)
}

// common process for sha224 and sha256
function sha224_256(hashBuffer: ArrayBuffer, input: string) {
  // * Initialization
  const hashDV = new DataView(hashBuffer)

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
  dataDV.setBigUint64(sigBytes + 1 + k, BITS_TOTAL, false)

  // * Processing

  function _doProcess(data: Uint8Array, i: number) {
    const currentBlock = data.slice(i * BLOCK_SIZE, (i + 1) * BLOCK_SIZE)
    const dv = new DataView(currentBlock.buffer)

    // Initialize the five working variables:
    const h0 = hashDV.getUint32(0, false)
    const h1 = hashDV.getUint32(4, false)
    const h2 = hashDV.getUint32(8, false)
    const h3 = hashDV.getUint32(12, false)
    const h4 = hashDV.getUint32(16, false)
    const h5 = hashDV.getUint32(20, false)
    const h6 = hashDV.getUint32(24, false)
    const h7 = hashDV.getUint32(28, false)
    let a = h0
    let b = h1
    let c = h2
    let d = h3
    let e = h4
    let f = h5
    let g = h6
    let h = h7

    // Prepare the message schedule W and (1 ≤ t ≤ 80)
    const W = new Uint32Array(64)
    for (let i = 0; i < W.length; i++) {
      if (i < 16)
        W[i] = dv.getUint32(i * 4, false) | 0
      else
        W[i] = sigma1(W[i - 2]) + W[i - 7] + sigma0(W[i - 15]) + W[i - 16]

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

    // Add this chunk's hash to result so far:
    hashDV.setUint32(0, (h0 + a) | 0, false)
    hashDV.setUint32(4, (h1 + b) | 0, false)
    hashDV.setUint32(8, (h2 + c) | 0, false)
    hashDV.setUint32(12, (h3 + d) | 0, false)
    hashDV.setUint32(16, (h4 + e) | 0, false)
    hashDV.setUint32(20, (h5 + f) | 0, false)
    hashDV.setUint32(24, (h6 + g) | 0, false)
    hashDV.setUint32(28, (h7 + h) | 0, false)
  }

  for (let i = 0; i < BLOCK_TOTAL; i++)
    _doProcess(data, i)

  return hashBuffer
}
