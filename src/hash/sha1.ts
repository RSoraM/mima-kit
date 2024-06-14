import { Hex, Utf8 } from '../core/codec'
import type { Codec } from '../core/codec'
import { ROTL } from '../core/utils'

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
export function sha1(input: string, codec: Codec = Hex) {
  // * Initialization
  const hashBuffer = new ArrayBuffer(20)
  const hashDV = new DataView(hashBuffer)
  hashDV.setUint32(0, 0x67452301, false)
  hashDV.setUint32(4, 0xEFCDAB89, false)
  hashDV.setUint32(8, 0x98BADCFE, false)
  hashDV.setUint32(12, 0x10325476, false)
  hashDV.setUint32(16, 0xC3D2E1F0, false)

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
    let a = h0
    let b = h1
    let c = h2
    let d = h3
    let e = h4

    // Prepare the message schedule W and (1 ≤ t ≤ 80)
    const W = new Uint32Array(80)
    for (let i = 0; i < 80; i++) {
      if (i < 16)
        W[i] = dv.getUint32(i * 4, false)
      else
        W[i] = ROTL(W[i - 3] ^ W[i - 8] ^ W[i - 14] ^ W[i - 16], 1)

      const T = ROTL(a, 5) + ft(b, c, d, i) + K(i) + e + W[i]
      e = d
      d = c
      c = ROTL(b, 30)
      b = a
      a = T
    }

    // Add this chunk's hash to result so far:
    hashDV.setUint32(0, (h0 + a) | 0, false)
    hashDV.setUint32(4, (h1 + b) | 0, false)
    hashDV.setUint32(8, (h2 + c) | 0, false)
    hashDV.setUint32(12, (h3 + d) | 0, false)
    hashDV.setUint32(16, (h4 + e) | 0, false)
  }

  for (let i = 0; i < BLOCK_TOTAL; i++)
    _doProcess(data, i)

  // * TRUNCATION

  return codec.stringify(hashBuffer)
}
