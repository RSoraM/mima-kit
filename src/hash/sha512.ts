import { Hex, Utf8 } from '../core/codec'
import type { Codec } from '../core/codec'
import { rotateRn } from '../core/utils'

// * Constants
const K = [0x428A2F98D728AE22n, 0x7137449123EF65CDn, 0xB5C0FBCFEC4D3B2Fn, 0xE9B5DBA58189DBBCn, 0x3956C25BF348B538n, 0x59F111F1B605D019n, 0x923F82A4AF194F9Bn, 0xAB1C5ED5DA6D8118n, 0xD807AA98A3030242n, 0x12835B0145706FBEn, 0x243185BE4EE4B28Cn, 0x550C7DC3D5FFB4E2n, 0x72BE5D74F27B896Fn, 0x80DEB1FE3B1696B1n, 0x9BDC06A725C71235n, 0xC19BF174CF692694n, 0xE49B69C19EF14AD2n, 0xEFBE4786384F25E3n, 0x0FC19DC68B8CD5B5n, 0x240CA1CC77AC9C65n, 0x2DE92C6F592B0275n, 0x4A7484AA6EA6E483n, 0x5CB0A9DCBD41FBD4n, 0x76F988DA831153B5n, 0x983E5152EE66DFABn, 0xA831C66D2DB43210n, 0xB00327C898FB213Fn, 0xBF597FC7BEEF0EE4n, 0xC6E00BF33DA88FC2n, 0xD5A79147930AA725n, 0x06CA6351E003826Fn, 0x142929670A0E6E70n, 0x27B70A8546D22FFCn, 0x2E1B21385C26C926n, 0x4D2C6DFC5AC42AEDn, 0x53380D139D95B3DFn, 0x650A73548BAF63DEn, 0x766A0ABB3C77B2A8n, 0x81C2C92E47EDAEE6n, 0x92722C851482353Bn, 0xA2BFE8A14CF10364n, 0xA81A664BBC423001n, 0xC24B8B70D0F89791n, 0xC76C51A30654BE30n, 0xD192E819D6EF5218n, 0xD69906245565A910n, 0xF40E35855771202An, 0x106AA07032BBD1B8n, 0x19A4C116B8D2D0C8n, 0x1E376C085141AB53n, 0x2748774CDF8EEB99n, 0x34B0BCB5E19B48A8n, 0x391C0CB3C5C95A63n, 0x4ED8AA4AE3418ACBn, 0x5B9CCA4F7763E373n, 0x682E6FF3D6B2B8A3n, 0x748F82EE5DEFB2FCn, 0x78A5636F43172F60n, 0x84C87814A1F0AB72n, 0x8CC702081A6439ECn, 0x90BEFFFA23631E28n, 0xA4506CEBDE82BDE9n, 0xBEF9A3F7B2C67915n, 0xC67178F2E372532Bn, 0xCA273ECEEA26619Cn, 0xD186B8C721C0C207n, 0xEADA7DD6CDE0EB1En, 0xF57D4F7FEE6ED178n, 0x06F067AA72176FBAn, 0x0A637DC5A2C898A6n, 0x113F9804BEF90DAEn, 0x1B710B35131C471Bn, 0x28DB77F523047D84n, 0x32CAAB7B40C72493n, 0x3C9EBE0A15C9BEBCn, 0x431D67C49C100D4Cn, 0x4CC5D4BECB3E42B6n, 0x597F299CFC657E2An, 0x5FCB6FAB3AD6FAECn, 0x6C44198C4A475817n]

// * Function
const Ch = (x: bigint, y: bigint, z: bigint) => (x & y) ^ ((~x) & z)
const Maj = (x: bigint, y: bigint, z: bigint) => (x & y) ^ (x & z) ^ (y & z)
const Sigma0 = (x: bigint) => rotateRn(x, 28n) ^ rotateRn(x, 34n) ^ rotateRn(x, 39n)
const Sigma1 = (x: bigint) => rotateRn(x, 14n) ^ rotateRn(x, 18n) ^ rotateRn(x, 41n)
const sigma0 = (x: bigint) => rotateRn(x, 1n) ^ rotateRn(x, 8n) ^ (x >> 7n)
const sigma1 = (x: bigint) => rotateRn(x, 19n) ^ rotateRn(x, 61n) ^ (x >> 6n)

// * Algorithm

export function sha384(input: string, codec: Codec = Hex): string {
  const hashBuffer = new ArrayBuffer(64)
  const hashDV = new DataView(hashBuffer)
  hashDV.setBigUint64(0, 0xCBBB9D5DC1059ED8n, false)
  hashDV.setBigUint64(8, 0x629A292A367CD507n, false)
  hashDV.setBigUint64(16, 0x9159015A3070DD17n, false)
  hashDV.setBigUint64(24, 0x152FECD8F70E5939n, false)
  hashDV.setBigUint64(32, 0x67332667FFC00B31n, false)
  hashDV.setBigUint64(40, 0x8EB44A8768581511n, false)
  hashDV.setBigUint64(48, 0xDB0C2E0D64F98FA7n, false)
  hashDV.setBigUint64(56, 0x47B5481DBEFA4FA4n, false)

  sha384_512(hashBuffer, input)

  return codec.stringify(hashBuffer.slice(0, 48))
}

export function sha512(input: string, codec: Codec = Hex): string {
  const hashBuffer = new ArrayBuffer(64)
  const hashDV = new DataView(hashBuffer)
  hashDV.setBigUint64(0, 0x6A09E667F3BCC908n, false)
  hashDV.setBigUint64(8, 0xBB67AE8584CAA73Bn, false)
  hashDV.setBigUint64(16, 0x3C6EF372FE94F82Bn, false)
  hashDV.setBigUint64(24, 0xA54FF53A5F1D36F1n, false)
  hashDV.setBigUint64(32, 0x510E527FADE682D1n, false)
  hashDV.setBigUint64(40, 0x9B05688C2B3E6C1Fn, false)
  hashDV.setBigUint64(48, 0x1F83D9ABFB41BD6Bn, false)
  hashDV.setBigUint64(56, 0x5BE0CD19137E2179n, false)

  sha384_512(hashBuffer, input)

  return codec.stringify(hashBuffer)
}

export function sha512t(t: number) {
  const hashBuffer = IVGen(t)
  return function (input: string, codec: Codec = Hex): string {
    const buffer = hashBuffer.slice(0)
    sha384_512(buffer, input)
    return codec.stringify(buffer.slice(0, t / 8))
  }
}

// common process for sha224 and sha256
function sha384_512(hashBuffer: ArrayBuffer, input: string) {
  // * Initialization
  const hashDV = new DataView(hashBuffer)

  const bytes = new Uint8Array(Utf8.parse(input))
  const sigBytes = bytes.byteLength
  const BLOCK_SIZE = 128
  const BLOCK_TOTAL = Math.ceil((sigBytes + 17) / BLOCK_SIZE)
  const BITS_TOTAL = BigInt(sigBytes * 8)
  if (BITS_TOTAL > 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFn)
    throw new Error('Message is too long')

  // * Preprocessing

  const data = new Uint8Array(new ArrayBuffer(BLOCK_TOTAL * BLOCK_SIZE))
  data.set(bytes)

  // appending the bit '1' to the message
  data[sigBytes] = 0x80

  // appending length
  const k = (112 - (sigBytes + 1) % BLOCK_SIZE) % BLOCK_SIZE
  const dataDV = new DataView(data.buffer)
  dataDV.setBigUint64(sigBytes + 1 + k, BITS_TOTAL >> 32n, false)
  dataDV.setBigUint64(sigBytes + 9 + k, BITS_TOTAL & 0xFFFFFFFFFFFFFFFFn, false)

  // * Processing

  function _doProcess(data: Uint8Array, i: number) {
    const currentBlock = data.slice(i * BLOCK_SIZE, (i + 1) * BLOCK_SIZE)
    const dv = new DataView(currentBlock.buffer)

    // Initialize the five working variables:
    const h0 = hashDV.getBigUint64(0, false)
    const h1 = hashDV.getBigUint64(8, false)
    const h2 = hashDV.getBigUint64(16, false)
    const h3 = hashDV.getBigUint64(24, false)
    const h4 = hashDV.getBigUint64(32, false)
    const h5 = hashDV.getBigUint64(40, false)
    const h6 = hashDV.getBigUint64(48, false)
    const h7 = hashDV.getBigUint64(56, false)
    let a = h0
    let b = h1
    let c = h2
    let d = h3
    let e = h4
    let f = h5
    let g = h6
    let h = h7

    // Prepare the message schedule W and (1 ≤ t ≤ 80)
    const W = new BigUint64Array(80)
    for (let i = 0; i < W.length; i++) {
      if (i < 16)
        W[i] = dv.getBigUint64(i * 8, false) | 0n
      else
        W[i] = sigma1(W[i - 2]) + W[i - 7] + sigma0(W[i - 15]) + W[i - 16]

      const T1 = h + Sigma1(e) + Ch(e, f, g) + K[i] + W[i]
      const T2 = Sigma0(a) + Maj(a, b, c)
      h = g
      g = f
      f = e
      e = (d + T1) & 0xFFFFFFFFFFFFFFFFn
      d = c
      c = b
      b = a
      a = (T1 + T2) & 0xFFFFFFFFFFFFFFFFn
    }

    // Add this chunk's hash to result so far:
    hashDV.setBigUint64(0, (h0 + a) | 0n, false)
    hashDV.setBigUint64(8, (h1 + b) | 0n, false)
    hashDV.setBigUint64(16, (h2 + c) | 0n, false)
    hashDV.setBigUint64(24, (h3 + d) | 0n, false)
    hashDV.setBigUint64(32, (h4 + e) | 0n, false)
    hashDV.setBigUint64(40, (h5 + f) | 0n, false)
    hashDV.setBigUint64(48, (h6 + g) | 0n, false)
    hashDV.setBigUint64(56, (h7 + h) | 0n, false)
  }

  for (let i = 0; i < BLOCK_TOTAL; i++)
    _doProcess(data, i)

  return hashBuffer
}

// SHA-512/t IV Generation Function
function IVGen(t: number) {
  if (t <= 0) {
    throw new Error('t must be greater than 0')
  }
  if (t >= 512) {
    throw new Error('t must be less than 512')
  }
  if (t === 384) {
    throw new Error('t must not be 384')
  }

  const hashBuffer = new ArrayBuffer(64)
  const hashDV = new DataView(hashBuffer)
  hashDV.setBigUint64(0, 0x6A09E667F3BCC908n ^ 0xA5A5A5A5A5A5A5A5n, false)
  hashDV.setBigUint64(8, 0xBB67AE8584CAA73Bn ^ 0xA5A5A5A5A5A5A5A5n, false)
  hashDV.setBigUint64(16, 0x3C6EF372FE94F82Bn ^ 0xA5A5A5A5A5A5A5A5n, false)
  hashDV.setBigUint64(24, 0xA54FF53A5F1D36F1n ^ 0xA5A5A5A5A5A5A5A5n, false)
  hashDV.setBigUint64(32, 0x510E527FADE682D1n ^ 0xA5A5A5A5A5A5A5A5n, false)
  hashDV.setBigUint64(40, 0x9B05688C2B3E6C1Fn ^ 0xA5A5A5A5A5A5A5A5n, false)
  hashDV.setBigUint64(48, 0x1F83D9ABFB41BD6Bn ^ 0xA5A5A5A5A5A5A5A5n, false)
  hashDV.setBigUint64(56, 0x5BE0CD19137E2179n ^ 0xA5A5A5A5A5A5A5A5n, false)

  sha384_512(hashBuffer, `SHA-512/${t}`)

  return hashBuffer
}
