import { createHash } from '../core/hash'
import { joinBuffer } from '../core/utils'
import { turboSHAKE128, turboSHAKE256 } from './turboSHAKE'

function lengthEncode(x: number): Uint8Array {
  const S: number[] = []
  while (x > 0) {
    S.unshift(x & 0xFF)
    x >>= 8
  }
  S.push(S.length)
  return new Uint8Array(S)
}

/**
 * KangarooTwelve 128
 *
 * @param {number} d - 输出长度 / Digest Size (bit)
 * @param {Uint8Array} [C] - 自定义参数 / Customization
 */
export function kt128(d: number, C = new Uint8Array()) {
  const digest = (M: Uint8Array) => {
    const length_encode = lengthEncode(C.length)
    const S = joinBuffer(M, C, length_encode)
    if (S.length <= 8192) {
      return turboSHAKE128(d, 0x07)(S)
    }
    else {
      // KangarooTwelve hopping
      const FinalNode: Uint8Array[] = []
      FinalNode.push(S.slice(0, 8192))
      FinalNode.push(new Uint8Array([0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]))
      let offset = 8192
      let block_i = 0
      while (offset < S.length) {
        const CV = turboSHAKE128(256, 0x0B)(S.slice(offset, offset += 8192))
        FinalNode.push(CV)
        block_i++
      }
      FinalNode.push(lengthEncode(block_i))
      FinalNode.push(new Uint8Array([0xFF, 0xFF]))
      return turboSHAKE128(d, 0x06)(joinBuffer(...FinalNode))
    }
  }

  return createHash(
    digest,
    {
      ALGORITHM: `KangarooTwelve128/${d}`,
      BLOCK_SIZE: 8192,
      DIGEST_SIZE: d >> 3,
    },
  )
}

/**
 * KangarooTwelve 256
 *
 * @param {number} d - 输出长度 / Digest Size (bit)
 * @param {Uint8Array} [C] - 自定义参数 / Customization
 */
export function kt256(d: number, C = new Uint8Array()) {
  const digest = (M: Uint8Array) => {
    const length_encode = lengthEncode(C.length)
    const S = joinBuffer(M, C, length_encode)
    if (S.length <= 8192) {
      return turboSHAKE256(d, 0x07)(S)
    }
    else {
      // KangarooTwelve hopping
      const FinalNode: Uint8Array[] = []
      FinalNode.push(S.slice(0, 8192))
      FinalNode.push(new Uint8Array([0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]))
      let offset = 8192
      let num_block = 0
      while (offset < S.length) {
        const CV = turboSHAKE256(512, 0x0B)(S.slice(offset, offset += 8192))
        FinalNode.push(CV)
        num_block++
      }
      FinalNode.push(lengthEncode(num_block))
      FinalNode.push(new Uint8Array([0xFF, 0xFF]))
      return turboSHAKE256(d, 0x06)(joinBuffer(...FinalNode))
    }
  }

  return createHash(
    digest,
    {
      ALGORITHM: `KangarooTwelve256/${d}`,
      BLOCK_SIZE: 8192,
      DIGEST_SIZE: d >> 3,
    },
  )
}
