import { createHash } from '../core/hash'
import { joinBuffer } from '../core/utils'
import { turboshake128, turboshake256 } from './turboSHAKE'

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
 * KangarooTwelve
 *
 * @param {number} d - 输出长度 / Digest Size (bit)
 * @param {Uint8Array} C - 自定义参数 / Customization
 * @param {typeof turboshake128} SHAKE - TurboSHAKE 函数 / Function
 * @param {number} cv - 中间压缩值长度 / Compressed Value Size (bit)
 */
function kt(d: number, C: Uint8Array, SHAKE: typeof turboshake128, cv: number) {
  return (M: Uint8Array) => {
    const length_encode = lengthEncode(C.length)
    const S = joinBuffer(M, C, length_encode)
    if (S.length <= 8192) {
      return SHAKE(d, 0x07)(S)
    }
    else {
      // KangarooTwelve hopping
      const FinalNode: Uint8Array[] = []
      FinalNode.push(S.slice(0, 8192))
      FinalNode.push(new Uint8Array([0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]))
      let offset = 8192
      let num_block = 0
      while (offset < S.length) {
        const CV = SHAKE(cv, 0x0B)(S.slice(offset, offset += 8192))
        FinalNode.push(CV)
        num_block++
      }
      FinalNode.push(lengthEncode(num_block))
      FinalNode.push(new Uint8Array([0xFF, 0xFF]))
      return SHAKE(d, 0x06)(joinBuffer(...FinalNode))
    }
  }
}

/**
 * KangarooTwelve 128
 *
 * @param {number} d - 输出长度 / Digest Size (bit)
 * @param {Uint8Array} [C] - 自定义参数 / Customization
 */
export function kt128(d: number, C = new Uint8Array()) {
  return createHash(
    kt(d, C, turboshake128, 256),
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
  return createHash(
    kt(d, C, turboshake256, 512),
    {
      ALGORITHM: `KangarooTwelve256/${d}`,
      BLOCK_SIZE: 8192,
      DIGEST_SIZE: d >> 3,
    },
  )
}
