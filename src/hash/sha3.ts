import { createHash } from '../core/hash'
import { sponge_1600 } from './keccak1600'

// * SHA3 Padding Function

/**
 * `SHA3` 填充函数 / Padding Function
 */
export interface Sha3Padding {
  /**
   * @param {number} r_byte - 处理速率 / Rate
   */
  (r_byte: number): {
    /**
     * @param {Uint8Array} M - 消息 / Message
     */
    (M: Uint8Array): Uint8Array
  }
}

/**
 * `SHA3` 填充函数 / Padding Function
 *
 * ```ts
 * M || 01 || 10*1
 * ```
 *
 * @param {number} r_byte - 处理速率 / Rate
 */
const sha3Padding: Sha3Padding = (r_byte: number) => {
  return (M: Uint8Array) => {
    const sig_byte = M.length
    const pad_byte = r_byte - (sig_byte % r_byte)
    const P = new Uint8Array(sig_byte + pad_byte)
    P.set(M)
    if (pad_byte === 1) {
      P[sig_byte] = 0x86
    }
    P[sig_byte] = 0x06
    P[P.length - 1] |= 0x80
    return P
  }
}

/**
 * `SHAKE` 填充函数 / Padding Function
 *
 * ```ts
 * M || 1111 || 10*1
 * ```
 *
 * @param {number} r_byte - 处理速率 / Rate
 */
const shakePadding: Sha3Padding = (r_byte: number) => {
  return (M: Uint8Array) => {
    const sig_byte = M.length
    const pad_byte = r_byte - (sig_byte % r_byte)
    const P = new Uint8Array(sig_byte + pad_byte)
    P.set(M)
    if (pad_byte === 1) {
      P[sig_byte] = 0x9F
    }
    P[sig_byte] = 0x1F
    P[P.length - 1] |= 0x80
    return P
  }
}

// * SHA3 Function Specification

/**
 * @param {number} c - 安全容量 / capacity (bit)
 * @param {number} d - 输出长度 / Digest Size (bit)
 * @param {Sha3Padding} padding - 填充函数 / Padding Function
 */
export function Keccak_c(c: number, d: number, padding: Sha3Padding) {
  const r = 1600 - c
  const rByte = r >> 3
  const pad = padding(rByte)
  return (M: Uint8Array) => sponge_1600(rByte, d >> 3, pad)(M)
}

export const sha3_224 = createHash(
  (M: Uint8Array) => Keccak_c(448, 224, sha3Padding)(M),
  {
    ALGORITHM: 'SHA3-224',
    BLOCK_SIZE: 144,
    DIGEST_SIZE: 28,
    OID: '2.16.840.1.101.3.4.2.7',
  },
)

export const sha3_256 = createHash(
  (M: Uint8Array) => Keccak_c(512, 256, sha3Padding)(M),
  {
    ALGORITHM: 'SHA3-256',
    BLOCK_SIZE: 136,
    DIGEST_SIZE: 32,
    OID: '2.16.840.1.101.3.4.2.8',
  },
)

export const sha3_384 = createHash(
  (M: Uint8Array) => Keccak_c(768, 384, sha3Padding)(M),
  {
    ALGORITHM: 'SHA3-384',
    BLOCK_SIZE: 104,
    DIGEST_SIZE: 48,
    OID: '2.16.840.1.101.3.4.2.9',
  },
)

export const sha3_512 = createHash(
  (M: Uint8Array) => Keccak_c(1024, 512, sha3Padding)(M),
  {
    ALGORITHM: 'SHA3-512',
    BLOCK_SIZE: 72,
    DIGEST_SIZE: 64,
    OID: '2.16.840.1.101.3.4.2.10',
  },
)

/**
 * @param {number} d - 输出长度 bit / output length bit
 */
export function shake128(d: number) {
  return createHash(
    (M: Uint8Array) => Keccak_c(256, d, shakePadding)(M),
    {
      ALGORITHM: `SHAKE128/${d}`,
      BLOCK_SIZE: 168,
      DIGEST_SIZE: d >> 3,
    },
  )
}

/**
 * @param {number} d - 输出长度 bit / output length bit
 */
export function shake256(d: number) {
  return createHash(
    (M: Uint8Array) => Keccak_c(512, d, shakePadding)(M),
    {
      ALGORITHM: `SHAKE256/${d}`,
      BLOCK_SIZE: 136,
      DIGEST_SIZE: d >> 3,
    },
  )
}
