import type { Codec } from '../core/codec'
import { HEX, UTF8 } from '../core/codec'
import { KitError, rotateL32, wrap } from '../core/utils'

// * Constants

const S0 = new Uint8Array([0x3E, 0x72, 0x5B, 0x47, 0xCA, 0xE0, 0x00, 0x33, 0x04, 0xD1, 0x54, 0x98, 0x09, 0xB9, 0x6D, 0xCB, 0x7B, 0x1B, 0xF9, 0x32, 0xAF, 0x9D, 0x6A, 0xA5, 0xB8, 0x2D, 0xFC, 0x1D, 0x08, 0x53, 0x03, 0x90, 0x4D, 0x4E, 0x84, 0x99, 0xE4, 0xCE, 0xD9, 0x91, 0xDD, 0xB6, 0x85, 0x48, 0x8B, 0x29, 0x6E, 0xAC, 0xCD, 0xC1, 0xF8, 0x1E, 0x73, 0x43, 0x69, 0xC6, 0xB5, 0xBD, 0xFD, 0x39, 0x63, 0x20, 0xD4, 0x38, 0x76, 0x7D, 0xB2, 0xA7, 0xCF, 0xED, 0x57, 0xC5, 0xF3, 0x2C, 0xBB, 0x14, 0x21, 0x06, 0x55, 0x9B, 0xE3, 0xEF, 0x5E, 0x31, 0x4F, 0x7F, 0x5A, 0xA4, 0x0D, 0x82, 0x51, 0x49, 0x5F, 0xBA, 0x58, 0x1C, 0x4A, 0x16, 0xD5, 0x17, 0xA8, 0x92, 0x24, 0x1F, 0x8C, 0xFF, 0xD8, 0xAE, 0x2E, 0x01, 0xD3, 0xAD, 0x3B, 0x4B, 0xDA, 0x46, 0xEB, 0xC9, 0xDE, 0x9A, 0x8F, 0x87, 0xD7, 0x3A, 0x80, 0x6F, 0x2F, 0xC8, 0xB1, 0xB4, 0x37, 0xF7, 0x0A, 0x22, 0x13, 0x28, 0x7C, 0xCC, 0x3C, 0x89, 0xC7, 0xC3, 0x96, 0x56, 0x07, 0xBF, 0x7E, 0xF0, 0x0B, 0x2B, 0x97, 0x52, 0x35, 0x41, 0x79, 0x61, 0xA6, 0x4C, 0x10, 0xFE, 0xBC, 0x26, 0x95, 0x88, 0x8A, 0xB0, 0xA3, 0xFB, 0xC0, 0x18, 0x94, 0xF2, 0xE1, 0xE5, 0xE9, 0x5D, 0xD0, 0xDC, 0x11, 0x66, 0x64, 0x5C, 0xEC, 0x59, 0x42, 0x75, 0x12, 0xF5, 0x74, 0x9C, 0xAA, 0x23, 0x0E, 0x86, 0xAB, 0xBE, 0x2A, 0x02, 0xE7, 0x67, 0xE6, 0x44, 0xA2, 0x6C, 0xC2, 0x93, 0x9F, 0xF1, 0xF6, 0xFA, 0x36, 0xD2, 0x50, 0x68, 0x9E, 0x62, 0x71, 0x15, 0x3D, 0xD6, 0x40, 0xC4, 0xE2, 0x0F, 0x8E, 0x83, 0x77, 0x6B, 0x25, 0x05, 0x3F, 0x0C, 0x30, 0xEA, 0x70, 0xB7, 0xA1, 0xE8, 0xA9, 0x65, 0x8D, 0x27, 0x1A, 0xDB, 0x81, 0xB3, 0xA0, 0xF4, 0x45, 0x7A, 0x19, 0xDF, 0xEE, 0x78, 0x34, 0x60])
const S1 = new Uint8Array([0x55, 0xC2, 0x63, 0x71, 0x3B, 0xC8, 0x47, 0x86, 0x9F, 0x3C, 0xDA, 0x5B, 0x29, 0xAA, 0xFD, 0x77, 0x8C, 0xC5, 0x94, 0x0C, 0xA6, 0x1A, 0x13, 0x00, 0xE3, 0xA8, 0x16, 0x72, 0x40, 0xF9, 0xF8, 0x42, 0x44, 0x26, 0x68, 0x96, 0x81, 0xD9, 0x45, 0x3E, 0x10, 0x76, 0xC6, 0xA7, 0x8B, 0x39, 0x43, 0xE1, 0x3A, 0xB5, 0x56, 0x2A, 0xC0, 0x6D, 0xB3, 0x05, 0x22, 0x66, 0xBF, 0xDC, 0x0B, 0xFA, 0x62, 0x48, 0xDD, 0x20, 0x11, 0x06, 0x36, 0xC9, 0xC1, 0xCF, 0xF6, 0x27, 0x52, 0xBB, 0x69, 0xF5, 0xD4, 0x87, 0x7F, 0x84, 0x4C, 0xD2, 0x9C, 0x57, 0xA4, 0xBC, 0x4F, 0x9A, 0xDF, 0xFE, 0xD6, 0x8D, 0x7A, 0xEB, 0x2B, 0x53, 0xD8, 0x5C, 0xA1, 0x14, 0x17, 0xFB, 0x23, 0xD5, 0x7D, 0x30, 0x67, 0x73, 0x08, 0x09, 0xEE, 0xB7, 0x70, 0x3F, 0x61, 0xB2, 0x19, 0x8E, 0x4E, 0xE5, 0x4B, 0x93, 0x8F, 0x5D, 0xDB, 0xA9, 0xAD, 0xF1, 0xAE, 0x2E, 0xCB, 0x0D, 0xFC, 0xF4, 0x2D, 0x46, 0x6E, 0x1D, 0x97, 0xE8, 0xD1, 0xE9, 0x4D, 0x37, 0xA5, 0x75, 0x5E, 0x83, 0x9E, 0xAB, 0x82, 0x9D, 0xB9, 0x1C, 0xE0, 0xCD, 0x49, 0x89, 0x01, 0xB6, 0xBD, 0x58, 0x24, 0xA2, 0x5F, 0x38, 0x78, 0x99, 0x15, 0x90, 0x50, 0xB8, 0x95, 0xE4, 0xD0, 0x91, 0xC7, 0xCE, 0xED, 0x0F, 0xB4, 0x6F, 0xA0, 0xCC, 0xF0, 0x02, 0x4A, 0x79, 0xC3, 0xDE, 0xA3, 0xEF, 0xEA, 0x51, 0xE6, 0x6B, 0x18, 0xEC, 0x1B, 0x2C, 0x80, 0xF7, 0x74, 0xE7, 0xFF, 0x21, 0x5A, 0x6A, 0x54, 0x1E, 0x41, 0x31, 0x92, 0x35, 0xC4, 0x33, 0x07, 0x0A, 0xBA, 0x7E, 0x0E, 0x34, 0x88, 0xB1, 0x98, 0x7C, 0xF3, 0x3D, 0x60, 0x6C, 0x7B, 0xCA, 0xD3, 0x1F, 0x32, 0x65, 0x04, 0x28, 0x64, 0xBE, 0x85, 0x9B, 0x2F, 0x59, 0x8A, 0xD7, 0xB0, 0x25, 0xAC, 0xAF, 0x12, 0x03, 0xE2, 0xF2])
const D = new Uint16Array([0x44D7, 0x26BC, 0x626B, 0x135E, 0x5789, 0x35E2, 0x7135, 0x09AF, 0x4D78, 0x2F13, 0x6BC4, 0x1AF1, 0x5E26, 0x3C4D, 0x789A, 0x47AC])

// * Functions

function mulPow2n(v: number, n: number) {
  return ((v << n | v >>> (31 - n)) & 0x7FFFFFFF)
}
function addMod31(a: number, b: number) {
  const c = a + b
  return (c & 0x7FFFFFFF) + (c >>> 31)
}

const L1 = (X: number) => X ^ rotateL32(X, 2) ^ rotateL32(X, 10) ^ rotateL32(X, 18) ^ rotateL32(X, 24)
const L2 = (X: number) => X ^ rotateL32(X, 8) ^ rotateL32(X, 14) ^ rotateL32(X, 22) ^ rotateL32(X, 30)
function BR(S: Uint32Array, X: Uint32Array) {
  X[0] = (S[15] & 0x7FFF8000) << 1 | S[14] & 0xFFFF
  X[1] = (S[11] & 0x0000FFFF) << 16 | S[9] >>> 15
  X[2] = (S[7] & 0x0000FFFF) << 16 | S[5] >>> 15
  X[3] = (S[2] & 0x0000FFFF) << 16 | S[0] >>> 15
}
function F(X0: number, X1: number, X2: number, R: Uint32Array) {
  const W = (X0 ^ R[0]) + R[1]
  const W1 = (R[0] + X1) & 0xFFFFFFFF
  const W2 = R[1] ^ X2
  const r0 = L1((W1 << 16) | (W2 >>> 16))
  R[0] = S0[r0 >>> 24] << 24 | S1[(r0 >>> 16) & 0xFF] << 16 | S0[(r0 >>> 8) & 0xFF] << 8 | S1[r0 & 0xFF]
  const r1 = L2((W2 << 16) | (W1 >>> 16))
  R[1] = S0[r1 >>> 24] << 24 | S1[(r1 >>> 16) & 0xFF] << 16 | S0[(r1 >>> 8) & 0xFF] << 8 | S1[r1 & 0xFF]
  return W
}
/**
 * 线性反馈移位寄存器有两种运行模式：初始化模式和工作模式，当输入 `u` 时为初始化模式，否则为工作模式
 *
 * @param {Uint32Array} S - 线性反馈移位寄存器(LFSR)
 * @param {number} u - 初始化模式下的输入
 */
function next(S: Uint32Array, u?: number) {
  let s16: number, v: number
  s16 = S[0]
  v = mulPow2n(S[0], 8)
  s16 = addMod31(s16, v)
  v = mulPow2n(S[4], 20)
  s16 = addMod31(s16, v)
  v = mulPow2n(S[10], 21)
  s16 = addMod31(s16, v)
  v = mulPow2n(S[13], 17)
  s16 = addMod31(s16, v)
  v = mulPow2n(S[15], 15)
  s16 = addMod31(s16, v)

  s16 = u ? addMod31(s16, u) : s16
  s16 = s16 || 0x7FFFFFFF
  for (let i = 0; i < 15; i++) {
    S[i] = S[i + 1]
  }
  S[15] = s16
}

// * ZUC Algorithm (presudo-random generator)

/**
 * @description
 * 3GPP ZUC algorithm is used to generate a key stream, each call returns a 32-bit key stream.
 *
 * 3GPP ZUC 算法用于生成密钥流，每次调用返回一个 32 位的密钥流.
 *
 * ```ts
 * const K = new Uint8Array(16)
 * const iv = new Uint8Array(16)
 * const zuc = zuc(K, iv)
 * zuc() // 32-bit number
 * ```
 */
export function zuc(K: Uint8Array, iv: Uint8Array) {
  if (K.byteLength !== 16) {
    throw new KitError('ZUC requires a key of 16 bytes')
  }
  if (iv.byteLength !== 16) {
    throw new KitError('ZUC requires an IV of 16 bytes')
  }
  const LFSR = new Uint32Array(16)
  const X = new Uint32Array(4)
  const R = new Uint32Array(2);
  (function init() {
    for (let i = 0; i < 16; i++) {
      LFSR[i] = K[i] << 23 | D[i] << 8 | iv[i]
    }
    for (let i = 0; i < 32; i++) {
      BR(LFSR, X)
      const W = F(X[0], X[1], X[2], R)
      next(LFSR, W >>> 1)
    }
    BR(LFSR, X)
    F(X[0], X[1], X[2], R)
    next(LFSR)
  })()

  return () => {
    BR(LFSR, X)
    const W = F(X[0], X[1], X[2], R) ^ X[3]
    next(LFSR)
    return W
  }
}

// * EEA3 & EIA3

function createEEA_IV(count: Uint8Array, bearer: number, direction: 0 | 1) {
  const iv = new Uint8Array(16)
  iv.set(count, 0)
  iv[4] = bearer << 3 | direction << 2
  iv.set(iv.subarray(0, 5), 8)
  return iv
}
function createEIA_IV(count: Uint8Array, bearer: number, direction: 0 | 1) {
  const iv = new Uint8Array(16)
  iv.set(count, 0)
  iv[4] = bearer << 3
  iv.set(iv.subarray(0, 5), 8)
  iv[8] ^= direction << 7
  iv[14] ^= direction << 7
  return iv
}
function getWord(Z: DataView, bit_offset: number) {
  const ti = bit_offset % 8
  const byte_offset = bit_offset >>> 3
  const W = ti === 0
    ? Z.getUint32(byte_offset, false)
    : Z.getUint32(byte_offset, false) << ti | Z.getUint32(byte_offset + 4, false) >>> (32 - ti)
  return W & 0xFFFFFFFF
}

export interface ZUCParams {
  /**
   * 32-bit counter
   *
   * 如果 `counter` 为 `number` 类型，则转换为小端存储的 `Uint8Array` 类型.
   * 如果 `counter` 为 `string` 类型，则通过 `COUNTER_CODEC` 转换为 `Uint8Array` 类型.
   * `COUNTER_CODEC` 通过 `ZUCConfig` 配置，默认为 `HEX`.
   */
  COUNTER: Uint8Array | number | string
  /**
   * 5-bit bearer
   */
  BEARER: number
  /**
   * 1-bit direction
   */
  DIRECTION: 0 | 1
  /**
   * 128-bit key
   *
   * 如果 `KEY` 为 `string` 类型，则通过 `KEY_CODEC` 转换为 `Uint8Array` 类型.
   * `KEY_CODEC` 通过 `ZUCConfig` 配置，默认为 `HEX`.
   */
  KEY: Uint8Array | string
  /**
   * 32-bit length
   */
  LENGTH: number
  M: Uint8Array | string
}
export interface ZUCConfig {
  /**
   * @default HEX
   */
  COUNTER_CODEC?: Codec
  /**
   * @default HEX
   */
  KEY_CODEC?: Codec
  /**
   * @default UTF8
   */
  INPUT_CODEC?: Codec
}
export interface ZUC3GPP {
  (param: ZUCParams, config?: ZUCConfig): Uint8Array
}
/**
 * @description
 * 3GPP ZUC encryption algorithm.
 *
 * 3GPP ZUC 加密算法.
 *
 * ```ts
 * const encrypt: ZUCParams = {...}
 * const decrypt: ZUCParams = {...}
 * const config: ZUCConfig = {...}
 * eea3(encrypt, config) // Uint8Array
 * eia3(decrypt, config) // Uint8Array
 * ```
 */
export const eea3 = wrap<ZUC3GPP>(
  (param: ZUCParams, config: ZUCConfig = {}) => {
    const { COUNTER_CODEC = HEX, KEY_CODEC = HEX, INPUT_CODEC = UTF8 } = config

    // 转换参数
    const { BEARER, DIRECTION } = param
    let { COUNTER, KEY, M, LENGTH } = param
    switch (typeof COUNTER) {
      case 'string':
        COUNTER = COUNTER_CODEC.parse(COUNTER)
        break
      case 'number':
        COUNTER = new Uint8Array([COUNTER >> 24, COUNTER >> 16, COUNTER >> 8, COUNTER])
        break
    }
    KEY = typeof KEY === 'string'
      ? KEY_CODEC.parse(KEY)
      : KEY
    M = typeof M === 'string'
      ? INPUT_CODEC.parse(M)
      : M

    // 生成密钥流
    LENGTH = M.byteLength << 3
    const WORD_COUNT = (LENGTH + 31) >> 5
    const EEA_KeyStream = new Uint8Array(WORD_COUNT << 2)
    const KSView = new DataView(EEA_KeyStream.buffer)
    const EEA_IV = createEEA_IV(COUNTER, BEARER, DIRECTION)
    const prg = zuc(KEY, EEA_IV)
    for (let i = 0; i < WORD_COUNT; i++) {
      KSView.setUint32(i << 2, prg(), false)
    }

    // 加密
    return M.map((_, i) => _ ^ EEA_KeyStream[i])
  },
  {
    ALGORITHM: 'ZUC-EEA3',
    KEY_SIZE: 16,
  },
)
/**
 * @description
 * 3GPP ZUC integrity algorithm.
 *
 * 3GPP ZUC 完整性算法.
 *
 * ```ts
 * const mac: ZUCParams = {...}
 * const config: ZUCConfig = {...}
 * eia3(mac, config) // Uint8Array
 * ```
 */
export const eia3 = wrap<ZUC3GPP>(
  (param: ZUCParams, config: ZUCConfig = {}) => {
    const { COUNTER_CODEC = HEX, KEY_CODEC = HEX, INPUT_CODEC = UTF8 } = config

    // 转换参数
    const { BEARER, DIRECTION } = param
    let { COUNTER, KEY, M, LENGTH } = param
    switch (typeof COUNTER) {
      case 'string':
        COUNTER = COUNTER_CODEC.parse(COUNTER)
        break
      case 'number':
        COUNTER = new Uint8Array([COUNTER >> 24, COUNTER >> 16, COUNTER >> 8, COUNTER])
        break
    }
    KEY = typeof KEY === 'string'
      ? KEY_CODEC.parse(KEY)
      : KEY
    M = typeof M === 'string'
      ? INPUT_CODEC.parse(M)
      : M

    // 生成密钥流
    const N = LENGTH + 64
    const WORD_COUNT = N + 31 >> 5
    const EIA_KeyStream = new Uint8Array(WORD_COUNT << 2)
    const KSView = new DataView(EIA_KeyStream.buffer)
    const EIA_IV = createEIA_IV(COUNTER, BEARER, DIRECTION)
    const prg = zuc(KEY, EIA_IV)
    for (let i = 0; i < WORD_COUNT; i++) {
      KSView.setUint32(i << 2, prg(), false)
    }

    // 计算 MAC
    let t = 0
    for (let i = 0; i < LENGTH; i++) {
      const bit = M[i >>> 3] & (1 << (7 - (i % 8)))
      if (bit) {
        t ^= getWord(KSView, i)
      }
    }
    t ^= getWord(KSView, LENGTH)
    t ^= KSView.getUint32(EIA_KeyStream.byteLength - 4)
    return new Uint8Array([t >> 24, t >> 16, t >> 8, t])
  },
  {
    ALGORITHM: 'ZUC-EIA3',
    KEY_SIZE: 16,
  },
)
