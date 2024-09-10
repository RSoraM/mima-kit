import type { Codec } from './codec'
import { HEX, UTF8 } from './codec'
import { KitError, joinBuffer } from './utils'

// * 分组加密算法包装器

interface BaseCipherAlgorithm<R = object> {
  /**
   * @param {Uint8Array} K - 密钥
   */
  (K: Uint8Array): {
    /**
     * @param {Uint8Array} M - 消息
     */
    encrypt: (M: Uint8Array) => Uint8Array
    /**
     * @param {Uint8Array} C - 密文
     */
    decrypt: (C: Uint8Array) => Uint8Array
  } & R
}
interface BaseCipherDescription {
  /**
   * cipher algorithm name
   *
   * 加密算法名称
   */
  ALGORITHM: string
  /**
   * Block size (byte)
   *
   * 分组大小 (字节)
   */
  BLOCK_SIZE: number
  /**
   * Key size (byte)
   *
   * 密钥大小 (字节)
   */
  KEY_SIZE: number
}
export type CipherAlgorithm =
  & BaseCipherAlgorithm<BaseCipherDescription>
  & BaseCipherDescription
export function createCipherAlgorithm(
  algorithm: BaseCipherAlgorithm,
  description: BaseCipherDescription,
): CipherAlgorithm {
  return Object.freeze(Object.assign(
    (K: Uint8Array) => Object.freeze(Object.assign(
      algorithm(K),
      description,
    )),
    description,
  ))
}

// * 填充方案包装器

interface doPad {
  /**
   * add padding
   *
   * 添加填充
   *
   * @param {Uint8Array} M - 消息
   * @param {number} BLOCK_SIZE - 分组大小
   */
  (M: Uint8Array, BLOCK_SIZE: number): Uint8Array
}
interface UnPad {
  /**
   * remove padding
   *
   * 移除填充
   *
   * @param {Uint8Array} P - 填充消息
   */
  (P: Uint8Array): Uint8Array
}
interface PaddingDescription {
  /**
   * padding scheme name
   *
   * 填充方案名称
   */
  ALGORITHM: string
}
export type Padding =
  & doPad & UnPad
  & PaddingDescription
export function createPadding(
  doPad: doPad,
  unPad: UnPad,
  description: PaddingDescription,
): Padding {
  return Object.freeze(Object.assign(
    (M: Uint8Array, BLOCK_SIZE?: number) => (
      typeof BLOCK_SIZE === 'number'
        ? doPad(M, BLOCK_SIZE)
        : unPad(M)
    ),
    description,
  ))
}

// * 填充方案

/**
 * @description
 * PKCS7 padding scheme.
 *
 * PKCS7 填充方案.
 */
export const PKCS7 = createPadding(
  (M: Uint8Array, BLOCK_SIZE: number) => {
    const pad = BLOCK_SIZE - M.byteLength % BLOCK_SIZE
    return joinBuffer(M, new Uint8Array(pad).map(() => pad))
  },
  (P: Uint8Array) => {
    const pad = P[P.byteLength - 1]
    return P.slice(0, P.byteLength - pad)
  },
  { ALGORITHM: 'PKCS#7' },
)

/**
 * @description
 * Zero padding scheme.
 *
 * 零填充方案.
 */
export const ZERO_PAD = createPadding(
  (M: Uint8Array, BLOCK_SIZE: number) => {
    const pad = BLOCK_SIZE - M.byteLength % BLOCK_SIZE
    return joinBuffer(M, new Uint8Array(pad))
  },
  (P: Uint8Array) => {
    let i = P.byteLength - 1
    while (P[i] === 0) {
      i = i - 1
      if (i < 0) {
        return new Uint8Array()
      }
    }
    return P.slice(0, i + 1)
  },
  { ALGORITHM: 'Zero Padding' },
)

/**
 * @description
 * ISO/IEC 7816 padding scheme.
 *
 * ISO/IEC 7816 填充方案.
 */
export const ISO7816_4 = createPadding(
  (M: Uint8Array, BLOCK_SIZE: number) => {
    const BLOCK_TOTAL = Math.ceil((M.byteLength + 1) / BLOCK_SIZE)
    const P = new Uint8Array(BLOCK_TOTAL * BLOCK_SIZE)
    P.set(M)
    P[M.byteLength] = 0x80
    return P
  },
  (P: Uint8Array) => {
    let i = P.byteLength - 1
    while (P[i] === 0x80) {
      i = i - 1
      if (i < 0) {
        console.warn('This message may not be ISO/IEC 7816-4 padded')
        return new Uint8Array()
      }
    }
    return P.slice(0, i + 1)
  },
  { ALGORITHM: 'ISO/IEC 7816-4' },
)

/**
 * @description
 * ANSI X9.23 padding scheme.
 *
 * ANSI X9.23 填充方案.
 */
export const ANSI_X923 = createPadding(
  (M: Uint8Array, BLOCK_SIZE: number) => {
    const BLOCK_TOTAL = Math.ceil((M.byteLength + 1) / BLOCK_SIZE)
    const P = new Uint8Array(BLOCK_TOTAL * BLOCK_SIZE)
    P.set(M)
    P[P.byteLength - 1] = P.byteLength - M.byteLength
    return P
  },
  (P: Uint8Array) => {
    const pad = P[P.byteLength - 1]
    return P.slice(0, P.byteLength - pad)
  },
  { ALGORITHM: 'ANSI X9.23' },
)

// * 工作模式包装器

interface ModeDescription {
  ALGORITHM: string
}
interface CipherModeDescription {
  ALGORITHM: string
  PADDING: Padding
  BLOCK_SIZE: number
  KEY_SIZE: number
}
interface Mode<T = ''> {
  (cipher: CipherAlgorithm, padding?: Padding): T extends 'ECB'
    ? (K: Uint8Array) => ReturnType<BaseCipherAlgorithm>
    : (K: Uint8Array, iv: Uint8Array) => ReturnType<BaseCipherAlgorithm>
}
interface CipherMode<T = 'iv'> extends ModeDescription {
  (cipher: CipherAlgorithm, padding?: Padding): T extends 'ECB'
    ? ((K: Uint8Array) => ReturnType<BaseCipherAlgorithm> & CipherModeDescription) & CipherModeDescription
    : ((K: Uint8Array, iv: Uint8Array) => ReturnType<BaseCipherAlgorithm> & CipherModeDescription) & CipherModeDescription
}
export function createCipherMode(mode: Mode<'ECB'>, description: ModeDescription): CipherMode<'ECB'>
export function createCipherMode(mode: Mode, description: ModeDescription): CipherMode
export function createCipherMode(mode: Mode | Mode<'ECB'>, description: ModeDescription): CipherMode | CipherMode<'ECB'> {
  const isECBMode = (mode: Mode | Mode<'ECB'>): mode is Mode<'ECB'> => description.ALGORITHM === 'ECB'
  return Object.freeze(Object.assign(
    (cipher: CipherAlgorithm, padding: Padding = PKCS7) => {
      const cipherDescription: CipherModeDescription = {
        ALGORITHM: `${description.ALGORITHM}-${cipher.ALGORITHM}`,
        PADDING: padding,
        BLOCK_SIZE: cipher.BLOCK_SIZE,
        KEY_SIZE: cipher.KEY_SIZE,
      }
      const fn = (K: Uint8Array, iv?: Uint8Array) => {
        const c = isECBMode(mode) ? mode(cipher, padding)(K) : mode(cipher, padding)(K, iv!)
        return Object.freeze(Object.assign(
          c,
          cipherDescription,
        ))
      }
      return Object.freeze(Object.assign(
        isECBMode(mode)
          ? (K: Uint8Array) => fn(K)
          : (K: Uint8Array, iv: Uint8Array) => fn(K, iv),
        cipherDescription,
      ))
    },
    description,
  ))
}

// * 工作模式

export const ecb = createCipherMode(
  (cipher: CipherAlgorithm, padding: Padding = PKCS7) =>
    (K: Uint8Array) => {
      const c = cipher(K)
      return ({
        encrypt: (M: Uint8Array) => {
          const P = padding(M, cipher.BLOCK_SIZE)
          const C = new Uint8Array(P.byteLength)
          for (let i = 0; i < P.byteLength; i += cipher.BLOCK_SIZE) {
            const B = P.slice(i, i + cipher.BLOCK_SIZE)
            C.set(c.encrypt(B), i)
          }
          return C
        },
        decrypt: (C: Uint8Array) => {
          if (C.byteLength % cipher.BLOCK_SIZE !== 0) {
            throw new KitError('Ciphertext length must be a multiple of block size')
          }
          const P = new Uint8Array(C.byteLength)
          for (let i = 0; i < C.byteLength; i += cipher.BLOCK_SIZE) {
            const B = C.slice(i, i + cipher.BLOCK_SIZE)
            P.set(c.decrypt(B), i)
          }
          return padding(P)
        },
      })
    },
  { ALGORITHM: 'ECB' },
)

export const cbc = createCipherMode(
  (cipher: CipherAlgorithm, padding: Padding = PKCS7) =>
    (K: Uint8Array, iv: Uint8Array) => {
      // iv 检查
      const BLOCK_SIZE = cipher.BLOCK_SIZE
      if (iv.byteLength !== BLOCK_SIZE) {
        throw new KitError('iv length must be equal to block size')
      }
      const c = cipher(K)
      return {
        encrypt: (M: Uint8Array) => {
          const P = padding(M, BLOCK_SIZE)
          const C = new Uint8Array(P.byteLength)
          let prev = iv
          for (let i = 0; i < P.byteLength; i += BLOCK_SIZE) {
            const B = P.slice(i, i + BLOCK_SIZE)
            B.forEach((_, i) => B[i] ^= prev[i])
            prev = c.encrypt(B)
            C.set(prev, i)
          }
          return C
        },
        decrypt: (C: Uint8Array) => {
          if (C.byteLength % BLOCK_SIZE !== 0) {
            throw new KitError('Ciphertext length must be a multiple of block size')
          }
          const P = new Uint8Array(C.byteLength)
          let prev = iv
          for (let i = 0; i < C.byteLength; i += BLOCK_SIZE) {
            const B = C.slice(i, i + BLOCK_SIZE)
            const _P = c.decrypt(B)
            _P.forEach((_, i) => _P[i] ^= prev[i])
            P.set(_P, i)
            prev = B
          }
          return padding(P)
        },
      }
    },
  { ALGORITHM: 'CBC' },
)

export const cfb = createCipherMode(
  (cipher: CipherAlgorithm, padding: Padding = PKCS7) =>
    (K: Uint8Array, iv: Uint8Array) => {
      // iv 检查
      const BLOCK_SIZE = cipher.BLOCK_SIZE
      if (iv.byteLength !== BLOCK_SIZE) {
        throw new KitError('iv length must be equal to block size')
      }
      const c = cipher(K)
      return {
        encrypt: (M: Uint8Array) => {
          const P = padding(M, BLOCK_SIZE)
          const C = new Uint8Array(P.byteLength)
          let prev = iv
          for (let i = 0; i < P.byteLength; i += BLOCK_SIZE) {
            const B = P.slice(i, i + BLOCK_SIZE)
            prev = c.encrypt(prev)
            prev.forEach((_, i) => prev[i] ^= B[i])
            C.set(prev, i)
          }
          return C
        },
        decrypt: (C: Uint8Array) => {
          if (C.byteLength % BLOCK_SIZE !== 0) {
            throw new KitError('Ciphertext length must be a multiple of block size')
          }
          const P = new Uint8Array(C.byteLength)
          let prev = iv
          for (let i = 0; i < C.byteLength; i += BLOCK_SIZE) {
            const B = C.slice(i, i + BLOCK_SIZE)
            const _P = c.encrypt(prev)
            _P.forEach((_, i) => _P[i] ^= B[i])
            P.set(_P, i)
            prev = B
          }
          return padding(P)
        },
      }
    },
  { ALGORITHM: 'CFB' },
)

export const ofb = createCipherMode(
  (cipher: CipherAlgorithm, padding: Padding = PKCS7) =>
    (K: Uint8Array, iv: Uint8Array) => {
      // iv 检查
      const BLOCK_SIZE = cipher.BLOCK_SIZE
      if (iv.byteLength !== BLOCK_SIZE) {
        throw new KitError('iv length must be equal to block size')
      }
      const c = cipher(K)
      return {
        encrypt: (M: Uint8Array) => {
          const P = padding(M, BLOCK_SIZE)
          const C = new Uint8Array(P.byteLength)
          let prev = iv
          for (let i = 0; i < P.byteLength; i += BLOCK_SIZE) {
            const B = P.slice(i, i + BLOCK_SIZE)
            prev = c.encrypt(prev)
            prev.forEach((_, i) => B[i] ^= _)
            C.set(B, i)
          }
          return C
        },
        decrypt: (C: Uint8Array) => {
          if (C.byteLength % BLOCK_SIZE !== 0) {
            throw new KitError('Ciphertext length must be a multiple of block size')
          }
          const P = new Uint8Array(C.byteLength)
          let prev = iv
          for (let i = 0; i < C.byteLength; i += BLOCK_SIZE) {
            const B = C.slice(i, i + BLOCK_SIZE)
            prev = c.encrypt(prev)
            B.forEach((_, i) => B[i] ^= prev[i])
            P.set(B, i)
          }
          return padding(P)
        },
      }
    },
  { ALGORITHM: 'OFB' },
)

export const ctr = createCipherMode(
  (cipher: CipherAlgorithm, padding: Padding = PKCS7) =>
    (K: Uint8Array, iv: Uint8Array) => {
      // iv 检查
      const BLOCK_SIZE = cipher.BLOCK_SIZE
      if (iv.byteLength !== BLOCK_SIZE) {
        throw new KitError('nonce(iv) length must be equal to block size')
      }
      const c = cipher(K)
      return {
        encrypt: (M: Uint8Array) => {
          const P = padding(M, BLOCK_SIZE)
          const C = new Uint8Array(P.byteLength)
          const NonceCounter = iv.slice(0)
          const view = new DataView(NonceCounter.buffer)
          const COUNTER_OFFSET = BLOCK_SIZE - 8
          let counter = view.getBigUint64(COUNTER_OFFSET, false)
          for (let i = 0; i < P.byteLength; i += BLOCK_SIZE) {
            view.setBigUint64(COUNTER_OFFSET, counter, false)
            const B = P.slice(i, i + BLOCK_SIZE)
            c.encrypt(NonceCounter).forEach((_, i) => B[i] ^= _)
            C.set(B, i)
            counter++
          }
          return C
        },
        decrypt: (C: Uint8Array) => {
          if (C.byteLength % BLOCK_SIZE !== 0) {
            throw new KitError('Ciphertext length must be a multiple of block size')
          }
          const P = new Uint8Array(C.byteLength)
          const NonceCounter = iv.slice(0)
          const view = new DataView(NonceCounter.buffer)
          const COUNTER_OFFSET = BLOCK_SIZE - 8
          let counter = view.getBigUint64(COUNTER_OFFSET, false)
          for (let i = 0; i < C.byteLength; i += BLOCK_SIZE) {
            view.setBigUint64(COUNTER_OFFSET, counter, false)
            const B = C.slice(i, i + BLOCK_SIZE)
            c.encrypt(NonceCounter).forEach((_, i) => B[i] ^= _)
            P.set(B, i)
            counter++
          }
          return padding(P)
        },
      }
    },
  { ALGORITHM: 'CTR' },
)

export const pcbc = createCipherMode(
  (cipher: CipherAlgorithm, padding: Padding = PKCS7) =>
    (K: Uint8Array, iv: Uint8Array) => {
      // iv 检查
      const BLOCK_SIZE = cipher.BLOCK_SIZE
      if (iv.byteLength !== BLOCK_SIZE) {
        throw new KitError('iv length must be equal to block size')
      }
      const c = cipher(K)
      return {
        encrypt: (M: Uint8Array) => {
          const P = padding(M, BLOCK_SIZE)
          const C = new Uint8Array(P.byteLength)
          const prev = iv.slice(0)
          for (let i = 0; i < P.byteLength; i += BLOCK_SIZE) {
            const B = P.slice(i, i + BLOCK_SIZE)
            prev.forEach((_, i) => prev[i] ^= B[i])
            const _C = c.encrypt(prev)
            C.set(_C, i)
            _C.forEach((_, i) => prev[i] = _C[i] ^ B[i])
          }
          return C
        },
        decrypt: (C: Uint8Array) => {
          if (C.byteLength % BLOCK_SIZE !== 0) {
            throw new KitError('Ciphertext length must be a multiple of block size')
          }
          const P = new Uint8Array(C.byteLength)
          const prev = iv.slice(0)
          for (let i = 0; i < C.byteLength; i += BLOCK_SIZE) {
            const B = C.slice(i, i + BLOCK_SIZE)
            const _P = c.decrypt(B)
            _P.forEach((_, i) => _P[i] ^= prev[i])
            P.set(_P, i)
            B.forEach((_, i) => prev[i] = B[i] ^ _P[i])
          }
          return padding(P)
        },
      }
    },
  { ALGORITHM: 'PCBC' },
)

// TODO GCM CCM

// * 加密套件包装器

export interface CipherConfig {
  /**
   * @default PKCS7
   */
  PADDING?: Padding
  /**
   * @default Hex
   */
  KEY_CODEC?: Codec
  /**
   * @default Hex
   */
  IV_CODEC?: Codec
  /**
   * @default UTF8
   */
  ENCRYPT_INPUT_CODEC?: Codec
  /**
   * @default HEX
   */
  ENCRYPT_OUTPUT_CODEC?: Codec
  /**
   * @default HEX
   */
  DECRYPT_INPUT_CODEC?: Codec
  /**
   * @default UTF8
   */
  DECRYPT_OUTPUT_CODEC?: Codec
}
interface SuiteDescription {
  ALGORITHM: string
  /**
   * padding scheme
   *
   * 填充方案
   */
  PADDING: Padding
  /**
   * Block size (byte)
   *
   * 分组大小 (字节)
   */
  BLOCK_SIZE: number
  /**
   * Key size (byte)
   *
   * 密钥大小 (字节)
   */
  KEY_SIZE: number
  KEY_CODEC: Codec
  /**
   * IV size (byte)
   *
   * IV 大小 (字节)
   */
  IV_SIZE: number
  IV_CODEC: Codec
  ENCRYPT_INPUT_CODEC?: Codec
  ENCRYPT_OUTPUT_CODEC?: Codec
  DECRYPT_INPUT_CODEC?: Codec
  DECRYPT_OUTPUT_CODEC?: Codec
}
interface CipherECB extends SuiteDescription {
  (K: string | Uint8Array): {
    encrypt: (M: string | Uint8Array, CODEC?: Codec) => string
    _encrypt: (M: Uint8Array) => Uint8Array
    decrypt: (C: string | Uint8Array, CODEC?: Codec) => string
    _decrypt: (C: Uint8Array) => Uint8Array
  } & SuiteDescription
}
interface CipherIV extends SuiteDescription {
  (K: string | Uint8Array, iv: string | Uint8Array): {
    encrypt: (M: string | Uint8Array, CODEC?: Codec) => string
    _encrypt: (M: Uint8Array) => Uint8Array
    decrypt: (C: string | Uint8Array, CODEC?: Codec) => string
    _decrypt: (C: Uint8Array) => Uint8Array
  } & SuiteDescription
}
type CipherSuite<T = 'iv'> = T extends 'ECB' ? CipherECB : CipherIV

/**
 * @description
 * Create a cipher suite.
 *
 * 创建一个加密套件.
 *
 * @param {CipherAlgorithm} algorithm - 加密算法
 * @param {CipherMode} mode - 工作模式
 * @param {CipherConfig} config - 配置
 */
export function createCipher(algorithm: CipherAlgorithm, mode: CipherMode<'ECB'>, config?: CipherConfig): CipherSuite<'ECB'>
export function createCipher(algorithm: CipherAlgorithm, mode: CipherMode, config?: CipherConfig): CipherSuite
export function createCipher(algorithm: CipherAlgorithm, mode: CipherMode | CipherMode<'ECB'>, config?: CipherConfig): CipherSuite | CipherSuite<'ECB'> {
  config = config || {}
  const { PADDING = PKCS7 } = config
  const { KEY_CODEC = HEX, IV_CODEC = HEX } = config
  const { ENCRYPT_INPUT_CODEC = UTF8, ENCRYPT_OUTPUT_CODEC = HEX } = config
  const { DECRYPT_INPUT_CODEC = HEX, DECRYPT_OUTPUT_CODEC = UTF8 } = config

  function isECBMode(mode: CipherMode | CipherMode<'ECB'>): mode is CipherMode<'ECB'> {
    return mode.ALGORITHM === 'ECB'
  }

  const description = {
    ALGORITHM: `${mode.ALGORITHM}-${algorithm.ALGORITHM}`,
    PADDING,
    BLOCK_SIZE: algorithm.BLOCK_SIZE,
    KEY_SIZE: algorithm.KEY_SIZE || algorithm.BLOCK_SIZE,
    KEY_CODEC,
    IV_SIZE: algorithm.BLOCK_SIZE,
    IV_CODEC,
    ENCRYPT_INPUT_CODEC,
    ENCRYPT_OUTPUT_CODEC,
    DECRYPT_INPUT_CODEC,
    DECRYPT_OUTPUT_CODEC,
  }

  const fn = (K: string | Uint8Array, iv?: string | Uint8Array) => {
    K = typeof K === 'string' ? KEY_CODEC.parse(K) : K
    iv = typeof iv === 'string' ? IV_CODEC.parse(iv) : iv
    const m = isECBMode(mode) ? mode(algorithm, PADDING)(K) : mode(algorithm, PADDING)(K, iv!)
    return Object.freeze({
      _encrypt: m.encrypt,
      encrypt: (M: string | Uint8Array, CODEC?: Codec) => {
        M = typeof M === 'string' ? ENCRYPT_INPUT_CODEC.parse(M) : M
        const codec = CODEC || ENCRYPT_OUTPUT_CODEC
        return codec.stringify(m.encrypt(M))
      },
      _decrypt: m.decrypt,
      decrypt: (C: string | Uint8Array, CODEC?: Codec) => {
        C = typeof C === 'string' ? DECRYPT_INPUT_CODEC.parse(C) : C
        const codec = CODEC || DECRYPT_OUTPUT_CODEC
        return codec.stringify(m.decrypt(C))
      },
      ...description,
    })
  }

  return Object.freeze(Object.assign(
    isECBMode(mode)
      ? (K: string | Uint8Array) => fn(K)
      : (K: string | Uint8Array, iv: string | Uint8Array) => fn(K, iv),
    description,
  ))
}
