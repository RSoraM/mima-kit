import type { Codec } from './codec'
import { HEX, UTF8 } from './codec'
import { KitError, joinBuffer } from './utils'

// * 分组加密算法包装器

interface Cipher {
  (K: Uint8Array): {
    encrypt: (M: Uint8Array) => Uint8Array
    decrypt: (C: Uint8Array) => Uint8Array
  }
}
interface CipherDescription {
  ALGORITHM: string
  BLOCK_SIZE: number
  KEY_SIZE?: number
}
interface BlockCipher extends CipherDescription {
  (K: Uint8Array): ReturnType<Cipher> & CipherDescription
}
export function createBlockCipher(
  cipher: Cipher,
  description: CipherDescription,
): BlockCipher {
  return Object.freeze(Object.assign(
    (K: Uint8Array) => Object.freeze(Object.assign(
      cipher(K),
      description,
    )),
    description,
  ))
}

// * 工作模式包装器

interface Mode {
  (cipher: ReturnType<BlockCipher>, padding: Padding, iv?: Uint8Array): ReturnType<Cipher>
}
interface ModeDescription {
  ALGORITHM: string
}
interface OperationMode extends Mode, ModeDescription { }
export function createOperationMode(
  mode: Mode,
  description: ModeDescription,
) {
  return Object.freeze(Object.assign(
    mode,
    description,
  ))
}

// * 工作模式

export const ecb = createOperationMode(
  (cipher: ReturnType<BlockCipher>, padding: Padding) => {
    return {
      encrypt: (M: Uint8Array) => {
        const P = padding(M, cipher.BLOCK_SIZE)
        const C = new Uint8Array(P.byteLength)
        for (let i = 0; i < P.byteLength; i += cipher.BLOCK_SIZE) {
          const B = P.slice(i, i + cipher.BLOCK_SIZE)
          C.set(cipher.encrypt(B), i)
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
          P.set(cipher.decrypt(B), i)
        }
        return padding.unPad(P)
      },
    }
  },
  { ALGORITHM: 'ECB' },
)

export const cbc = createOperationMode(
  (cipher: ReturnType<BlockCipher>, padding: Padding, iv?: Uint8Array) => {
    // iv 检查
    const BLOCK_SIZE = cipher.BLOCK_SIZE
    if (!iv) {
      throw new KitError('iv is required for CBC mode')
    }
    if (iv.byteLength !== BLOCK_SIZE) {
      throw new KitError('iv length must be equal to block size')
    }

    return {
      encrypt: (M: Uint8Array) => {
        const P = padding(M, BLOCK_SIZE)
        const C = new Uint8Array(P.byteLength)
        let prev = iv
        for (let i = 0; i < P.byteLength; i += BLOCK_SIZE) {
          const B = P.slice(i, i + BLOCK_SIZE)
          B.forEach((_, i) => B[i] ^= prev[i])
          prev = cipher.encrypt(B)
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
          const _P = cipher.decrypt(B)
          _P.forEach((_, i) => _P[i] ^= prev[i])
          P.set(_P, i)
          prev = B
        }
        return padding.unPad(P)
      },
    }
  },
  { ALGORITHM: 'CBC' },
)

export const cfb = createOperationMode(
  (cipher: ReturnType<BlockCipher>, padding: Padding, iv?: Uint8Array) => {
    // iv 检查
    const BLOCK_SIZE = cipher.BLOCK_SIZE
    if (!iv) {
      throw new KitError('iv is required for CFB mode')
    }
    if (iv.byteLength !== BLOCK_SIZE) {
      throw new KitError('iv length must be equal to block size')
    }

    return {
      encrypt: (M: Uint8Array) => {
        const P = padding(M, BLOCK_SIZE)
        const C = new Uint8Array(P.byteLength)
        let prev = iv
        for (let i = 0; i < P.byteLength; i += BLOCK_SIZE) {
          const B = P.slice(i, i + BLOCK_SIZE)
          prev = cipher.encrypt(prev)
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
          const _P = cipher.encrypt(prev)
          _P.forEach((_, i) => _P[i] ^= B[i])
          P.set(_P, i)
          prev = B
        }
        return padding.unPad(P)
      },
    }
  },
  { ALGORITHM: 'CFB' },
)

export const ofb = createOperationMode(
  (cipher: ReturnType<BlockCipher>, padding: Padding, iv?: Uint8Array) => {
    // iv 检查
    const BLOCK_SIZE = cipher.BLOCK_SIZE
    if (!iv) {
      throw new KitError('iv is required for OFB mode')
    }
    if (iv.byteLength !== BLOCK_SIZE) {
      throw new KitError('iv length must be equal to block size')
    }

    return {
      encrypt: (M: Uint8Array) => {
        const P = padding(M, BLOCK_SIZE)
        const C = new Uint8Array(P.byteLength)
        let prev = iv
        for (let i = 0; i < P.byteLength; i += BLOCK_SIZE) {
          const B = P.slice(i, i + BLOCK_SIZE)
          prev = cipher.encrypt(prev)
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
          prev = cipher.encrypt(prev)
          B.forEach((_, i) => B[i] ^= prev[i])
          P.set(B, i)
        }
        return padding.unPad(P)
      },
    }
  },
  { ALGORITHM: 'OFB' },
)

export const ctr = createOperationMode(
  (cipher: ReturnType<BlockCipher>, padding: Padding, nonce?: Uint8Array) => {
    // iv 检查
    const BLOCK_SIZE = cipher.BLOCK_SIZE
    if (!nonce) {
      throw new KitError('nonce(iv) is required for CTR mode')
    }
    if (nonce.byteLength !== BLOCK_SIZE) {
      throw new KitError('nonce(iv) length must be equal to block size')
    }

    return {
      encrypt: (M: Uint8Array) => {
        const P = padding(M, BLOCK_SIZE)
        const C = new Uint8Array(P.byteLength)
        const NonceCounter = nonce.slice(0)
        const view = new DataView(NonceCounter.buffer)
        const COUNTER_OFFSET = BLOCK_SIZE - 8
        let counter = view.getBigUint64(COUNTER_OFFSET, false)
        for (let i = 0; i < P.byteLength; i += BLOCK_SIZE) {
          view.setBigUint64(COUNTER_OFFSET, counter, false)
          const B = P.slice(i, i + BLOCK_SIZE)
          cipher.encrypt(NonceCounter).forEach((_, i) => B[i] ^= _)
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
        const NonceCounter = nonce.slice(0)
        const view = new DataView(NonceCounter.buffer)
        const COUNTER_OFFSET = BLOCK_SIZE - 8
        let counter = view.getBigUint64(COUNTER_OFFSET, false)
        for (let i = 0; i < C.byteLength; i += BLOCK_SIZE) {
          view.setBigUint64(COUNTER_OFFSET, counter, false)
          const B = C.slice(i, i + BLOCK_SIZE)
          cipher.encrypt(NonceCounter).forEach((_, i) => B[i] ^= _)
          P.set(B, i)
          counter++
        }
        return padding.unPad(P)
      },
    }
  },
  { ALGORITHM: 'CTR' },
)

// * 填充方案包装器

interface doPad {
  /**
   * @param {Uint8Array} M - 消息
   * @param {number} BLOCK_SIZE - 分组大小
   */
  (M: Uint8Array, BLOCK_SIZE: number): Uint8Array
}
interface UnPad {
  /**
   * @param {Uint8Array} P - 填充消息
   */
  (P: Uint8Array): Uint8Array
}
interface PaddingDescription {
  ALGORITHM: string
}
interface Padding extends doPad, PaddingDescription {
  unPad: UnPad
}
export function createPaddingScheme(
  doPad: doPad,
  unPad: UnPad,
  description: PaddingDescription,
): Padding {
  return Object.freeze(Object.assign(
    doPad,
    {
      unPad,
      ...description,
    },
  ))
}

// * 填充方案

/**
 * @description
 * PKCS7 padding scheme.
 *
 * PKCS7 填充方案.
 */
export const PKCS7 = createPaddingScheme(
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
export const ZeroPadding = createPaddingScheme(
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
  { ALGORITHM: 'ZeroPadding' },
)

/**
 * @description
 * ISO/IEC 7816 padding scheme.
 *
 * ISO/IEC 7816 填充方案.
 */
export const ISO7816_4 = createPaddingScheme(
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
export const ANSI_X923 = createPaddingScheme(
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

// * 加密套件包装器

export interface CipherSuiteConfig {
  cipher: BlockCipher
  mode: OperationMode
  /**
   * @default PKCS7
   */
  padding?: Padding
  key: string | Uint8Array
  /**
   * @default Hex
   */
  KEY_CODEC?: Codec
  iv?: string | Uint8Array
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
interface CipherSuiteDescription {
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
interface CipherSuite extends CipherSuiteDescription {
  encrypt: (M: string | Uint8Array, CODEC?: Codec) => string
  _encrypt: (M: Uint8Array) => Uint8Array
  decrypt: (C: string | Uint8Array, CODEC?: Codec) => string
  _decrypt: (C: Uint8Array) => Uint8Array
}
export function createCipherSuite(config: CipherSuiteConfig): CipherSuite {
  let { key } = config
  const { cipher, KEY_CODEC = HEX } = config
  key = typeof key === 'string' ? KEY_CODEC.parse(key) : key
  const c = cipher(key)

  let { iv } = config
  const { mode, IV_CODEC = HEX, padding = PKCS7 } = config
  iv = typeof iv === 'string' ? IV_CODEC.parse(iv) : iv
  const m = mode(c, padding, iv)

  const { ENCRYPT_INPUT_CODEC = UTF8, ENCRYPT_OUTPUT_CODEC = HEX } = config
  const { DECRYPT_INPUT_CODEC = HEX, DECRYPT_OUTPUT_CODEC = UTF8 } = config

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
    ALGORITHM: `${mode.ALGORITHM}-${cipher.ALGORITHM}`,
    PADDING: padding,
    BLOCK_SIZE: cipher.BLOCK_SIZE,
    KEY_SIZE: cipher.KEY_SIZE || cipher.BLOCK_SIZE,
    KEY_CODEC,
    IV_SIZE: cipher.BLOCK_SIZE,
    IV_CODEC,
    ENCRYPT_INPUT_CODEC,
    ENCRYPT_OUTPUT_CODEC,
    DECRYPT_INPUT_CODEC,
    DECRYPT_OUTPUT_CODEC,
  })
}
