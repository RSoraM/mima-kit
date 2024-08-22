import type { Codec } from './codec'
import { HEX } from './codec'
import { joinBuffer } from './utils'

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
}
/**
 * @description
 * Block Cipher algorithm interface
 *
 * 分组加密算法的接口
 */
interface BlockCipher extends CipherDescription {
  /**
   * @param {string | Uint8Array} K - 密钥
   * @param {Codec} KCodec - 密钥编解码器(default: Hex)
   */
  (K: string | Uint8Array, KCodec?: Codec): {
    /**
     * @param {string | Uint8Array} M - 明文
     * @param {Codec} MCodec - 明文编解码器(default: Hex)
     */
    encrypt: (M: string | Uint8Array, MCodec?: Codec) => Uint8Array
    /**
     * @param {string | Uint8Array} C - 密文
     * @param {Codec} CCodec - 密文编解码器(default: Hex)
     */
    decrypt: (C: string | Uint8Array, CCodec?: Codec) => Uint8Array
  } & CipherDescription
}
/**
 * @description
 * Create a wrapper for the Block Cipher algorithm
 *
 * 为分组加密算法创建一个包装
 *
 * @param {Cipher} Cipher - 分组加密算法
 * @param {CipherDescription} description - 算法描述
 */
export function createBlockCipher(Cipher: Cipher, description: CipherDescription): BlockCipher {
  return Object.assign(
    (K: string | Uint8Array, KCodec = HEX) => {
      K = typeof K === 'string' ? KCodec.parse(K) : K
      const cipher = Cipher(K)
      return {
        encrypt: (M: string | Uint8Array, MCodec = HEX) => {
          M = typeof M === 'string' ? MCodec.parse(M) : M
          return cipher.encrypt(M)
        },
        decrypt: (C: string | Uint8Array, CCodec = HEX) => {
          C = typeof C === 'string' ? CCodec.parse(C) : C
          return cipher.decrypt(C)
        },
        ...description,
      }
    },
    description,
  )
}

// * 工作模式包装器

interface Mode {
  (cipher: ReturnType<BlockCipher>, padding: Padding, iv?: Uint8Array): ReturnType<Cipher>
}
interface ModeDescription {
  ALGORITHM: string
}
/**
 * @description
 * Operation mode interface
 *
 * 操作模式的接口
 */
interface OperationMode extends ModeDescription {
  (cipher: ReturnType<BlockCipher>, padding: Padding, iv?: string | Uint8Array, ivCodec?: Codec): ReturnType<Cipher>
}
/**
 * @description
 * Create a wrapper for the operation mode
 *
 * 为操作模式创建一个包装
 *
 * @param {Mode} mode - 工作模式
 * @param {ModeDescription} description - 描述
 * @returns
 */
export function createOperationMode(mode: Mode, description: ModeDescription): OperationMode {
  return Object.assign(
    (cipher: ReturnType<BlockCipher>, padding: Padding, iv?: string | Uint8Array, ivCodec: Codec = HEX) => {
      iv = typeof iv === 'string' ? ivCodec.parse(iv) : iv
      return mode(cipher, padding, iv)
    },
    description,
  )
}

// * 工作模式

/**
 * @description
 * cr
 *
 * 创建一个 CBC 工作模式
 *
 */
export const cbc = createOperationMode(
  (cipher: ReturnType<BlockCipher>, padding: Padding, iv?: Uint8Array) => {
    // iv 检查
    const BLOCK_SIZE = cipher.BLOCK_SIZE
    if (!iv) {
      throw new Error('iv is required')
    }
    if (iv.byteLength !== BLOCK_SIZE) {
      throw new Error('Invalid iv length')
    }

    return {
      encrypt: (M: Uint8Array) => {
        const P = padding(M, BLOCK_SIZE)
        const C = new Uint8Array(P.byteLength)
        let previousB = iv
        for (let i = 0; i < P.byteLength; i += BLOCK_SIZE) {
          const B = P.slice(i, i + BLOCK_SIZE)
          B.forEach((_, i) => B[i] ^= previousB[i])
          previousB = cipher.encrypt(B)
          C.set(previousB, i)
        }
        return C
      },
      decrypt: (C: Uint8Array) => {
        if (C.byteLength % BLOCK_SIZE !== 0)
          throw new Error('Invalid ciphertext length')
        const P = new Uint8Array(C.byteLength)
        let prev = iv
        for (let i = 0; i < C.byteLength; i += BLOCK_SIZE) {
          const block = C.slice(i, i + BLOCK_SIZE)
          const _P = cipher.decrypt(block)
          P.set(_P.map((v, i) => v ^ prev[i]), i)
          prev = block
        }
        return padding.unPad(P)
      },
    }
  },
  { ALGORITHM: 'CBC' },
)

// * 填充方案包装器

/**
 * @param {Uint8Array} M - 消息
 * @param {number} BLOCK_SIZE - 分组大小
 */
interface doPad {
  (M: Uint8Array, BLOCK_SIZE: number): Uint8Array
}
/**
 * @param {Uint8Array} P - 填充消息
 */
interface UnPad {
  (P: Uint8Array): Uint8Array
}
interface PaddingDescription {
  ALGORITHM: string
}
/**
 * @description
 * Padding Scheme interface
 *
 * 填充方案的接口
 */
interface Padding extends doPad, PaddingDescription {
  unPad: UnPad
}
/**
 * @description
 * create a wrapper for the padding scheme
 *
 * 为填充方案创建一个包装
 *
 * @param {doPad} doPad - 填充消息函数
 * @param {unPad} unPad - 移除填充函数
 * @param {PaddingDescription} description - 方案描述
 */
export function createPaddingScheme(
  doPad: doPad,
  unPad: UnPad,
  description: PaddingDescription,
): Padding {
  return Object.assign(doPad, { unPad, ...description })
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
        throw new Error('Invalid padding')
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
        throw new Error('Invalid padding')
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

/**
 * @description
 * Cipher Suite Config
 *
 * 加密套件配置
 */
export interface CipherSuiteConfig {
  cipher: BlockCipher
  key: string | Uint8Array
  /**
   * @description
   * key encoding
   *
   * 密钥编码
   *
   * @default Hex
   */
  key_codec?: Codec
  mode: OperationMode
  iv?: string | Uint8Array
  /**
   * @description
   * iv encoding
   *
   * 初始化向量编码
   *
   * @default Hex
   */
  iv_codec?: Codec
  /**
   * @description
   * padding scheme
   *
   * 填充方案
   *
   * @default PKCS7
   */
  padding?: Padding
  /**
   * @description
   * Encryption output encoding, default is `undefined`, i.e. no encoding, return `Uint8Array`. When specifying encoding, return the encoded string
   *
   * 加密输出编码, 默认为 `undefined`, 即不进行编码, 返回 `Uint8Array`. 当指定编码时, 返回编码后的字符串
   */
  encrypt_output_codec?: Codec
  /**
   * @description
   * Decryption output encoding, default is `undefined`, i.e. no encoding, return `Uint8Array`. When specifying encoding, return the encoded string
   *
   * 解密输出编码, 默认为 `undefined`, 即不进行编码, 返回 `Uint8Array`. 当指定编码时, 返回编码后的字符串
   */
  decrypt_output_codec?: Codec
}
interface CipherSuiteDescription {
  ALGORITHM: string
  PADDING: string
  BLOCK_SIZE: number
  KEY_SIZE: number
  KEY_CODEC: string
  IV_SIZE: number
  IV_CODEC: string
  ENCRYPT_OUTPUT_CODEC?: string
  DECRYPT_OUTPUT_CODEC?: string
}
interface CipherSuite extends CipherSuiteDescription {
  encrypt: (M: string | Uint8Array, codec?: Codec) => string | Uint8Array
  decrypt: (C: string | Uint8Array, codec?: Codec) => string | Uint8Array
}

/**
 * @description
 * Create a cipher suite
 *
 * 创建加密套件
 *
 * @param {CipherSuiteConfig} suite - 加密套件参数
 */
export function createCipherSuite(suite: CipherSuiteConfig): CipherSuite {
  const { cipher, key, key_codec: keyCodec = HEX } = suite
  const { mode, iv, iv_codec: ivCodec = HEX, padding = PKCS7 } = suite
  const { encrypt_output_codec, decrypt_output_codec } = suite

  const c = cipher(key, keyCodec)
  const m = mode(c, padding, iv, ivCodec)
  return {
    encrypt: (M: string | Uint8Array, codec: Codec = HEX) => {
      M = typeof M === 'string' ? codec.parse(M) : M
      return encrypt_output_codec ? encrypt_output_codec.stringify(m.encrypt(M)) : m.encrypt(M)
    },
    decrypt: (C: string | Uint8Array, codec: Codec = HEX) => {
      C = typeof C === 'string' ? codec.parse(C) : C
      return decrypt_output_codec ? decrypt_output_codec.stringify(m.decrypt(C)) : m.decrypt(C)
    },
    ALGORITHM: `${mode.ALGORITHM}-${cipher.ALGORITHM}`,
    PADDING: padding.ALGORITHM,
    BLOCK_SIZE: cipher.BLOCK_SIZE,
    KEY_SIZE: cipher.BLOCK_SIZE,
    KEY_CODEC: keyCodec.FORMAT,
    IV_SIZE: cipher.BLOCK_SIZE,
    IV_CODEC: ivCodec.FORMAT,
    ENCRYPT_OUTPUT_CODEC: encrypt_output_codec?.FORMAT,
    DECRYPT_OUTPUT_CODEC: decrypt_output_codec?.FORMAT,
  }
}
