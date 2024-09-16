import type { Codec } from './codec'
import { HEX, UTF8 } from './codec'
import { KitError, joinBuffer, wrap } from './utils'

// * 分组加密算法包装器

export interface Cipherable {
  /**
   * @param {Uint8Array} M - 消息
   */
  encrypt: (M: Uint8Array) => Uint8Array
  /**
   * @param {Uint8Array} C - 密文
   */
  decrypt: (C: Uint8Array) => Uint8Array
}
export interface CipherInfo {
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
export interface Cipher extends CipherInfo {
  /**
   * @param {Uint8Array} K - 密钥
   */
  (K: Uint8Array): Cipherable & CipherInfo
}
export function createCipher(
  algorithm: (K: Uint8Array) => Cipherable,
  description: CipherInfo,
): Cipher {
  return wrap(
    (K: Uint8Array) => wrap(
      algorithm(K),
      description,
    ),
    description,
  )
}

// * 填充方案包装器

export interface doPad {
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
export interface UnPad {
  /**
   * remove padding
   *
   * 移除填充
   *
   * @param {Uint8Array} P - 填充消息
   */
  (P: Uint8Array): Uint8Array
}
export interface PaddingInfo {
  ALGORITHM: string
}
export interface Padding extends doPad, UnPad, PaddingInfo {
}
export function createPadding(
  doPad: doPad,
  unPad: UnPad,
  description: PaddingInfo,
): Padding {
  return wrap(
    (M: Uint8Array, BLOCK_SIZE?: number) => (
      typeof BLOCK_SIZE === 'number'
        ? doPad(M, BLOCK_SIZE)
        : unPad(M)
    ),
    description,
  )
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

export const NoPadding = createPadding(
  (M: Uint8Array) => M,
  (P: Uint8Array) => P,
  { ALGORITHM: 'No Padding' },
)

// * 工作模式

function inc32(iv: Uint8Array) {
  const view = new DataView(iv.buffer)
  let counter = view.getUint32(iv.byteLength - 4, false)
  counter = (counter + 1) % 0xFFFFFFFF
  view.setUint32(iv.byteLength - 4, counter, false)
  return iv
}

export interface ModeVerifiable {
  /**
   * @param {Uint8Array} C - 密文
   * @param {Uint8Array} A - 附加数据
   * @returns {Uint8Array} - 签名
   */
  _sign: (C: Uint8Array, A?: Uint8Array) => Uint8Array
  /**
   * @param {string | Uint8Array} C - 密文
   * @param {string | Uint8Array} A - 附加数据
   * @returns {string} - 签名
   */
  sign: (C: string | Uint8Array, A?: string | Uint8Array) => string
  /**
   * @param {Uint8Array} T - 签名
   * @param {Uint8Array} C - 密文
   * @param {Uint8Array} A - 附加数据
   * @returns {boolean} - 是否验证通过
   */
  _verify: (T: Uint8Array, C: Uint8Array, A?: Uint8Array) => boolean
  /**
   * @param {string | Uint8Array} T - 签名
   * @param {string | Uint8Array} C - 密文
   * @param {string | Uint8Array} A - 附加数据
   * @returns {boolean} - 是否验证通过
   */
  verify: (T: string | Uint8Array, C: string | Uint8Array, A?: string | Uint8Array) => boolean
}
export interface ModeCipherable {
  /**
   * @param {Uint8Array} M - 消息
   */
  _encrypt: (M: Uint8Array) => Uint8Array
  /**
   * @param {string | Uint8Array} M - 消息
   * @param {Codec} CODEC - 输出编码器
   */
  encrypt: (M: string | Uint8Array, CODEC?: Codec) => string
  /**
   * @param {Uint8Array} C - 密文
   */
  _decrypt: (C: Uint8Array) => Uint8Array
  /**
   * @param {string | Uint8Array} C - 密文
   * @param {Codec} CODEC - 输出编码器
   */
  decrypt: (C: string | Uint8Array, CODEC?: Codec) => string
}

export interface ECBConfig {
  /**
   * @default PKCS7
   */
  PADDING?: Padding
  /**
   * @default HEX
   */
  KEY_CODEC?: Codec
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
export interface ECBModeBaseInfo {
  ALGORITHM: string
}
export interface ECBModeInfo extends CipherInfo, ECBModeBaseInfo, Required<ECBConfig> {
}
export interface ECBMode extends ECBModeBaseInfo {
  (cipher: Cipher, config?: ECBConfig):
    ((K: string | Uint8Array) =>
      ModeCipherable & ECBModeInfo) & ECBModeInfo
}
/**
 * @description
 * Electronic Codebook mode.
 *
 * 电子密码本模式.
 */
export const ecb = wrap<ECBMode>(
  (cipher: Cipher, config: ECBConfig = {}) => {
    const { PADDING = PKCS7 } = config
    const { KEY_CODEC = HEX } = config
    const { ENCRYPT_INPUT_CODEC = UTF8, ENCRYPT_OUTPUT_CODEC = HEX } = config
    const { DECRYPT_INPUT_CODEC = HEX, DECRYPT_OUTPUT_CODEC = UTF8 } = config

    const info: ECBModeInfo = {
      ALGORITHM: `ECB-${cipher.ALGORITHM}`,
      BLOCK_SIZE: cipher.BLOCK_SIZE,
      KEY_SIZE: cipher.KEY_SIZE,
      PADDING,
      KEY_CODEC,
      ENCRYPT_INPUT_CODEC,
      ENCRYPT_OUTPUT_CODEC,
      DECRYPT_INPUT_CODEC,
      DECRYPT_OUTPUT_CODEC,
    }

    const suite = (K: string | Uint8Array) => {
      K = typeof K === 'string' ? KEY_CODEC.parse(K) : K
      const c = cipher(K)
      const encrypt = (M: Uint8Array) => {
        const P = PADDING(M, cipher.BLOCK_SIZE)
        const C = new Uint8Array(P.byteLength)
        for (let i = 0; i < P.byteLength; i += cipher.BLOCK_SIZE) {
          const B = P.subarray(i, i + cipher.BLOCK_SIZE)
          C.set(c.encrypt(B), i)
        }
        return C
      }
      const decrypt = (C: Uint8Array) => {
        if (C.byteLength % cipher.BLOCK_SIZE !== 0) {
          throw new KitError('Ciphertext length must be a multiple of block size')
        }
        const P = new Uint8Array(C.byteLength)
        for (let i = 0; i < C.byteLength; i += cipher.BLOCK_SIZE) {
          const B = C.subarray(i, i + cipher.BLOCK_SIZE)
          P.set(c.decrypt(B), i)
        }
        return PADDING(P)
      }
      const cipherable: ModeCipherable = {
        _encrypt: encrypt,
        _decrypt: decrypt,
        encrypt: (M: string | Uint8Array, CODEC?: Codec) => {
          M = typeof M === 'string' ? ENCRYPT_INPUT_CODEC.parse(M) : M
          const C = encrypt(M)
          return (CODEC || ENCRYPT_OUTPUT_CODEC).stringify(C)
        },
        decrypt: (C: string | Uint8Array, CODEC?: Codec) => {
          C = typeof C === 'string' ? DECRYPT_INPUT_CODEC.parse(C) : C
          const P = decrypt(C)
          return (CODEC || DECRYPT_OUTPUT_CODEC).stringify(P)
        },
      }
      return wrap(cipherable, info)
    }

    return wrap(suite, info)
  },
  { ALGORITHM: 'ECB' },
)

export interface CBCConfig extends ECBConfig {
  /**
   * @default HEX
   */
  IV_CODEC?: Codec
}
export interface CBCModeBaseInfo extends ECBModeBaseInfo {
}
export interface CBCModeInfo extends CipherInfo, CBCModeBaseInfo, Required<CBCConfig> {
  /**
   * IV size (byte)
   *
   * IV 大小 (字节)
   */
  IV_SIZE: number
}
export interface CBCMode extends CBCModeBaseInfo {
  (cipher: Cipher, config?: CBCConfig):
    ((K: string | Uint8Array, iv: string | Uint8Array) =>
      ModeCipherable & CBCModeInfo) & CBCModeInfo
}
/**
 * @description
 * Cipher Block Chaining mode.
 *
 * 密码块链接模式.
 */
export const cbc = wrap<CBCMode>(
  (cipher: Cipher, config: CBCConfig = {}) => {
    const { PADDING = PKCS7 } = config
    const { KEY_CODEC = HEX, IV_CODEC = HEX } = config
    const { ENCRYPT_INPUT_CODEC = UTF8, ENCRYPT_OUTPUT_CODEC = HEX } = config
    const { DECRYPT_INPUT_CODEC = HEX, DECRYPT_OUTPUT_CODEC = UTF8 } = config

    const info: CBCModeInfo = {
      ALGORITHM: `CBC-${cipher.ALGORITHM}`,
      BLOCK_SIZE: cipher.BLOCK_SIZE,
      KEY_SIZE: cipher.KEY_SIZE,
      IV_SIZE: cipher.BLOCK_SIZE,
      PADDING,
      KEY_CODEC,
      IV_CODEC,
      ENCRYPT_INPUT_CODEC,
      ENCRYPT_OUTPUT_CODEC,
      DECRYPT_INPUT_CODEC,
      DECRYPT_OUTPUT_CODEC,
    }

    const suite = (K: string | Uint8Array, iv: string | Uint8Array) => {
      K = typeof K === 'string' ? KEY_CODEC.parse(K) : K
      iv = typeof iv === 'string' ? IV_CODEC.parse(iv) : iv
      // iv 检查
      const BLOCK_SIZE = cipher.BLOCK_SIZE
      if (iv.byteLength !== BLOCK_SIZE) {
        throw new KitError('iv length must be equal to block size')
      }
      const c = cipher(K)
      const encrypt = (M: Uint8Array) => {
        const P = PADDING(M, BLOCK_SIZE)
        const C = new Uint8Array(P.byteLength)
        let prev = iv.slice(0)
        for (let i = 0; i < P.byteLength; i += BLOCK_SIZE) {
          const B = P.subarray(i, i + BLOCK_SIZE)
          prev.forEach((_, i) => prev[i] ^= B[i])
          prev = c.encrypt(prev)
          C.set(prev, i)
        }
        return C
      }
      const decrypt = (C: Uint8Array) => {
        if (C.byteLength % BLOCK_SIZE !== 0) {
          throw new KitError('Ciphertext length must be a multiple of block size')
        }
        const P = new Uint8Array(C.byteLength)
        let prev = iv
        for (let i = 0; i < C.byteLength; i += BLOCK_SIZE) {
          const B = C.slice(i, i + BLOCK_SIZE)
          c.decrypt(B).forEach((_, i) => prev[i] ^= _)
          P.set(prev, i)
          prev = B
        }
        return PADDING(P)
      }
      const cipherable: ModeCipherable = {
        _encrypt: encrypt,
        _decrypt: decrypt,
        encrypt: (M: string | Uint8Array, CODEC?: Codec) => {
          M = typeof M === 'string' ? ENCRYPT_INPUT_CODEC.parse(M) : M
          const C = encrypt(M)
          return (CODEC || ENCRYPT_OUTPUT_CODEC).stringify(C)
        },
        decrypt: (C: string | Uint8Array, CODEC?: Codec) => {
          C = typeof C === 'string' ? DECRYPT_INPUT_CODEC.parse(C) : C
          const P = decrypt(C)
          return (CODEC || DECRYPT_OUTPUT_CODEC).stringify(P)
        },
      }
      return wrap(cipherable, info)
    }

    return wrap(suite, info)
  },
  { ALGORITHM: 'CBC' },
)

export interface PCBCConfig extends CBCConfig {
}
export interface PCBCModeBaseInfo extends CBCModeBaseInfo {
}
export interface PCBCModeInfo extends CipherInfo, PCBCModeBaseInfo, Required<PCBCConfig> {
  /**
   * IV size (byte)
   *
   * IV 大小 (字节)
   */
  IV_SIZE: number
}
export interface PCBCMode extends PCBCModeBaseInfo {
  (cipher: Cipher, config?: PCBCConfig):
    ((K: string | Uint8Array, iv: string | Uint8Array) =>
      ModeCipherable & PCBCModeInfo) & PCBCModeInfo
}
/**
 * @description
 * Propagating Cipher Block Chaining mode.
 *
 * 传播密码块链接模式.
 */
export const pcbc = wrap<PCBCMode>(
  (cipher: Cipher, config: CBCConfig = {}) => {
    const { PADDING = PKCS7 } = config
    const { KEY_CODEC = HEX, IV_CODEC = HEX } = config
    const { ENCRYPT_INPUT_CODEC = UTF8, ENCRYPT_OUTPUT_CODEC = HEX } = config
    const { DECRYPT_INPUT_CODEC = HEX, DECRYPT_OUTPUT_CODEC = UTF8 } = config

    const info: PCBCModeInfo = {
      ALGORITHM: `PCBC-${cipher.ALGORITHM}`,
      BLOCK_SIZE: cipher.BLOCK_SIZE,
      KEY_SIZE: cipher.KEY_SIZE,
      IV_SIZE: cipher.BLOCK_SIZE,
      PADDING,
      KEY_CODEC,
      IV_CODEC,
      ENCRYPT_INPUT_CODEC,
      ENCRYPT_OUTPUT_CODEC,
      DECRYPT_INPUT_CODEC,
      DECRYPT_OUTPUT_CODEC,
    }

    const suite = (K: string | Uint8Array, iv: string | Uint8Array) => {
      K = typeof K === 'string' ? KEY_CODEC.parse(K) : K
      iv = typeof iv === 'string' ? IV_CODEC.parse(iv) : iv
      // iv 检查
      const BLOCK_SIZE = cipher.BLOCK_SIZE
      if (iv.byteLength !== BLOCK_SIZE) {
        throw new KitError('iv length must be equal to block size')
      }
      const c = cipher(K)
      const encrypt = (M: Uint8Array) => {
        const P = PADDING(M, BLOCK_SIZE)
        const C = new Uint8Array(P.byteLength)
        const prev = iv.slice(0)
        for (let i = 0; i < P.byteLength; i += BLOCK_SIZE) {
          // TODO can be subarray?
          const B = P.slice(i, i + BLOCK_SIZE)
          prev.forEach((_, i) => prev[i] ^= B[i])
          const _C = c.encrypt(prev)
          C.set(_C, i)
          _C.forEach((_, i) => prev[i] = _C[i] ^ B[i])
        }
        return C
      }
      const decrypt = (C: Uint8Array) => {
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
        return PADDING(P)
      }
      const cipherable: ModeCipherable = {
        _encrypt: encrypt,
        _decrypt: decrypt,
        encrypt: (M: string | Uint8Array, CODEC?: Codec) => {
          M = typeof M === 'string' ? ENCRYPT_INPUT_CODEC.parse(M) : M
          const C = encrypt(M)
          return (CODEC || ENCRYPT_OUTPUT_CODEC).stringify(C)
        },
        decrypt: (C: string | Uint8Array, CODEC?: Codec) => {
          C = typeof C === 'string' ? DECRYPT_INPUT_CODEC.parse(C) : C
          const P = decrypt(C)
          return (CODEC || DECRYPT_OUTPUT_CODEC).stringify(P)
        },
      }
      return wrap(cipherable, info)
    }

    return wrap(suite, info)
  },
  { ALGORITHM: 'PCBC' },
)

export interface CFBConfig extends CBCConfig {
}
export interface CFBModeBaseInfo extends CBCModeBaseInfo {
}
export interface CFBModeInfo extends CipherInfo, CFBModeBaseInfo, Required<CFBConfig> {
  /**
   * IV size (byte)
   *
   * IV 大小 (字节)
   */
  IV_SIZE: number
}
export interface CFBMode extends CFBModeBaseInfo {
  (cipher: Cipher, config?: CFBConfig):
    ((K: string | Uint8Array, iv: string | Uint8Array) =>
      ModeCipherable & CFBModeInfo) & CFBModeInfo
}
/**
 * @description
 * Cipher Feedback mode.
 *
 * 密码反馈模式.
 */
export const cfb = wrap<CFBMode>(
  (cipher: Cipher, config: CBCConfig = {}) => {
    const { PADDING = PKCS7 } = config
    const { KEY_CODEC = HEX, IV_CODEC = HEX } = config
    const { ENCRYPT_INPUT_CODEC = UTF8, ENCRYPT_OUTPUT_CODEC = HEX } = config
    const { DECRYPT_INPUT_CODEC = HEX, DECRYPT_OUTPUT_CODEC = UTF8 } = config

    const info: CFBModeInfo = {
      ALGORITHM: `CFB-${cipher.ALGORITHM}`,
      BLOCK_SIZE: cipher.BLOCK_SIZE,
      KEY_SIZE: cipher.KEY_SIZE,
      IV_SIZE: cipher.BLOCK_SIZE,
      PADDING,
      KEY_CODEC,
      IV_CODEC,
      ENCRYPT_INPUT_CODEC,
      ENCRYPT_OUTPUT_CODEC,
      DECRYPT_INPUT_CODEC,
      DECRYPT_OUTPUT_CODEC,
    }

    const suite = (K: string | Uint8Array, iv: string | Uint8Array) => {
      K = typeof K === 'string' ? KEY_CODEC.parse(K) : K
      iv = typeof iv === 'string' ? IV_CODEC.parse(iv) : iv
      // iv 检查
      const BLOCK_SIZE = cipher.BLOCK_SIZE
      if (iv.byteLength !== BLOCK_SIZE) {
        throw new KitError('iv length must be equal to block size')
      }
      const c = cipher(K)
      const encrypt = (M: Uint8Array) => {
        const P = PADDING(M, BLOCK_SIZE)
        const C = new Uint8Array(P.byteLength)
        let prev = iv
        for (let i = 0; i < P.byteLength; i += BLOCK_SIZE) {
          const B = P.subarray(i, i + BLOCK_SIZE)
          prev = c.encrypt(prev)
          prev.forEach((_, i) => prev[i] ^= B[i])
          C.set(prev.subarray(0, B.byteLength), i)
        }
        return C
      }
      const decrypt = (C: Uint8Array) => {
        const P = new Uint8Array(C.byteLength)
        let prev = iv
        for (let i = 0; i < C.byteLength; i += BLOCK_SIZE) {
          const B = C.subarray(i, i + BLOCK_SIZE)
          prev = c.encrypt(prev)
          B.forEach((_, i) => prev[i] ^= B[i])
          P.set(prev.subarray(0, B.byteLength), i)
          prev = B
        }
        return PADDING(P)
      }
      const cipherable: ModeCipherable = {
        _encrypt: encrypt,
        _decrypt: decrypt,
        encrypt: (M: string | Uint8Array, CODEC?: Codec) => {
          M = typeof M === 'string' ? ENCRYPT_INPUT_CODEC.parse(M) : M
          const C = encrypt(M)
          return (CODEC || ENCRYPT_OUTPUT_CODEC).stringify(C)
        },
        decrypt: (C: string | Uint8Array, CODEC?: Codec) => {
          C = typeof C === 'string' ? DECRYPT_INPUT_CODEC.parse(C) : C
          const P = decrypt(C)
          return (CODEC || DECRYPT_OUTPUT_CODEC).stringify(P)
        },
      }
      return wrap(cipherable, info)
    }

    return wrap(suite, info)
  },
  { ALGORITHM: 'CFB' },
)

export interface OFBConfig extends CBCConfig {
}
export interface OFBModeBaseInfo extends CBCModeBaseInfo {
}
export interface OFBModeInfo extends CipherInfo, OFBModeBaseInfo, Required<OFBConfig> {
  /**
   * IV size (byte)
   *
   * IV 大小 (字节)
   */
  IV_SIZE: number
}
export interface OFBMode extends OFBModeBaseInfo {
  (cipher: Cipher, config?: OFBConfig):
    ((K: string | Uint8Array, iv: string | Uint8Array) =>
      ModeCipherable & OFBModeInfo) & OFBModeInfo
}
/**
 * @description
 * Output Feedback mode.
 *
 * 输出反馈模式.
 */
export const ofb = wrap<OFBMode>(
  (cipher: Cipher, config: CBCConfig = {}) => {
    const { PADDING = PKCS7 } = config
    const { KEY_CODEC = HEX, IV_CODEC = HEX } = config
    const { ENCRYPT_INPUT_CODEC = UTF8, ENCRYPT_OUTPUT_CODEC = HEX } = config
    const { DECRYPT_INPUT_CODEC = HEX, DECRYPT_OUTPUT_CODEC = UTF8 } = config

    const info: OFBModeInfo = {
      ALGORITHM: `OFB-${cipher.ALGORITHM}`,
      BLOCK_SIZE: cipher.BLOCK_SIZE,
      KEY_SIZE: cipher.KEY_SIZE,
      IV_SIZE: cipher.BLOCK_SIZE,
      PADDING,
      KEY_CODEC,
      IV_CODEC,
      ENCRYPT_INPUT_CODEC,
      ENCRYPT_OUTPUT_CODEC,
      DECRYPT_INPUT_CODEC,
      DECRYPT_OUTPUT_CODEC,
    }

    const suite = (K: string | Uint8Array, iv: string | Uint8Array) => {
      K = typeof K === 'string' ? KEY_CODEC.parse(K) : K
      iv = typeof iv === 'string' ? IV_CODEC.parse(iv) : iv
      // iv 检查
      const BLOCK_SIZE = cipher.BLOCK_SIZE
      if (iv.byteLength !== BLOCK_SIZE) {
        throw new KitError('iv length must be equal to block size')
      }
      const c = cipher(K)
      let prev = c.encrypt(iv)
      let S = prev
      let current = 1
      const squeeze = (count: number) => {
        if (current > count) {
          return S
        }
        let offset = S.byteLength
        const buffer = new Uint8Array(count * BLOCK_SIZE)
        buffer.set(S)
        while (current < count) {
          prev = c.encrypt(prev)
          buffer.set(prev, offset)
          offset += BLOCK_SIZE
          current++
        }
        S = buffer
        return S
      }
      const encrypt = (M: Uint8Array) => {
        const P = PADDING(M, BLOCK_SIZE)
        const BLOCK_TOTAL = Math.ceil(P.byteLength / BLOCK_SIZE)
        S = squeeze(BLOCK_TOTAL)
        return P.map((_, i) => _ ^ S[i])
      }
      const decrypt = (C: Uint8Array) => {
        const BLOCK_TOTAL = Math.ceil(C.byteLength / BLOCK_SIZE)
        S = squeeze(BLOCK_TOTAL)
        return PADDING(C.map((_, i) => _ ^ S[i]))
      }
      const cipherable: ModeCipherable = {
        _encrypt: encrypt,
        _decrypt: decrypt,
        encrypt: (M: string | Uint8Array, CODEC?: Codec) => {
          M = typeof M === 'string' ? ENCRYPT_INPUT_CODEC.parse(M) : M
          const C = encrypt(M)
          return (CODEC || ENCRYPT_OUTPUT_CODEC).stringify(C)
        },
        decrypt: (C: string | Uint8Array, CODEC?: Codec) => {
          C = typeof C === 'string' ? DECRYPT_INPUT_CODEC.parse(C) : C
          const P = decrypt(C)
          return (CODEC || DECRYPT_OUTPUT_CODEC).stringify(P)
        },
      }
      return wrap(cipherable, info)
    }

    return wrap(suite, info)
  },
  { ALGORITHM: 'OFB' },
)

export interface CTRConfig extends CBCConfig {
}
export interface CTRModeBaseInfo extends CBCModeBaseInfo {
}
export interface CTRModeInfo extends CipherInfo, CTRModeBaseInfo, Required<CTRConfig> {
  /**
   * IV size (byte)
   *
   * IV 大小 (字节)
   */
  IV_SIZE: number
}
export interface CTRMode extends CTRModeBaseInfo {
  (cipher: Cipher, config?: CTRConfig):
    ((K: string | Uint8Array, iv: string | Uint8Array) =>
      ModeCipherable & CTRModeInfo) & CTRModeInfo
}
/**
 * @description
 * Counter mode.
 *
 * 计数器模式.
 */
export const ctr = wrap<CTRMode>(
  (cipher: Cipher, config: CBCConfig = {}) => {
    const { PADDING = PKCS7 } = config
    const { KEY_CODEC = HEX, IV_CODEC = HEX } = config
    const { ENCRYPT_INPUT_CODEC = UTF8, ENCRYPT_OUTPUT_CODEC = HEX } = config
    const { DECRYPT_INPUT_CODEC = HEX, DECRYPT_OUTPUT_CODEC = UTF8 } = config

    const info: CTRModeInfo = {
      ALGORITHM: `CTR-${cipher.ALGORITHM}`,
      BLOCK_SIZE: cipher.BLOCK_SIZE,
      KEY_SIZE: cipher.KEY_SIZE,
      IV_SIZE: cipher.BLOCK_SIZE,
      PADDING,
      KEY_CODEC,
      IV_CODEC,
      ENCRYPT_INPUT_CODEC,
      ENCRYPT_OUTPUT_CODEC,
      DECRYPT_INPUT_CODEC,
      DECRYPT_OUTPUT_CODEC,
    }

    const suite = (K: string | Uint8Array, iv: string | Uint8Array) => {
      K = typeof K === 'string' ? KEY_CODEC.parse(K) : K
      iv = typeof iv === 'string' ? IV_CODEC.parse(iv) : iv
      // iv 检查
      const BLOCK_SIZE = cipher.BLOCK_SIZE
      if (iv.byteLength !== BLOCK_SIZE) {
        throw new KitError('nonce(iv) length must be equal to block size')
      }
      const c = cipher(K)
      let counter = iv.slice(0)
      let current = 1
      let S = c.encrypt(counter)
      const squeeze = (count: number) => {
        if (current > count) {
          return S
        }
        let offset = S.byteLength
        const buffer = new Uint8Array(count * BLOCK_SIZE)
        buffer.set(S)
        while (current < count) {
          counter = inc32(counter)
          buffer.set(c.encrypt(counter), offset)
          offset += BLOCK_SIZE
          current++
        }
        S = buffer
        return S
      }
      const encrypt = (M: Uint8Array) => {
        const P = PADDING(M, BLOCK_SIZE)
        const BLOCK_TOTAL = Math.ceil(P.byteLength / BLOCK_SIZE)
        S = squeeze(BLOCK_TOTAL)
        return P.map((_, i) => _ ^ S[i])
      }
      const decrypt = (C: Uint8Array) => {
        const BLOCK_TOTAL = Math.ceil(C.byteLength / BLOCK_SIZE)
        S = squeeze(BLOCK_TOTAL)
        return PADDING(C.map((_, i) => _ ^ S[i]))
      }
      const cipherable: ModeCipherable = {
        _encrypt: encrypt,
        _decrypt: decrypt,
        encrypt: (M: string | Uint8Array, CODEC?: Codec) => {
          M = typeof M === 'string' ? ENCRYPT_INPUT_CODEC.parse(M) : M
          const C = encrypt(M)
          return (CODEC || ENCRYPT_OUTPUT_CODEC).stringify(C)
        },
        decrypt: (C: string | Uint8Array, CODEC?: Codec) => {
          C = typeof C === 'string' ? DECRYPT_INPUT_CODEC.parse(C) : C
          const P = decrypt(C)
          return (CODEC || DECRYPT_OUTPUT_CODEC).stringify(P)
        },
      }
      return wrap(cipherable, info)
    }

    return wrap(suite, info)
  },
  { ALGORITHM: 'CTR' },
)

export interface GCMConfig extends CBCConfig {
  /**
   * Additional data codec
   *
   * 附加数据编解码器
   *
   * @default UTF8
   */
  ADDITIONAL_DATA_CODEC?: Codec
  /**
   * Authentication tag size (byte)
   *
   * 认证标签大小 (字节)
   *
   * @default 16
   */
  AUTH_TAG_SIZE?: number
  /**
   * @default HEX
   */
  AUTH_TAG_CODEC?: Codec
}
export interface GCMModeBaseInfo extends CBCModeBaseInfo {
  /**
   * IV size (byte)
   *
   * IV 大小 (字节)
   *
   * @default 12
   */
  IV_SIZE: number
}
export interface GCMModeInfo extends CipherInfo, GCMModeBaseInfo, Required<GCMConfig> {
}
export interface GCMMode extends GCMModeBaseInfo {
  (cipher: Cipher, config?: GCMConfig):
    ((K: string | Uint8Array, iv: string | Uint8Array) =>
      ModeCipherable & ModeVerifiable & GCMModeInfo) & GCMModeInfo
}
function GF128Mul(X: Uint8Array, Y: Uint8Array): Uint8Array {
  // R: E1000000000000000000000000000000
  const RH = 0xE1n << 56n

  const YView = new DataView(Y.buffer)
  let VH = YView.getBigUint64(0, false)
  let VL = YView.getBigUint64(8, false)
  let ZH = 0n
  let ZL = 0n

  for (let i = 0; i < 16; i++) {
    const x = X[i]
    for (let j = 7; j >= 0; j--) {
      if ((x >> j) & 1) {
        ZH ^= VH
        ZL ^= VL
      }
      const carry = VL & 1n
      VL = (VH << 63n) | (VL >> 1n)
      VL = VL & 0xFFFFFFFFFFFFFFFFn
      VH = (VH >> 1n)
      if (carry) {
        VH ^= RH
      }
    }
  }

  const Z = new Uint8Array(16)
  const ZView = new DataView(Z.buffer)
  ZView.setBigUint64(0, ZH, false)
  ZView.setBigUint64(8, ZL, false)
  return Z
}
function GHASH(H: Uint8Array, A: Uint8Array, C: Uint8Array) {
  const A_BLOCK_TOTAL = Math.ceil(A.byteLength / 16)
  const C_BLOCK_TOTAL = Math.ceil(C.byteLength / 16)
  const D = new Uint8Array((A_BLOCK_TOTAL + C_BLOCK_TOTAL + 1) * 16)
  const view = new DataView(D.buffer)
  D.set(A)
  D.set(C, A_BLOCK_TOTAL * 16)
  view.setBigUint64(D.byteLength - 16, BigInt(A.byteLength << 3), false)
  view.setBigUint64(D.byteLength - 8, BigInt(C.byteLength << 3), false)
  let X = new Uint8Array(16)
  for (let i = 0; i < D.byteLength; i += 16) {
    const B = D.subarray(i, i + 16)
    X.forEach((_, i) => X[i] ^= B[i])
    X = GF128Mul(H, X)
  }
  return X
}
/**
 * @description
 * Galois/Counter Mode.
 *
 * 伽罗瓦/计数器模式.
 */
export const gcm = wrap<GCMMode>(
  (cipher: Cipher, config: GCMConfig = {}) => {
    const BLOCK_SIZE = cipher.BLOCK_SIZE
    if (BLOCK_SIZE !== 16) {
      throw new KitError('GCM mode requires a cipher with a block size of 128 bits')
    }
    const { PADDING = PKCS7 } = config
    const { KEY_CODEC = HEX, IV_CODEC = HEX } = config
    const { ENCRYPT_INPUT_CODEC = UTF8, ENCRYPT_OUTPUT_CODEC = HEX } = config
    const { DECRYPT_INPUT_CODEC = HEX, DECRYPT_OUTPUT_CODEC = UTF8 } = config
    const { AUTH_TAG_SIZE = 16 } = config
    const { ADDITIONAL_DATA_CODEC = UTF8, AUTH_TAG_CODEC = HEX } = config

    const info: GCMModeInfo = {
      ALGORITHM: `GCM-${cipher.ALGORITHM}`,
      BLOCK_SIZE: cipher.BLOCK_SIZE,
      KEY_SIZE: cipher.KEY_SIZE,
      IV_SIZE: 12,
      PADDING,
      KEY_CODEC,
      IV_CODEC,
      ENCRYPT_INPUT_CODEC,
      ENCRYPT_OUTPUT_CODEC,
      DECRYPT_INPUT_CODEC,
      DECRYPT_OUTPUT_CODEC,
      AUTH_TAG_SIZE,
      AUTH_TAG_CODEC,
      ADDITIONAL_DATA_CODEC,
    }

    const suite = (K: string | Uint8Array, iv: string | Uint8Array) => {
      K = typeof K === 'string' ? KEY_CODEC.parse(K) : K
      iv = typeof iv === 'string' ? IV_CODEC.parse(iv) : iv
      const c = cipher(K)
      const H = c.encrypt(new Uint8Array(BLOCK_SIZE))
      let IV = new Uint8Array(16)
      if (iv.byteLength === 12) {
        IV.set(iv)
        IV[15] = 1
      }
      else {
        IV = GHASH(H, new Uint8Array(), iv.slice(0))
      }
      let S = c.encrypt(IV)
      let current = 0
      const squeeze = (count: number) => {
        if (current > count) {
          return S
        }
        let offset = S.byteLength
        const buffer = new Uint8Array((count + 1) * BLOCK_SIZE)
        buffer.set(S)
        while (current < count) {
          IV = inc32(IV)
          buffer.set(c.encrypt(IV), offset)
          offset += BLOCK_SIZE
          current++
        }
        S = buffer
        return S
      }
      const encrypt = (M: Uint8Array) => {
        const P = NoPadding(M, BLOCK_SIZE)
        const BLOCK_TOTAL = Math.ceil(P.byteLength / BLOCK_SIZE)
        S = squeeze(BLOCK_TOTAL)
        return P.map((_, i) => _ ^ S[i + 16])
      }
      const decrypt = (C: Uint8Array) => {
        const BLOCK_TOTAL = Math.ceil(C.byteLength / BLOCK_SIZE)
        S = squeeze(BLOCK_TOTAL)
        return NoPadding(C.map((_, i) => _ ^ S[i + 16]))
      }
      const cipherable: ModeCipherable = {
        _encrypt: encrypt,
        _decrypt: decrypt,
        encrypt: (M: string | Uint8Array, CODEC?: Codec) => {
          M = typeof M === 'string' ? ENCRYPT_INPUT_CODEC.parse(M) : M
          const C = encrypt(M)
          return (CODEC || ENCRYPT_OUTPUT_CODEC).stringify(C)
        },
        decrypt: (C: string | Uint8Array, CODEC?: Codec) => {
          C = typeof C === 'string' ? DECRYPT_INPUT_CODEC.parse(C) : C
          const P = decrypt(C)
          return (CODEC || DECRYPT_OUTPUT_CODEC).stringify(P)
        },
      }
      const sign = (C: Uint8Array, A: Uint8Array = new Uint8Array()) => {
        const T = GHASH(H, A, C)
        T.forEach((_, i) => T[i] ^= S[i])
        return T.slice(0, AUTH_TAG_SIZE)
      }
      const verify = (T: Uint8Array, C: Uint8Array, A?: Uint8Array) => {
        if (T.byteLength !== AUTH_TAG_SIZE) {
          return false
        }
        const T1 = sign(C, A)
        return T.every((_, i) => _ === T1[i])
      }
      const verifiable: ModeVerifiable = {
        _sign: sign,
        _verify: verify,
        sign: (C: string | Uint8Array, A: string | Uint8Array = new Uint8Array()) => {
          C = typeof C === 'string' ? DECRYPT_INPUT_CODEC.parse(C) : C
          A = typeof A === 'string' ? ADDITIONAL_DATA_CODEC.parse(A) : A
          const T = sign(C, A)
          return AUTH_TAG_CODEC.stringify(T)
        },
        verify: (T: string | Uint8Array, C: string | Uint8Array, A?: string | Uint8Array) => {
          T = typeof T === 'string' ? AUTH_TAG_CODEC.parse(T) : T
          C = typeof C === 'string' ? DECRYPT_INPUT_CODEC.parse(C) : C
          A = typeof A === 'string' ? ADDITIONAL_DATA_CODEC.parse(A) : A
          return verify(T, C, A)
        },
      }
      return wrap(cipherable, verifiable, info)
    }

    return wrap(suite, info)
  },
  {
    ALGORITHM: 'GCM',
    IV_SIZE: 12,
  },
)

// * 流加密算法包装器

export interface StreamCipherConfig {
  /**
   * @default HEX
   */
  KEY_CODEC?: Codec
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
export interface StreamCipherable extends ModeCipherable { }
export interface StreamCipherInfo {
  ALGORITHM: string
  /**
   * Key size (byte)
   *
   * 密钥大小 (字节)
   */
  KEY_SIZE: number
}
export interface StreamCipher extends StreamCipherInfo {
  /**
   * @param {string | Uint8Array} K - 密钥
   * @param {StreamCipherConfig} config - 配置
   */
  (K: string | Uint8Array, config?: StreamCipherConfig): StreamCipherable & StreamCipherInfo
}
export function createStreamCipher(
  algorithm: (K: Uint8Array) => Cipherable,
  description: StreamCipherInfo,
): StreamCipher {
  return wrap(
    (K: string | Uint8Array, config?: StreamCipherConfig) => {
      config = config || {}
      const { KEY_CODEC = HEX } = config
      const { ENCRYPT_INPUT_CODEC = UTF8, ENCRYPT_OUTPUT_CODEC = HEX } = config
      const { DECRYPT_INPUT_CODEC = HEX, DECRYPT_OUTPUT_CODEC = UTF8 } = config

      K = typeof K === 'string' ? KEY_CODEC.parse(K) : K
      const c = algorithm(K)
      const encrypt = (M: string | Uint8Array, CODEC?: Codec) => {
        M = typeof M === 'string' ? ENCRYPT_INPUT_CODEC.parse(M) : M
        const C = c.encrypt(M)
        return (CODEC || ENCRYPT_OUTPUT_CODEC).stringify(C)
      }
      const decrypt = (C: string | Uint8Array, CODEC?: Codec) => {
        C = typeof C === 'string' ? DECRYPT_INPUT_CODEC.parse(C) : C
        const P = c.decrypt(C)
        return (CODEC || DECRYPT_OUTPUT_CODEC).stringify(P)
      }

      const cipherable: StreamCipherable = {
        _encrypt: c.encrypt,
        _decrypt: c.decrypt,
        encrypt,
        decrypt,
      }
      return wrap(cipherable, description)
    },
    description,
  )
}
