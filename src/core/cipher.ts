import { Counter, KitError, U8, joinBuffer, wrap } from './utils'

// * 公共接口

export interface Cipherable {
  /**
   * @param {Uint8Array} plaintext - 明文 / plaintext
   */
  encrypt: (plaintext: Uint8Array) => U8
  /**
   * @param {Uint8Array} ciphertext - 密文 / ciphertext
   */
  decrypt: (ciphertext: Uint8Array) => U8
}

export interface CipherInfo {
  ALGORITHM: string
  /** 推荐的密钥大小 / Recommended key size (byte) */
  KEY_SIZE: number
  /** 最小密钥大小 / Minimum key size (byte) */
  MIN_KEY_SIZE: number
  /** 最大密钥大小 / Maximum key size (byte) */
  MAX_KEY_SIZE: number
}
export interface IVCipherInfo extends CipherInfo {
  /** 推荐的 IV 大小 / Recommended IV size (byte) */
  IV_SIZE: number
  /** 最小 IV 大小 / Minimum IV size (byte) */
  MIN_IV_SIZE: number
  /** 最大 IV 大小 / Maximum IV size (byte) */
  MAX_IV_SIZE: number
}
export interface Cipher {
  /**
   * @param {Uint8Array} key - 密钥 / Key
   */
  (key: Uint8Array): Cipherable
}
export interface IVCipher {
  /**
   * @param {Uint8Array} key - 密钥 / Key
   * @param {Uint8Array} iv - 初始化向量 / Initialization Vector
   */
  (key: Uint8Array, iv: Uint8Array): Cipherable
}

// * 对称密钥算法包装器

export interface BlockCipherInfo extends CipherInfo {
  /** 分组大小 / Block size (byte) */
  BLOCK_SIZE: number
}
export interface BlockCipher extends BlockCipherInfo {
  /**
   * @param {Uint8Array} key - 密钥 / Key
   */
  (key: Uint8Array): Cipherable & BlockCipherInfo
}
export interface StreamCipherInfo extends CipherInfo {
}
export interface StreamCipher extends StreamCipherInfo {
  /**
   * @param {Uint8Array} key - 密钥 / Key
   */
  (key: Uint8Array): Cipherable & StreamCipherInfo
}
export interface IVStreamCipherInfo extends IVCipherInfo {
}
export interface IVStreamCipher extends IVStreamCipherInfo {
  /**
   * @param {Uint8Array} key - 密钥 / Key
   * @param {Uint8Array} iv - 初始化向量 / Initialization Vector
   */
  (key: Uint8Array, iv: Uint8Array): Cipherable & IVStreamCipherInfo
}

export function createCipher(algorithm: Cipher, description: BlockCipherInfo): BlockCipher
export function createCipher(algorithm: Cipher, description: StreamCipherInfo): StreamCipher
export function createCipher(algorithm: IVCipher, description: IVStreamCipherInfo): IVStreamCipher
export function createCipher(
  algorithm: Cipher | IVCipher,
  description: BlockCipherInfo | StreamCipherInfo | IVStreamCipherInfo,
) {
  return wrap(
    (key: Uint8Array, iv: Uint8Array) => wrap(algorithm(key, iv), description),
    description,
  )
}

// * 填充方案包装器

export interface DoPad {
  /**
   * 添加填充 / add padding
   * @param {Uint8Array} M - 消息 / Message
   * @param {number} BLOCK_SIZE - 分组大小 / Block size
   */
  (M: Uint8Array, BLOCK_SIZE: number): U8
}
export interface UnPad {
  /**
   * 移除填充 / remove padding
   * @param {Uint8Array} P - 填充消息 / Padded message
   */
  (P: Uint8Array): U8
}
export interface PaddingInfo {
  ALGORITHM: string
}
export interface Padding extends DoPad, UnPad, PaddingInfo {
}
export function createPadding(
  doPad: DoPad,
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

/** PKCS7 填充方案 / Padding Scheme */
export const PKCS7_PAD = createPadding(
  (M: Uint8Array, BLOCK_SIZE: number) => {
    const pad = BLOCK_SIZE - M.length % BLOCK_SIZE
    return joinBuffer(M, new Uint8Array(pad).fill(pad))
  },
  (P: Uint8Array) => {
    const pad = P[P.length - 1]
    return new U8(P.slice(0, P.length - pad))
  },
  { ALGORITHM: 'PKCS#7' },
)

/** ISO/IEC 7816 填充方案 / Padding Scheme */
export const ISO7816_PAD = createPadding(
  (M: Uint8Array, BLOCK_SIZE: number) => {
    const BLOCK_TOTAL = Math.ceil((M.length + 1) / BLOCK_SIZE)
    const P = new U8(BLOCK_TOTAL * BLOCK_SIZE)
    P.set(M)
    P[M.length] = 0x80
    return P
  },
  (P: Uint8Array) => {
    let i = P.length - 1
    while (P[i] === 0x80) {
      i = i - 1
      if (i < 0) {
        console.warn('This message may not be ISO/IEC 7816-4 padded')
        return new U8()
      }
    }
    return new U8(P.slice(0, i + 1))
  },
  { ALGORITHM: 'ISO/IEC 7816-4' },
)

/** ANSI X9.23 填充方案 / Padding Scheme */
export const X923_PAD = createPadding(
  (M: Uint8Array, BLOCK_SIZE: number) => {
    const BLOCK_TOTAL = Math.ceil((M.length + 1) / BLOCK_SIZE)
    const P = new U8(BLOCK_TOTAL * BLOCK_SIZE)
    P.set(M)
    P[P.length - 1] = P.length - M.length
    return P
  },
  (P: Uint8Array) => {
    const pad = P[P.length - 1]
    return new U8(P.slice(0, P.length - pad))
  },
  { ALGORITHM: 'ANSI X9.23' },
)

/** Zero 零填充方案 / Padding Scheme */
export const ZERO_PAD = createPadding(
  (M: Uint8Array, BLOCK_SIZE: number) => {
    const pad = BLOCK_SIZE - M.length % BLOCK_SIZE
    return joinBuffer(M, new Uint8Array(pad))
  },
  (P: Uint8Array) => {
    let i = P.length - 1
    while (P[i] === 0) {
      i = i - 1
      if (i < 0) {
        return new U8()
      }
    }
    return new U8(P.slice(0, i + 1))
  },
  { ALGORITHM: 'Zero Padding' },
)

/** 无填充 / No Padding */
export const NO_PAD = createPadding(
  (M: Uint8Array) => new U8(M.slice(0)),
  (P: Uint8Array) => new U8(P.slice(0)),
  { ALGORITHM: 'No Padding' },
)

// * 工作模式

export interface ModeBaseInfo {
  ALGORITHM: string
}
export interface ModeInfo extends BlockCipherInfo {
  /** 填充方案 / Padding Scheme */
  PADDING: Padding
  /** 推荐的 IV 大小 / Recommended IV size (byte) */
  IV_SIZE: number
  /** 最小 IV 大小 / Minimum IV size (byte) */
  MIN_IV_SIZE: number
  /** 最大 IV 大小 / Maximum IV size (byte) */
  MAX_IV_SIZE: number
}
export interface Mode extends ModeBaseInfo {
  /**
   * @param {BlockCipher} cipher - 分组加密算法 / Block cipher
   * @param {Padding} padding - 填充方案 / Padding Scheme (default: PKCS7)
   */
  (cipher: BlockCipher, padding?: Padding): {
    /**
     * @param {Uint8Array} key - 密钥 / Key
     * @param {Uint8Array} iv - 初始化向量 / Initialization Vector
     */
    (key: Uint8Array, iv: Uint8Array): Cipherable & ModeInfo
  } & ModeInfo
}

export interface ECBMode extends ModeBaseInfo {
  /**
   * @param {BlockCipher} cipher - 分组加密算法 / Block cipher
   * @param {Padding} padding - 填充方案 / Padding Scheme (default: PKCS7)
   */
  (cipher: BlockCipher, padding?: Padding): {
    /**
     * ECB 不使用 IV, 如果提供 IV, 将被忽略. 仅为与其他模式兼容
     *
     * ECB do not use IV, if you provide IV, it will be ignored. It is only for compatibility with other Modes
     *
     * @param {Uint8Array} key - 密钥 / Key
     * @param {Uint8Array} [iv] - 初始化向量 / Initialization Vector
     */
    (key: Uint8Array, iv?: Uint8Array): Cipherable & ModeInfo
  } & ModeInfo
}
/** 电子密码本模式 / Electronic Code Book Mode */
export const ecb = wrap<ECBMode>(
  (cipher: BlockCipher, padding: Padding = PKCS7_PAD) => {
    const info: ModeInfo = {
      ALGORITHM: `ECB-${cipher.ALGORITHM}`,
      PADDING: padding,
      BLOCK_SIZE: cipher.BLOCK_SIZE,
      KEY_SIZE: cipher.KEY_SIZE,
      MIN_KEY_SIZE: cipher.MIN_KEY_SIZE,
      MAX_KEY_SIZE: cipher.MAX_KEY_SIZE,
      IV_SIZE: 0,
      MIN_IV_SIZE: 0,
      MAX_IV_SIZE: 0,
    }
    const suite = (K: Uint8Array) => {
      const { BLOCK_SIZE } = cipher
      const c = cipher(K)
      const encrypt = (M: Uint8Array) => {
        const P = padding(M, BLOCK_SIZE)
        const C = new U8(P.length)
        for (let i = 0; i < P.length;) {
          const offset = i
          const B = P.subarray(i, i += BLOCK_SIZE)
          C.set(c.encrypt(B), offset)
        }
        return C
      }
      const decrypt = (C: Uint8Array) => {
        if (C.length % BLOCK_SIZE !== 0) {
          throw new KitError('Decryption error')
        }
        const P = new U8(C.length)
        for (let i = 0; i < C.length;) {
          const offset = i
          const B = C.subarray(i, i += BLOCK_SIZE)
          P.set(c.decrypt(B), offset)
        }
        return padding(P)
      }
      return wrap({ encrypt, decrypt }, info)
    }
    return wrap(suite, info)
  },
  { ALGORITHM: 'ECB' },
)

export interface CBCMode extends Mode {
}
/** 密码块链接模式 / Cipher Block Chaining Mode */
export const cbc = wrap<CBCMode>(
  (cipher: BlockCipher, padding: Padding = PKCS7_PAD) => {
    const info: ModeInfo = {
      ALGORITHM: `CBC-${cipher.ALGORITHM}`,
      PADDING: padding,
      BLOCK_SIZE: cipher.BLOCK_SIZE,
      KEY_SIZE: cipher.KEY_SIZE,
      MIN_KEY_SIZE: cipher.MIN_KEY_SIZE,
      MAX_KEY_SIZE: cipher.MAX_KEY_SIZE,
      IV_SIZE: cipher.BLOCK_SIZE,
      MIN_IV_SIZE: cipher.BLOCK_SIZE,
      MAX_IV_SIZE: cipher.BLOCK_SIZE,
    }
    const suite = (K: Uint8Array, iv: Uint8Array) => {
      // iv 检查
      const { BLOCK_SIZE } = cipher
      if (iv.length !== BLOCK_SIZE) {
        throw new KitError(`${info.ALGORITHM} iv must be ${BLOCK_SIZE} byte`)
      }
      const c = cipher(K)
      const encrypt = (M: Uint8Array) => {
        const P = padding(M, BLOCK_SIZE)
        const C = new U8(P.length)
        let prev = iv.slice(0)
        for (let i = 0; i < P.length;) {
          const offset = i
          const B = P.subarray(i, i += BLOCK_SIZE)
          prev.forEach((_, i) => prev[i] ^= B[i])
          prev = c.encrypt(prev)
          C.set(prev, offset)
        }
        return C
      }
      const decrypt = (C: Uint8Array) => {
        if (C.length % BLOCK_SIZE !== 0) {
          throw new KitError('Decryption error')
        }
        const P = new U8(C.length)
        let prev = iv
        for (let i = 0; i < C.length;) {
          const offset = i
          const B = C.slice(i, i += BLOCK_SIZE)
          c.decrypt(B).forEach((_, i) => prev[i] ^= _)
          P.set(prev, offset)
          prev = B
        }
        return padding(P)
      }
      return wrap({ encrypt, decrypt }, info)
    }

    return wrap(suite, info)
  },
  { ALGORITHM: 'CBC' },
)

export interface PCBCMode extends Mode {
}
/** 传播密码块链接模式 / Propagating Cipher Block Chaining Mode */
export const pcbc = wrap<PCBCMode>(
  (cipher: BlockCipher, padding: Padding = PKCS7_PAD) => {
    const info: ModeInfo = {
      ALGORITHM: `PCBC-${cipher.ALGORITHM}`,
      PADDING: padding,
      BLOCK_SIZE: cipher.BLOCK_SIZE,
      KEY_SIZE: cipher.KEY_SIZE,
      MIN_KEY_SIZE: cipher.MIN_KEY_SIZE,
      MAX_KEY_SIZE: cipher.MAX_KEY_SIZE,
      IV_SIZE: cipher.BLOCK_SIZE,
      MIN_IV_SIZE: cipher.BLOCK_SIZE,
      MAX_IV_SIZE: cipher.BLOCK_SIZE,
    }
    const suite = (K: Uint8Array, IV: Uint8Array) => {
      // iv 检查
      const { BLOCK_SIZE } = cipher
      if (IV.length !== BLOCK_SIZE) {
        throw new KitError(`${info.ALGORITHM} iv must be ${BLOCK_SIZE} byte`)
      }
      const c = cipher(K)
      const encrypt = (M: Uint8Array) => {
        const P = padding(M, BLOCK_SIZE)
        const C = new U8(P.length)
        const prev = IV.slice(0)
        for (let i = 0; i < P.length;) {
          const offset = i
          const B = P.subarray(i, i += BLOCK_SIZE)
          prev.forEach((_, i) => prev[i] ^= B[i])
          const _C = c.encrypt(prev)
          C.set(_C, offset)
          prev.forEach((_, i) => prev[i] = _C[i] ^ B[i])
        }
        return C
      }
      const decrypt = (C: Uint8Array) => {
        if (C.length % BLOCK_SIZE !== 0) {
          throw new KitError('Decryption error')
        }
        const P = new U8(C.length)
        const prev = IV.slice(0)
        for (let i = 0; i < C.length;) {
          const offset = i
          const B = C.slice(i, i += BLOCK_SIZE)
          const _P = c.decrypt(B)
          _P.forEach((_, i) => _P[i] ^= prev[i])
          P.set(_P, offset)
          B.forEach((_, i) => prev[i] = B[i] ^ _P[i])
        }
        return padding(P)
      }
      return wrap({ encrypt, decrypt }, info)
    }
    return wrap(suite, info)
  },
  { ALGORITHM: 'PCBC' },
)

export interface CFBMode extends Mode {
}
/** 密码反馈模式 / Cipher Feedback Mode */
export const cfb = wrap<CFBMode>(
  (cipher: BlockCipher, padding: Padding = PKCS7_PAD) => {
    const info: ModeInfo = {
      ALGORITHM: `CFB-${cipher.ALGORITHM}`,
      PADDING: padding,
      BLOCK_SIZE: cipher.BLOCK_SIZE,
      KEY_SIZE: cipher.KEY_SIZE,
      MIN_KEY_SIZE: cipher.MIN_KEY_SIZE,
      MAX_KEY_SIZE: cipher.MAX_KEY_SIZE,
      IV_SIZE: cipher.BLOCK_SIZE,
      MIN_IV_SIZE: cipher.BLOCK_SIZE,
      MAX_IV_SIZE: cipher.BLOCK_SIZE,
    }
    const suite = (K: Uint8Array, iv: Uint8Array) => {
      // iv 检查
      const { BLOCK_SIZE } = cipher
      if (iv.length !== BLOCK_SIZE) {
        throw new KitError(`${info.ALGORITHM} iv must be ${BLOCK_SIZE} byte`)
      }
      const c = cipher(K)
      const encrypt = (M: Uint8Array) => {
        const P = padding(M, BLOCK_SIZE)
        const C = new U8(P.length)
        let prev = iv
        for (let i = 0; i < P.length;) {
          const offset = i
          const B = P.subarray(i, i += BLOCK_SIZE)
          prev = c.encrypt(prev)
          prev.forEach((_, i) => prev[i] ^= B[i])
          C.set(prev.subarray(0, B.length), offset)
        }
        return C
      }
      const decrypt = (C: Uint8Array) => {
        const P = new U8(C.length)
        let prev = iv
        for (let i = 0; i < C.length;) {
          const offset = i
          const B = C.subarray(i, i += BLOCK_SIZE)
          prev = c.encrypt(prev)
          B.forEach((_, i) => prev[i] ^= B[i])
          P.set(prev.subarray(0, B.length), offset)
          prev = B
        }
        return padding(P)
      }
      return wrap({ encrypt, decrypt }, info)
    }
    return wrap(suite, info)
  },
  { ALGORITHM: 'CFB' },
)

export interface OFBMode extends Mode {
}
/** 输出反馈模式 / Output Feedback Mode */
export const ofb = wrap<OFBMode>(
  (cipher: BlockCipher, padding: Padding = PKCS7_PAD) => {
    const info: ModeInfo = {
      ALGORITHM: `OFB-${cipher.ALGORITHM}`,
      PADDING: padding,
      BLOCK_SIZE: cipher.BLOCK_SIZE,
      KEY_SIZE: cipher.KEY_SIZE,
      MIN_KEY_SIZE: cipher.MIN_KEY_SIZE,
      MAX_KEY_SIZE: cipher.MAX_KEY_SIZE,
      IV_SIZE: cipher.BLOCK_SIZE,
      MIN_IV_SIZE: cipher.BLOCK_SIZE,
      MAX_IV_SIZE: cipher.BLOCK_SIZE,
    }
    const suite = (K: Uint8Array, iv: Uint8Array) => {
      // iv 检查
      const { BLOCK_SIZE } = cipher
      if (iv.length !== BLOCK_SIZE) {
        throw new KitError(`${info.ALGORITHM} iv must be ${BLOCK_SIZE} byte`)
      }
      const c = cipher(K)
      let prev = c.encrypt(iv)
      let S = prev
      let SByte = BLOCK_SIZE
      const squeeze = (TByte: number) => {
        if (SByte > TByte) {
          return S
        }
        const buffer = [S]
        while (SByte < TByte) {
          prev = c.encrypt(prev)
          buffer.push(prev)
          SByte += BLOCK_SIZE
        }
        S = joinBuffer(...buffer)
        return S
      }
      const encrypt = (M: Uint8Array) => {
        const P = padding(M, BLOCK_SIZE)
        S = squeeze(P.length)
        return P.map((_, i) => _ ^ S[i])
      }
      const decrypt = (C: Uint8Array) => {
        S = squeeze(C.length)
        return padding(C.map((_, i) => _ ^ S[i]))
      }
      return wrap({ encrypt, decrypt }, info)
    }
    return wrap(suite, info)
  },
  { ALGORITHM: 'OFB' },
)

export interface CTRMode extends Mode {
}
/** 计数器模式 / Counter Mode */
export const ctr = wrap<CTRMode>(
  (cipher: BlockCipher, padding: Padding = PKCS7_PAD) => {
    const info: ModeInfo = {
      ALGORITHM: `CTR-${cipher.ALGORITHM}`,
      PADDING: padding,
      BLOCK_SIZE: cipher.BLOCK_SIZE,
      KEY_SIZE: cipher.KEY_SIZE,
      MIN_KEY_SIZE: cipher.MIN_KEY_SIZE,
      MAX_KEY_SIZE: cipher.MAX_KEY_SIZE,
      IV_SIZE: cipher.BLOCK_SIZE,
      MIN_IV_SIZE: cipher.BLOCK_SIZE,
      MAX_IV_SIZE: cipher.BLOCK_SIZE,
    }
    const suite = (K: Uint8Array, iv: Uint8Array) => {
      // iv 检查
      const { BLOCK_SIZE } = cipher
      if (iv.length !== BLOCK_SIZE) {
        throw new KitError(`{info.ALGORITHM} iv must be ${BLOCK_SIZE} byte`)
      }
      const c = cipher(K)
      const counter = new Counter(iv.slice())
      let S = new U8()
      let SByte = 0
      const squeeze = (TByte: number) => {
        if (SByte > TByte) {
          return S
        }
        const buffer = [S]
        while (SByte < TByte) {
          buffer.push(c.encrypt(counter))
          counter.inc()
          SByte += BLOCK_SIZE
        }
        S = joinBuffer(...buffer)
        return S
      }
      const encrypt = (M: Uint8Array) => {
        const P = padding(M, BLOCK_SIZE)
        S = squeeze(P.length)
        return P.map((_, i) => _ ^ S[i])
      }
      const decrypt = (C: Uint8Array) => {
        S = squeeze(C.length)
        return padding(C.map((_, i) => _ ^ S[i]))
      }
      return wrap({ encrypt, decrypt }, info)
    }
    return wrap(suite, info)
  },
  { ALGORITHM: 'CTR' },
)

export interface GCMVerifiable {
  /**
   * @param {Uint8Array} cipherText - 密文 / ciphertext
   * @param {Uint8Array} additional_data - 附加数据 / Additional data
   * @returns {Uint8Array} - 认证标签 / Authentication tag
   */
  sign: (cipherText: Uint8Array, additional_data?: Uint8Array) => U8
  /**
   * @param {Uint8Array} auth_tag - 认证标签 / Authentication tag
   * @param {Uint8Array} ciphertext - 密文 / ciphertext
   * @param {Uint8Array} additional_data - 附加数据 / Additional data
   */
  verify: (auth_tag: Uint8Array, ciphertext: Uint8Array, additional_data?: Uint8Array) => boolean
}
export interface GCMModeInfo extends ModeInfo {
  /**
   * 认证标签大小 / Authentication tag size (byte)
   *
   * @default 16
   */
  AUTH_TAG_SIZE: number
}
export interface GCMMode extends ModeBaseInfo {
  /**
   * @param {BlockCipher} cipher - 分组加密算法 / Block cipher
   * @param {Padding} padding - 填充方案 / Padding Scheme (default: PKCS7)
   * @param {number} tag_size - 标签大小 / Authentication tag size (default: 16)
   */
  (cipher: BlockCipher, padding?: Padding, tag_size?: number): {
    /**
     * @param {Uint8Array} key - 密钥 / Key
     * @param {Uint8Array} iv - 初始化向量 / Initialization Vector
     */
    (key: Uint8Array, iv: Uint8Array): Cipherable & GCMVerifiable & GCMModeInfo
  } & GCMModeInfo
}
function GF128Mul(X: Uint8Array, Y: Uint8Array) {
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

  const Z = new U8(16)
  const ZView = new DataView(Z.buffer)
  ZView.setBigUint64(0, ZH, false)
  ZView.setBigUint64(8, ZL, false)
  return Z
}
function GHASH(H: Uint8Array, A: Uint8Array, C: Uint8Array) {
  const A_BLOCK_TOTAL = Math.ceil(A.length / 16)
  const C_BLOCK_TOTAL = Math.ceil(C.length / 16)
  const D = new Uint8Array((A_BLOCK_TOTAL + C_BLOCK_TOTAL + 1) * 16)
  const view = new DataView(D.buffer)
  D.set(A)
  D.set(C, A_BLOCK_TOTAL * 16)
  view.setBigUint64(D.length - 16, BigInt(A.length << 3), false)
  view.setBigUint64(D.length - 8, BigInt(C.length << 3), false)
  let X = new U8(16)
  for (let i = 0; i < D.length; i += 16) {
    const B = D.subarray(i, i + 16)
    X.forEach((_, i) => X[i] ^= B[i])
    X = GF128Mul(H, X)
  }
  return X
}
/** 伽罗瓦计数器模式 / Galois Counter Mode */
export const gcm = wrap<GCMMode>(
  (
    cipher: BlockCipher,
    padding: Padding = PKCS7_PAD,
    tag_size: number = 16,
  ) => {
    const { BLOCK_SIZE } = cipher
    if (BLOCK_SIZE !== 16) {
      throw new KitError('GCM cipher block must be 128 bit')
    }
    const info: GCMModeInfo = {
      ALGORITHM: `GCM-${cipher.ALGORITHM}`,
      PADDING: padding,
      BLOCK_SIZE: cipher.BLOCK_SIZE,
      KEY_SIZE: cipher.KEY_SIZE,
      MIN_KEY_SIZE: cipher.MIN_KEY_SIZE,
      MAX_KEY_SIZE: cipher.MAX_KEY_SIZE,
      IV_SIZE: 12,
      MIN_IV_SIZE: 0,
      MAX_IV_SIZE: Infinity,
      AUTH_TAG_SIZE: tag_size,
    }
    const suite = (K: Uint8Array, iv: Uint8Array) => {
      const c = cipher(K)
      const H = c.encrypt(new Uint8Array(BLOCK_SIZE))
      let IV = new Counter(16)
      if (iv.length === 12) {
        IV.set(iv)
        IV[15] = 1
      }
      else {
        IV = new Counter(GHASH(H, new Uint8Array(), iv.slice(0)))
      }
      let S = c.encrypt(IV)
      let SByte = 0
      const squeeze = (TByte: number) => {
        if (SByte > TByte) {
          return S
        }
        const buffer = [S]
        while (SByte < TByte) {
          IV.inc()
          buffer.push(c.encrypt(IV))
          SByte += BLOCK_SIZE
        }
        S = joinBuffer(...buffer)
        return S
      }
      const encrypt = (M: Uint8Array) => {
        const P = padding(M, BLOCK_SIZE)
        S = squeeze(P.length)
        return P.map((_, i) => _ ^ S[i + BLOCK_SIZE])
      }
      const decrypt = (C: Uint8Array) => {
        S = squeeze(C.length)
        return padding(C.map((_, i) => _ ^ S[i + BLOCK_SIZE]))
      }
      const sign = (C: Uint8Array, A: Uint8Array = new Uint8Array()) => {
        const T = GHASH(H, A, C)
        T.forEach((_, i) => T[i] ^= S[i])
        return T.slice(0, tag_size)
      }
      const verify = (T: Uint8Array, C: Uint8Array, A?: Uint8Array) => {
        if (T.length !== tag_size) {
          return false
        }
        const T1 = sign(C, A)
        return T.every((_, i) => _ === T1[i])
      }
      return wrap({ encrypt, decrypt, sign, verify }, info)
    }
    return wrap(suite, info)
  },
  {
    ALGORITHM: 'GCM',
    IV_SIZE: 12,
  },
)
