import type { BlockCipher, BlockCipherInfo } from '../../core/cipher'
import { cbc, createCipher } from '../../core/cipher'
import type { FpECUtils } from '../../core/ec'
import { BIPoint, Fp, FpEC, U8Point } from '../../core/ec'
import type { FpECPoint, FpMECParams, FpWECParams } from '../../core/ecParams'
import type { Digest, KeyHash } from '../../core/hash'
import { KitError, U8, genBitMask, genRandomBI, getBIBits, joinBuffer, mod, modInverse } from '../../core/utils'
import type { KDF } from '../../core/kdf'
import { x963kdf } from '../../core/kdf'
import { aes } from '../blockCipher/aes'
import { sha256 } from '../../hash/sha256'
import { hmac } from '../../hash/hmac'

// * Interfaces

export interface ECPublicKey<T = bigint | Uint8Array> {
  /** 椭圆曲线公钥 / Elliptic Curve Public Key */
  readonly Q: Readonly<FpECPoint<T>>
}
export interface ECPrivateKey<T = bigint | Uint8Array> {
  /** 椭圆曲线私钥 / Elliptic Curve Private Key */
  readonly d: T
}
/** 椭圆曲线密钥对 / Elliptic Curve Key Pair */
export interface ECKeyPair<T = bigint | Uint8Array> extends ECPrivateKey<T>, ECPublicKey<T> {
}

export interface ECDH {
  /**
   * @param {ECPrivateKey} s_key - 己方私钥 / Self Private Key
   * @param {ECPublicKey} p_key - 对方公钥 / Counterparty Public Key
   */
  (s_key: ECPrivateKey, p_key: ECPublicKey): FpECPoint<U8>
}

export interface ECMQV {
  /**
   * @param {ECKeyPair} u1 - 己方密钥对 / Self Key Pair
   * @param {ECKeyPair} u2 - 己方临时密钥对 / Self Temporary Key Pair
   * @param {ECPublicKey} v1 - 对方公钥 / Counterparty Public Key
   * @param {ECPublicKey} v2 - 对方临时公钥 / Counterparty Temporary Public Key
   */
  (u1: ECKeyPair, u2: ECKeyPair, v1: ECPublicKey, v2: ECPublicKey): FpECPoint<U8>
}

export interface ECDSASignature<T = bigint | Uint8Array> {
  /** 临时公钥 / Temporary Public Key */
  r: T
  /** 签名值 / Signature Value */
  s: T
}
export interface ECDSA {
  /**
   * @param {Digest} [hash=sha256] - 摘要函数 / Digest Function
   */
  (hash?: Digest): {
    /**
     * @param {ECPrivateKey} s_key - 签名方私钥 / Signer's Private Key
     * @param {Uint8Array} M - 消息 / Message
     */
    sign: (s_key: ECPrivateKey, M: Uint8Array) => ECDSASignature<U8>
    /**
     * @param {ECPublicKey} p_key - 签名方公钥 / Signer's Public Key
     * @param {Uint8Array} M - 消息 / Message
     */
    verify: (p_key: ECPublicKey, M: Uint8Array, signature: ECDSASignature) => boolean
  }
}

export interface IVBlockCipher extends BlockCipherInfo {
  (K: Uint8Array, iv: Uint8Array): ReturnType<BlockCipher>
}
export interface ECIESConfig {
  /** 分组密码算法 / Block Cipher Algorithm (default: AES-256-GCM) */
  cipher?: IVBlockCipher
  /** 密钥哈希函数 / Key Hash Function (default: HMAC-SHA-256) */
  mac?: KeyHash
  /** 密钥派生函数 / Key Derivation Function (default: ANSI-X9.63-KDF with SHA-256) */
  kdf?: KDF
  /** 附加数据1 / Additional Data 1 (default: empty) */
  S1?: Uint8Array
  /** 附加数据2 / Additional Data 2 (default: empty) */
  S2?: Uint8Array
  /** 初始化向量 / Initialization Vector (default: Uint8Array(cipher.BLOCK_SIZE)) */
  iv?: Uint8Array
}
export interface ECIESCiphertext {
  /** 临时公钥 / Temporary Public Key */
  R: ECPublicKey
  /** 密文 / Ciphertext */
  C: Uint8Array
  /** 校验值 / Check Value */
  D: Uint8Array
}
export interface ECIESEncrypt {
  /**
   * 椭圆曲线集成加密算法
   *
   * Elliptic Curve Integrated Encryption Scheme
   *
   * @param {ECPublicKey} p_key - 接收方公钥 / Recipient's Public Key
   * @param {Uint8Array} M - 明文 / Plaintext
   */
  (p_key: ECPublicKey, M: Uint8Array): ECIESCiphertext
}
export interface ECIESDecrypt {
  /**
   * 椭圆曲线集成解密算法
   *
   * Elliptic Curve Integrated Decryption Scheme
   *
   * @param {ECPrivateKey} s_key - 接收方私钥 / Recipient's Private Key
   * @param {ECIESCiphertext} C - 密文 / Ciphertext
   */
  (s_key: ECPrivateKey, C: ECIESCiphertext): U8
}
export interface ECIES {
  /**
   * @param {IVBlockCipher} [config.cipher] - 分组密码算法 / Block Cipher Algorithm (default: AES-256-GCM)
   * @param {KeyHash} [config.mac] - 密钥哈希函数 / Key Hash Function (default: HMAC-SHA-256)
   * @param {KDF} [config.kdf] - 密钥派生函数 / Key Derivation Function (default: ANSI-X9.63-KDF with SHA-256)
   * @param {Uint8Array} [config.S1] - 附加数据1 / Additional Data 1 (default: empty)
   * @param {Uint8Array} [config.S2] - 附加数据2 / Additional Data 2 (default: empty)
   * @param {Uint8Array} [config.iv] - 初始化向量 / Initialization Vector (default: Uint8Array(cipher.BLOCK_SIZE))
   */
  (config?: ECIESConfig): {
    encrypt: ECIESEncrypt
    decrypt: ECIESDecrypt
  }
}

export interface FpECCrypto {
  utils: {
    /**
     * 判断公钥是否合法
     *
     * Determine if the public key is legal
     */
    isLegalPK: (p_key: ECPublicKey) => boolean
    /**
     * 判断私钥是否合法
     *
     * Determine if the private key is legal
     */
    isLegalSK: (s_key: ECPrivateKey) => boolean
    /**
     * 点转换为字节串，默认不压缩
     *
     * Convert Point to Byte String, not compressed by default
     */
    PointToU8: (point: FpECPoint, compress?: boolean) => U8
    /**
     * 字节串转换为点
     *
     * Convert Byte String to Point
     */
    U8ToPoint: (buffer: Uint8Array) => FpECPoint<U8>
  } & FpECUtils
  /**
   * 生成椭圆曲线密钥
   *
   * Generate Elliptic Curve Key
   */
  gen: {
    /** 生成密钥对 / Generate Key Pair */
    (type?: 'key_pair'): ECKeyPair<U8>
    /** 生成私钥 / Generate Private Key */
    (type: 'private_key'): ECPrivateKey<U8>
    /** 生成公钥 / Generate Public Key */
    (type: 'public_key', s_key: ECPrivateKey): ECKeyPair<U8>
  }
  /**
   * 椭圆曲线迪菲-赫尔曼, 密钥协商算法
   *
   * Elliptic Curve Diffie-Hellman Key Agreement Algorithm
   */
  dh: ECDH
  /**
   * 椭圆曲线余因子迪菲-赫尔曼, 密钥协商算法
   *
   * Elliptic Curve Co-factor Diffie-Hellman Key Agreement Algorithm
   */
  cdh: ECDH
  /**
   * 椭圆曲线梅内泽斯-奎-范斯通密钥协商算法
   *
   * Elliptic Curve Menezes-Qu-Vanstone Key Agreement Algorithm
   */
  mqv: ECMQV
  /**
   * 椭圆曲线数字签名
   *
   * Elliptic Curve Digital Signature Algorithm
   */
  dsa: ECDSA
  /**
   * 椭圆曲线集成加密算法
   *
   * Elliptic Curve Integrated Encryption Scheme
   */
  ies: ECIES
}

// * Functions

/**
 * 定义 ECIES 配置
 *
 * Define ECIES Configuration
 */
export function defineECIES(config?: ECIESConfig) {
  config = config ?? {}
  const {
    cipher = cbc(aes(256)),
    mac = hmac(sha256),
    kdf = x963kdf(sha256),
    S1 = new Uint8Array(0),
    S2 = new Uint8Array(0),
    iv = new Uint8Array(cipher.BLOCK_SIZE),
  } = config
  return { cipher, mac, kdf, S1, S2, iv }
}

// * EC Algorithms

/**
 * 素域椭圆曲线密码学组件
 *
 * Prime Field Elliptic Curve Cryptography Components
 */
export function FpECC(curve: FpWECParams | FpMECParams): FpECCrypto {
  const { p, a, b, G, n, h } = curve
  const p_bit = getBIBits(p)
  const p_byte = (p_bit + 7) >> 3
  const n_bit = getBIBits(n)
  const n_mask = genBitMask(n_bit)
  const { addPoint, mulPoint } = FpEC(curve)
  const { plus, multiply, root } = Fp(p)

  const isLegalPK: FpECCrypto['utils']['isLegalPK'] = (p_key: ECPublicKey): boolean => {
    const { Q } = p_key
    // P != O
    if (Q.isInfinity) {
      return false
    }
    // P(x, y) ∈ E
    const P = BIPoint(Q)
    const { x, y } = P
    if (x < 0n || x >= p || y < 0n || y >= p) {
      return false
    }

    if (curve.type === 'Weierstrass') {
      // y^2 = x^3 + ax + b
      const l = multiply(y, y)
      const r = plus(multiply(x, x, x), multiply(a, x), b)
      if (l !== r) {
        return false
      }
      // nP = O
      const nP = mulPoint(P, n)
      return nP.isInfinity
    }
    if (curve.type === 'Montgomery') {
      // By^2 = x^3 + Ax^2 + x
      const l = multiply(b, y, y)
      const r = plus(multiply(x, x, x), multiply(a, x, x), x)
      if (l !== r) {
        return false
      }
      // nP = O
      const nP = mulPoint(P, n)
      return nP.isInfinity
    }
    // unknown curve type
    else {
      return false
    }
  }
  const isLegalSK: FpECCrypto['utils']['isLegalSK'] = (s_key: ECPrivateKey): boolean => {
    const d = typeof s_key.d === 'bigint' ? s_key.d : U8.from(s_key.d).toBI()
    if (d < 0n || d >= p) {
      return false
    }
    return !mulPoint(G, d).isInfinity
  }
  const PointToU8: FpECCrypto['utils']['PointToU8'] = (point: FpECPoint, compress = false): U8 => {
    if (point.isInfinity) {
      return new U8([0x00])
    }
    const { x, y } = U8Point(point, p_byte)
    const sign_y = y[y.length - 1] & 1
    const PC = new U8([compress ? 0x02 | sign_y : 0x04])
    const X1 = x
    const Y1 = compress ? new U8() : y
    return joinBuffer(PC, X1, Y1)
  }
  const U8ToPoint: FpECCrypto['utils']['U8ToPoint'] = (buffer: Uint8Array): FpECPoint<U8> => {
    const point_buffer = U8.from(buffer)
    const PC = point_buffer[0]
    if (PC === 0x00) {
      if (point_buffer.length !== 1) {
        throw new KitError('Invalid Point')
      }
      return U8Point()
    }
    if (PC !== 0x02 && PC !== 0x03 && PC !== 0x04) {
      throw new KitError('Invalid Point')
    }
    // 无压缩
    if (PC === 0x04) {
      if (point_buffer.length !== (p_byte << 1) + 1) {
        throw new KitError('Invalid Point')
      }
      const x = point_buffer.slice(1, p_byte + 1)
      const y = point_buffer.slice(p_byte + 1)
      return { isInfinity: false, x, y }
    }
    // 解压缩
    else {
      if (point_buffer.length !== p_byte + 1) {
        throw new KitError('Invalid Point')
      }
      const x_buffer = point_buffer.slice(1)
      const x = x_buffer.toBI()
      const sign_y = BigInt(PC & 1)
      if (curve.type === 'Weierstrass') {
        let y = 0n
        y = plus(multiply(x, x, x), multiply(a, x), b)
        y = root(y)
        y = (y & 1n) === sign_y ? y : p - y
        return U8Point({ isInfinity: false, x: x_buffer, y }, p_byte)
      }
      else if (curve.type === 'Montgomery') {
        let y = 0n
        y = plus(multiply(x, x, x), multiply(a, x, x), x)
        y = root(y / b)
        y = (y & 1n) === sign_y ? y : p - y
        return U8Point({ isInfinity: false, x: x_buffer, y }, p_byte)
      }
      else {
        throw new KitError('Unknown curve type')
      }
    }
  }
  // Key generation
  function gen(type?: 'key_pair'): ECKeyPair<U8>
  function gen(type: 'private_key'): ECPrivateKey<U8>
  function gen(type: 'public_key', s_key: ECPrivateKey): ECKeyPair<U8>
  function gen(
    type: 'key_pair' | 'private_key' | 'public_key' = 'key_pair',
    s_key?: ECPrivateKey,
  ) {
    if (type === 'key_pair') {
      // private key
      const { buffer, result: d } = genRandomBI(n, p_byte)
      // public key
      const _ = mulPoint(G, d)
      const Q = U8Point(_, p_byte)
      return { Q, d: buffer }
    }
    else if (type === 'private_key') {
      return { d: genRandomBI(n, p_byte).buffer }
    }
    else if (type === 'public_key') {
      const d_buffer = typeof s_key!.d === 'bigint' ? U8.fromBI(s_key!.d) : U8.from(s_key!.d)
      const d = typeof s_key!.d === 'bigint' ? s_key!.d : d_buffer.toBI()
      if (d === 0n) {
        throw new KitError('Invalid private key')
      }
      const _ = mulPoint(G, d)
      const Q = U8Point(_, p_byte)
      return { Q, d: d_buffer }
    }
  }
  // Key agreement
  const ecdh: ECDH = (s_key: ECPrivateKey, p_key: ECPublicKey) => {
    if (!isLegalPK(p_key)) {
      throw new KitError('Invalid public key')
    }
    if (!isLegalSK(s_key)) {
      throw new KitError('Invalid private key')
    }
    const Q = p_key.Q
    const d = s_key.d
    const S = mulPoint(Q, d)
    if (S.isInfinity) {
      throw new KitError('the result of ECDH is the point at infinity')
    }
    return U8Point(S, p_byte)
  }
  const eccdh: ECDH = (s_key: ECPrivateKey, p_key: ECPublicKey) => {
    if (!isLegalPK(p_key)) {
      throw new KitError('Invalid public key')
    }
    if (!isLegalSK(s_key)) {
      throw new KitError('Invalid private key')
    }
    const Q = p_key.Q
    const d = typeof s_key.d === 'bigint' ? s_key.d : U8.from(s_key.d).toBI()
    const S = mulPoint(Q, d * h)
    if (S.isInfinity) {
      throw new KitError('the result of ECCDH is the point at infinity')
    }
    return U8Point(S, p_byte)
  }
  const ecmqv: ECMQV = (u1: ECKeyPair, u2: ECKeyPair, v1: ECPublicKey, v2: ECPublicKey) => {
    if (!isLegalPK(v1) || !isLegalPK(v2)) {
      throw new KitError('Invalid public key')
    }
    const ceilLog2n = n_bit
    const L = 1n << BigInt(Math.ceil(ceilLog2n / 2))
    const u1d = typeof u1.d === 'bigint' ? u1.d : U8.from(u1.d).toBI()
    const u2d = typeof u2.d === 'bigint' ? u2.d : U8.from(u2.d).toBI()
    const u2Qx = typeof u2.Q.x === 'bigint' ? u2.Q.x : U8.from(u2.Q.x).toBI()
    const v2Qx = typeof v2.Q.x === 'bigint' ? v2.Q.x : U8.from(v2.Q.x).toBI()
    const Q2u = mod(u2Qx, L) + L
    const Q2v = mod(v2Qx, L) + L
    const s = mod(u2d + Q2u * u1d, n)
    const P = mulPoint(addPoint(v2.Q, mulPoint(v1.Q, Q2v)), s * h)
    if (P.isInfinity) {
      throw new KitError('Public key not available')
    }
    return U8Point(P, p_byte)
  }
  // Digital signature
  const ecdsa: ECDSA = (hash: Digest = sha256) => {
    const sign = (s_key: ECPrivateKey, M: Uint8Array) => {
      const d = typeof s_key.d === 'bigint' ? s_key.d : U8.from(s_key.d).toBI()
      let r = 0n
      let s = 0n
      let z = hash(M).toBI()
      while (z > n_mask) {
        z = z >> 1n
      }
      do {
        const K = gen()
        const k = K.d.toBI()
        const x1 = K.Q.x.toBI()
        r = mod(x1, n)
        if (r === 0n)
          continue

        s = modInverse(k, n) * mod(z + r * d, n)
        s = mod(s, n)
      } while (s === 0n)
      const r_buffer = U8.fromBI(r)
      const s_buffer = U8.fromBI(s)
      return { r: r_buffer, s: s_buffer }
    }
    const verify = (p_key: ECPublicKey, M: Uint8Array, signature: ECDSASignature) => {
      const { Q } = p_key
      const r = typeof signature.r === 'bigint' ? signature.r : U8.from(signature.r).toBI()
      const s = typeof signature.s === 'bigint' ? signature.s : U8.from(signature.s).toBI()
      if (r <= 0n || r >= n || s <= 0n || s >= n) {
        return false
      }
      let z = hash(M).toBI()
      while (z > n_mask) {
        z = z >> 1n
      }
      const w = modInverse(s, n)
      const u1 = mod(z * w, n)
      const u2 = mod(r * w, n)
      const P = addPoint(mulPoint(G, u1), mulPoint(Q, u2))
      const v = mod(P.x, n)
      return v === r
    }
    return { sign, verify }
  }
  // Integrated encryption scheme
  const ecies: ECIES = (config?: ECIESConfig) => {
    const { cipher, mac, kdf, S1, S2, iv } = defineECIES(config)
    const encrypt = (p_key: ECPublicKey, M: Uint8Array) => {
      if (!isLegalPK(p_key)) {
        throw new KitError('Invalid public key')
      }
      let s_key: ECKeyPair
      let deriveShare: FpECPoint<U8>
      do {
        s_key = gen()
        deriveShare = ecdh(s_key, p_key)
      } while (deriveShare.isInfinity)
      const Z = deriveShare.x
      const K = kdf((cipher.KEY_SIZE + mac.KEY_SIZE) << 3, joinBuffer(Z, S1))
      const KE = K.slice(0, cipher.KEY_SIZE)
      const KM = K.slice(cipher.KEY_SIZE, cipher.KEY_SIZE + mac.KEY_SIZE)
      const _cipher = cipher(KE, iv)
      const R: ECPublicKey = { Q: s_key.Q }
      const C = _cipher.encrypt(M)
      const D = mac(KM, joinBuffer(C, S2))
      return { R, C, D }
    }
    const decrypt = (s_key: ECPrivateKey, CT: ECIESCiphertext) => {
      const { R, C, D } = CT
      // 密钥派生
      const deriveShare = ecdh(s_key, R)
      if (deriveShare.isInfinity) {
        throw new KitError('ECIES Decryption failed')
      }
      const Z = deriveShare.x
      const K = kdf((cipher.KEY_SIZE + mac.KEY_SIZE) << 3, joinBuffer(Z, S1))
      const KE = K.slice(0, cipher.KEY_SIZE)
      const KM = K.slice(cipher.KEY_SIZE, cipher.KEY_SIZE + mac.KEY_SIZE)
      const _cipher = cipher(KE, iv)
      // 校验
      if (mac(KM, joinBuffer(C, S2)).some((v, i) => v !== D[i])) {
        throw new KitError('ECIES Decryption failed')
      }
      const M = _cipher.decrypt(C)
      // 解密
      return new U8(M)
    }
    return { encrypt, decrypt }
  }

  return {
    utils: {
      addPoint,
      mulPoint,
      isLegalPK,
      isLegalSK,
      PointToU8,
      U8ToPoint,
    },
    gen,
    dh: ecdh,
    cdh: eccdh,
    mqv: ecmqv,
    dsa: ecdsa,
    ies: ecies,
  }
}

// * Algorithms for Test

/**
 * ! 此加密算法仅用于测试 ECIES
 * ! This encryption algorithm is only used for testing ECIES
 */
export const es_xor = createCipher(
  (K: Uint8Array) => {
    const encrypt = (M: Uint8Array) => new U8(M.map((v, i) => v ^ K[i]))
    const decrypt = (C: Uint8Array) => new U8(C.map((v, i) => v ^ K[i]))
    return { encrypt, decrypt }
  },
  {
    ALGORITHM: 'ES-XOR',
    BLOCK_SIZE: 20,
    KEY_SIZE: 20,
    MIN_KEY_SIZE: 20,
    MAX_KEY_SIZE: 20,
  },
)
