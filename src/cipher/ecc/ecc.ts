import type { BlockCipher, BlockCipherInfo } from '../../core/cipher'
import type { AffinePoint } from '../../core/coordinate_system'
import type { ECJacobian, ECLópezDahab, FbKECParams, FbPECParams, FpMECParams, FpWECParams } from '../../core/ec'
import type { Digest, KeyHash } from '../../core/hash'
import type { KDF } from '../../core/kdf'
import { aes } from '../../cipher/blockCipher/aes'
import { cbc, createCipher } from '../../core/cipher'
import { EC } from '../../core/ec'
import { x963kdf } from '../../core/kdf'
import { genBitMask, genRandomBI, getBIBits, joinBuffer, KitError, mod, modInverse, U8  } from '../../core/utils'
import { hmac } from '../../hash/hmac'
import { sha256 } from '../../hash/sha256'

// * Interfaces

export interface ECPublicKey {
  /** 椭圆曲线公钥 / Elliptic Curve Public Key */
  readonly Q: Readonly<AffinePoint>
}
export interface ECPrivateKey {
  /** 椭圆曲线私钥 / Elliptic Curve Private Key */
  readonly d: bigint
}
export interface ECKeyPair extends ECPrivateKey, ECPublicKey {}

export interface ECDH {
  /**
   * @param {ECPrivateKey} s_key - 己方私钥 / Self Private Key
   * @param {ECPublicKey} p_key - 对方公钥 / Counterparty Public Key
   */
  (s_key: ECPrivateKey, p_key: ECPublicKey): AffinePoint
}

export interface ECMQV {
  /**
   * @param {ECKeyPair} u1 - 己方密钥对 / Self Key Pair
   * @param {ECKeyPair} u2 - 己方临时密钥对 / Self Temporary Key Pair
   * @param {ECPublicKey} v1 - 对方公钥 / Counterparty Public Key
   * @param {ECPublicKey} v2 - 对方临时公钥 / Counterparty Temporary Public Key
   */
  (u1: ECKeyPair, u2: ECKeyPair, v1: ECPublicKey, v2: ECPublicKey): AffinePoint
}

export interface ECDSASignature {
  /** 临时公钥 / Temporary Public Key */
  r: bigint
  /** 签名值 / Signature Value */
  s: bigint
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
    sign: (s_key: ECPrivateKey, M: Uint8Array) => ECDSASignature
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

/**
 * 椭圆曲线密码学
 *
 * Elliptic Curve Crypto
 *
 * @template P - 点类型 / Point Type
 * @template C - 曲线参数类型 / Curve Parameters Type
 */
export interface ECCBase {
  /**
   * 生成椭圆曲线密钥
   *
   * Generate Elliptic Curve Key
   */
  gen: {
    /** 生成密钥对 / Generate Key Pair */
    (type?: 'key_pair'): ECKeyPair
    /** 生成私钥 / Generate Private Key */
    (type: 'private_key'): ECPrivateKey
    /** 生成公钥 / Generate Public Key */
    (type: 'public_key', s_key: ECPrivateKey): ECKeyPair
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
export interface ECCFpWeierstrass extends ECCBase {
  parameters: FpWECParams
  utils: ECJacobian
}
export interface ECCFpMontgomery extends ECCBase {
  parameters: FpMECParams
  utils: ECJacobian
}
export interface ECCFbPseudoRandom extends ECCBase {
  parameters: FbPECParams
  utils: ECLópezDahab
}
export interface ECCFbKoblitz extends ECCBase {
  parameters: FbKECParams
  utils: ECLópezDahab
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

// * ECC

export function ECC(curve: FpWECParams): ECCFpWeierstrass
export function ECC(curve: FpMECParams): ECCFpMontgomery
export function ECC(curve: FbPECParams): ECCFbPseudoRandom
export function ECC(curve: FbKECParams): ECCFbKoblitz
export function ECC(curve: FpWECParams | FpMECParams | FbPECParams | FbKECParams) {
  let ec
  switch (curve.type) {
    case 'Weierstrass':
    case 'Montgomery':
      ec = EC(curve)
      break
    case 'Pseudo-Random':
    case 'Koblitz':
      ec = EC(curve)
      break
    default:
      throw new KitError('unsupported curve type')
  }
  let toCatalyst
  switch (ec.catalyst) {
    case 'jacobian':
      toCatalyst = ec.cs.toJacobian
      break
    case 'ld':
      toCatalyst = ec.cs.toLD
      break
    default:
      throw new KitError('unsupported catalyst type')
  }

  const { G, n, h } = curve
  /** 优化基点 */
  const CG = toCatalyst(G)
  const n_bit = getBIBits(n)
  const n_mask = genBitMask(n_bit)
  const p = 'p' in curve ? curve.p : undefined
  const p_bit = p ? getBIBits(p) : undefined
  const p_byte = p ? (p_bit! + 7) >> 3 : undefined
  const m = 'm' in curve ? curve.m : undefined
  const m_bit = m ? getBIBits(m) : undefined
  const m_byte = m ? (m_bit! + 7) >> 3 : undefined
  const ele_byte = p_byte ?? m_byte!

  const { addPoint, mulPoint, isLegalSK, isLegalPK } = ec
  const toAffine = ec.cs.toAffine

  function gen(type?: 'key_pair'): ECKeyPair
  function gen(type: 'private_key'): ECPrivateKey
  function gen(type: 'public_key', s_key: ECPrivateKey): ECKeyPair
  function gen(
    type: 'key_pair' | 'private_key' | 'public_key' = 'key_pair',
    s_key?: ECPrivateKey,
  ) {
    if (type === 'key_pair') {
      // private key
      const { result: d } = genRandomBI(n, ele_byte)
      // public key
      const _ = mulPoint(CG as any, d)
      const Q = toAffine(_)

      return { Q, d }
    }
    else if (type === 'private_key') {
      const { result: d } = genRandomBI(n, ele_byte)
      return { d }
    }
    else if (type === 'public_key') {
      const d = s_key!.d
      if (d === 0n)
        throw new KitError('Invalid private key')

      const _ = mulPoint(CG as any, d)
      const Q = toAffine(_)

      return { Q, d }
    }
    throw new KitError('Invalid type')
  }

  const dh: ECDH = (s_key: ECPrivateKey, p_key: ECPublicKey) => {
    if (!isLegalPK(p_key.Q))
      throw new KitError('Invalid public key')

    if (!isLegalSK(s_key.d))
      throw new KitError('Invalid private key')

    const Q = toCatalyst(p_key.Q)
    const d = s_key.d
    const S = mulPoint(Q as any, d)
    if (S.isInfinity)
      throw new KitError('the result of ECDH is the point at infinity')

    return toAffine(S)
  }
  const cdh: ECDH = (s_key: ECPrivateKey, p_key: ECPublicKey) => {
    if (!isLegalPK(p_key.Q))
      throw new KitError('Invalid public key')

    if (!isLegalSK(s_key.d))
      throw new KitError('Invalid private key')

    const Q = toCatalyst(p_key.Q)
    const d = s_key.d
    const S = mulPoint(Q as any, d * h)
    if (S.isInfinity)
      throw new KitError('the result of ECDH is the point at infinity')

    return toAffine(S)
  }
  const mqv: ECMQV = (u1: ECKeyPair, u2: ECKeyPair, v1: ECPublicKey, v2: ECPublicKey) => {
    if (!isLegalPK(v1.Q) || !isLegalPK(v2.Q))
      throw new KitError('Invalid public key')

    const ceilLog2n = n_bit
    const L = 1n << BigInt(Math.ceil(ceilLog2n / 2))
    const u1d = u1.d
    const u2d = u2.d
    const u2Qx = u2.Q.x
    const v2Qx = v2.Q.x
    const Q2u = mod(u2Qx, L) + L
    const Q2v = mod(v2Qx, L) + L
    const s = mod(u2d + Q2u * u1d, n)
    const v2Q = toCatalyst(v2.Q)
    const v1Q = toCatalyst(v1.Q)
    const P = mulPoint(addPoint(v2Q as any, mulPoint(v1Q as any, Q2v) as any) as any, s * h)
    if (P.isInfinity)
      throw new KitError('Public key not available')

    return toAffine(P)
  }
  const dsa: ECDSA = (hash: Digest = sha256) => {
    const sign = (s_key: ECPrivateKey, M: Uint8Array) => {
      const d = s_key.d
      let r = 0n
      let s = 0n
      let z = hash(M).toBI()
      while (z > n_mask) {
        z = z >> 1n
      }
      do {
        const K = gen()
        const k = K.d
        const x1 = K.Q.x
        r = mod(x1, n)
        if (r === 0n)
          continue

        s = modInverse(k, n) * mod(z + r * d, n)
        s = mod(s, n)
      } while (s === 0n)

      return { r, s }
    }
    const verify = (p_key: ECPublicKey, M: Uint8Array, signature: ECDSASignature) => {
      const Q = toCatalyst(p_key.Q)
      const r = signature.r
      const s = signature.s
      if (r <= 0n || r >= n || s <= 0n || s >= n)
        return false

      let z = hash(M).toBI()
      while (z > n_mask) {
        z = z >> 1n
      }
      const w = modInverse(s, n)
      const u1 = mod(z * w, n)
      const u2 = mod(r * w, n)
      const P_j = addPoint(mulPoint(CG as any, u1) as any, mulPoint(Q as any, u2) as any)
      const P = toAffine(P_j)
      const v = mod(P.x, n)

      return v === r
    }

    return { sign, verify }
  }
  const ies: ECIES = (config?: ECIESConfig) => {
    const { cipher, mac, kdf, S1, S2, iv } = defineECIES(config)
    const encrypt = (p_key: ECPublicKey, M: Uint8Array) => {
      if (!isLegalPK(p_key.Q))
        throw new KitError('Invalid public key')

      let s_key: ECKeyPair
      let deriveShare: AffinePoint
      do {
        s_key = gen()
        deriveShare = dh(s_key, p_key)
      } while (deriveShare.isInfinity)

      const Z = U8.fromBI(deriveShare.x)
      const K = kdf((cipher.KEY_SIZE + mac.KEY_SIZE), joinBuffer(Z, S1))
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
      const deriveShare = dh(s_key, R)
      if (deriveShare.isInfinity)
        throw new KitError('ECIES Decryption failed')

      const Z = U8.fromBI(deriveShare.x)
      const K = kdf((cipher.KEY_SIZE + mac.KEY_SIZE), joinBuffer(Z, S1))
      const KE = K.slice(0, cipher.KEY_SIZE)
      const KM = K.slice(cipher.KEY_SIZE, cipher.KEY_SIZE + mac.KEY_SIZE)
      const _cipher = cipher(KE, iv)
      // 校验
      if (mac(KM, joinBuffer(C, S2)).some((v, i) => v !== D[i]))
        throw new KitError('ECIES Decryption failed')

      // 解密
      const M = _cipher.decrypt(C)

      return new U8(M)
    }
    return { encrypt, decrypt }
  }

  return {
    parameters: curve,
    utils: ec,
    gen,
    dh,
    cdh,
    mqv,
    dsa,
    ies,
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
