import type { BlockCipher, BlockCipherInfo } from '../../core/cipher'
import { cbc, createCipher } from '../../core/cipher'
import { Fp, FpEC, type FpECUtils } from '../../core/ec'
import type { FpECPoint, FpWECParams } from '../../core/ecParams'
import type { Digest, KeyHash } from '../../core/hash'
import { KitError, U8, genRandomBI, getBIBits, joinBuffer, mod, modInverse, modPrimeSquare } from '../../core/utils'
import type { KDF } from '../../core/kdf'
import { x963kdf } from '../../core/kdf'
import { aes } from '../blockCipher/aes'
import { sha256 } from '../../hash/sha256'
import { hmac } from '../../hash/hmac'

// * Interfaces

interface ECPublicKey {
  /**
   * 素域椭圆曲线公钥
   *
   * Prime Field Elliptic Curve Public Key
   */
  readonly Q: Readonly<FpECPoint>
}
interface ECPrivateKey {
  /**
   * 素域椭圆曲线私钥
   *
   * Prime Field Elliptic Curve Private Key
   */
  readonly d: bigint
}
/**
 * 椭圆曲线密钥对
 *
 * Elliptic Curve Key Pair
 */
interface ECKeyPair extends ECPrivateKey, ECPublicKey {
}

interface ECDH {
  (s_key: ECPrivateKey, p_key: ECPublicKey): FpECPoint
}

interface ECMQV {
  (u1: ECKeyPair, u2: ECKeyPair, v1: ECPublicKey, v2: ECPublicKey): FpECPoint
}

interface ECDSASignature {
  /**
   * 临时公钥
   *
   * Temporary Public Key
   */
  r: bigint
  /**
   * 签名值
   *
   * Signature Value
   */
  s: bigint
}
interface ECDSA {
  (hash?: Digest): {
    sign: (s_key: ECPrivateKey, M: Uint8Array) => ECDSASignature
    verify: (p_key: ECPublicKey, M: Uint8Array, signature: ECDSASignature) => boolean
  }
}

interface IVBlockCipher extends BlockCipherInfo {
  (K: Uint8Array, iv: Uint8Array): ReturnType<BlockCipher>
}
interface ECIESConfig {
  /**
   * 分组密码算法 / Block Cipher Algorithm (default: AES-256-GCM)
   */
  cipher?: IVBlockCipher
  /**
   * 密钥哈希函数 / Key Hash Function (default: HMAC-SHA-256)
   */
  mac?: KeyHash
  /**
   * 密钥派生函数 / Key Derivation Function (default: ANSI-X9.63-KDF with SHA-256)
   */
  kdf?: KDF
  /**
   * 附加数据1 / Additional Data 1 (default: empty)
   */
  S1?: Uint8Array
  /**
   * 附加数据2 / Additional Data 2 (default: empty)
   */
  S2?: Uint8Array
  /**
   * 初始化向量 / Initialization Vector (default: Uint8Array(cipher.BLOCK_SIZE))
   */
  iv?: Uint8Array
}
interface ECIESCiphertext {
  /**
   * 临时公钥
   *
   * Temporary Public Key
   */
  R: ECPublicKey
  /**
   * 密文
   *
   * Ciphertext
   */
  C: Uint8Array
  /**
   * 校验值
   *
   * Check Value
   */
  D: Uint8Array
}
interface ECIESEncrypt {
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
interface ECIESDecrypt {
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
interface ECIES {
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

interface FpECCrypto {
  utils: FpECUtils
  /**
   * 生成椭圆曲线密钥对
   *
   * Generate Elliptic Curve Key Pair
   */
  genKey: () => ECKeyPair
  /**
   * 椭圆曲线迪菲-赫尔曼, 密钥协商算法
   *
   * Elliptic Curve Diffie-Hellman Key Agreement Algorithm
   */
  ecdh: ECDH
  /**
   * 椭圆曲线余因子迪菲-赫尔曼, 密钥协商算法
   *
   * Elliptic Curve Co-factor Diffie-Hellman Key Agreement Algorithm
   */
  eccdh: ECDH
  /**
   * 椭圆曲线梅内泽斯-奎-范斯通密钥协商算法
   *
   * Elliptic Curve Menezes-Qu-Vanstone Key Agreement Algorithm
   */
  ecmqv: ECMQV
  /**
   * 椭圆曲线数字签名
   *
   * Elliptic Curve Digital Signature Algorithm
   */
  ecdsa: ECDSA
  /**
   * 椭圆曲线集成加密算法
   *
   * Elliptic Curve Integrated Encryption Scheme
   */
  ecies: ECIES
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
  U8ToPoint: (buffer: Uint8Array) => FpECPoint
}

// * Functions

/**
 * 定义 ECIES 配置
 *
 * Define ECIES Configuration
 *
 * @param {IVBlockCipher} [config.cipher] - 分组密码算法 / Block Cipher Algorithm (default: AES-256-GCM)
 * @param {KeyHash} [config.mac] - 密钥哈希函数 / Key Hash Function (default: HMAC-SHA-256)
 * @param {KDF} [config.kdf] - 密钥派生函数 / Key Derivation Function (default: ANSI-X9.63-KDF with SHA-256)
 * @param {Uint8Array} [config.S1] - 附加数据1 / Additional Data 1 (default: empty)
 * @param {Uint8Array} [config.S2] - 附加数据2 / Additional Data 2 (default: empty)
 * @param {Uint8Array} [config.iv] - 初始化向量 / Initialization Vector (default: Uint8Array(cipher.BLOCK_SIZE))
 */
export function defineECIES(config?: ECIESConfig) {
  const {
    cipher = cbc(aes(256)),
    mac = hmac(sha256),
    kdf = x963kdf(sha256),
    S1 = new Uint8Array(0),
    S2 = new Uint8Array(0),
    iv = new Uint8Array(cipher.BLOCK_SIZE),
  } = config ?? {}
  return { cipher, mac, kdf, S1, S2, iv }
}

function createMask(n: number) {
  let mask = 0n
  for (let i = 0; i < n; i++) {
    mask = (mask << 1n) | 1n
  }
  return mask
}

// * EC Algorithms

/**
 * 素域椭圆曲线密码学组件
 *
 * Prime Field Elliptic Curve Cryptography Components
 */
export function FpECC(curve: FpWECParams): FpECCrypto {
  const { p, a, b, G, n, h } = curve
  const p_bits = getBIBits(p)
  const p_bytes = (p_bits + 7) >> 3
  const n_bits = getBIBits(n)
  const n_mask = createMask(n_bits)
  const FpECOpt = FpEC(curve)
  const FpOpt = Fp(p)
  const { addPoint, mulPoint } = FpECOpt
  const { plus, multiply } = FpOpt

  const isLegalPK = (p_key: ECPublicKey): boolean => {
    const { Q } = p_key
    // P != O
    if (Q.isInfinity) {
      return false
    }
    // P(x, y) ∈ E
    const { x, y } = Q
    if (x < 0n || x >= p || y < 0n || y >= p) {
      return false
    }
    // y^2 = x^3 + ax + b
    const l = multiply(y, y)
    const r = plus(multiply(x, x, x), multiply(a, x), b)
    if (l !== r) {
      return false
    }
    // nP = O
    const nP = mulPoint(Q, n)
    if (!nP.isInfinity) {
      return false
    }
    return true
  }
  const isLegalSK = (s_key: ECPrivateKey): boolean => {
    const { d } = s_key
    if (d < 0n || d >= p) {
      return false
    }
    return true
  }
  const PointToU8 = (point: FpECPoint, compress = false): U8 => {
    if (point.isInfinity) {
      return new U8([0x00])
    }
    const PC = new U8([compress ? 0x02 | Number(point.y & 1n) : 0x04])
    const X1 = U8.fromBI(point.x, p_bytes)
    const Y1 = compress ? new U8() : U8.fromBI(point.y, p_bytes)
    return joinBuffer(PC, X1, Y1)
  }
  const U8ToPoint = (buffer: Uint8Array): FpECPoint => {
    const u8 = U8.from(buffer)
    const PC = BigInt(u8[0])
    if (PC === 0x00n) {
      if (u8.length !== 1) {
        throw new KitError('Invalid Point')
      }
      return { isInfinity: true, x: 0n, y: 0n }
    }
    if (PC !== 0x02n && PC !== 0x03n && PC !== 0x04n) {
      throw new KitError('Invalid Point')
    }
    // 无压缩
    if (PC === 0x04n) {
      if (u8.length !== (p_bytes << 1) + 1) {
        throw new KitError('Invalid Point')
      }
      const x = u8.slice(1, p_bytes + 1).toBI()
      const y = u8.slice(p_bytes + 1).toBI()
      return { isInfinity: false, x, y }
    }
    // 解压缩
    else {
      if (u8.length !== p_bytes + 1) {
        throw new KitError('Invalid Point')
      }
      const x = u8.slice(1).toBI()
      let y = 0n
      y = plus(multiply(x, x, x), multiply(a, x), b)
      y = modPrimeSquare(y, p)
      y = (y & 1n) === (PC & 1n) ? y : p - y
      return { isInfinity: false, x, y }
    }
  }
  const genKey = () => {
    // private key
    const d = genRandomBI(n - 2n, n_bits >> 3)
    // public key
    const Q = mulPoint(G, d)
    return { Q, d }
  }
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
    return S
  }
  const eccdh: ECDH = (s_key: ECPrivateKey, p_key: ECPublicKey) => {
    if (!isLegalPK(p_key)) {
      throw new KitError('Invalid public key')
    }
    if (!isLegalSK(s_key)) {
      throw new KitError('Invalid private key')
    }
    const Q = p_key.Q
    const d = s_key.d
    const S = mulPoint(Q, d * h)
    if (S.isInfinity) {
      throw new KitError('the result of ECCDH is the point at infinity')
    }
    return S
  }
  const ecmqv: ECMQV = (u1: ECKeyPair, u2: ECKeyPair, v1: ECPublicKey, v2: ECPublicKey) => {
    if (!isLegalPK(v1) || !isLegalPK(v2)) {
      throw new KitError('Invalid public key')
    }
    const ceilLog2n = n_bits
    const L = 1n << BigInt(Math.ceil(ceilLog2n / 2))
    const Q2u = mod(u2.Q.x, L) + L
    const Q2v = mod(v2.Q.x, L) + L
    const s = mod(u2.d + Q2u * u1.d, n)
    const P = mulPoint(addPoint(v2.Q, mulPoint(v1.Q, Q2v)), s)
    if (P.isInfinity) {
      throw new KitError('Public key not available')
    }
    return P
  }
  const ecdsa: ECDSA = (hash: Digest = sha256) => {
    const sign = (s_key: ECPrivateKey, M: Uint8Array) => {
      const { d } = s_key
      let r = 0n
      let s = 0n
      let z = U8.from(hash(M)).toBI()
      while (z > n_mask) {
        z = z >> 1n
      }
      do {
        const K = genKey()
        const [k, x1] = [K.d, K.Q.x]
        r = mod(x1, n)
        if (r === 0n)
          continue

        s = modInverse(k, n) * (z + r * d)
        s = mod(s, n)
      } while (s === 0n)
      return { r, s }
    }
    const verify = (p_key: ECPublicKey, M: Uint8Array, signature: ECDSASignature) => {
      const { Q } = p_key
      const { r, s } = signature
      if (r <= 0n || r >= n || s <= 0n || s >= n) {
        return false
      }
      let z = U8.from(hash(M)).toBI()
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
  const ecies: ECIES = (config?: ECIESConfig) => {
    const { cipher, mac, kdf, S1, S2, iv } = defineECIES(config)
    const encrypt = (p_key: ECPublicKey, M: Uint8Array) => {
      if (!isLegalPK(p_key)) {
        throw new KitError('Invalid public key')
      }
      let s_key: ECKeyPair
      let deriveShare: FpECPoint
      do {
        s_key = genKey()
        deriveShare = ecdh(s_key, p_key)
      } while (deriveShare.isInfinity)
      const Z = U8.fromBI(deriveShare.x)
      const K = kdf((cipher.KEY_SIZE + mac.KEY_SIZE) << 3, joinBuffer(Z, S1))
      const KE = K.slice(0, cipher.KEY_SIZE)
      const KM = K.slice(cipher.KEY_SIZE, cipher.KEY_SIZE + mac.KEY_SIZE)
      const _cipher = cipher(KE, iv)
      const _mac = mac(KM)
      const R: ECPublicKey = { Q: s_key.Q }
      const C = _cipher.encrypt(M)
      const D = _mac(joinBuffer(C, S2))
      return { R, C, D }
    }
    const decrypt = (s_key: ECPrivateKey, CT: ECIESCiphertext) => {
      const { R, C, D } = CT
      // 密钥派生
      const deriveShare = ecdh(s_key, R)
      if (deriveShare.isInfinity) {
        throw new KitError('ECIES Decryption failed')
      }
      const Z = U8.fromBI(deriveShare.x)
      const K = kdf((cipher.KEY_SIZE + mac.KEY_SIZE) << 3, joinBuffer(Z, S1))
      const KE = K.slice(0, cipher.KEY_SIZE)
      const KM = K.slice(cipher.KEY_SIZE, cipher.KEY_SIZE + mac.KEY_SIZE)
      const _cipher = cipher(KE, iv)
      const _mac = mac(KM)
      // 校验
      if (_mac(joinBuffer(C, S2)).some((v, i) => v !== D[i])) {
        throw new KitError('ECIES Decryption failed')
      }
      const M = _cipher.decrypt(C)
      // 解密
      return new U8(M)
    }
    return { encrypt, decrypt }
  }
  return {
    utils: FpECOpt,
    isLegalPK,
    isLegalSK,
    PointToU8,
    U8ToPoint,
    genKey,
    ecdh,
    eccdh,
    ecmqv,
    ecdsa,
    ecies,
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
