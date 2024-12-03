import { aes } from '../cipher/blockCipher/aes'
import { hmac } from '../hash/hmac'
import { sha256 } from '../hash/sha256'
import { type BlockCipher, type BlockCipherInfo, cbc } from './cipher'
import type { FpECParams, FpECPoint } from './eccParams'
import type { Digest, KeyHash } from './hash'
import { ANSI_X963_KDF, type KDF } from './kdf'
import { KitError, U8, genRandomBI, joinBuffer, mod, modInverse, modPow, modPrimeSquare } from './utils'

// * Functions

/**
 * 素域运算
 *
 * Prime Field Operations
 */
function Fp(p: bigint) {
  const plus = (...args: bigint[]) => args.reduce((acc, cur) => mod(acc + cur, p))
  const multiply = (...args: bigint[]) => args.reduce((acc, cur) => mod(acc * cur, p))
  const subtract = (a: bigint, ...args: bigint[]) => {
    const b: bigint[] = args.map(v => mod(p - v, p))
    return plus(a, ...b)
  }
  const divide = (a: bigint, b: bigint) => {
    b = modInverse(b, p)
    return multiply(a, b)
  }
  return { plus, multiply, subtract, divide }
}

/**
 * 素域椭圆曲线运算
 *
 * Prime Field Elliptic Curve Operations
 */
function FpECUtils(curve: FpECParams): FpEllipticCurveUtils {
  const { p, a, b, n, n_bit_length } = curve
  const { plus, multiply, subtract, divide } = Fp(p)
  const n_byte_length = n_bit_length >> 3

  const addPoint = (A: FpECPoint, B: FpECPoint): FpECPoint => {
    const [x1, y1] = [A.x, A.y]
    const [x2, y2] = [B.x, B.y]

    // O + P = P
    if (A.isInfinity)
      return B
    if (B.isInfinity)
      return A

    // P + (-P) = O
    if (x1 === x2 && y1 !== y2) {
      return {
        isInfinity: true,
        x: 0n,
        y: 0n,
      }
    }

    let λ = 0n
    // P1 + P2
    if (x1 !== x2) {
      // λ = (y2 - y1) / (x2 - x1)
      const numerator = subtract(y2, y1)
      const denominator = subtract(x2, x1)
      λ = divide(numerator, denominator)
    }
    // P1 + P1
    else {
      // λ = (3 * x1 * x1 + a) / 2 * y1
      const numerator = plus(multiply(3n, x1, x1), a)
      const denominator = multiply(2n, y1)
      λ = divide(numerator, denominator)
    }

    // x3 = λ * λ - x1 - x2
    const x3 = subtract(multiply(λ, λ), x1, x2)
    // y3 = λ * (x1 - x3) - y1
    const y3 = subtract(multiply(λ, subtract(x1, x3)), y1)

    return { x: x3, y: y3 }
  }
  const mulPoint = (P: FpECPoint, k: bigint): FpECPoint => {
    if (k === 0n) {
      return { isInfinity: true, x: 0n, y: 0n }
    }
    else if (k === 1n) {
      return P
    }
    else if (k & 1n) {
      return addPoint(P, mulPoint(P, k - 1n))
    }
    else {
      return mulPoint(addPoint(P, P), k / 2n)
    }
  }
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
    const l = modPow(y, 2n, p)
    const r = mod(modPow(x, 3n, p) + a * x + b, p)
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
  const pointToU8 = (point: FpECPoint, compress = false): U8 => {
    if (point.isInfinity) {
      return new U8([0x00])
    }
    const PC = new U8([compress ? 0x02 | Number(point.y & 1n) : 0x04])
    const X1 = U8.fromBI(point.x)
    const Y1 = compress ? new U8() : U8.fromBI(point.y)
    return joinBuffer(PC, X1, Y1)
  }
  const U8ToPoint = (buffer: Uint8Array): FpECPoint => {
    const u8 = U8.from(buffer)
    const PC = BigInt(u8[0])
    if (PC === 0x00n) {
      return { isInfinity: true, x: 0n, y: 0n }
    }
    if (PC !== 0x02n && PC !== 0x03n && PC !== 0x04n) {
      throw new KitError('Invalid point conversion')
    }
    // 无压缩
    if (PC === 0x04n) {
      const x = u8.slice(1, n_byte_length + 1).toBI()
      const y = u8.slice(n_byte_length + 1).toBI()
      return { isInfinity: false, x, y }
    }
    // 解压缩
    else {
      const x = u8.slice(1).toBI()

      let y = 0n
      y = x * x * x + a * x + b
      y = modPrimeSquare(y, p)
      y = (y & 1n) === (PC & 1n) ? y : p - y

      return { isInfinity: false, x, y }
    }
  }

  return { addPoint, mulPoint, isLegalPK, isLegalSK, pointToU8, U8ToPoint }
}

// * EC Algorithms

/**
 * 素域椭圆曲线密码学组件
 *
 * Prime Field Elliptic Curve Cryptography Components
 */
export function FpEC(curve: FpECParams): FpEllipticCurve {
  const { G, n, n_mask, n_bit_length } = curve
  const utils = FpECUtils(curve)
  const { addPoint, mulPoint, isLegalPK, isLegalSK } = utils
  const genKey = () => {
    // private key
    const d = genRandomBI(n - 2n, n_bit_length >> 3)
    // public key
    const Q = mulPoint(G, d)
    return { Q, d }
  }
  const ecdh = (s_key: ECPrivateKey, p_key: ECPublicKey) => {
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
  const ecmqv = (u1: ECKeyPair, u2: ECKeyPair, v1: ECPublicKey, v2: ECPublicKey) => {
    if (!isLegalPK(v1) || !isLegalPK(v2)) {
      throw new KitError('Invalid public key')
    }
    const ceilLog2n = n_bit_length
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
  const ecdsa = (key: ECPrivateKey | ECPublicKey, hash: Digest) => {
    const sign = (M: Uint8Array): ECDSASignature => {
      if (!('d' in key)) {
        throw new KitError('Missing necessary parameters to sign')
      }
      const { d } = key
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
    const verify = (M: Uint8Array, signature: ECDSASignature): boolean => {
      if (!('Q' in key)) {
        throw new KitError('Missing necessary parameters to sign')
      }
      const { Q } = key
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
  const eciesEncrypt: ECIESEncrypt = (
    p_key: ECPublicKey,
    cipher: IVBlockCipher = cbc(aes(256)),
    KDF: KDF = ANSI_X963_KDF(sha256),
    k_hash: KeyHash = hmac(sha256),
    S1 = new Uint8Array(0),
    S2 = new Uint8Array(0),
    iv = new Uint8Array(cipher.BLOCK_SIZE),
  ) => {
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
    const K = KDF((cipher.KEY_SIZE + k_hash.KEY_SIZE) << 3, joinBuffer(Z, S1))
    const KE = K.slice(0, cipher.KEY_SIZE)
    const KM = K.slice(cipher.KEY_SIZE, cipher.KEY_SIZE + k_hash.KEY_SIZE)
    const _cipher = cipher(KE, iv)
    const _mac = k_hash(KM)
    const R: ECPublicKey = { Q: s_key.Q }
    return (M: Uint8Array) => {
      const C = _cipher.encrypt(M)
      const D = _mac(joinBuffer(C, S2))
      return { R, C, D }
    }
  }
  const eciesDecrypt: ECIESDecrypt = (
    s_key: ECPrivateKey,
    cipher: IVBlockCipher = cbc(aes(256)),
    KDF: KDF = ANSI_X963_KDF(sha256),
    k_hash: KeyHash = hmac(sha256),
    S1 = new Uint8Array(0),
    S2 = new Uint8Array(0),
    iv = new Uint8Array(cipher.BLOCK_SIZE),
  ) => {
    return (CT: ECIESCipherText) => {
      const { R, C, D } = CT
      // 密钥派生
      const deriveShare = ecdh(s_key, R)
      if (deriveShare.isInfinity) {
        throw new KitError('ECIES Decryption failed')
      }
      const Z = U8.fromBI(deriveShare.x)
      const K = KDF((cipher.KEY_SIZE + k_hash.KEY_SIZE) << 3, joinBuffer(Z, S1))
      const KE = K.slice(0, cipher.KEY_SIZE)
      const KM = K.slice(cipher.KEY_SIZE, cipher.KEY_SIZE + k_hash.KEY_SIZE)
      const _cipher = cipher(KE, iv)
      const _mac = k_hash(KM)
      // 校验
      if (_mac(joinBuffer(C, S2)).some((v, i) => v !== D[i])) {
        throw new KitError('ECIES Decryption failed')
      }
      const M = _cipher.decrypt(C)
      // 解密
      return new U8(M)
    }
  }

  return {
    genKey,
    ecdh,
    ecmqv,
    ecdsa,
    eciesEncrypt,
    eciesDecrypt,
    ...utils,
  }
}

// * Interfaces

interface ECIESCipherText {
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
   * @param {IVBlockCipher} [cipher] - 分组密码算法 / Block Cipher Algorithm (default: AES-256-GCM)
   * @param {KDF} [KDF] - 密钥派生函数 / Key Derivation Function (default: ANSI-X9.63-KDF with SHA-256)
   * @param {KeyHash} [k_hash] - 密钥哈希函数 / Key Hash Function (default: HMAC-SHA-256)
   * @param {Uint8Array} [S1] - 附加数据1 / Additional Data 1
   * @param {Uint8Array} [S2] - 附加数据2 / Additional Data 2
   * @param {Uint8Array} [iv] - 初始化向量 / Initialization Vector
   */
  (
    p_key: ECPublicKey,
    cipher?: IVBlockCipher,
    KDF?: KDF,
    k_hash?: KeyHash,
    S1?: Uint8Array,
    S2?: Uint8Array,
    iv?: Uint8Array,
  ): (M: Uint8Array) => ECIESCipherText
}

interface ECIESDecrypt {
  /**
   * 椭圆曲线集成解密算法
   *
   * Elliptic Curve Integrated Decryption Scheme
   *
   * @param {ECPrivateKey} s_key - 接收方私钥 / Recipient's Private Key
   * @param {IVBlockCipher} [cipher] - 分组密码算法 / Block Cipher Algorithm (default: AES-256-GCM)
   * @param {KDF} [KDF] - 密钥派生函数 / Key Derivation Function (default: ANSI-X9.63-KDF with SHA-256)
   * @param {KeyHash} [k_hash] - 密钥哈希函数 / Key Hash Function (default: HMAC-SHA-256)
   * @param {Uint8Array} [S1] - 附加数据1 / Additional Data 1
   * @param {Uint8Array} [S2] - 附加数据2 / Additional Data 2
   * @param {Uint8Array} [iv] - 初始化向量 / Initialization Vector
   */
  (
    s_key: ECPrivateKey,
    cipher?: IVBlockCipher,
    KDF?: KDF,
    k_hash?: KeyHash,
    S1?: Uint8Array,
    S2?: Uint8Array,
    iv?: Uint8Array,
  ): (CT: ECIESCipherText) => Uint8Array
}

interface FpEllipticCurveUtils {
  /**
   * 素域椭圆曲线点加法
   *
   * Prime Field Elliptic Curve Point Addition
   */
  addPoint: (A: FpECPoint, B: FpECPoint) => FpECPoint
  /**
   * 素域椭圆曲线点乘法
   *
   * Prime Field Elliptic Curve Point Multiplication
   */
  mulPoint: (P: FpECPoint, k: bigint) => FpECPoint
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
  pointToU8: (point: FpECPoint, compress?: boolean) => U8
  /**
   * 字节串转换为点
   *
   * Convert Byte String to Point
   */
  U8ToPoint: (buffer: Uint8Array) => FpECPoint
}

interface FpEllipticCurve extends FpEllipticCurveUtils {
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
  ecdh: (s_key: ECPrivateKey, p_key: ECPublicKey) => FpECPoint
  /**
   * 椭圆曲线梅内泽斯-奎-范斯通密钥协商算法
   *
   * Elliptic Curve Menezes-Qu-Vanstone Key Agreement Algorithm
   */
  ecmqv: (u1: ECKeyPair, u2: ECKeyPair, v1: ECPublicKey, v2: ECPublicKey) => FpECPoint
  /**
   * 椭圆曲线数字签名算法
   *
   * Elliptic Curve Digital Signature Algorithm
   */
  ecdsa: (key: ECPrivateKey | ECPublicKey, hash: Digest) => {
    sign: (M: Uint8Array) => ECDSASignature
    verify: (M: Uint8Array, signature: ECDSASignature) => boolean
  }
  /**
   * 椭圆曲线集成加密算法
   *
   * Elliptic Curve Integrated Encryption Scheme
   */
  eciesEncrypt: ECIESEncrypt
  /**
   * 椭圆曲线集成解密算法
   *
   * Elliptic Curve Integrated Decryption Scheme
   */
  eciesDecrypt: ECIESDecrypt
}

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

/**
 * 椭圆曲线数字签名
 *
 * Elliptic Curve Digital Signature Algorithm
 */
interface ECDSASignature {
  r: bigint
  s: bigint
}

interface IVBlockCipher extends BlockCipherInfo {
  (K: Uint8Array, iv: Uint8Array): ReturnType<BlockCipher>
}
