import type { FpECPoint } from '../../core/ecParams'
import { sm2p256v1 } from '../../core/ecParams'
import type { Hash } from '../../core/hash'
import type { KDF } from '../../core/kdf'
import { x963kdf } from '../../core/kdf'
import { sm3 } from '../../hash/sm3'
import { KitError, U8, genBitMask, genRandomBI, getBIBits, joinBuffer, mod, modInverse } from '../../core/utils'
import type { ECKeyPair, ECPrivateKey, ECPublicKey } from './ecc'
import { FpECC } from './ecc'

interface SM2DI {
  /**
   * SM2 可辨别标识散列
   *
   * SM2 Distinguishable Identity Hash
   *
   * @param {Uint8Array} id - 用户标识 / User Identity
   * @param {ECPublicKey} key - 公钥 / Public Key
   * @param {Hash} hash - 哈希算法 / Hash Algorithm (default: SM3)
   */
  (id: Uint8Array, key: ECPublicKey, hash?: Hash): U8
}

interface SM2DH {
  /**
   * SM2 椭圆曲线迪菲-赫尔曼, 密钥协商算法
   *
   * SM2 Elliptic Curve Diffie-Hellman Key Agreement Algorithm
   *
   * @param {ECKeyPair} KA - 己方密钥对 / Self Key Pair
   * @param {ECPublicKey} KX - 己方临时密钥对 / Self Temporary Key Pair
   * @param {ECPublicKey} KB - 对方公钥 / Opposite Public Key
   * @param {ECPublicKey} KY - 对方临时公钥 / Opposite Temporary Public Key
   * @param [Uint8Array] ZA - 发起方标识派生值 / Initiator Identity Derived Value
   * @param [Uint8Array] ZB - 接收方标识派生值 / Receiver Identity Derived Value
   * @returns {U8} - 密钥材料 / Keying Material
   */
  (KA: ECKeyPair, KX: ECKeyPair, KB: ECPublicKey, KY: ECPublicKey, ZA?: Uint8Array, ZB?: Uint8Array): U8
}

interface SM2DSASignature {
  r: bigint
  s: bigint
}
interface SM2DSA {
  /**
   * SM2 椭圆曲线数字签名
   *
   * SM2 Elliptic Curve Digital Signature Algorithm
   *
   * @param {Hash} hash - 哈希算法 / Hash Algorithm (default: SM3)
   */
  (hash?: Hash): {
    /**
     * @param {Uint8Array} Z - 标识派生值 / Identity Derived Value
     * @param {ECPrivateKey} key - 签名方私钥 / Signer Private Key
     * @param {Uint8Array} M - 消息 / Message
     */
    sign: (Z: Uint8Array, key: ECPrivateKey, M: Uint8Array) => SM2DSASignature
    /**
     * @param {Uint8Array} Z - 标识派生值 / Identity Derived Value
     * @param {ECPublicKey} key - 签名方公钥 / Signer Public Key
     * @param {Uint8Array} M - 消息 / Message
     * @param {SM2DSASignature} S - 签名 / Signature
     */
    verify: (Z: Uint8Array, key: ECPublicKey, M: Uint8Array, S: SM2DSASignature) => boolean
  }
}

interface SM2Encrypt {
  /**
   * SM2 椭圆曲线加密
   *
   * SM2 Elliptic Curve Encryption
   *
   * @param {ECPublicKey} p_key - 接收方公钥 / Receiver Public Key
   * @param {Uint8Array} M - 明文 / Plaintext
   */
  (p_key: ECPublicKey, M: Uint8Array): U8
}
interface SM2Decrypt {
  /**
   * SM2 椭圆曲线解密
   *
   * SM2 Elliptic Curve Decryption
   *
   * @param {ECPrivateKey} s_key - 解密方私钥 / Decryptor Private Key
   * @param {Uint8Array} C - 密文 / Ciphertext
   */
  (s_key: ECPrivateKey, C: Uint8Array): U8
}
interface SM2EncryptionScheme {
  /**
   * SM2 椭圆曲线加密方案
   *
   * SM2 Elliptic Curve Encryption Scheme
   *
   * @param {Hash} hash - 哈希算法 / Hash Algorithm (default: SM3)
   * @param {KDF} kdf - 密钥派生函数 / Key Derivation Function (default: X9.63 KDF with SM3)
   * @param {'c1c2c3' | 'c1c3c2'} order - 密文分段顺序 / Ciphertext Segment Order (default: 'c1c3c2')
   */
  (hash?: Hash, kdf?: KDF, order?: 'c1c2c3' | 'c1c3c2'): {
    encrypt: SM2Encrypt
    decrypt: SM2Decrypt
  }
}

interface FpSM2Crypto {
  /**
   * 生成椭圆曲线密钥对
   *
   * Generate Elliptic Curve Key Pair
   */
  genKey: () => ECKeyPair
  /**
   * SM2 可辨别标识散列
   *
   * SM2 Distinguishable Identity Hash
   */
  di: SM2DI
  /**
   * SM2 椭圆曲线加密方案
   *
   * SM2 Elliptic Curve Encryption Scheme
   */
  es: SM2EncryptionScheme
  /**
   * SM2 椭圆曲线迪菲-赫尔曼, 密钥协商算法
   *
   * SM2 Elliptic Curve Diffie-Hellman Key Agreement Algorithm
   */
  dh: SM2DH
  /**
   * SM2 椭圆曲线数字签名
   *
   * SM2 Elliptic Curve Digital Signature Algorithm
   */
  dsa: SM2DSA
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

/**
 * SM2 椭圆曲线公钥密码算法
 *
 * Public Key Cryptography Algorithm SM2 Based on Elliptic Curves
 *
 * @param {FpECParams} curve - 椭圆曲线参数 / Elliptic Curve Parameters (default: sm2p256v1)
 */
export function sm2(curve = sm2p256v1): FpSM2Crypto {
  const { p, a, b, G, n, h } = curve
  const p_bits = getBIBits(p)
  const p_bytes = (p_bits + 7) >> 3
  const ecc = FpECC(curve)
  const { addPoint, mulPoint } = ecc.utils

  const genKey = ecc.genKey
  const isLegalPK = ecc.isLegalPK
  const isLegalSK = ecc.isLegalSK
  const PointToU8 = ecc.PointToU8
  const U8ToPoint = ecc.U8ToPoint
  const di: SM2DI = (id: Uint8Array, key: ECPublicKey, hash: Hash = sm3) => {
    const ent = id.length << 3
    if (ent > 0xFFFF) {
      throw new KitError('ID长度超过了最大限制')
    }
    const ENT = new Uint8Array([ent >> 8, ent & 0xFF])
    const _a = U8.fromBI(a)
    const _b = U8.fromBI(b)
    const xG = U8.fromBI(G.x)
    const yG = U8.fromBI(G.y)
    const xA = U8.fromBI(key.Q.x)
    const yA = U8.fromBI(key.Q.y)
    const ZA = hash(joinBuffer(ENT, id, _a, _b, xG, yG, xA, yA))

    return ZA
  }
  const w = Math.ceil(getBIBits(n) / 2) - 1
  const w_mask = genBitMask(w)
  const dh: SM2DH = (
    KA: ECKeyPair,
    KX: ECKeyPair,
    KB: ECPublicKey,
    KY: ECPublicKey,
    ZA = new Uint8Array(),
    ZB = new Uint8Array(),
  ) => {
    if (isLegalPK(KB) === false || isLegalPK(KY) === false) {
      throw new KitError('非法的公钥')
    }
    const x1 = (1n << BigInt(w)) + (KX.Q.x & w_mask)
    const x2 = (1n << BigInt(w)) + (KY.Q.x & w_mask)

    const t = mod(KA.d + KX.d * x1, n)
    const V = mulPoint(addPoint(KB.Q, mulPoint(KY.Q, x2)), h * t)
    if (V.isInfinity) {
      throw new KitError('协商失败')
    }
    const xu = U8.fromBI(V.x)
    const yu = U8.fromBI(V.y)
    return joinBuffer(xu, yu, ZA, ZB)
  }
  const dsa: SM2DSA = (hash: Hash = sm3) => {
    if (hash.DIGEST_SIZE !== 32) {
      throw new KitError('不支持的哈希算法')
    }

    // shortcut
    const sign = (Z: Uint8Array, key: ECPrivateKey, M: Uint8Array) => {
      const dA = key.d
      let r = 0n
      let s = 0n
      const e = hash(joinBuffer(Z, M)).toBI()
      do {
        const k = genRandomBI(n)
        const p = mulPoint(G, k)
        r = mod(e + p.x, n)
        if (r === 0n || r + k === n) {
          continue
        }
        s = mod(mod(k - r * dA, n) * modInverse(1n + dA, n), n)
        if (s === 0n) {
          continue
        }
        break
      } while (1)
      return { r, s }
    }
    const verify = (Z: Uint8Array, key: ECPublicKey, M: Uint8Array, S: SM2DSASignature) => {
      const PA = key.Q
      const { r, s } = S
      if (r <= 0n || r >= n || s <= 0n || s >= n) {
        return false
      }
      const e = hash(joinBuffer(Z, M)).toBI()
      const t = mod(r + s, n)
      if (t === 0n) {
        return false
      }
      const p = addPoint(
        mulPoint(G, s),
        mulPoint(PA, t),
      )
      const R = mod(e + p.x, n)
      return R === r
    }

    return { sign, verify }
  }
  const es: SM2EncryptionScheme = (hash = sm3, kdf = x963kdf(sm3), order = 'c1c3c2') => {
    const encrypt: SM2Encrypt = (p_key: ECPublicKey, M: Uint8Array) => {
      const C1 = genKey()
      const S = mulPoint(p_key.Q, h)
      if (S.isInfinity) {
        throw new KitError('加密失败')
      }
      const { x, y } = mulPoint(p_key.Q, C1.d)
      const x2 = U8.fromBI(x)
      const y2 = U8.fromBI(y)
      const ikm = joinBuffer(x2, y2)
      const C2 = kdf(M.length << 3, ikm)
      C2.forEach((_, i) => C2[i] ^= M[i])
      const C3 = hash(joinBuffer(x2, M, y2))
      if (order === 'c1c2c3') {
        return joinBuffer(PointToU8(C1.Q), C2, C3)
      }
      else {
        return joinBuffer(PointToU8(C1.Q), C3, C2)
      }
    }
    const decrypt: SM2Decrypt = (s_key: ECPrivateKey, C: Uint8Array) => {
      const C1_Length = (p_bytes << 1) + 1
      const C3_Length = hash.DIGEST_SIZE
      const C2_Length = C.length - C1_Length - C3_Length
      const C1 = U8ToPoint(C.subarray(0, C1_Length))
      const S = mulPoint(C1, h)
      if (S.isInfinity) {
        throw new KitError('解密失败')
      }
      const { x, y } = mulPoint(C1, s_key.d)
      const x2 = U8.fromBI(x)
      const y2 = U8.fromBI(y)
      const ikm = joinBuffer(x2, y2)
      const t = kdf(C2_Length << 3, ikm)
      let C2: Uint8Array
      let C3: Uint8Array
      if (order === 'c1c2c3') {
        C2 = C.subarray(C1_Length, C1_Length + C2_Length)
        C3 = C.subarray(C1_Length + C2_Length)
      }
      else {
        C3 = C.subarray(C1_Length, C1_Length + C3_Length)
        C2 = C.subarray(C1_Length + C3_Length)
      }
      const M = t.map((_, i) => t[i] ^ C2[i])
      const u = hash(joinBuffer(x2, M, y2))
      u.forEach((_, i) => {
        if (u[i] !== C3[i]) {
          throw new KitError('解密失败')
        }
      })
      return M
    }
    return { encrypt, decrypt }
  }

  return {
    genKey,
    di,
    es,
    dh,
    dsa,
    isLegalPK,
    isLegalSK,
    PointToU8,
    U8ToPoint,
  }
}
