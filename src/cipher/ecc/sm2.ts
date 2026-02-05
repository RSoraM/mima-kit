import type { CSUtils } from '../../core/coordinate_system';
import type { ECJacobian, ECLópezDahab, FbKECParams, FbPECParams, FpMECParams, FpWECParams } from '../../core/ec';
import { sm2p256v1 } from '../../core/ec_params';
import type { Hash } from '../../core/hash';
import type { KDF } from '../../core/kdf';
import { x963kdf } from '../../core/kdf';
import { genBitMask, getBIBits, joinBuffer, KitError, mod, modInverse, U8 } from '../../core/utils';
import { sm3 } from '../../hash/sm3';
import type {
  ECCBase,
  ECCFbKoblitz,
  ECCFbPseudoRandom,
  ECCFpMontgomery,
  ECCFpWeierstrass,
  ECKeyPair,
  ECPrivateKey,
  ECPublicKey,
} from './ecc';
import { ECC } from './ecc';

export interface SM2DI {
  /**
   * SM2 可辨别标识散列
   *
   * SM2 Distinguishable Identity Hash
   *
   * @param {Uint8Array} id - 用户标识 / User Identity
   * @param {ECPublicKey} key - 公钥 / Public Key
   * @param {Hash} hash - 哈希算法 / Hash Algorithm (default: SM3)
   */
  (id: Uint8Array, key: ECPublicKey, hash?: Hash): U8;
}

export interface SM2DH {
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
  (KA: ECKeyPair, KX: ECKeyPair, KB: ECPublicKey, KY: ECPublicKey, ZA?: Uint8Array, ZB?: Uint8Array): U8;
}

export interface SM2DSASignature {
  r: bigint;
  s: bigint;
}
export interface SM2DSA {
  /**
   * SM2 椭圆曲线数字签名
   *
   * SM2 Elliptic Curve Digital Signature Algorithm
   *
   * @param {Hash} hash - 哈希算法 / Hash Algorithm (default: SM3)
   */
  (
    hash?: Hash,
  ): {
    /**
     * @param {Uint8Array} Z - 标识派生值 / Identity Derived Value
     * @param {ECPrivateKey} key - 签名方私钥 / Signer Private Key
     * @param {Uint8Array} M - 消息 / Message
     */
    sign: (Z: Uint8Array, key: ECPrivateKey, M: Uint8Array) => SM2DSASignature;
    /**
     * @param {Uint8Array} Z - 标识派生值 / Identity Derived Value
     * @param {ECPublicKey} key - 签名方公钥 / Signer Public Key
     * @param {Uint8Array} M - 消息 / Message
     * @param {SM2DSASignature} S - 签名 / Signature
     */
    verify: (Z: Uint8Array, key: ECPublicKey, M: Uint8Array, S: SM2DSASignature) => boolean;
  };
}

export interface SM2Encrypt {
  /**
   * SM2 椭圆曲线加密
   *
   * SM2 Elliptic Curve Encryption
   *
   * @param {ECPublicKey} p_key - 接收方公钥 / Receiver Public Key
   * @param {Uint8Array} M - 明文 / Plaintext
   */
  (p_key: ECPublicKey, M: Uint8Array): U8;
}
export interface SM2Decrypt {
  /**
   * SM2 椭圆曲线解密
   *
   * SM2 Elliptic Curve Decryption
   *
   * @param {ECPrivateKey} s_key - 解密方私钥 / Decryptor Private Key
   * @param {Uint8Array} C - 密文 / Ciphertext
   */
  (s_key: ECPrivateKey, C: Uint8Array): U8;
}
export interface SM2EncryptionScheme {
  /**
   * SM2 椭圆曲线加密方案
   *
   * SM2 Elliptic Curve Encryption Scheme
   *
   * @param {Hash} hash - 哈希算法 / Hash Algorithm (default: SM3)
   * @param {KDF} kdf - 密钥派生函数 / Key Derivation Function (default: X9.63 KDF with SM3)
   * @param {'c1c2c3' | 'c1c3c2'} order - 密文分段顺序 / Ciphertext Segment Order (default: 'c1c3c2')
   */
  (
    hash?: Hash,
    kdf?: KDF,
    order?: 'c1c2c3' | 'c1c3c2',
  ): {
    encrypt: SM2Encrypt;
    decrypt: SM2Decrypt;
  };
}

export interface SM2Base {
  /**
   * 生成 SM2 椭圆曲线密钥
   *
   * Generate SM2 Elliptic Curve Key
   */
  gen: ECCBase['gen'];
  /**
   * SM2 可辨别标识散列
   *
   * SM2 Distinguishable Identity Hash
   */
  di: SM2DI;
  /**
   * SM2 椭圆曲线加密方案
   *
   * SM2 Elliptic Curve Encryption Scheme
   */
  es: SM2EncryptionScheme;
  /**
   * SM2 椭圆曲线迪菲-赫尔曼, 密钥协商算法
   *
   * SM2 Elliptic Curve Diffie-Hellman Key Agreement Algorithm
   */
  dh: SM2DH;
  /**
   * SM2 椭圆曲线数字签名
   *
   * SM2 Elliptic Curve Digital Signature Algorithm
   */
  dsa: SM2DSA;
}
export interface SM2FpWeierstrass extends SM2Base {
  parameters: FpWECParams;
  utils: ECJacobian;
}
export interface SM2FpMontgomery extends SM2Base {
  parameters: FpMECParams;
  utils: ECJacobian;
}
export interface SM2FbPseudoRandom extends SM2Base {
  parameters: FbPECParams;
  utils: ECLópezDahab;
}
export interface SM2FbKoblitz extends SM2Base {
  parameters: FbKECParams;
  utils: ECLópezDahab;
}

/**
 * SM2 椭圆曲线公钥密码算法
 *
 * Public Key Cryptography Algorithm SM2 Based on Elliptic Curves
 *
 * @param curve - 椭圆曲线参数 / Elliptic Curve Parameters (default: sm2p256v1)
 */
export function sm2(curve: undefined): SM2FpWeierstrass;
export function sm2(curve: FpWECParams): SM2FpWeierstrass;
export function sm2(curve: FpMECParams): SM2FpMontgomery;
export function sm2(curve: FbPECParams): SM2FbPseudoRandom;
export function sm2(curve: FbKECParams): SM2FbKoblitz;
export function sm2(curve: FpWECParams | FpMECParams | FbPECParams | FbKECParams = sm2p256v1) {
  let ecc: ECCFpWeierstrass | ECCFpMontgomery | ECCFbPseudoRandom | ECCFbKoblitz;
  switch (curve.type) {
    case 'Weierstrass':
      ecc = ECC(curve);
      break;
    case 'Montgomery':
      ecc = ECC(curve);
      break;
    case 'Pseudo-Random':
      ecc = ECC(curve);
      break;
    case 'Koblitz':
      ecc = ECC(curve);
      break;
    default:
      throw new KitError('unsupported curve type');
  }
  let toCatalyst: CSUtils['toJacobian'] | CSUtils['toLD'];
  switch (ecc.utils.catalyst) {
    case 'jacobian':
      toCatalyst = ecc.utils.cs.toJacobian;
      break;
    case 'ld':
      toCatalyst = ecc.utils.cs.toLD;
      break;
    default:
      throw new KitError('unsupported catalyst type');
  }

  const { G, a, b, n, h } = curve;
  /** 优化基点 */
  const CG = toCatalyst(G);
  const p = 'p' in curve ? curve.p : undefined;
  const p_bit = p ? getBIBits(p) : undefined;
  const p_byte = p ? (p_bit! + 7) >> 3 : undefined;
  const m = 'm' in curve ? curve.m : undefined;
  const m_bit = m ? getBIBits(m) : undefined;
  const m_byte = m ? (m_bit! + 7) >> 3 : undefined;
  const ele_byte = p_byte ?? m_byte!;

  const { addPoint, mulPoint, isLegalPK } = ecc.utils;
  const toAffine = ecc.utils.cs.toAffine;

  const a_buffer = U8.fromBI(a);
  const b_buffer = U8.fromBI(b);
  const Gx_buffer = U8.fromBI(G.x);
  const Gy_buffer = U8.fromBI(G.y);

  const gen = ecc.gen;
  const PointToU8 = ecc.utils.PointToU8;
  const U8ToPoint = ecc.utils.U8ToPoint;
  const di: SM2DI = (id: Uint8Array, key: ECPublicKey, hash: Hash = sm3) => {
    const ent = id.length << 3;
    if (ent > 0xffff) throw new KitError('ID长度超过了最大限制');

    const ENT = new Uint8Array([ent >> 8, ent & 0xff]);
    const a = a_buffer;
    const b = b_buffer;
    const Gx = Gx_buffer;
    const Gy = Gy_buffer;
    const Ax = typeof key.Q.x === 'bigint' ? U8.fromBI(key.Q.x) : U8.from(key.Q.x);
    const Ay = typeof key.Q.y === 'bigint' ? U8.fromBI(key.Q.y) : U8.from(key.Q.y);
    const ZA = hash(joinBuffer(ENT, id, a, b, Gx, Gy, Ax, Ay));

    return ZA;
  };
  const w = Math.ceil(getBIBits(n) / 2) - 1;
  const w_mask = genBitMask(w);
  const dh: SM2DH = (
    KA: ECKeyPair,
    KX: ECKeyPair,
    KB: ECPublicKey,
    KY: ECPublicKey,
    ZA = new Uint8Array(),
    ZB = new Uint8Array(),
  ) => {
    if (isLegalPK(KB.Q) === false || isLegalPK(KY.Q) === false) throw new KitError('非法的公钥');

    const KA_d = KA.d;
    const KX_d = KX.d;
    const KX_Q_x = KX.Q.x;
    const KY_Q_x = KY.Q.x;
    const x1 = (1n << BigInt(w)) + (KX_Q_x & w_mask);
    const x2 = (1n << BigInt(w)) + (KY_Q_x & w_mask);

    const t = mod(KA_d + KX_d * x1, n);
    const KBQ = toCatalyst(KB.Q);
    const KYQ = toCatalyst(KY.Q);
    const V_j = mulPoint(addPoint(KBQ as any, mulPoint(KYQ as any, x2) as any) as any, h * t);
    if (V_j.isInfinity) throw new KitError('协商失败');

    const V = toAffine(V_j);
    const xu = U8.fromBI(V.x);
    const yu = U8.fromBI(V.y);

    return joinBuffer(xu, yu, ZA, ZB);
  };
  const dsa: SM2DSA = (hash: Hash = sm3) => {
    if (hash.DIGEST_SIZE !== 32) throw new KitError('不支持的哈希算法');

    const sign = (Z: Uint8Array, key: ECPrivateKey, M: Uint8Array) => {
      const dA = key.d;
      let r = 0n;
      let s = 0n;
      const e = hash(joinBuffer(Z, M)).toBI();
      do {
        const k = gen('private_key').d;
        const p = toAffine(mulPoint(CG as any, k));
        r = mod(e + p.x, n);
        if (r === 0n || r + k === n) continue;

        const numerator = mod(k - r * dA, n);
        const denominator = modInverse(1n + dA, n);
        s = mod(numerator * denominator, n);
        if (s === 0n) continue;
        break;
        // biome-ignore lint/correctness/noConstantCondition: <try not to throw an error when the probability event does not happen, just repeat the process>
      } while (1);

      return { r, s };
    };
    const verify = (Z: Uint8Array, key: ECPublicKey, M: Uint8Array, S: SM2DSASignature) => {
      const PA = toCatalyst(key.Q);
      const { r, s } = S;
      if (r <= 0n || r >= n || s <= 0n || s >= n) return false;

      const e = hash(joinBuffer(Z, M)).toBI();
      const t = mod(r + s, n);
      if (t === 0n) return false;

      const p = toAffine(addPoint(mulPoint(CG as any, s) as any, mulPoint(PA as any, t) as any));
      const R = mod(e + p.x, n);

      return R === r;
    };

    return { sign, verify };
  };
  const es: SM2EncryptionScheme = (hash = sm3, kdf = x963kdf(sm3), order = 'c1c3c2') => {
    const encrypt: SM2Encrypt = (p_key: ECPublicKey, M: Uint8Array) => {
      const C1 = gen();
      const Q = toCatalyst(p_key.Q);
      const S = mulPoint(Q as any, h);
      if (S.isInfinity) throw new KitError('加密失败');

      const { x, y } = toAffine(mulPoint(Q as any, C1.d));
      const x2 = U8.fromBI(x);
      const y2 = U8.fromBI(y);
      const ikm = joinBuffer(x2, y2);
      const C2 = kdf(M.length, ikm);
      C2.forEach((_, i) => {
        C2[i] ^= M[i];
      });
      const C3 = hash(joinBuffer(x2, M, y2));

      return order === 'c1c2c3' ? joinBuffer(PointToU8(C1.Q), C2, C3) : joinBuffer(PointToU8(C1.Q), C3, C2);
    };
    const decrypt: SM2Decrypt = (s_key: ECPrivateKey, C: Uint8Array) => {
      const C1_Length = (ele_byte << 1) + 1;
      const C3_Length = hash.DIGEST_SIZE;
      const C2_Length = C.length - C1_Length - C3_Length;
      const C1 = toCatalyst(U8ToPoint(C.subarray(0, C1_Length)));
      const S = mulPoint(C1 as any, h);
      if (S.isInfinity) throw new KitError('解密失败');

      const { x, y } = toAffine(mulPoint(C1 as any, s_key.d));
      const x2 = U8.fromBI(x);
      const y2 = U8.fromBI(y);
      const ikm = joinBuffer(x2, y2);
      const t = kdf(C2_Length, ikm);
      let C2: Uint8Array;
      let C3: Uint8Array;
      if (order === 'c1c2c3') {
        C2 = C.subarray(C1_Length, C1_Length + C2_Length);
        C3 = C.subarray(C1_Length + C2_Length);
      } else {
        C3 = C.subarray(C1_Length, C1_Length + C3_Length);
        C2 = C.subarray(C1_Length + C3_Length);
      }
      const M = t.map((_, i) => t[i] ^ C2[i]);
      const u = hash(joinBuffer(x2, M, y2));
      const isEqual = u.length === C3.length && u.every((val, i) => val === C3[i]);
      if (!isEqual) throw new KitError('解密失败');

      return M;
    };

    return { encrypt, decrypt };
  };

  return {
    utils: ecc.utils,
    gen,
    di,
    es,
    dh,
    dsa,
  };
}
