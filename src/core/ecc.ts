import type { Digest } from './hash'
import { KitError, U8ToBI, mod, modInverse } from './utils'

// * Constants

export const sm2p256v1: FpECParams = {
  p: 0xFFFFFFFE_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_00000000_FFFFFFFF_FFFFFFFFn,
  a: 0xFFFFFFFE_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_00000000_FFFFFFFF_FFFFFFFCn,
  b: 0x28E9FA9E_9D9F5E34_4D5A9E4B_CF6509A7_F39789F5_15AB8F92_DDBCBD41_4D940E93n,
  G: {
    x: 0x32C4AE2C_1F198119_5F990446_6A39C994_8FE30BBF_F2660BE1_715A4589_334C74C7n,
    y: 0xBC3736A2_F4F6779C_59BDCEE3_6B692153_D0A9877C_C62A4740_02DF32E5_2139F0A0n,
  },
  n: 0xFFFFFFFE_FFFFFFFF_FFFFFFFF_FFFFFFFF_7203DF6B_21C6052B_53BBF409_39D54123n,
  n_mask: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFn,
  n_bit_length: 256,
}

export const secp192k1: FpECParams = {
  p: 0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFE_FFFFEE37n,
  a: 0x00000000_00000000_00000000_00000000_00000000_00000000n,
  b: 0x00000000_00000000_00000000_00000000_00000000_00000003n,
  G: {
    x: 0xDB4FF10E_C057E9AE_26B07D02_80B7F434_1DA5D1B1_EAE06C7Dn,
    y: 0x9B2F2F6D_9C5628A7_844163D0_15BE8634_4082AA88_D95E2F9Dn,
  },
  n: 0xFFFFFFFF_FFFFFFFF_FFFFFFFE_26F2FC17_0F69466A_74DEFD8Dn,
  n_mask: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFn,
  n_bit_length: 192,
}

export const secp192r1: FpECParams = {
  p: 0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFE_FFFFFFFF_FFFFFFFFn,
  a: 0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFE_FFFFFFFF_FFFFFFFCn,
  b: 0x64210519_E59C80E7_0FA7E9AB_72243049_FEB8DEEC_C146B9B1n,
  S: 0x3045AE6F_C8422F64_ED579528_D38120EA_E12196D5n,
  G: {
    x: 0x188DA80E_B03090F6_7CBF20EB_43A18800_F4FF0AFD_82FF1012n,
    y: 0x07192B95_FFC8DA78_631011ED_6B24CDD5_73F977A1_1E794811n,
  },
  n: 0xFFFFFFFF_FFFFFFFF_FFFFFFFF_99DEF836_146BC9B1_B4D22831n,
  n_mask: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFn,
  n_bit_length: 192,
}

export const secp224k1: FpECParams = {
  p: 0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFE_FFFFE56Dn,
  a: 0x00000000_00000000_00000000_00000000_00000000_00000000_00000000n,
  b: 0x00000000_00000000_00000000_00000000_00000000_00000000_00000005n,
  G: {
    x: 0xA1455B33_4DF099DF_30FC28A1_69A467E9_E47075A9_0F7E650E_B6B7A45Cn,
    y: 0x7E089FED_7FBA3442_82CAFBD6_F7E319F7_C0B0BD59_E2CA4BDB_556D61A5n,
  },
  n: 0x01_00000000_00000000_00000000_0001DCE8_D2EC6184_CAF0A971_769FB1F7n,
  n_mask: 0x1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFn,
  n_bit_length: 225,
}

export const secp224r1: FpECParams = {
  p: 0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_00000000_00000000_00000001n,
  a: 0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFE_FFFFFFFF_FFFFFFFF_FFFFFFFEn,
  b: 0xB4050A85_0C04B3AB_F5413256_5044B0B7_D7BFD8BA_270B3943_2355FFB4n,
  S: 0xBD713447_99D5C7FC_DC45B59F_A3B9AB8F_6A948BC5n,
  G: {
    x: 0xB70E0CBD_6BB4BF7F_321390B9_4A03C1D3_56C21122_343280D6_115C1D21n,
    y: 0xBD376388_B5F723FB_4C22DFE6_CD4375A0_5A074764_44D58199_85007E34n,
  },
  n: 0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFF16A2_E0B8F03E_13DD2945_5C5C2A3Dn,
  n_mask: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFn,
  n_bit_length: 224,

}

export const secp256k1: FpECParams = {
  p: 0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFE_FFFFFC2Fn,
  a: 0x00000000_00000000_00000000_00000000_00000000_00000000_00000000_00000000n,
  b: 0x00000000_00000000_00000000_00000000_00000000_00000000_00000000_00000007n,
  G: {
    x: 0x79BE667E_F9DCBBAC_55A06295_CE870B07_029BFCDB_2DCE28D9_59F2815B_16F81798n,
    y: 0x483ADA77_26A3C465_5DA4FBFC_0E1108A8_FD17B448_A6855419_9C47D08F_FB10D4B8n,
  },
  n: 0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFE_BAAEDCE6_AF48A03B_BFD25E8C_D0364141n,
  n_mask: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFn,
  n_bit_length: 256,
}

export const secp256r1: FpECParams = {
  p: 0xFFFFFFFF_00000001_00000000_00000000_00000000_FFFFFFFF_FFFFFFFF_FFFFFFFFn,
  a: 0xFFFFFFFF_00000001_00000000_00000000_00000000_FFFFFFFF_FFFFFFFF_FFFFFFFCn,
  b: 0x5AC635D8_AA3A93E7_B3EBBD55_769886BC_651D06B0_CC53B0F6_3BCE3C3E_27D2604Bn,
  S: 0xC49D3608_86E70493_6A6678E1_139D26B7_819F7E90n,
  G: {
    x: 0x6B17D1F2_E12C4247_F8BCE6E5_63A440F2_77037D81_2DEB33A0_F4A13945_D898C296n,
    y: 0x4FE342E2_FE1A7F9B_8EE7EB4A_7C0F9E16_2BCE3357_6B315ECE_CBB64068_37BF51F5n,
  },
  n: 0xFFFFFFFF_00000000_FFFFFFFF_FFFFFFFF_BCE6FAAD_A7179E84_F3B9CAC2_FC632551n,
  n_mask: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFn,
  n_bit_length: 256,
}

export const secp384r1: FpECParams = {
  p: 0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFE_FFFFFFFF_00000000_00000000_FFFFFFFFn,
  a: 0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFE_FFFFFFFF_00000000_00000000_FFFFFFFCn,
  b: 0xB3312FA7_E23EE7E4_988E056B_E3F82D19_181D9C6E_FE814112_0314088F_5013875A_C656398D_8A2ED19D_2A85C8ED_D3EC2AEFn,
  S: 0xA335926A_A319A27A_1D00896A_6773A482_7ACDAC73n,
  G: {
    x: 0xAA87CA22_BE8B0537_8EB1C71E_F320AD74_6E1D3B62_8BA79B98_59F741E0_82542A38_5502F25D_BF55296C_3A545E38_72760AB7n,
    y: 0x3617DE4A_96262C6F_5D9E98BF_9292DC29_F8F41DBD_289A147C_E9DA3113_B5F0B8C0_0A60B1CE_1D7E819D_7A431D7C_90EA0E5Fn,
  },
  n: 0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_C7634D81_F4372DDF_581A0DB2_48B0A77A_ECEC196A_CCC52973n,
  n_mask: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFn,
  n_bit_length: 384,

}

export const secp521r1: FpECParams = {
  p: 0x01FF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFFn,
  a: 0x01FF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFCn,
  b: 0x0051_953EB961_8E1C9A1F_929A21A0_B68540EE_A2DA725B_99B315F3_B8B48991_8EF109E1_56193951_EC7E937B_1652C0BD_3BB1BF07_3573DF88_3D2C34F1_EF451FD4_6B503F00n,
  S: 0xD09E8800_291CB853_96CC6717_393284AA_A0DA64BAn,
  G: {
    x: 0x00C6_858E06B7_0404E9CD_9E3ECB66_2395B442_9C648139_053FB521_F828AF60_6B4D3DBA_A14B5E77_EFE75928_FE1DC127_A2FFA8DE_3348B3C1_856A429B_F97E7E31_C2E5BD66n,
    y: 0x0118_39296A78_9A3BC004_5C8A5FB4_2C7D1BD9_98F54449_579B4468_17AFBD17_273E662C_97EE7299_5EF42640_C550B901_3FAD0761_353C7086_A272C240_88BE9476_9FD16650n,
  },
  n: 0x01FF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFA_51868783_BF2F966B_7FCC0148_F709A5D0_3BB5C9B8_899C47AE_BB6FB71E_91386409n,
  n_mask: 0x1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFn,
  n_bit_length: 521,
}

// * Functions

/** 素域运算 */
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

/** 素域椭圆曲线运算 */
function FpEC(curve: FpECParams) {
  const { p, a } = curve
  const { plus, multiply, subtract, divide } = Fp(p)

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

  return { addPoint, mulPoint }
}

/** 生成随机大整数 */
function genRandomBI(max: bigint, byte: number = 0): bigint {
  let result = 0n

  // 计算字节数
  let _byte = 0
  for (let _ = max; _ > 0; _ >>= 8n) {
    _byte++
  }
  if (byte > _byte) {
    throw new KitError('Byte length exceeds the maximum value')
  }

  // 使用指定字节数
  byte = byte || _byte

  // 生成随机数
  const buffer = new Uint8Array(byte)
  do {
    crypto.getRandomValues(buffer)
    result = U8ToBI(buffer)
  } while (result >= max)

  return result
}

// * EC Algorithms

/**
 * @description
 * Generate Elliptic Curve Key Pair
 *
 * 生成椭圆曲线密钥对
 */
export function genECKeyPair(curve: FpECParams): Required<ECKeyPair> {
  const { G, n, n_bit_length } = curve
  const { mulPoint } = FpEC(curve)

  // private key
  const d = genRandomBI(n - 2n, n_bit_length >> 3)

  // public key
  const Q = mulPoint(G, d)

  return { d, Q }
}

/**
 * @description
 * Elliptic Curve Digital Signature Algorithm
 *
 * 椭圆曲线数字签名算法
 */
export function ECDSA(curve: FpECParams, hash: Digest) {
  const { n, G, n_mask } = curve
  const { mulPoint, addPoint } = FpEC(curve)

  /**
   * @param {ECPrivateKey} d - 签名者的私钥
   * @param {Uint8Array} M - 消息
   */
  function sign(d: ECPrivateKey, M: Uint8Array): ECSignature {
    let r = 0n
    let s = 0n

    let z = U8ToBI(hash(M))
    while (z > n_mask) {
      z = z >> 1n
    }

    do {
      const K = genECKeyPair(curve)
      const [k, x1] = [K.d, K.Q.x]
      r = mod(x1, n)
      if (r === 0n)
        continue

      s = modInverse(k, n) * (z + r * d)
      s = mod(s, n)
    } while (s === 0n)

    return { r, s }
  }

  /**
   * @param {ECPublicKey} Q - 签名者的公钥
   * @param {Uint8Array} M - 消息
   * @param {ECSignature} signature - 签名
   */
  function verify(Q: ECPublicKey, M: Uint8Array, signature: ECSignature): boolean {
    // TODO 检查 Q 是否在曲线上

    const { r, s } = signature
    if (r <= 0n || r >= n || s <= 0n || s >= n) {
      return false
    }

    let z = U8ToBI(hash(M))
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

/**
 * @description
 * Elliptic Curve Diffie-Hellman Key Agreement Algorithm
 *
 * 椭圆曲线迪菲-赫尔曼, 密钥协商算法
 *
 * @param {FpECParams} curve - 椭圆曲线参数
 * @param {ECPrivateKey} d - 己方的私钥
 * @param {ECPublicKey} Q - 对方的公钥
 */
export function ECDH(curve: FpECParams, d: ECPrivateKey, Q: ECPublicKey) {
  const { mulPoint } = FpEC(curve)
  return mulPoint(Q, d)
}

// * Interfaces

/** 伪射坐标表示的椭圆曲线的点 */
interface FpECPoint {
  isInfinity?: boolean
  x: bigint
  y: bigint
}

/** 素域椭圆曲线参数 */
interface FpECParams {
  /** Prime */
  readonly p: bigint
  readonly a: bigint
  readonly b: bigint
  /** SEED */
  readonly S?: bigint
  /** Base point */
  readonly G: FpECPoint
  /** Order */
  readonly n: bigint
  readonly n_mask: bigint
  readonly n_bit_length: number
}

/** 素域椭圆曲线私钥 */
type ECPrivateKey = bigint

/** 素域椭圆曲线公钥 */
type ECPublicKey = FpECPoint

/** 椭圆曲线密钥对 */
interface ECKeyPair {
  /** Private key */
  d?: ECPrivateKey
  /** Public key */
  Q: ECPublicKey
}

/** 椭圆曲线数字签名 */
interface ECSignature {
  r: bigint
  s: bigint
}
