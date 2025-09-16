import type { AffinePoint, CSUtils, JacobianPoint, LDPoint } from './coordinate_system'
import type { GFUtils } from './galois_field'
import { CoordinateSystem } from './coordinate_system'
import { GF, GF2 } from './galois_field'
import { getBIBits, joinBuffer, KitError, U8 } from './utils'

// * Elliptic Curve Interfaces

interface PointAddition<P> {
  /**
   * 椭圆曲线点加法
   *
   * Elliptic Curve Point Addition
   */
  (A: P, B: P): P
}
interface PointMultiplication<P> {
  /**
   * 椭圆曲线点乘法
   *
   * Elliptic Curve Point Multiplication
   */
  (P: P, k: bigint | Uint8Array): P
}

interface ECBase {
  /**
   * 域运算
   *
   * Field Operations
   */
  field: GFUtils
  /**
   * 坐标系工具
   *
   * Coordinate System Tools
   */
  cs: CSUtils
  /**
   * 椭圆曲线点加法 (仿射坐标系)
   *
   * Elliptic Curve Point Addition (Affine Coordinate System)
   */
  _addPoint: (A: AffinePoint, B: AffinePoint) => AffinePoint
  /**
   * 椭圆曲线点乘法 (仿射坐标系)
   *
   * Elliptic Curve Point Multiplication (Affine Coordinate System)
   */
  _mulPoint: (P: AffinePoint, k: bigint | Uint8Array) => AffinePoint
  /**
   * 仿射点转换为字节串
   *
   * Convert Affine Point to Byte String
   *
   * @param {boolean} [compress=false] - 是否压缩 / Whether to compress
   */
  PointToU8: (point: AffinePoint, compress?: boolean) => U8
  /**
   * 字节串转换为仿射点
   *
   * Convert Byte String to Point
   */
  U8ToPoint: (buffer: Uint8Array) => AffinePoint
  /**
   * 判断公钥是否合法
   *
   * Determine if the public key is legal
   */
  isLegalPK: (Q: AffinePoint) => boolean
  /**
   * 判断私钥是否合法
   *
   * Determine if the private key is legal
   */
  isLegalSK: (d: bigint | Uint8Array) => boolean
}
export interface ECJacobian extends ECBase {
  catalyst: 'jacobian'
  addPoint: PointAddition<JacobianPoint>
  mulPoint: PointMultiplication<JacobianPoint>
}
export interface ECLópezDahab extends ECBase {
  catalyst: 'ld'
  addPoint: PointAddition<LDPoint>
  mulPoint: PointMultiplication<LDPoint>
}

// * Elliptic Curve Parameters Interfaces

/**
 * 椭圆曲线参数
 *
 * Elliptic Curve Parameters
 */
interface ECParams {
  /** Coefficient a */
  readonly a: bigint
  /** Coefficient b */
  readonly b: bigint
  /** Base point */
  readonly G: Readonly<AffinePoint>
  /** Order */
  readonly n: bigint
  /** co-factor */
  readonly h: bigint
}

/**
 * 素域椭圆曲线参数
 *
 * Prime Field Elliptic Curve Parameters
 */
interface FpECParams extends ECParams {
  /** Prime */
  readonly p: bigint
}

/**
 * 素域 Weierstrass 椭圆曲线参数
 *
 * Prime Field Weierstrass Elliptic Curve Parameters
 */
export interface FpWECParams extends FpECParams {
  type: 'Weierstrass'
}

/**
 * 素域 Montgomery 椭圆曲线参数
 *
 * Prime Field Montgomery Elliptic Curve Parameters
 */
export interface FpMECParams extends FpECParams {
  type: 'Montgomery'
}

/**
 * 素域 Twisted Edwards 椭圆曲线参数
 *
 * Prime Field Twisted Edwards Elliptic Curve Parameters
 */
export interface FpTECParams extends FpECParams {
  type: 'TwistedEdwards'
}

/**
 * 二进制域椭圆曲线参数
 *
 * Binary Field Elliptic Curve Parameters
 */
interface FbECParams extends ECParams {
  /** Degree of the reduction polynomial */
  readonly m: bigint
  /** Irreducible polynomial */
  readonly IP: bigint
}

/**
 * 二进制域 伪随机 椭圆曲线参数
 *
 * Binary Field Pseudo-Random Elliptic Curve Parameters
 */
export interface FbPECParams extends FbECParams {
  type: 'Pseudo-Random'
}

/**
 * 二进制域 Koblitz 椭圆曲线参数
 *
 * Binary Field Koblitz Elliptic Curve Parameters
 */
export interface FbKECParams extends FbECParams {
  type: 'Koblitz'
}

// * Functions

function LadderMultiply(add: PointAddition<AffinePoint>, P: AffinePoint, k: bigint | Uint8Array,): AffinePoint
function LadderMultiply(add: PointAddition<JacobianPoint>, P: JacobianPoint, k: bigint | Uint8Array): JacobianPoint
function LadderMultiply(add: PointAddition<LDPoint>, P: LDPoint, k: bigint | Uint8Array,): LDPoint
function LadderMultiply(
  add: PointAddition<any>,
  P: JacobianPoint | LDPoint | AffinePoint,
  k: bigint | Uint8Array,
) {
  k = typeof k === 'bigint' ? k : U8.from(k).toBI()

  let R0
  let R1
  switch (P.type) {
    case 'affine':
      R0 = { type: 'affine', isInfinity: true, x: 0n, y: 0n }
      R1 = { type: 'affine', isInfinity: P.isInfinity, x: P.x, y: P.y }
      break
    case 'jacobian':
      R0 = { type: 'jacobian', isInfinity: true, x: 1n, y: 1n, z: 0n }
      R1 = { type: 'jacobian', isInfinity: P.isInfinity, x: P.x, y: P.y, z: P.z }
      break
    case 'ld':
      R0 = { type: 'ld', isInfinity: true, x: 1n, y: 1n, z: 0n }
      R1 = { type: 'ld', isInfinity: P.isInfinity, x: P.x, y: P.y, z: P.z }
      break
    default:
      throw new KitError('unknown coordinate system')
  }

  // MSb -> LSb
  const bit_array = k.toString(2).split('')
  for (const bit of bit_array) {
    if (bit === '1') {
      R0 = add(R0, R1)
      R1 = add(R1, R1)
    }
    else {
      R1 = add(R0, R1)
      R0 = add(R0, R0)
    }
  }
  return R0
}

// * FpEC Components

/**
 * 素域 Weierstrass 椭圆曲线运算
 *
 * Prime Field Weierstrass Elliptic Curve Operations
 *
 * y^2 = x^3 + ax + b
 */
export function FpWEC(curve: FpWECParams): ECJacobian {
  const { p, n, a, b, G } = curve
  const p_bit = getBIBits(p)
  const p_byte = (p_bit + 7) >> 3
  const field = GF(p)
  const cs = CoordinateSystem(field)

  const { add, sub, mul, div, root, include } = field
  const { toAffine, toJacobian } = cs

  const _addPoint = (A: AffinePoint, B: AffinePoint): AffinePoint => {
    // O + P = P
    if (A.isInfinity)
      return B
    if (B.isInfinity)
      return A

    const { x: X1, y: Y1 } = A
    const { x: X2, y: Y2 } = B

    const U = sub(X1, X2) === 0n

    // P + (-P) = O
    if (U && add(Y1, Y2) === 0n)
      return toAffine(undefined)
    if (U && Y1 === 0n)
      return toAffine(undefined)

    let λ = 0n
    // P1 + P1
    if (U) {
      // λ = (3 * x1 * x1 + a) / 2 * y1
      const numerator = add(mul(3n, X1, X1), a)
      const denominator = mul(2n, Y1)
      λ = div(numerator, denominator)
    }
    // P1 + P2
    else {
      // λ = (y2 - y1) / (x2 - x1)
      const numerator = sub(Y2, Y1)
      const denominator = sub(X2, X1)
      λ = div(numerator, denominator)
    }

    // x3 = λ * λ - x1 - x2
    const x3 = sub(mul(λ, λ), X1, X2)
    // y3 = λ * (x1 - x3) - y1
    const y3 = sub(mul(λ, sub(X1, x3)), Y1)

    return { type: 'affine', isInfinity: false, x: x3, y: y3 }
  }

  const addPoint = (A: JacobianPoint, B: JacobianPoint): JacobianPoint => {
    // O + P = P
    if (A.isInfinity)
      return B
    if (B.isInfinity)
      return A

    const [X1, Y1, Z1] = [A.x, A.y, A.z]
    const [X2, Y2, Z2] = [B.x, B.y, B.z]

    // 计算中间变量
    const ZZ1 = mul(Z1, Z1)
    const ZZ2 = mul(Z2, Z2)

    const U1 = mul(X1, ZZ2)
    const U2 = mul(X2, ZZ1)
    const S1 = mul(Y1, ZZ2, Z2)
    const S2 = mul(Y2, ZZ1, Z1)

    // P + (-P) = O
    if (U1 === U2 && S1 !== S2)
      return { type: 'jacobian', isInfinity: true, x: 1n, y: 1n, z: 0n }

    // P1 + P1
    if (U1 === U2 && S1 === S2) {
      const [X, Y, Z] = [X1, Y1, Z1]

      // Z3 = 2 * Y1 * Z1
      const Z3 = mul(2n, Y, Z)
      if (Z3 === 0n)
        return { type: 'jacobian', isInfinity: true, x: 1n, y: 1n, z: 0n }

      const XX = mul(X, X)
      const YY = mul(Y, Y)
      const ZZ = ZZ1
      const S = mul(4n, X, YY)
      // M = 3 * XX + a * ZZ^2
      const M = add(mul(3n, XX), mul(a, ZZ, ZZ))

      // X3 = M^2 - 2 * S
      const X3 = sub(mul(M, M), mul(2n, S))
      // Y3 = M * (S - X3) - 8 * YYYY
      const Y3 = sub(mul(M, sub(S, X3)), mul(8n, YY, YY))

      return { type: 'jacobian', isInfinity: false, x: X3, y: Y3, z: Z3 }
    }
    // P1 + P2
    else {
      const H = sub(U2, U1)

      // Z3 = H * Z1 * Z2
      const Z3 = mul(H, Z1, Z2)
      if (Z3 === 0n)
        return { type: 'jacobian', isInfinity: true, x: 1n, y: 1n, z: 0n }

      const R = sub(S2, S1)
      const HH = mul(H, H)
      const HHH = mul(H, HH)
      const U1HH = mul(U1, HH)

      // X3 = R^2 - H^3 - 2 * U1 * H^2
      const X3 = sub(mul(R, R), HHH, mul(2n, U1HH))
      // Y3 = R * (U1 * H^2 - X3) - S1 * H^3
      const Y3 = sub(mul(R, sub(U1HH, X3)), mul(S1, HHH))

      return { type: 'jacobian', isInfinity: false, x: X3, y: Y3, z: Z3 }
    }
  }

  const _mulPoint = (P: AffinePoint, k: bigint | Uint8Array): AffinePoint => LadderMultiply(_addPoint, P, k)

  const mulPoint = (P: JacobianPoint, k: bigint | Uint8Array): JacobianPoint => LadderMultiply(addPoint, P, k)

  const isLegalPK = (P: AffinePoint) => {
    // P != O
    if (P.isInfinity)
      return false

    // P(x, y) ∈ E
    const { x, y } = toAffine(P)
    if (!include(x) || !include(y))
      return false

    // y^2 = x^3 + ax + b
    const l = mul(y, y)
    const r = add(mul(x, x, x), mul(a, x), b)
    if (l !== r)
      return false

    // nP = O
    const nP = mulPoint(toJacobian(P), n)
    return nP.isInfinity
  }

  const isLegalSK = (k: bigint | Uint8Array) => {
    k = typeof k === 'bigint' ? k : U8.from(k).toBI()
    if (k <= 0n || k >= n)
      return false

    return !mulPoint(toJacobian(G), k).isInfinity
  }

  const PointToU8 = (point: AffinePoint, compress = false): U8 => {
    if (point.isInfinity)
      return new U8([0x00])

    const { x, y } = point
    const sign_y = Number(y & 1n)
    const PC = new U8([compress ? 0x02 | sign_y : 0x04])
    const X1 = U8.fromBI(x, p_byte)
    const Y1 = compress ? new U8() : U8.fromBI(y, p_byte)

    return joinBuffer(PC, X1, Y1)
  }

  const U8ToPoint = (buffer: Uint8Array): AffinePoint => {
    const point_buffer = U8.from(buffer)
    const PC = point_buffer[0]
    if (PC !== 0x00 && PC !== 0x02 && PC !== 0x03 && PC !== 0x04)
      throw new KitError('Invalid Point')

    // 无穷远点
    if (PC === 0x00 && point_buffer.length === 1)
      return toAffine(undefined)

    // 无压缩
    if (PC === 0x04 && point_buffer.length === (p_byte << 1) + 1) {
      const x = point_buffer.slice(1, p_byte + 1).toBI()
      const y = point_buffer.slice(p_byte + 1).toBI()

      return { type: 'affine', isInfinity: false, x, y }
    }
    // 解压缩
    if ((PC === 0x02 || PC === 0x03) && point_buffer.length === p_byte + 1) {
      const x_buffer = point_buffer.slice(1)
      const x = x_buffer.toBI()
      const sign_y = BigInt(PC & 1)

      let y: bigint
      y = add(mul(x, x, x), mul(a, x), b)
      y = root(y)
      y = (y & 1n) === sign_y ? y : sub(p, y)

      return { type: 'affine', isInfinity: false, x, y }
    }

    throw new KitError('Invalid Point')
  }

  return {
    field,
    cs,
    catalyst: 'jacobian',
    addPoint,
    mulPoint,
    _addPoint,
    _mulPoint,
    isLegalPK,
    isLegalSK,
    PointToU8,
    U8ToPoint,
  }
}

/**
 * 素域 Montgomery 椭圆曲线运算
 *
 * Prime Field Montgomery Elliptic Curve Operations
 *
 * b * y^2 = x^3 + a * x^2 + x
 */
export function FpMEC(curve: FpMECParams): ECJacobian {
  const { p, n, a, b, G } = curve
  const p_bit = getBIBits(p)
  const p_byte = (p_bit + 7) >> 3
  const field = GF(p)
  const cs = CoordinateSystem(field)

  const { add, sub, mul, div, root, include } = field
  const { toAffine, toJacobian } = cs

  const _addPoint = (A: AffinePoint, B: AffinePoint): AffinePoint => {
    // O + P = P
    if (A.isInfinity)
      return B
    if (B.isInfinity)
      return A

    const { x: X1, y: Y1 } = A
    const { x: X2, y: Y2 } = B

    const U = sub(X1, X2) === 0n

    // P + (-P) = O
    if (U && add(Y1, Y2) === 0n)
      return toAffine(undefined)
    if (U && Y1 === 0n)
      return toAffine(undefined)

    let λ = 0n
    // P1 + P1
    if (U) {
      // λ = (3 * x1 * x1 + 2 * a * x1 + 1) / 2 * b * y1
      const numerator = add(mul(3n, X1, X1), mul(2n, a, X1), 1n)
      const denominator = mul(2n, b, Y1)
      λ = div(numerator, denominator)
    }
    // P1 + P2
    else {
      // λ = (y2 - y1) / (x2 - x1)
      const numerator = sub(Y2, Y1)
      const denominator = sub(X2, X1)
      λ = div(numerator, denominator)
    }

    // x3 = b * λ * λ - a - x1 - x2
    const X3 = sub(mul(λ, λ, b), a, X1, X2)
    // y3 = (2 x1 + x2 + a) * λ - b * λ * λ * λ - y1
    const Y3 = sub(mul(2n * X1 + X2 + a, λ), mul(λ, λ, λ, b), Y1)

    return { type: 'affine', isInfinity: false, x: X3, y: Y3 }
  }

  const addPoint = (A: JacobianPoint, B: JacobianPoint): JacobianPoint => {
    // O + P = P
    if (A.isInfinity)
      return B
    if (B.isInfinity)
      return A

    const [X1, Y1, Z1] = [A.x, A.y, A.z]
    const [X2, Y2, Z2] = [B.x, B.y, B.z]

    // 计算中间变量
    const ZZ1 = mul(Z1, Z1) // Z1^2
    const ZZ2 = mul(Z2, Z2) // Z2^2
    const U1 = mul(X1, ZZ2)
    const U2 = mul(X2, ZZ1)
    const S1 = mul(Y1, ZZ2, Z2)
    const S2 = mul(Y2, ZZ1, Z1)
    const H = sub(U2, U1) // H = U2 - U1
    const R = sub(S2, S1) // R = S2 - S1

    // P + (-P) = O
    if (H === 0n && R !== 0n)
      return { type: 'jacobian', isInfinity: true, x: 1n, y: 1n, z: 0n }

    // P1 + P1
    if (H === 0n && R === 0n) {
      const [X, Y, Z] = [X1, Y1, Z1]

      // Z3 = 2 * b * Y1 * Z1 = λ 的分母
      const Z3 = mul(2n, b, Y, Z)
      if (Z3 === 0n)
        return { type: 'jacobian', isInfinity: true, x: 1n, y: 1n, z: 0n }

      const XX = mul(X, X)
      const YY = mul(Y, Y)
      const ZZ = ZZ1
      const ZZZZ = mul(ZZ, ZZ)
      // N = 3 * X1^2 + 2 * a * X1 * Z1^2 + Z1^4 (λ 的分子，已清除分母)
      const N = add(mul(3n, XX), mul(2n, a, X, ZZ), ZZZZ)
      const NN = mul(N, N)

      // X3 = b * N^2 - a * Z3^2 - 8 * b^2 * X1 * Y1^2
      const X3 = sub(mul(b, NN), mul(a, Z3, Z3), mul(8n, b, b, X, YY))
      // Y3 = 4 * b^2 * (3 * X1 + a * Z1^2) * N * Y1^2 - b * N^3 - 8 * b^3 * Y1^4
      const Y3 = sub(mul(4n, b, b, add(mul(3n, X), mul(a, ZZ)), N, YY), mul(b, NN, N), mul(8n, b, b, b, YY, YY))

      return { type: 'jacobian', isInfinity: false, x: X3, y: Y3, z: Z3 }
    }
    // P1 + P2
    else {
      const Z3 = mul(H, Z1, Z2)
      if (Z3 === 0n)
        return { type: 'jacobian', isInfinity: true, x: 1n, y: 1n, z: 0n }

      const HH = mul(H, H) // HH = H^2

      const X3 = sub(mul(b, R, R), mul(a, ZZ1, ZZ2, HH), mul(add(U1, U2), HH))
      const Y3 = sub(mul(R, sub(mul(U1, HH), X3)), mul(S1, HH, H))

      return { type: 'jacobian', isInfinity: false, x: X3, y: Y3, z: Z3 }
    }
  }

  const _mulPoint = (P: AffinePoint, k: bigint | Uint8Array): AffinePoint => LadderMultiply(_addPoint, P, k)

  const mulPoint = (P: JacobianPoint, k: bigint | Uint8Array): JacobianPoint => LadderMultiply(addPoint, P, k)

  const isLegalPK = (P: AffinePoint) => {
    // P != O
    if (P.isInfinity)
      return false

    // P(x, y) ∈ E
    const { x, y } = toAffine(P)
    if (!include(x) || !include(y))
      return false

    // b * y^2 = x^3 + a * x^2 + x
    const l = mul(b, y, y)
    const r = add(mul(x, x, x), mul(a, x, x), x)
    if (l !== r)
      return false

    // nP = O
    const nP = mulPoint(toJacobian(P), n)
    return nP.isInfinity
  }

  const isLegalSK = (k: bigint | Uint8Array) => {
    k = typeof k === 'bigint' ? k : U8.from(k).toBI()
    if (k <= 0n || k >= n)
      return false

    return !mulPoint(toJacobian(G), k).isInfinity
  }

  const PointToU8 = (point: AffinePoint, compress = false): U8 => {
    if (point.isInfinity)
      return new U8([0x00])

    const { x, y } = point
    const sign_y = Number(y & 1n)
    const PC = new U8([compress ? 0x02 | sign_y : 0x04])
    const X1 = U8.fromBI(x, p_byte)
    const Y1 = compress ? new U8() : U8.fromBI(y, p_byte)

    return joinBuffer(PC, X1, Y1)
  }

  const U8ToPoint = (buffer: Uint8Array): AffinePoint => {
    const point_buffer = U8.from(buffer)
    const PC = point_buffer[0]
    if (PC !== 0x00 && PC !== 0x02 && PC !== 0x03 && PC !== 0x04)
      throw new KitError('Invalid Point')

    // 无穷远点
    if (PC === 0x00 && point_buffer.length === 1)
      return toAffine(undefined)

    // 无压缩
    if (PC === 0x04 && point_buffer.length === (p_byte << 1) + 1) {
      const x = point_buffer.slice(1, p_byte + 1).toBI()
      const y = point_buffer.slice(p_byte + 1).toBI()

      return { type: 'affine', isInfinity: false, x, y }
    }
    // 解压缩
    if ((PC === 0x02 || PC === 0x03) && point_buffer.length === p_byte + 1) {
      const x_buffer = point_buffer.slice(1)
      const x = x_buffer.toBI()
      const sign_y = BigInt(PC & 1)

      let y: bigint
      y = add(mul(x, x, x), mul(a, x, x), x)
      y = div(y, b)
      y = root(y)
      y = (y & 1n) === sign_y ? y : sub(p, y)

      return { type: 'affine', isInfinity: false, x, y }
    }

    throw new KitError('Invalid Point')
  }

  return {
    field,
    cs,
    catalyst: 'jacobian',
    addPoint,
    mulPoint,
    _addPoint,
    _mulPoint,
    isLegalPK,
    isLegalSK,
    PointToU8,
    U8ToPoint,
  }
}

// * FbEC Components

/**
 * 二进制域椭圆曲线运算
 *
 * Binary Field Elliptic Curve Operations
 *
 * y^2 + xy = x^3 + ax^2 + b
 */
export function FbEC(curve: FbKECParams | FbPECParams): ECLópezDahab {
  const { m, IP, a, b, n, G } = curve
  const field = GF2(m, IP)
  const cs = CoordinateSystem(field)
  const m_byte = (Number(m) + 7) >> 3

  const { add, sub, mul, div, squ, root, include } = field
  const { toAffine, toLD } = cs

  const _addPoint = (A: AffinePoint, B: AffinePoint): AffinePoint => {
    // O + P = P
    if (A.isInfinity)
      return B
    if (B.isInfinity)
      return A

    const { x: X1, y: Y1 } = A
    const { x: X2, y: Y2 } = B

    // P + (-P) = O
    const T = sub(X1, X2) === 0n
    if (T && add(X1, Y2) === Y1)
      return toAffine(undefined)
    if (T && X1 === 0n)
      // 若 x1 为 0，则切线斜率不存在，结果为无穷远点
      return toAffine(undefined)

    let λ = 0n
    // P1 + P1
    if (T) {
      // λ = x1 + y1 / x1
      λ = add(X1, div(Y1, X1))
    }
    // P1 + P2
    else {
      // λ = (y2 + y1) / (x2 + x1)
      const numerator = add(Y2, Y1)
      const denominator = add(X2, X1)
      λ = div(numerator, denominator)
    }

    // x3 = λ * λ + λ + a + x1 + x2
    const x3 = add(mul(λ, λ), λ, a, X1, X2)
    // y3 = λ * (x1 + x3) + x3 + y1
    const y3 = add(mul(λ, add(X1, x3)), x3, Y1)

    return { type: 'affine', isInfinity: false, x: x3, y: y3 }
  }

  const addPoint = (P: LDPoint, Q: LDPoint): LDPoint => {
    // O + P = P
    if (P.isInfinity)
      return Q
    if (Q.isInfinity)
      return P

    const [X1, Y1, Z1] = [P.x, P.y, P.z]
    const [X2, Y2, Z2] = [Q.x, Q.y, Q.z]

    // 计算中间变量
    const A = add(mul(X1, Z2), mul(X2, Z1))
    const B = add(mul(Y1, Z2, Z2), mul(Y2, Z1, Z1))

    // P + (-P) = O
    if (A === 0n && B !== 0n)
      return { type: 'ld', isInfinity: true, x: 1n, y: 1n, z: 0n }
    if (A === 0n && B === 0n && X1 === 0n)
      return { type: 'ld', isInfinity: true, x: 1n, y: 1n, z: 0n }

    // P1 + P1
    if (A === 0n && B === 0n) {
      const [X, Y, Z] = [X1, Y1, Z1]
      const A = squ(X)
      const B = squ(Z)
      const Z3 = mul(A, B)
      const C = squ(A)
      const D = mul(b, squ(B))
      const X3 = add(C, D)
      const Y3 = add(
        mul(D, Z3),
        mul(X3, add(mul(a, Z3), squ(Y), D)),
      )

      return { type: 'ld', isInfinity: false, x: X3, y: Y3, z: Z3 }
    }
    // P1 + P2
    else {
      const C = mul(Z1, A)
      const D = mul(Z2, C)
      const Z3 = squ(D)
      const X3 = add(mul(D, add(squ(A), B)), squ(B), mul(a, Z3))
      const E = mul(C, D)
      const F = mul(squ(E), Y2)
      const G = add(X3, mul(X2, E))
      const Y3 = add(mul(Z3, X3), F, mul(B, D, G))

      return { type: 'ld', isInfinity: false, x: X3, y: Y3, z: Z3 }
    }
  }

  const _mulPoint = (P: AffinePoint, k: bigint | Uint8Array): AffinePoint => LadderMultiply(_addPoint, P, k)

  const mulPoint = (P: LDPoint, k: bigint | Uint8Array): LDPoint => LadderMultiply(addPoint, P, k)

  const isLegalPK = (P: AffinePoint) => {
    // P != O
    if (P.isInfinity)
      return false

    // P(x, y) ∈ E
    const { x, y } = toAffine(P)
    if (!include(x) || !include(y))
      return false

    // y^2 + xy = x^3 + ax^2 + b
    const l = add(squ(y), mul(x, y))
    const r = add(mul(x, x, x), mul(a, x, x), b)
    if (l !== r)
      return false

    return mulPoint(toLD(P), n).isInfinity
  }

  const isLegalSK = (k: bigint | Uint8Array) => {
    k = typeof k === 'bigint' ? k : U8.from(k).toBI()
    if (k <= 0n || k >= (n - 2n))
      return false

    return !mulPoint(toLD(G), k).isInfinity
  }

  const PointToU8 = (point: AffinePoint, compress = false): U8 => {
    if (point.isInfinity)
      return new U8([0x00])

    const { x, y } = toAffine(point)
    const sign_y = Number(div(y, x) & 1n)
    const PC = new U8([compress ? 0x02 | sign_y : 0x04])
    const X1 = U8.fromBI(x, m_byte)
    const Y1 = compress ? new U8() : U8.fromBI(y, m_byte)

    return joinBuffer(PC, X1, Y1)
  }

  const U8ToPoint = (buffer: Uint8Array): AffinePoint => {
    const point_buffer = U8.from(buffer)
    const PC = point_buffer[0]
    if (PC !== 0x00 && PC !== 0x02 && PC !== 0x03 && PC !== 0x04)
      throw new KitError('Invalid Point')

    // 无穷远点
    if (PC === 0x00 && point_buffer.length === 1)
      return toAffine(undefined)

    // 无压缩
    if (PC === 0x04 && point_buffer.length === (m_byte << 1) + 1) {
      const x = point_buffer.slice(1, m_byte + 1).toBI()
      const y = point_buffer.slice(m_byte + 1).toBI()

      return { type: 'affine', isInfinity: false, x, y }
    }
    // 解压缩
    if ((PC === 0x02 || PC === 0x03) && point_buffer.length === m_byte + 1) {
      const x_buffer = point_buffer.slice(1)
      const x = x_buffer.toBI()
      const sign_y = BigInt(PC & 1)

      let y: bigint
      if (x === 0n) {
        y = root(b)
      }
      else {
        y = add(mul(x, x, x), mul(a, x), 1n)
        y = div(y, x)
        y = mul(y, x)
        y = root(y)
      }
      y = (y & 1n) === sign_y ? y : add(y, 1n)

      return { type: 'affine', isInfinity: false, x, y }
    }

    throw new KitError('Invalid Point')
  }

  return {
    field,
    cs,
    catalyst: 'ld',
    addPoint,
    mulPoint,
    _addPoint,
    _mulPoint,
    isLegalPK,
    isLegalSK,
    PointToU8,
    U8ToPoint,
  }
}

// * EC

/**
 * 椭圆曲线运算
 *
 * Elliptic Curve Operations
 */
export function EC(curve: FpWECParams | FpMECParams): ECJacobian
export function EC(curve: FbPECParams | FbKECParams): ECLópezDahab
export function EC(curve: FpWECParams | FpMECParams | FbPECParams | FbKECParams) {
  switch (curve.type) {
    case 'Weierstrass':
      return FpWEC(curve)
    case 'Montgomery':
      return FpMEC(curve)
    case 'Pseudo-Random':
    case 'Koblitz':
      return FbEC(curve)
    default:
      throw new KitError('unknown curve type')
  }
}
