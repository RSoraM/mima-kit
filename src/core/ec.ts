import type { FpMECParams, FpTECParams, FpWECParams } from './ecParams'
import type { AffinePoint, CSUtils, GFUtils, JacobianPoint } from './field'
import { CoordinateSystem, GF } from './field'
import { U8 } from './utils'

// * Interfaces

export interface ECUtils extends CSUtils {
  /**
   * 域运算
   *
   * Field Operations
   */
  gf: GFUtils
  /**
   * 素域椭圆曲线点加法 (雅可比坐标系)
   *
   * Prime Field Elliptic Curve Point Addition (Jacobian Coordinate System)
   */
  addPoint: (A: JacobianPoint, B: JacobianPoint) => JacobianPoint
  /**
   * 素域椭圆曲线点乘法 (雅可比坐标系)
   *
   * Prime Field Elliptic Curve Point Multiplication (Jacobian Coordinate System)
   */
  mulPoint: (P: JacobianPoint, k: bigint | Uint8Array) => JacobianPoint
  /**
   * 素域椭圆曲线点加法 (仿射坐标系)
   *
   * Prime Field Elliptic Curve Point Addition (Affine Coordinate System)
   *
   * @deprecated 仅作参考，不推荐使用 / For reference only, not recommended for use
   */
  _addPoint?: (A: AffinePoint, B: AffinePoint) => AffinePoint<bigint>
  /**
   * 素域椭圆曲线点乘法 (仿射坐标系)
   *
   * Prime Field Elliptic Curve Point Multiplication (Affine Coordinate System)
   *
   * @deprecated 仅作参考，不推荐使用 / For reference only, not recommended for use
   */
  _mulPoint?: (P: AffinePoint, k: bigint | Uint8Array) => AffinePoint<bigint>
}

// * FpEC Components

function LadderMultiply(
  add: ECUtils['addPoint'],
  P: JacobianPoint,
  k: bigint | Uint8Array,
): JacobianPoint {
  k = typeof k === 'bigint' ? k : U8.from(k).toBI()

  let R0: JacobianPoint = { isInfinity: true, x: 0n, y: 1n, z: 0n }
  let R1: JacobianPoint = { isInfinity: P.isInfinity, x: P.x, y: P.y, z: P.z }

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

/**
 * 素域椭圆曲线运算
 *
 * Prime Field Elliptic Curve Operations
 */
export function FpEC(curve: FpWECParams | FpMECParams | FpTECParams): ECUtils {
  switch (curve.type) {
    case 'Weierstrass':
      return FpWEC(curve)
    case 'Montgomery':
      return FpMEC(curve)
    case 'TwistedEdwards':
      return FpTEC(curve)
  }
}

/**
 * 素域 Weierstrass 椭圆曲线运算
 *
 * Prime Field Weierstrass Elliptic Curve Operations
 */
export function FpWEC(curve: FpWECParams): ECUtils {
  const { p, a } = curve
  const gf = GF(p)
  const cs = CoordinateSystem(gf)

  const { add, sub, mul, div } = gf
  const { toAffine } = cs

  const _addPoint = (A: AffinePoint, B: AffinePoint): AffinePoint<bigint> => {
    // O + P = P
    if (A.isInfinity)
      return toAffine(B, 'bigint')
    if (B.isInfinity)
      return toAffine(A, 'bigint')

    let [x1, y1] = [A.x, A.y]
    let [x2, y2] = [B.x, B.y]

    x1 = typeof x1 === 'bigint' ? x1 : U8.from(x1).toBI()
    y1 = typeof y1 === 'bigint' ? y1 : U8.from(y1).toBI()
    x2 = typeof x2 === 'bigint' ? x2 : U8.from(x2).toBI()
    y2 = typeof y2 === 'bigint' ? y2 : U8.from(y2).toBI()

    // P + (-P) = O
    if (sub(x1, x2) === 0n && add(y1, y2) === 0n)
      return { isInfinity: true, x: 0n, y: 0n }

    let λ = 0n
    // P1 + P2
    if (x1 !== x2) {
      // λ = (y2 - y1) / (x2 - x1)
      const numerator = sub(y2, y1)
      const denominator = sub(x2, x1)
      λ = div(numerator, denominator)
    }
    // P1 + P1
    else {
      // 若 y1 为 0，则切线斜率不存在，结果为无穷远点
      if (y1 === 0n)
        return { isInfinity: true, x: 0n, y: 0n }

      // λ = (3 * x1 * x1 + a) / 2 * y1
      const numerator = add(mul(3n, x1, x1), a)
      const denominator = mul(2n, y1)
      λ = div(numerator, denominator)
    }

    // x3 = λ * λ - x1 - x2
    const x3 = sub(mul(λ, λ), x1, x2)
    // y3 = λ * (x1 - x3) - y1
    const y3 = sub(mul(λ, sub(x1, x3)), y1)

    return { isInfinity: false, x: x3, y: y3 }
  }

  const addPoint = (A: JacobianPoint, B: JacobianPoint): JacobianPoint => {
    // O + P = P
    if (A.isInfinity)
      return B
    if (B.isInfinity)
      return A

    // P + (-P) = O
    if (sub(A.x, B.x) === 0n && add(A.y, B.y) === 0n)
      return { isInfinity: true, x: 1n, y: 1n, z: 0n }

    const U1 = mul(A.x, B.z, B.z)
    const U2 = mul(B.x, A.z, A.z)
    const S1 = mul(A.y, B.z, B.z, B.z)
    const S2 = mul(B.y, A.z, A.z, A.z)

    if (U1 === U2 && S1 !== S2)
      return { isInfinity: true, x: 1n, y: 1n, z: 0n }

    // P1 + P1
    if (U1 === U2 && S1 === S2) {
      const XX = mul(A.x, A.x)
      const YY = mul(A.y, A.y)
      const ZZ = mul(A.z, A.z)
      const S = mul(4n, A.x, YY)
      // M = 3 * XX + a * ZZ^2
      const M = add(
        mul(3n, XX),
        mul(a, ZZ, ZZ),
      )
      // X3 = M^2 - 2 * S
      const X3 = sub(
        mul(M, M),
        mul(2n, S),
      )
      // Y3 = M * (S - X3) - 8 * YYYY
      const Y3 = sub(
        mul(M, sub(S, X3)),
        mul(8n, YY, YY),
      )
      // Z3 = 2 * Y1 * Z1
      const Z3 = mul(2n, A.y, A.z)

      return { isInfinity: false, x: X3, y: Y3, z: Z3 }
    }
    // P1 + P2
    else {
      const H = sub(U2, U1)
      const R = sub(S2, S1)
      const HH = mul(H, H)
      const HHH = mul(H, HH)
      const U1HH = mul(U1, HH)
      // X3 = R^2 - H^3 - 2 * U1 * H^2
      const X3 = sub(
        mul(R, R),
        HHH,
        mul(2n, U1HH),
      )
      // Y3 = R * (U1 * H^2 - X3) - S1 * H^3
      const Y3 = sub(
        mul(R, sub(U1HH, X3)),
        mul(S1, HHH),
      )
      // Z3 = H * Z1 * Z2
      const Z3 = mul(H, A.z, B.z)

      return { isInfinity: false, x: X3, y: Y3, z: Z3 }
    }
  }

  const mulPoint = (P: JacobianPoint, k: bigint | Uint8Array): JacobianPoint => LadderMultiply(addPoint, P, k)

  return {
    gf,
    addPoint,
    mulPoint,
    _addPoint,
    ...cs,
  }
}

/**
 * 素域 Montgomery 椭圆曲线运算
 *
 * Prime Field Montgomery Elliptic Curve Operations
 */
export function FpMEC(curve: FpMECParams): ECUtils {
  const { p, a, b } = curve
  const gf = GF(p)
  const cs = CoordinateSystem(gf)

  const { add, sub, mul, div } = gf
  const { toAffine } = cs

  const _addPoint = (A: AffinePoint, B: AffinePoint): AffinePoint<bigint> => {
    // O + P = P
    if (A.isInfinity)
      return toAffine(B, 'bigint')
    if (B.isInfinity)
      return toAffine(A, 'bigint')

    let [x1, y1] = [A.x, A.y]
    let [x2, y2] = [B.x, B.y]

    x1 = typeof x1 === 'bigint' ? x1 : U8.from(x1).toBI()
    y1 = typeof y1 === 'bigint' ? y1 : U8.from(y1).toBI()
    x2 = typeof x2 === 'bigint' ? x2 : U8.from(x2).toBI()
    y2 = typeof y2 === 'bigint' ? y2 : U8.from(y2).toBI()

    // P + (-P) = O
    if (sub(x1, x2) === 0n && add(y1, y2) === 0n)
      return { isInfinity: true, x: 0n, y: 0n }

    let λ = 0n
    // P1 + P2
    if (x1 !== x2) {
      // λ = (y2 - y1) / (x2 - x1)
      const numerator = sub(y2, y1)
      const denominator = sub(x2, x1)
      λ = div(numerator, denominator)
    }
    // P1 + P1
    else {
      // 若 y1 为 0，则切线斜率不存在，结果为无穷远点
      if (y1 === 0n)
        return { isInfinity: true, x: 0n, y: 0n }

      // λ = (3 * x1 * x1 + 2 * a * x1 + 1) / 2 * b * y1
      const numerator = add(mul(3n, x1, x1), mul(2n, a, x1), 1n)
      const denominator = mul(2n, b, y1)
      λ = div(numerator, denominator)
    }

    // x3 = b * λ * λ - a - x1 - x2
    const x3 = sub(mul(λ, λ, b), a, x1, x2)
    // y3 = (2 x1 + x2 + a) * λ - b * λ * λ * λ - y1
    const y3 = sub(mul(2n * x1 + x2 + a, λ), mul(λ, λ, λ, b), y1)

    return { isInfinity: false, x: x3, y: y3 }
  }

  const addPoint = (A: JacobianPoint, B: JacobianPoint): JacobianPoint => {
    // O + P = P
    if (A.isInfinity)
      return B
    if (B.isInfinity)
      return A

    const X1 = A.x
    const Y1 = A.y
    const Z1 = A.z
    const X2 = B.x
    const Y2 = B.y
    const Z2 = B.z
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
      return { isInfinity: true, x: 1n, y: 1n, z: 0n }

    // P1 + P1
    if (H === 0n && R === 0n) {
      // 若 Y1 为 0，则切线斜率不存在，结果为无穷远点
      if (Y1 === 0n)
        return { isInfinity: true, x: 1n, y: 1n, z: 0n }

      const ZZ = ZZ1
      const Z4 = mul(ZZ, ZZ)
      const XX = mul(X1, X1)
      // N = 3 * X1^2 + 2 * a * X1 * Z1^2 + Z1^4 (λ 的分子，已清除分母)
      const N = add(
        mul(3n, XX),
        mul(2n, a, X1, ZZ),
        Z4,
      )
      // Z3 = 2 * b * Y1 * Z1 = λ 的分母
      const Z3 = mul(2n, b, Y1, Z1)
      const YY = mul(Y1, Y1)

      // X3 = b * N^2 - a * Z3^2 - 8 * b^2 * X1 * Y1^2
      const X3 = sub(
        mul(b, N, N),
        mul(a, Z3, Z3),
        mul(8n, b, b, X1, YY),
      )
      // Y3 = 4 * b^2 * (3 * X1 + a * Z1^2) * N * Y1^2 - b * N^3 - 8 * b^3 * Y1^4
      const Y3 = sub(
        mul(4n, b, b, add(mul(3n, X1), mul(a, ZZ)), N, YY),
        mul(b, N, N, N),
        mul(8n, b, b, b, YY, YY),
      )
      return { isInfinity: false, x: X3, y: Y3, z: Z3 }
    }
    // P1 + P2
    else {
      const HH = mul(H, H) // HH = H^2
      const X3 = sub(
        mul(b, R, R),
        mul(a, ZZ1, ZZ2, HH),
        mul(add(U1, U2), HH),
      )
      const Y3 = sub(
        mul(R, sub(mul(U1, HH), X3)),
        mul(S1, HH, H),
      )
      const Z3 = mul(H, Z1, Z2)

      return { isInfinity: false, x: X3, y: Y3, z: Z3 }
    }
  }

  const mulPoint = (P: JacobianPoint, k: bigint | Uint8Array): JacobianPoint => LadderMultiply(addPoint, P, k)

  return {
    gf,
    _addPoint,
    addPoint,
    mulPoint,
    ...cs,
  }
}

/**
 * 素域 Twisted Edwards 椭圆曲线运算
 *
 * Prime Field Twisted Edwards Elliptic Curve Operations
 */
// eslint-disable-next-line unused-imports/no-unused-vars
export function FpTEC(curve: FpTECParams): ECUtils {
  // TODO
  return {} as any
}
