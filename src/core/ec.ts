import type { FbKECParams, FbPECParams, FpMECParams, FpTECParams, FpWECParams } from './ecParams'
import type { AffinePoint, CSUtils, GFUtils, JacobianPoint, LDPoint } from './field'
import { CoordinateSystem, GF, GF2 } from './field'
import { U8 } from './utils'

// * Interfaces

export interface ECUtils<P = JacobianPoint> extends CSUtils {
  /**
   * 域运算
   *
   * Field Operations
   */
  gf: GFUtils
  /**
   * 素域椭圆曲线点加法
   *
   * Prime Field Elliptic Curve Point Addition
   */
  addPoint: (A: P, B: P) => P
  /**
   * 素域椭圆曲线点乘法
   *
   * Prime Field Elliptic Curve Point Multiplication
   */
  mulPoint: (P: P, k: bigint | Uint8Array) => P
  /**
   * 素域椭圆曲线点加法 (仿射坐标系)
   *
   * Prime Field Elliptic Curve Point Addition (Affine Coordinate System)
   *
   * @deprecated 仅作参考，不推荐使用 / For reference only, not recommended for use
   */
  _addPoint: (A: AffinePoint, B: AffinePoint) => AffinePoint<bigint>
  /**
   * 素域椭圆曲线点乘法 (仿射坐标系)
   *
   * Prime Field Elliptic Curve Point Multiplication (Affine Coordinate System)
   *
   * @deprecated 仅作参考，不推荐使用 / For reference only, not recommended for use
   */
  _mulPoint: (P: AffinePoint, k: bigint | Uint8Array) => AffinePoint<bigint>
}

// * FpEC Components

function LadderMultiply(add: ECUtils<JacobianPoint>['addPoint'], P: JacobianPoint, k: bigint | Uint8Array): JacobianPoint
function LadderMultiply(add: ECUtils<AffinePoint>['addPoint'], P: AffinePoint<bigint>, k: bigint | Uint8Array,): AffinePoint<bigint>
function LadderMultiply(add: ECUtils<LDPoint>['addPoint'], P: LDPoint, k: bigint | Uint8Array,): LDPoint
function LadderMultiply(
  add: ECUtils<any>['addPoint'],
  P: JacobianPoint | LDPoint | AffinePoint,
  k: bigint | Uint8Array,
) {
  k = typeof k === 'bigint' ? k : U8.from(k).toBI()

  let R0
  let R1
  if ('z' in P) {
    R0 = P.type === 'jacobian'
      ? { type: 'jacobian', isInfinity: true, x: 1n, y: 1n, z: 0n }
      : { type: 'ld', isInfinity: true, x: 1n, y: 1n, z: 0n }
    R1 = P.type === 'jacobian'
      ? { type: 'jacobian', isInfinity: P.isInfinity, x: P.x, y: P.y, z: P.z }
      : { type: 'ld', isInfinity: P.isInfinity, x: P.x, y: P.y, z: P.z }
  }
  else {
    R0 = { isInfinity: true, x: 0n, y: 0n }
    R1 = { isInfinity: P.isInfinity, x: P.x, y: P.y }
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

    const { x: X1, y: Y1 } = toAffine(A)
    const { x: X2, y: Y2 } = toAffine(B)

    const U = sub(X1, X2) === 0n

    // P + (-P) = O
    if (U && add(Y1, Y2) === 0n)
      return { isInfinity: true, x: 0n, y: 0n }
    if (U && Y1 === 0n)
      return { isInfinity: true, x: 0n, y: 0n }

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

    return { isInfinity: false, x: x3, y: y3 }
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

  const _mulPoint = (P: AffinePoint, k: bigint | Uint8Array): AffinePoint<bigint> => LadderMultiply(_addPoint, toAffine(P), k)

  const mulPoint = (P: JacobianPoint, k: bigint | Uint8Array): JacobianPoint => LadderMultiply(addPoint, P, k)

  return {
    gf,
    addPoint,
    mulPoint,
    _addPoint,
    _mulPoint,
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

    const { x: X1, y: Y1 } = toAffine(A)
    const { x: X2, y: Y2 } = toAffine(B)

    const U = sub(X1, X2) === 0n

    // P + (-P) = O
    if (U && add(Y1, Y2) === 0n)
      return { isInfinity: true, x: 0n, y: 0n }
    if (U && Y1 === 0n)
      return { isInfinity: true, x: 0n, y: 0n }

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

    return { isInfinity: false, x: X3, y: Y3 }
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

  const _mulPoint = (P: AffinePoint, k: bigint | Uint8Array): AffinePoint<bigint> => LadderMultiply(_addPoint, toAffine(P), k)

  const mulPoint = (P: JacobianPoint, k: bigint | Uint8Array): JacobianPoint => LadderMultiply(addPoint, P, k)

  return {
    gf,
    addPoint,
    mulPoint,
    _addPoint,
    _mulPoint,
    ...cs,
  }
}

/**
 * 素域 Twisted Edwards 椭圆曲线运算
 *
 * Prime Field Twisted Edwards Elliptic Curve Operations
 */
export function FpTEC(curve: FpTECParams): ECUtils {
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

    const { x: X1, y: Y1 } = toAffine(A)
    const { x: X2, y: Y2 } = toAffine(B)

    // P + (-P) = O
    if (sub(X1, X2) === 0n && add(Y1, Y2) === 0n)
      return { isInfinity: true, x: 0n, y: 0n }

    // Twisted Edwards 点加法公式:
    // x3 = (x1*y2 + y1*x2) / (1 + d*x1*x2*y1*y2)
    // y3 = (y1*y2 - a*x1*x2) / (1 - d*x1*x2*y1*y2)
    const x1y2 = mul(X1, Y2)
    const y1x2 = mul(Y1, X2)
    const x1x2 = mul(X1, X2)
    const y1y2 = mul(Y1, Y2)
    const dx1x2y1y2 = mul(b, x1x2, y1y2)

    const denominator1 = add(1n, dx1x2y1y2)
    const denominator2 = sub(1n, dx1x2y1y2)

    // 如果分母为零，则结果为无穷远点
    if (denominator1 === 0n || denominator2 === 0n)
      return { isInfinity: true, x: 0n, y: 0n }

    const x3 = div(add(x1y2, y1x2), denominator1)
    const y3 = div(sub(y1y2, mul(a, x1x2)), denominator2)

    return { isInfinity: false, x: x3, y: y3 }
  }

  const addPoint = (A: JacobianPoint, B: JacobianPoint): JacobianPoint => {
    // 转换为仿射坐标进行加法，然后再转回雅可比坐标
    // 注意：这种方法效率较低，但为了简单起见先这样实现
    const affA = toAffine(A, 'bigint')
    const affB = toAffine(B, 'bigint')
    const affResult = _addPoint(affA, affB)

    if (affResult.isInfinity)
      return { type: 'jacobian', isInfinity: true, x: 1n, y: 1n, z: 0n }

    return cs.toJacobian(affResult)
  }

  const _mulPoint = (P: AffinePoint, k: bigint | Uint8Array): AffinePoint<bigint> => LadderMultiply(_addPoint, toAffine(P), k)

  const mulPoint = (P: JacobianPoint, k: bigint | Uint8Array): JacobianPoint => LadderMultiply(addPoint, P, k)

  return {
    gf,
    addPoint,
    mulPoint,
    _addPoint,
    _mulPoint,
    ...cs,
  }
}

// * FbEC Components

/**
 * 二进制域椭圆曲线运算
 *
 * Binary Field Elliptic Curve Operations
 */
export function FbEC(curve: FbKECParams | FbPECParams): ECUtils<LDPoint> {
  const { m, IP, a, b } = curve
  const gf = GF2(m, IP)
  const cs = CoordinateSystem(gf)

  const { add, sub, mul, div, squ } = gf
  const { toAffine } = cs

  const _addPoint = (A: AffinePoint, B: AffinePoint): AffinePoint<bigint> => {
    // O + P = P
    if (A.isInfinity)
      return toAffine(B, 'bigint')
    if (B.isInfinity)
      return toAffine(A, 'bigint')

    const { x: X1, y: Y1 } = toAffine(A)
    const { x: X2, y: Y2 } = toAffine(B)

    // P + (-P) = O
    const T = sub(X1, X2) === 0n
    if (T && add(X1, Y2) === Y1)
      return { isInfinity: true, x: 0n, y: 0n }
    if (T && X1 === 0n)
      // 若 x1 为 0，则切线斜率不存在，结果为无穷远点
      return { isInfinity: true, x: 0n, y: 0n }

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

    return { isInfinity: false, x: x3, y: y3 }
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

  const _mulPoint = (P: AffinePoint, k: bigint | Uint8Array): AffinePoint<bigint> => LadderMultiply(_addPoint, toAffine(P), k)

  const mulPoint = (P: LDPoint, k: bigint | Uint8Array): LDPoint => LadderMultiply(addPoint, P, k)

  return {
    gf,
    addPoint,
    mulPoint,
    _addPoint,
    _mulPoint,
    ...cs,
  }
}
