import type { FpECParams, FpECPoint } from './ecParams'
import { mod, modInverse } from './utils'

// * Interfaces

export interface FpECUtils {
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
}

// * FpEC Components

/**
 * 素域运算
 *
 * Prime Field Operations
 */
export function Fp(p: bigint) {
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
export function FpEC(curve: FpECParams): FpECUtils {
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
