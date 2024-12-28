import type { FpECPoint, FpMECParams, FpTECParams, FpWECParams } from './ecParams'
import { mod, modInverse, modPrimeSquare } from './utils'

// * Interfaces

export interface FpUtils {
  /** 素域加法 / Prime Field Addition */
  plus: (...args: bigint[]) => bigint
  /** 素域乘法 / Prime Field Multiplication */
  multiply: (...args: bigint[]) => bigint
  /** 素域减法 / Prime Field Subtraction */
  subtract: (a: bigint, ...args: bigint[]) => bigint
  /** 素域除法 / Prime Field Division */
  divide: (a: bigint, b: bigint) => bigint
  /** 素域取模 / Prime Field Modulus */
  mod: (a: bigint) => bigint
  /** 素域逆元 / Prime Field Modular Inverse */
  inverse: (a: bigint) => bigint
  /** 素域平方根 / Prime Field Square Root */
  root: (a: bigint) => bigint
}

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
 * 素域运算 / Prime Field Operations
 */
export function Fp(p: bigint): FpUtils {
  const _mod = (a: bigint) => mod(a, p)
  const inverse = (a: bigint) => modInverse(a, p)
  const root = (a: bigint) => modPrimeSquare(a, p)

  const plus = (...args: bigint[]) => args.reduce((acc, cur) => _mod(acc + cur))
  const multiply = (...args: bigint[]) => args.reduce((acc, cur) => _mod(acc * cur))
  const subtract = (a: bigint, ...args: bigint[]) => {
    const b: bigint[] = args.map(v => _mod(p - v))
    return plus(a, ...b)
  }
  const divide = (a: bigint, b: bigint) => multiply(a, inverse(b))
  return {
    plus,
    multiply,
    subtract,
    divide,
    mod: _mod,
    inverse,
    root,
  }
}

/**
 * 素域椭圆曲线运算
 *
 * Prime Field Elliptic Curve Operations
 */
export function FpEC(curve: FpWECParams | FpMECParams | FpTECParams): FpECUtils {
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
export function FpWEC(curve: FpWECParams): FpECUtils {
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

/**
 * 素域 Montgomery 椭圆曲线运算
 *
 * Prime Field Montgomery Elliptic Curve Operations
 */
export function FpMEC(curve: FpMECParams): FpECUtils {
  const { p, a, b } = curve
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

    // P1 + P2
    if (x1 !== x2) {
      const l = divide(subtract(y2, y1), subtract(x2, x1))
      // x3 = b * l^2 - a - x1 - x2
      const x3 = subtract(multiply(l, l, b), a, x1, x2)
      // y3 = (2x1 + x2 + a)l - b * l^3 - y1
      const y3 = subtract(multiply(2n * x1 + x2 + a, l), multiply(l, l, l, b), y1)
      return { x: x3, y: y3 }
    }
    // P1 + P1
    else {
      // l = (3x^2 + 2ax + 1) / 2by
      const l_numerator = plus(multiply(3n, x1, x1), multiply(2n, a, x1), 1n)
      const l_denominator = multiply(2n, b, y1)
      const l = divide(l_numerator, l_denominator)
      // x3 = b * l^2 - a - 2x
      const x3 = subtract(multiply(l, l, b), a, x1 << 1n)
      // y3 = (2x + x + a)l - b * l^3 - y
      const y3 = subtract(multiply(x1 * 3n + a, l), multiply(b, l, l, l), y1)
      return { x: x3, y: y3 }
    }
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

/**
 * 素域 Twisted Edwards 椭圆曲线运算
 *
 * Prime Field Twisted Edwards Elliptic Curve Operations
 */
// eslint-disable-next-line unused-imports/no-unused-vars
export function FpTEC(curve: FpTECParams): FpECUtils {
  // TODO
  return {} as any
}
