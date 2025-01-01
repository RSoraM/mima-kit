import type { FpECPoint, FpMECParams, FpTECParams, FpWECParams } from './ecParams'
import { U8, mod, modInverse, modPow, modPrimeSquare } from './utils'

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
  /** 素域幂运算 / Prime Field Power */
  pow: (a: bigint, b: bigint) => bigint
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
  addPoint: (A: FpECPoint, B: FpECPoint) => FpECPoint<bigint>
  /**
   * 素域椭圆曲线点乘法
   *
   * Prime Field Elliptic Curve Point Multiplication
   */
  mulPoint: (P: FpECPoint, k: bigint | Uint8Array) => FpECPoint<bigint>
}

// * FpEC Components

/** 素域运算 / Prime Field Operations */
export function Fp(p: bigint): FpUtils {
  const _mod = (a: bigint) => mod(a, p)
  const inverse = (a: bigint) => modInverse(a, p)
  const root = (a: bigint) => modPrimeSquare(a, p)
  const pow = (a: bigint, b: bigint) => modPow(a, b, p)

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
    pow,
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

  const addPoint = (A: FpECPoint, B: FpECPoint): FpECPoint<bigint> => {
    let [x1, y1] = [A.x, A.y]
    let [x2, y2] = [B.x, B.y]

    x1 = typeof x1 === 'bigint' ? x1 : U8.from(x1).toBI()
    y1 = typeof y1 === 'bigint' ? y1 : U8.from(y1).toBI()
    x2 = typeof x2 === 'bigint' ? x2 : U8.from(x2).toBI()
    y2 = typeof y2 === 'bigint' ? y2 : U8.from(y2).toBI()

    // O + P = P
    if (A.isInfinity) {
      const isInfinity = B.isInfinity
      return { isInfinity, x: x2, y: y2 }
    }
    if (B.isInfinity) {
      const isInfinity = A.isInfinity
      return { isInfinity, x: x1, y: y1 }
    }

    // P + (-P) = O
    if (x1 === x2 && y1 !== y2) {
      return { isInfinity: true, x: 0n, y: 0n }
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

    return { isInfinity: false, x: x3, y: y3 }
  }
  const mulPoint = (P: FpECPoint, k: bigint | Uint8Array): FpECPoint<bigint> => {
    k = typeof k === 'bigint' ? k : U8.from(k).toBI()
    if (k === 0n) {
      return { isInfinity: true, x: 0n, y: 0n }
    }
    else if (k === 1n) {
      const isInfinity = P.isInfinity
      const x = typeof P.x === 'bigint' ? P.x : U8.from(P.x).toBI()
      const y = typeof P.y === 'bigint' ? P.y : U8.from(P.y).toBI()
      return { isInfinity, x, y }
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

  // TODO 蒙哥马利梯子优化
  const addPoint = (A: FpECPoint, B: FpECPoint): FpECPoint<bigint> => {
    let [x1, y1] = [A.x, A.y]
    let [x2, y2] = [B.x, B.y]

    x1 = typeof x1 === 'bigint' ? x1 : U8.from(x1).toBI()
    y1 = typeof y1 === 'bigint' ? y1 : U8.from(y1).toBI()
    x2 = typeof x2 === 'bigint' ? x2 : U8.from(x2).toBI()
    y2 = typeof y2 === 'bigint' ? y2 : U8.from(y2).toBI()

    // O + P = P
    if (A.isInfinity) {
      const isInfinity = B.isInfinity
      return { isInfinity, x: x2, y: y2 }
    }
    if (B.isInfinity) {
      const isInfinity = A.isInfinity
      return { isInfinity, x: x1, y: y1 }
    }

    // P + (-P) = O
    if (x1 === x2 && y1 !== y2) {
      return { isInfinity: true, x: 0n, y: 0n }
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
      // λ = (3 * x1 * x1 + 2 * a * x1 + 1) / 2 * b * y1
      const numerator = plus(multiply(3n, x1, x1), multiply(2n, a, x1), 1n)
      const denominator = multiply(2n, b, y1)
      λ = divide(numerator, denominator)
    }

    // x3 = b * λ * λ - a - x1 - x2
    const x3 = subtract(multiply(λ, λ, b), a, x1, x2)
    // y3 = (2 x1 + x2 + a) * λ - b * λ * λ * λ - y1
    const y3 = subtract(multiply(2n * x1 + x2 + a, λ), multiply(λ, λ, λ, b), y1)
    return { isInfinity: false, x: x3, y: y3 }
  }
  const mulPoint = (P: FpECPoint, k: bigint | Uint8Array): FpECPoint<bigint> => {
    k = typeof k === 'bigint' ? k : U8.from(k).toBI()
    if (k === 0n) {
      return { isInfinity: true, x: 0n, y: 0n }
    }
    else if (k === 1n) {
      const isInfinity = P.isInfinity
      const x = typeof P.x === 'bigint' ? P.x : U8.from(P.x).toBI()
      const y = typeof P.y === 'bigint' ? P.y : U8.from(P.y).toBI()
      return { isInfinity, x, y }
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
