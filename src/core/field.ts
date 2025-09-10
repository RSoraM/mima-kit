import { KitError, mod, modInverse, modPow, modPrimeSquareRoot, U8 } from './utils'

// * Interfaces

/**
 * 伽罗瓦域运算接口
 *
 * Galois Field Operations Interface
 */
export interface GFUtils {
  add: (...args: bigint[]) => bigint
  sub: (a: bigint, ...args: bigint[]) => bigint
  mul: (...args: bigint[]) => bigint
  div: (a: bigint, b: bigint) => bigint
  mod: (a: bigint) => bigint
  inv: (a: bigint) => bigint
  pow: (a: bigint, b: bigint) => bigint
  squ: (a: bigint) => bigint
  root: (a: bigint) => bigint
}

/**
 * 仿射坐标系的点
 *
 * Affine Coordinate Point
 */
export interface AffinePoint<T = bigint | Uint8Array> {
  isInfinity: boolean
  x: T
  y: T
}

/**
 * 雅可比坐标系的点
 *
 * Jacobian Coordinate Point
 */
export interface JacobianPoint {
  isInfinity: boolean
  x: bigint
  y: bigint
  z: bigint
}

/**
 * 坐标系转换接口
 *
 * Coordinate System Conversion Interface
 */
export interface CSUtils {
  /**
   * 雅可比坐标系 -> 仿射坐标系
   *
   * Jacobian Coordinate System to Affine Coordinate System
   */
  toAffine: {
    (P: JacobianPoint, format?: 'bigint'): AffinePoint<bigint>
    (P: JacobianPoint, format: 'u8', byte?: number): AffinePoint<U8>
    (P: AffinePoint, format?: 'bigint'): AffinePoint<bigint>
    (P: AffinePoint, format: 'u8', byte?: number): AffinePoint<U8>
    (P: undefined, format?: 'bigint'): AffinePoint<bigint>
    (P: undefined, format: 'u8', byte?: number): AffinePoint<U8>
  }
  /**
   * 仿射坐标系 -> 雅可比坐标系 (bigint)
   *
   * Affine Coordinate System to Jacobian Coordinate System (bigint)
   */
  toJacobian: {
    (P: JacobianPoint): JacobianPoint
    (P: AffinePoint): JacobianPoint
    (P: undefined): JacobianPoint
  }
}

// * Galois Field

/**
 * 伽罗瓦素域
 *
 * Galois Field of prime order
 *
 * @param {bigint} p - 素数 / prime number
 */
export function GF(p: bigint): GFUtils {
  const _mod = (a: bigint) => mod(a, p)

  // 乘法逆元
  const inv = (a: bigint) => modInverse(a, p)

  // 指数运算
  const pow = (a: bigint, b: bigint) => modPow(a, b, p)

  // 模素平方根
  const root = (a: bigint) => modPrimeSquareRoot(a, p)

  // 素域加法
  const add = (...args: bigint[]) => args.reduce((acc, cur) => _mod(acc + cur))

  // 素域减法
  const sub = (a: bigint, ...args: bigint[]) => {
    const b: bigint[] = args.map(v => _mod(p - v))
    return add(a, ...b)
  }

  // 素域乘法
  const mul = (...args: bigint[]) => args.reduce((acc, cur) => _mod(acc * cur))

  // 素域除法
  const div = (a: bigint, b: bigint) => mul(a, inv(b))

  // 素域平方
  const squ = (a: bigint) => _mod(a * a)

  return {
    add,
    sub,
    mul,
    div,
    mod: _mod,
    inv,
    pow,
    squ,
    root,
  }
}

/**
 * 二进制域
 *
 * Binary Field
 *
 * @param {number} m - 次数 / degree
 * @param {bigint} IP - 不可约多项式 / irreducible polynomial
 */
export function GF2(m: bigint, IP: bigint): GFUtils {
  const mask = (1n << m) - 1n
  const topBit = 1n << m

  // 要求 IP 最高项为 x^m
  if ((IP & topBit) === 0n)
    throw new KitError('Irreducible polynomial IP must have degree m (set bit at x^m)')

  // 约化：按 IP 做多项式模约化
  function reduce(a: bigint): bigint {
    let r = a
    const deg_b = bitLength(IP) - 1
    // r >> m 快速判断是否仍有高于 m 的项
    while ((r >> m) !== 0n) {
      const shift = bitLength(r) - deg_b - 1
      r ^= (IP << BigInt(shift))
    }
    return r & mask
  }

  // 多项式加法与减法: a + b mod 2 = a ^ b
  const add = (...args: bigint[]) => args.reduce((acc, cur) => acc ^ cur) & mask
  const sub = add

  // 多项式乘法: 俄罗斯乘法 + 单步约化
  const mul = (a: bigint, b: bigint): bigint => {
    let result = 0n
    let a_val = a & mask
    let b_val = b & mask
    const highBit = 1n << (m - 1n)

    while (b_val) {
      if (b_val & 1n)
        result ^= a_val
      b_val >>= 1n

      const carry = (a_val & highBit) !== 0n
      a_val = (a_val << 1n) & mask
      if (carry)
        a_val ^= (IP & mask) // 用 IP 去掉 x^m 项的约化
    }

    return result & mask
  }

  // 专用平方: 每个比特 i -> 2i，然后约化
  const squ = (a: bigint): bigint => {
    let x = a & mask
    let r = 0n
    let i = 0n
    while (x) {
      if (x & 1n)
        r ^= (1n << (2n * i))
      x >>= 1n
      i += 1n
    }
    return reduce(r)
  }

  // Itoh–Tsujii 逆元: a^(2^m-2) = ∏_{i=1}^{m-1} a^{2^i}
  const inv = (a: bigint): bigint => {
    a &= mask
    if (a === 0n)
      throw new KitError('Division by zero')
    let acc = 1n
    let t = a
    for (let i = 1; i <= Number(m) - 1; i++) {
      t = squ(t)       // t = a^{2^i}
      acc = mul(acc, t)
    }
    return acc & mask  // acc = a^{2^m-2}
  }

  // 多项式除法: a / b = a * inv(b)
  const div = (a: bigint, b: bigint): bigint => mul(a, inv(b))

  // 幂运算: 针对 2 的幂优化，否则通用平方-乘
  const pow = (a: bigint, b: bigint): bigint => {
    if (b === 0n)
      return 1n
    if (b < 0n)
      return inv(pow(a, -b))

    // 如果 b 是 2 的幂，只需重复平方
    if ((b & (b - 1n)) === 0n) {
      let r = a & mask
      let e = b
      while (e > 1n) {
        r = squ(r)
        e >>= 1n
      }
      return r
    }

    // 通用：平方-乘
    let result = 1n
    let base = a & mask
    let exp = b
    while (exp > 0n) {
      if (exp & 1n)
        result = mul(result, base)
      base = mul(base, base)
      exp >>= 1n
    }
    return result & mask
  }

  // 平方根：重复平方 m-1 次 (a -> a^{2^(m-1)})
  const root = (a: bigint): bigint => {
    let r = a & mask
    const end = Number(m) - 1
    for (let i = 0; i < end; i++) {
      r = squ(r)
    }
    return r
  }

  // 辅助：bit 长度
  function bitLength(n: bigint): number {
    if (n === 0n)
      return 0
    return n.toString(2).length
  }

  const mod = (a: bigint) => reduce(a & (mask | topBit))

  return {
    add,
    sub,
    mul,
    div,
    mod,
    inv,
    pow,
    squ,
    root,
  }
}

// * Coordinate Systems

export function CoordinateSystem(gf: GFUtils): CSUtils {
  const { mul, inv, mod } = gf

  const isJacobian = (P: JacobianPoint | AffinePoint): P is JacobianPoint => {
    return 'z' in P
  }
  const toBI = (value: Uint8Array | bigint): bigint => {
    return typeof value === 'bigint' ? value : U8.from(value).toBI()
  }
  const toU8 = (value: Uint8Array | bigint, byte?: number): U8 => {
    return typeof value === 'bigint' ? U8.fromBI(value, byte) : U8.from(value)
  }

  function toAffine(
    P?: JacobianPoint | AffinePoint,
    format: 'bigint' | 'u8' = 'bigint',
    byte?: number,
  ) {
    if (!P || P.isInfinity) {
      return format === 'bigint'
        ? { isInfinity: true, x: 0n, y: 0n }
        : { isInfinity: true, x: new U8(), y: new U8() }
    }

    if (!isJacobian(P)) {
      return {
        isInfinity: false,
        x: format === 'bigint' ? toBI(P.x) : toU8(P.x, byte),
        y: format === 'bigint' ? toBI(P.y) : toU8(P.y, byte),
      }
    }

    if (P.z === 0n)
      return { isInfinity: true, x: 0n, y: 0n }

    if (P.z === 1n)
      return { isInfinity: false, x: mod(P.x), y: mod(P.y) }

    const z_inv = inv(P.z)
    const z_inv2 = mul(z_inv, z_inv)
    const z_inv3 = mul(z_inv2, z_inv)
    const x = mul(P.x, z_inv2)
    const y = mul(P.y, z_inv3)

    return {
      isInfinity: false,
      x: format === 'bigint' ? x : toU8(x, byte),
      y: format === 'bigint' ? y : toU8(y, byte),
    }
  }

  function toJacobian(
    P?: JacobianPoint | AffinePoint,
  ) {
    if (!P || P.isInfinity)
      return { isInfinity: true, x: 1n, y: 1n, z: 0n }

    if (isJacobian(P))
      return P

    return {
      isInfinity: false,
      x: toBI(P.x),
      y: toBI(P.y),
      z: 1n,
    }
  }

  return {
    toAffine: toAffine as CSUtils['toAffine'],
    toJacobian: toJacobian as CSUtils['toJacobian'],
  }
}
