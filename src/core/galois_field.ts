import { getBIBits, KitError, mod, modInverse, modPow, modPrimeSquareRoot } from './utils'

// * Interfaces

/**
 * 伽罗瓦域运算接口
 *
 * Galois Field Operations Interface
 */
export interface GFUtils {
  include: (a: bigint) => boolean
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

  // 辅助：是否在域内
  const include = (a: bigint) => a >= 0n && a < p

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
    include,
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
  /** m - 1 */
  const m_1 = Number(m - 1n)
  /** 2^n */
  const p_n = 1n << m
  /** 2^n - 1 */
  const mask = p_n - 1n

  // 要求 IP 最高项为 x^m
  if ((IP & p_n) === 0n)
    throw new KitError('Irreducible polynomial IP must have degree m (set bit at x^m)')

  // 约化：按 IP 做多项式模约化
  function reduce(a: bigint): bigint {
    let r = a
    const deg_b = getBIBits(IP) - 1
    // r >> m 快速判断是否仍有高于 m 的项
    while ((r >> m) !== 0n) {
      const shift = getBIBits(r) - deg_b - 1
      r ^= (IP << BigInt(shift))
    }
    return r & mask
  }

  // 多项式加法与减法: a + b mod 2 = a ^ b
  const add = (...args: bigint[]) => args.reduce((acc, cur) => acc ^ cur) & mask
  const sub = add

  // 多项式乘法: 俄罗斯乘法 + 单步约化
  const _mul = (a: bigint, b: bigint): bigint => {
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
  const mul = (...args: bigint[]) => args.reduce((acc, cur) => _mul(acc, cur))

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
    for (let i = 1; i <= m_1; i++) {
      t = squ(t)       // t = a^{2^i}
      acc = _mul(acc, t)
    }
    return acc & mask  // acc = a^{2^m-2}
  }

  // 多项式除法: a / b = a * inv(b)
  const div = (a: bigint, b: bigint): bigint => _mul(a, inv(b))

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
        result = _mul(result, base)
      base = _mul(base, base)
      exp >>= 1n
    }
    return result & mask
  }

  // 平方根：重复平方 m-1 次 (a -> a^{2^(m-1)})
  const root = (a: bigint): bigint => {
    let r = a & mask
    const end = m_1
    for (let i = 0; i < end; i++) {
      r = squ(r)
    }
    return r
  }

  // 辅助：是否在域内
  function include(a: bigint): boolean {
    return a >= 0n && a < mask
  }

  const mod = (a: bigint) => reduce(a & (mask | p_n))

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
    include,
  }
}
