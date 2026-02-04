import { KitError, mod, modInverse, modPow, modPrimeSquareRoot } from './utils';

// * Interfaces

/**
 * 伽罗瓦域运算接口
 *
 * Galois Field Operations Interface
 */
export interface GFUtils {
  include: (a: bigint) => boolean;
  add: (...args: bigint[]) => bigint;
  sub: (a: bigint, ...args: bigint[]) => bigint;
  mul: (...args: bigint[]) => bigint;
  div: (a: bigint, b: bigint) => bigint;
  mod: (a: bigint) => bigint;
  inv: (a: bigint) => bigint;
  pow: (a: bigint, b: bigint) => bigint;
  squ: (a: bigint) => bigint;
  root: (a: bigint) => bigint;
}

// * Galois Field

/**
 * 素域
 *
 * Prime Field
 *
 * @param {bigint} p - 素数 / prime number
 */
export function GF(p: bigint): GFUtils {
  const _mod = (a: bigint) => mod(a, p);

  // 乘法逆元
  const inv = (a: bigint) => modInverse(a, p);

  // 指数运算
  const pow = (a: bigint, b: bigint) => modPow(a, b, p);

  // 模素平方根
  const root = (a: bigint) => modPrimeSquareRoot(a, p);

  // 素域加法
  const add = (...args: bigint[]) => args.reduce((acc, cur) => _mod(acc + cur));

  // 素域减法
  const sub = (a: bigint, ...args: bigint[]) => {
    const b: bigint[] = args.map((v) => _mod(p - v));
    return add(a, ...b);
  };

  // 素域乘法
  const mul = (...args: bigint[]) => args.reduce((acc, cur) => _mod(acc * cur));

  // 素域除法
  const div = (a: bigint, b: bigint) => mul(a, inv(b));

  // 素域平方
  const squ = (a: bigint) => _mod(a * a);

  // 辅助：是否在域内
  const include = (a: bigint) => a >= 0n && a < p;

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
  };
}

/**
 * 二元扩域
 *
 * Binary Field
 *
 * @param {number} m - 次数 / degree
 * @param {bigint} IP - 不可约多项式 / irreducible polynomial
 */
export function GF2(m: bigint, IP: bigint): GFUtils {
  /** m - 1 */
  const m_1 = Number(m - 1n);
  /** 2^m */
  const m_h = 1n << m;
  /** 2^n - 1 */
  const mask = m_h - 1n;

  // 要求 IP 最高项为 x^m
  if ((IP & m_h) === 0n) throw new KitError('Irreducible polynomial must have degree m (set bit at x^m)');

  // 多项式加法与减法: a + b mod 2 = a ^ b
  const add = (...args: bigint[]) => args.reduce((acc, cur) => acc ^ cur) & mask;
  const sub = add;

  // 约化: 按 IP 做多项式模约化
  function reduce(poly: bigint): bigint {
    let result = poly;
    const irreducible_degree = Number(m);

    // 计算多项式的最高位
    let poly_degree = result.toString(2).length - 1;

    // 当多项式度数 >= m 时进行约简
    while (poly_degree >= irreducible_degree) {
      const shift = poly_degree - irreducible_degree;
      // 将不可约多项式左移 shift 位后异或到结果中
      result ^= IP << BigInt(shift);

      // 更新多项式度数（优化：直接跳过连续的0）
      poly_degree = result.toString(2).length - 1;
    }

    return result;
  }

  // 乘法
  const _mul = (a: bigint, b: bigint): bigint => {
    if (a === 0n || b === 0n) return 0n;

    let result = 0n;
    let a_val = a & mask;
    let b_val = b & mask;
    const ipMask = IP & mask;

    // 使用更高效的位运算优化
    while (b_val) {
      // 使用位运算优化：检查最低位
      result ^= b_val & 1n ? a_val : 0n;
      b_val >>= 1n;

      // 优化进位处理
      if (a_val & (1n << (m - 1n))) {
        a_val = (a_val << 1n) & mask;
        a_val ^= ipMask;
      } else {
        a_val = (a_val << 1n) & mask;
      }
    }

    return result;
  };
  const mul = (...args: bigint[]) => args.reduce((acc, cur) => _mul(acc, cur));

  // 专用平方
  const squ = (a: bigint): bigint => {
    if (a === 0n) return 0n;
    if (a === 1n) return 1n;

    let r = 0n;
    for (let x = a & mask, i = 0n; x > 0n; x >>= 1n, i++) {
      if (x & 1n) r |= 1n << (2n * i);
    }

    return reduce(r);
  };

  // Itoh–Tsujii 逆元: a^(2^m-2) = ∏_{i=1}^{m-1} a^{2^i}
  const inv = (a: bigint): bigint => {
    a &= mask;
    if (a === 0n) throw new KitError('Division by zero');
    let acc = 1n;
    let t = a;
    for (let i = 1; i <= m_1; i++) {
      // t = a^{2^i}
      t = _mul(t, t);
      acc = _mul(acc, t);
    }

    // acc = a^{2^m-2}
    return acc & mask;
  };

  // 除法
  const div = (a: bigint, b: bigint): bigint => {
    a &= mask;
    b &= mask;
    if (b === 0n) throw new KitError('Division by zero');
    return mul(a, inv(b));
  };

  // 幂运算: 针对 2 的幂优化，否则通用平方-乘
  const pow = (a: bigint, b: bigint): bigint => {
    if (b === 0n) return 1n;
    if (a === 0n) return 0n;
    if (b < 0n) return inv(pow(a, -b));

    // 如果 b 是 2 的幂，只需重复平方
    if ((b & (b - 1n)) === 0n) {
      let r = a & mask;
      let e = b;
      while (e > 1n) {
        r = mul(r, r);
        e >>= 1n;
      }
      return r;
    }

    // 通用：平方-乘
    let result = 1n;
    let base = a & mask;
    let exp = b;
    while (exp > 0n) {
      if (exp & 1n) result = _mul(result, base);
      base = _mul(base, base);
      exp >>= 1n;
    }
    return result & mask;
  };

  // 平方根：重复平方 m-1 次 (a -> a^{2^(m-1)})
  const root = (a: bigint): bigint => pow(a, 1n << BigInt(m_1));

  // 辅助：是否在域内
  const include = (a: bigint): boolean => a >= 0n && a <= mask;

  const mod = (a: bigint) => reduce(a & (mask | m_h));

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
  };
}
