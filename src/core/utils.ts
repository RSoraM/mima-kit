import type { Codec } from './codec'
import { UTF8 } from './codec'

// * Math utility functions

/** 8-bit 循环左移 */
export function rotateL8(x: number, n: number) {
  x &= 0xFF
  n %= 8
  x = (x << n) | (x >>> (8 - n))
  return x & 0xFF
}

/** 8-bit 循环右移 */
export function rotateR8(x: number, n: number) {
  x &= 0xFF
  n %= 8
  x = (x >>> n) | (x << (8 - n))
  return x & 0xFF
}

/** 16-bit 循环左移 */
export function rotateL16(x: number, n: number) {
  x &= 0xFFFF
  n %= 16
  x = (x << n) | (x >>> (16 - n))
  return x & 0xFFFF
}

/** 16-bit 循环右移 */
export function rotateR16(x: number, n: number) {
  x &= 0xFFFF
  n %= 16
  x = (x >>> n) | (x << (16 - n))
  return x & 0xFFFF
}

/** 32-bit 循环左移 */
export function rotateL32(x: number, n: number) {
  x >>>= 0
  n %= 32
  x = (x << n) | (x >>> (32 - n))
  return x >>> 0
}

/** 32-bit 循环右移 */
export function rotateR32(x: number, n: number) {
  x >>>= 0
  n %= 32
  x = (x >>> n) | (x << (32 - n))
  return x >>> 0
}

/** 64-bit 循环左移 */
export function rotateL64(x: bigint, n: bigint) {
  x &= 0xFFFFFFFFFFFFFFFFn
  n %= 64n
  x = (x << n) | (x >> (64n - n))
  return x & 0xFFFFFFFFFFFFFFFFn
}

/** 64-bit 循环右移 */
export function rotateR64(x: bigint, n: bigint) {
  x &= 0xFFFFFFFFFFFFFFFFn
  n %= 64n
  x = (x >> n) | (x << (64n - n))
  return x & 0xFFFFFFFFFFFFFFFFn
}

/** 128-bit 循环左移 */
export function rotateL128(x: bigint, n: bigint) {
  x &= 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFn
  n %= 128n
  x = (x << n) | (x >> (128n - n))
  return x & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFn
}

/** 128-bit 循环右移 */
export function rotateR128(x: bigint, n: bigint) {
  x &= 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFn
  n %= 128n
  x = (x >> n) | (x << (128n - n))
  return x & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFn
}

/**
 * 获取大整数的比特长度
 *
 * Get the bit length of a BigInt
 */
export function getBIBits(n: bigint) {
  let bytes = 0
  while (n > 0) {
    bytes++
    n >>= 1n
  }
  return bytes
}

/**
 * 生成随机大整数
 *
 * Generate Random BigInt
 */
export function genRandomBI(max: bigint, byte: number = 0): bigint {
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
  const buffer = new U8(byte)
  do {
    crypto.getRandomValues(buffer)
    result = buffer.toBI()
  } while (result >= max)

  return result
}

/**
 * 扩展欧几里得算法
 *
 * Extended Euclidean Algorithm
 *
 * - gcd: 最大公约数 / greatest common divisor
 * - a_inv: a 的模逆 / modular inverse of a
 * - b_inv: b 的模逆 / modular inverse of b
 */
function extendedEuclidean(a: bigint, b: bigint) {
  let [s0, s1, t0, t1, r0, r1] = [1n, 0n, 0n, 1n, a, b]

  if (b === 0n) {
    return {
      gcd: a,
      a_inv: 1n,
      b_inv: 0n,
    }
  }

  while (r1 !== 0n) {
    const q = r0 / r1;
    [r0, r1] = [r1, r0 - q * r1];
    [s0, s1] = [s1, s0 - q * s1];
    [t0, t1] = [t1, t0 - q * t1]
  }

  return {
    gcd: r0,
    a_inv: s0,
    b_inv: t0,
  }
}

/**
 * 勒让德符号
 *
 * Legendre Symbol
 */
function legendreSymbol(a: bigint, p: bigint): bigint {
  return modPow(a, (p - 1n) >> 1n, p)
}

/**
 * 托内利-香克斯算法
 *
 * Tonelli-Shanks Algorithm
 */
function tonelliShanks(a: bigint, p: bigint): bigint {
  if (legendreSymbol(a, p) !== 1n) {
    throw new KitError('There is no square root')
  }
  if (a === 0n) {
    return 0n
  }
  if (p === 2n) {
    return a
  }
  if (p % 4n === 3n) {
    return modPow(a, (p + 1n) >> 2n, p)
  }

  let q = p - 1n
  let s = 0n
  while (mod(q, 2n) === 0n) {
    q >>= 1n
    s++
  }

  let z = 2n
  while (legendreSymbol(z, p) !== p - 1n) {
    z++
  }

  let m = s
  let c = modPow(z, q, p)
  let t = modPow(a, q, p)
  let r = modPow(a, (q + 1n) >> 1n, p)

  while (t !== 0n && t !== 1n) {
    let t2i = t
    let i = 1n
    for (; i < m; i++) {
      t2i = modPow(t2i, 2n, p)
      if (t2i === 1n) {
        break
      }
    }

    const b = modPow(c, 1n << (m - i - 1n), p)
    m = i
    c = modPow(b, 2n, p)
    t = t * c % p
    r = r * b % p
  }

  return r
}

/**
 * 最大公约数
 *
 * Greatest Common Divisor
 */
export function gcd(a: bigint, b: bigint): bigint {
  return extendedEuclidean(a, b).gcd
}

/**
 * 最小公倍数
 *
 * Least Common Multiple
 */
export function lcm(a: bigint, b: bigint): bigint {
  return a * b / gcd(a, b)
}

/**
 * 求模: a mod b
 *
 * Modulo operation: a mod b
 *
 * @param {bigint} a - dividend
 * @param {bigint} b - divisor
 */
export function mod(a: bigint, b: bigint): bigint {
  const r = a % b
  return r < 0n ? r + b : r
}

/**
 * 模幂运算: x ^ y mod n
 *
 * Modular exponentiation: x ^ y mod n
 *
 * @param {bigint} x - base
 * @param {bigint} y - exponent
 * @param {bigint} n - modulus
 */
export function modPow(x: bigint, y: bigint, n: bigint): bigint {
  x %= n
  let r = 1n
  while (y > 0n) {
    if ((y & 1n) === 1n)
      r = r * x % n
    x = x * x % n
    y >>= 1n
  }
  return r
}

/**
 * 模逆运算: e ≡ x ^ -1 (mod n)
 *
 * Modular inverse operation: e ≡ x ^ -1 (mod n)
 *
 * @param {bigint} x - base
 * @param {bigint} n - modulus
 */
export function modInverse(x: bigint, n: bigint): bigint {
  const { gcd, a_inv: inv } = extendedEuclidean(x, n)
  if (gcd !== 1n) {
    throw new KitError('Modular inverse does not exist')
  }
  return mod(inv, n)
}

/**
 * 模素平方根运算: n ^ 0.5 (mod p)
 *
 * Modular prime square operation: n ^ 0.5 (mod p)
 */
export function modPrimeSquare(n: bigint, p: bigint): bigint {
  n = mod(n, p)
  return tonelliShanks(n, p)
}

// * Buffer utility functions

/**
 * @extends Uint8Array
 */
export class U8 extends Uint8Array {
  /**
   * stringify U8 to encoded string
   *
   * 将 U8 编码为字符串
   */
  to(codec: Codec) {
    return codec(this)
  }

  /**
   * Convert U8 to BigInt
   *
   * 将 U8 转换为 BigInt
   */
  toBI() {
    let bigint = 0n
    this.forEach(byte => bigint = (bigint << 8n) | BigInt(byte))
    return bigint
  }

  /**
   * Convert U8 to Uint8Array
   *
   * 将 U8 转换为 Uint8Array
   */
  toUint8Array() {
    return new Uint8Array(this)
  }

  /**
   * Convert string to U8 (default encoding: UTF-8)
   *
   * 将 字符串 转换为 U8 (默认编码: UTF-8)
   *
   */
  static fromString(input: string, codec = UTF8) {
    return codec(input)
  }

  /**
   * Convert BigInt to U8
   *
   * 将 BigInt 转换为 U8
   */
  static fromBI(bigint: bigint, length?: number) {
    length = length || (getBIBits(bigint) + 7) >> 3
    const buffer = new U8(length)
    for (let i = buffer.length - 1; i >= 0; i--) {
      buffer[i] = Number(bigint & 0xFFn)
      bigint >>= 8n
    }
    return buffer
  }

  static from(arrayLike: ArrayLike<number>): U8
  static from(arrayLike: Iterable<number>, mapfn?: (v: number, k: number) => number, thisArg?: any): U8
  static from<T>(arrayLike: ArrayLike<T>, mapfn: (v: T, k: number) => number, thisArg?: any): U8
  static from(arrayLike: any, mapfn?: any, thisArg?: any): U8 {
    return new U8(super.from(arrayLike, mapfn, thisArg))
  }

  filter(predicate: (value: number, index: number, array: Uint8Array) => any, thisArg?: any): U8 {
    return new U8(super.filter(predicate, thisArg))
  }

  map(callbackfn: (value: number, index: number, array: Uint8Array) => number, thisArg?: any): U8 {
    return new U8(super.map(callbackfn, thisArg))
  }

  static of(...items: number[]): U8 {
    return new U8(super.of(...items))
  }

  toReversed(): U8 {
    return new U8(super.reverse())
  }

  toSorted(compareFn?: ((a: number, b: number) => number) | undefined): U8 {
    return new U8(super.sort(compareFn))
  }

  reverse(): U8 {
    return new U8(super.reverse())
  }

  slice(start?: number, end?: number): U8 {
    return new U8(super.slice(start, end))
  }

  subarray(begin?: number, end?: number): U8 {
    return new U8(super.subarray(begin, end))
  }

  with(index: number, value: number): U8 {
    return new U8(super.with(index, value))
  }
}

/**
 * Merging multiple ArrayBuffers
 *
 * 合并多个 ArrayBuffer
 */
export function joinBuffer(...buffers: ArrayBuffer[]) {
  const byteTotal = buffers.reduce((acc, cur) => acc + cur.byteLength, 0)
  const result = new U8(byteTotal)
  let offset = 0
  for (const buffer of buffers) {
    result.set(new U8(buffer), offset)
    offset += buffer.byteLength
  }
  return result
}

/**
 * resize ArrayBuffer
 *
 * 调整 ArrayBuffer 大小
 *
 * @param {ArrayBuffer} buffer
 * @param {number} size - byte
 */
export function resizeBuffer(buffer: ArrayBuffer, size: number) {
  const B = new U8(size)
  B.set(new U8(buffer))
  return B
}

export class Counter extends U8 {
  /**
   * @param {number} offset - 计数器偏移 / counter offset
   * @param {number} length - 计数器长度 / counter length
   */
  inc(offset?: number, length?: number) {
    // 如果不提供偏移，则默认计数器从 0 开始
    offset = offset || 0
    if (offset < 0 || offset >= this.length) {
      throw new KitError('Invalid counter offset')
    }
    // 如果不提供长度，则默认计数器长度为剩余长度
    length = length || this.length - offset
    if (length < 0 || offset + length > this.length) {
      throw new KitError('Invalid counter length')
    }
    for (let i = offset + length - 1; i >= offset; i--) {
      if (this[i] < 0xFF) {
        this[i] += 1
        break
      }
      this[i] = 0
    }
  }
}

// * Other utility functions

export function wrap<T = any>(...args: any[]): T {
  if (args.length === 0) {
    return {} as T
  }
  // @ts-expect-error Object assign
  return Object.assign(...args)
}

export class KitError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'mima-kit Error'
  }
}
