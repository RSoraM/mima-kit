import type { Codec } from './codec'

// * Math utility functions

/** 32-bit 循环左移 */
export function rotateL32(x: number, n: number) {
  return ((x << n) | (x >>> (32 - n))) >>> 0
}

/** 32-bit 循环右移 */
export function rotateR32(x: number, n: number) {
  return (x >>> n) | (x << (32 - n)) >>> 0
}

/**
 * 位循环左移 / Rotate Left
 *
 * @param {number} bit - 位数 / bit
 * @param {number | bigint} x - 数值 / value
 * @param {number | bigint} n - 位移 / shift
 * @param {bigint} [mask] - 位掩码 / bit mask
 */
export function rotateL(
  bit: number | bigint,
  x: number | bigint,
  n: number | bigint,
  mask?: bigint,
) {
  bit = BigInt(bit)
  mask ??= genBitMask(bit)
  x = BigInt(x)
  n = BigInt(n)
  x &= mask
  n %= bit
  x = (x << n) | (x >> (bit - n))
  return x & mask
}

/**
 * 位循环右移 / Rotate Right
 *
 * @param {number} bit - 位数 / bit
 * @param {number | bigint} x - 数值 / value
 * @param {number | bigint} n - 位移 / shift
 * @param {bigint} [mask] - 位掩码 / bit mask
 */
export function rotateR(
  bit: number | bigint,
  x: number | bigint,
  n: number | bigint,
  mask?: bigint,
) {
  bit = BigInt(bit)
  mask ??= genBitMask(bit)
  x = BigInt(x)
  n = BigInt(n)
  x &= mask
  n %= bit
  x = (x >> n) | (x << (bit - n))
  return x & mask
}

/** 生成随机大整数 / Generate Random BigInt */
export function genRandomBI(max: bigint, byte: number) {
  let result = 0n

  // 生成随机数
  const buffer = new U8(byte)
  do {
    crypto.getRandomValues(buffer)
    result = buffer.toBI()
  } while (result >= max)

  return { buffer, result }
}

/**
 * 获取大整数的比特长度
 *
 * Get the bit length of a BigInt
 */
export function getBIBits(n: bigint) {
  let bit = 0
  while (n > 0) {
    bit++
    n >>= 1n
  }
  return bit
}

/**
 * 生成位掩码 / Generate Bit Mask
 *
 * @param {number} w - 位数 / bit
 *
 * ```ts
 * const mask = genBitMask(8) // 0xFFn
 * ```
 */
export function genBitMask(w: number | bigint) {
  w = BigInt(w)
  let mask = 0x0n
  for (let i = 0; i < w; i++) {
    mask = (mask << 1n) | 1n
  }
  return mask
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
export function extendedEuclidean(a: bigint, b: bigint) {
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
export function legendreSymbol(a: bigint, p: bigint): bigint {
  return modPow(a, (p - 1n) >> 1n, p)
}

/**
 * 托内利-香克斯算法
 *
 * Tonelli-Shanks Algorithm
 */
export function tonelliShanks(a: bigint, p: bigint): bigint {
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
    if (y & 1n)
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
   * 从 U8 中获取一个字 / Get a word from U8
   *
   * @param {number} word_byte - 字长 / word size
   * @param {number} index - 字索引 / word index
   * @param {boolean} [little_endian] - 是否为小端序 / little-endian (default: false)
   */
  getWord(word_byte: number, index: number, little_endian = false): bigint {
    const offset = index * word_byte
    const buffer = this.subarray(offset, offset + word_byte)
    return little_endian ? buffer.toBI(true) : buffer.toBI()
  }

  /**
   * 将一个字写入 U8 / Set a word to U8
   *
   * @param {number} word_byte - 字长 / word size
   * @param {number} index - 字索引 / word index
   * @param {bigint | Uint8Array} word - 字 / word
   * @param {boolean} [little_endian] - 是否为小端序 / little-endian (default: false)
   */
  setWord(word_byte: number, index: number, word: bigint | Uint8Array, little_endian = false) {
    const offset = index * word_byte
    const buffer = typeof word === 'bigint' ? U8.fromBI(word, word_byte) : word
    this.set(little_endian ? buffer.toReversed() : buffer, offset)
  }

  /**
   * U8 视图 / U8 view
   *
   * @param {number} word_byte - 字长 / word size
   */
  view(word_byte: number) {
    const length = Math.floor(this.length / word_byte)
    const get = (index: number, little_endian = false) => this.getWord(word_byte, index, little_endian)
    const set = (index: number, word: bigint | Uint8Array, little_endian = false) => this.setWord(word_byte, index, word, little_endian)
    return { get, set, length }
  }

  /**
   * 将 U8 编码为字符串 / stringify U8 to encoded string
   */
  to(codec: Codec) {
    return codec(this)
  }

  /**
   * 将 U8 转换为 BigInt / Convert U8 to BigInt
   *
   * @param {boolean} [little_endian] - 是否为小端序 / little-endian (default: false)
   */
  toBI(little_endian = false) {
    const buffer = little_endian ? this.toReversed() : this
    let bigint = 0n
    buffer.forEach(byte => bigint = (bigint << 8n) | BigInt(byte))
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
   * Convert string to U8
   *
   * 将 字符串 转换为 U8
   */
  static fromString(input: string, codec: Codec): U8 {
    return codec(input)
  }

  /**
   * Convert BigInt to U8
   *
   * 将 BigInt 转换为 U8
   */
  static fromBI(bigint: bigint, length?: number, little_endian = false): U8 {
    length = length || (getBIBits(bigint) + 7) >> 3
    const buffer = new U8(length)
    if (little_endian) {
      for (let i = 0; i < buffer.length; i++) {
        buffer[i] = Number(bigint & 0xFFn)
        bigint >>= 8n
      }
    }
    else {
      for (let i = buffer.length - 1; i >= 0; i--) {
        buffer[i] = Number(bigint & 0xFFn)
        bigint >>= 8n
      }
    }
    return buffer
  }

  static from(arrayLike: Iterable<number>): U8
  static from<T>(arrayLike: Iterable<T>, mapfn: (v: T, k: number) => number, thisArg?: any): U8
  static from(arrayLike: ArrayLike<number>): U8
  static from<T>(arrayLike: ArrayLike<T>, mapfn: (v: T, k: number) => number, thisArg?: any): U8
  static from(arrayLike: any, mapfn?: any, thisArg?: any): U8 {
    return new U8(super.from(arrayLike, mapfn, thisArg))
  }

  filter(predicate: (value: number, index: number, array: this) => any, thisArg?: any): U8 {
    return new U8(super.filter(predicate, thisArg))
  }

  map(callbackfn: (value: number, index: number, array: this) => number, thisArg?: any): U8 {
    return new U8(super.map(callbackfn, thisArg))
  }

  static of(...items: number[]): U8 {
    return new U8(super.of(...items))
  }

  toReversed(): this {
    return super.reverse()
  }

  toSorted(compareFn?: ((a: number, b: number) => number) | undefined): this {
    return super.sort(compareFn)
  }

  reverse(): this {
    return super.reverse()
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

type TypedArray
  = Uint8Array  | Int8Array | Uint8ClampedArray
  | Uint16Array | Int16Array
  | Uint32Array | Int32Array

/**
 * Convert TypedArray to Uint8Array
 *
 * 将 TypedArray 转换为 Uint8Array
 */
export function u8(source: TypedArray): Uint8Array {
  return new Uint8Array(
    source.buffer,
    source.byteOffset,
    source.byteLength,
  )
}

/**
 * Convert TypedArray to Uint16Array
 *
 * 将 TypedArray 转换为 Uint16Array
 */
export function u16(source: TypedArray): Uint16Array {
  return new Uint16Array(
    source.buffer,
    source.byteOffset,
    source.byteLength >> 1,
  )
}

/**
 * Convert TypedArray to Uint32Array
 *
 * 将 TypedArray 转换为 Uint32Array
 */
export function u32(source: TypedArray): Uint32Array {
  return new Uint32Array(
    source.buffer,
    source.byteOffset,
    source.byteLength >> 2,
  )
}

/**
 * Merging multiple ArrayBuffers
 *
 * 合并多个 ArrayBuffer
 */
export function joinBuffer(...buffers: Uint8Array[]) {
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
export function resizeBuffer(buffer: Uint8Array, size: number) {
  const B = new U8(size)
  B.set(new U8(buffer))
  return B
}

const nibbleReverseMap = [0x0n, 0x8n, 0x4n, 0xCn, 0x2n, 0xAn, 0x6n, 0xEn, 0x1n, 0x9n, 0x5n, 0xDn, 0x3n, 0xBn, 0x7n, 0xFn]

/**
 * 快速翻转字节位序 / Fast Reverse Byte's Bit Order
 *
 * @param {number} byte - 字节 / byte
 */
export function reverseBit(byte: number) {
  byte &= 0xFF
  const b_h = nibbleReverseMap[byte >> 4]
  const b_l = nibbleReverseMap[byte & 0xF]
  return (b_l << 4n) | b_h
}

export class Counter extends U8 {
  /**
   * @param {number} offset - 计数器偏移 / counter offset
   * @param {number} length - 计数器长度 / counter length
   */
  inc(offset?: number, length?: number, little_endian = false) {
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
    if (little_endian) {
      for (let i = offset; i < offset + length; i++) {
        if (this[i] < 0xFF) {
          this[i] += 1
          break
        }
        this[i] = 0
      }
    }
    else {
      for (let i = offset + length - 1; i >= offset; i--) {
        if (this[i] < 0xFF) {
          this[i] += 1
          break
        }
        this[i] = 0
      }
    }
  }
}

// * Other utility functions

export function trying<T>(
  fn: () => T,
): [Error, null] | [null, T] {
  try {
    const result = fn()
    return [null, result]
  }
  catch (error) {
    return error instanceof Error
    ? [error, null]
    : [new KitError('Unknown error'), null]
  }
}

export function wrap<T = any>(...args: any[]): T {
  // @ts-expect-error Object assign
  return Object.assign(...args)
}

export class KitError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'mima-kit Error'
  }
}
