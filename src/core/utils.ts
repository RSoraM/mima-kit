/** 字符编解码器 / String Codec */
export interface Codec {
  /**
   * 将编码字符串解析为 Uint8Array
   *
   * Parse encoded string to Uint8Array
   */
  (input: string): U8
  /**
   * 将 Uint8Array 编码为字符串
   *
   * Stringify Uint8Array to encoded string
   */
  (input: Uint8Array): string
  FORMAT: string
}
function createCodec(
    parse: (input: string) => U8,
    stringify: (input: Uint8Array) => string,
    format: string,
): Codec {
  function codec(input: string): U8
  function codec(input: Uint8Array): string
  function codec(input: string | Uint8Array) {
    if (typeof input === 'string') {
      return parse(input)
    }
    else {
      return stringify(input)
    }
  }
  return wrap(codec, { FORMAT: format })
}

/** provided by xingluo233 */
function UTF8ToU8(input: string) {
  const buffer: number[] = []
  for (let i = 0; i < input.length; i++) {
    const char_code = input.codePointAt(i)
    if (char_code === undefined) {
      continue
    }
    else if (char_code < 0x80) {
      buffer.push(char_code)
    }
    else if (char_code < 0x800) {
      buffer.push(0xC0 | (char_code >> 6))
      buffer.push(0x80 | (char_code & 0x3F))
    }
    else if (char_code < 0x10000) {
      buffer.push(0xE0 | (char_code >> 12))
      buffer.push(0x80 | ((char_code >> 6) & 0x3F))
      buffer.push(0x80 | (char_code & 0x3F))
    }
    else if (char_code < 0x110000) {
      buffer.push(0xF0 | (char_code >> 18))
      buffer.push(0x80 | ((char_code >> 12) & 0x3F))
      buffer.push(0x80 | ((char_code >> 6) & 0x3F))
      buffer.push(0x80 | (char_code & 0x3F))
      i++
    }
  }
  return U8.from(buffer)
}
/** provided by xingluo233 */
function U8ToUTF8(input: Uint8Array) {
  const str = []
  let i = 0
  while (i < input.length) {
    const byte1 = input[i++]
    if (byte1 < 0x80) {
      str.push(String.fromCharCode(byte1))
    }
    else if (byte1 >= 0xC0 && byte1 < 0xE0) {
      const byte2 = input[i++]
      const char_code = ((byte1 & 0x1F) << 6) | (byte2 & 0x3F)
      str.push(String.fromCharCode(char_code))
    }
    else if (byte1 >= 0xE0 && byte1 < 0xF0) {
      const byte2 = input[i++]
      const byte3 = input[i++]
      const char_code = ((byte1 & 0x0F) << 12) | ((byte2 & 0x3F) << 6) | (byte3 & 0x3F)
      str.push(String.fromCharCode(char_code))
    }
    else if (byte1 >= 0xF0 && byte1 < 0xF8) {
      const byte2 = input[i++]
      const byte3 = input[i++]
      const byte4 = input[i++]
      const char_code = ((byte1 & 0x07) << 18) | ((byte2 & 0x3F) << 12) | ((byte3 & 0x3F) << 6) | (byte4 & 0x3F)
      str.push(String.fromCodePoint(char_code))
    }
  }
  return str.join('')
}
/** UTF-8 编解码器 / Codec */
export const UTF8 = createCodec(UTF8ToU8, U8ToUTF8, 'utf-8')

function HEXToU8(input: string) {
  const arr = input.match(/[\da-f]{2}/gi)
  if (arr == null) {
    return new U8()
  }
  return new U8(arr.map(h => Number.parseInt(h, 16)))
}
function U8ToHEX(input: Uint8Array) {
  let result = ''
  for (let i = 0; i < input.length; i++) {
    result += input[i].toString(16).padStart(2, '0')
  }
  return result
}
/** hex 编解码器 / Codec */
export const HEX = createCodec(HEXToU8, U8ToHEX, 'hex')

function B64ToU8(input: string) {
  return B64CommonParse(input, false)
}
function U8ToB64(input: Uint8Array) {
  return B64CommonStringify(input, false)
}
/** base64 编解码器 / Codec */
export const B64 = createCodec(B64ToU8, U8ToB64, 'base64')

function B64URLToU8(input: string) {
  return B64CommonParse(input, true)
}
function U8ToB64URL(input: Uint8Array) {
  return B64(input).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
}
/** base64url 编解码器 / Codec */
export const B64URL = createCodec(B64URLToU8, U8ToB64URL, 'base64url')

/**
 * provided by xingluo233
 *
 * B64CommonParse can parse B64 or B64url string to Uint8Array
 *
 * B64CommonParse 可以将 B64 或者 B64url 字符串解析为 Uint8Array
 *
 * @param {string} input - B64 或 B64url 字符串
 * @param {boolean} url - 是否是 B64url 字符串
 */
function B64CommonParse(input: string, url: boolean) {
  const map = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
  if (url) {
    input = input.replace(/-/g, '+').replace(/_/g, '/')
    while (input.length % 4) {
      input += '='
    }
  }
  input = input.replace(/[^A-Z0-9+/]/gi, '')
  const length = input.length * 0.75
  const result = new U8(length)

  let i = 0
  let j = 0
  while (i < input.length) {
    const a = map.indexOf(input.charAt(i++))
    const b = map.indexOf(input.charAt(i++))
    const c = map.indexOf(input.charAt(i++))
    const d = map.indexOf(input.charAt(i++))

    const combined = (a << 18) | (b << 12) | (c << 6) | d

    result[j++] = (combined >> 16) & 0xFF
    result[j++] = (combined >> 8) & 0xFF
    result[j++] = combined & 0xFF
  }
  return result
}

/**
 * B64CommonStringify can stringify Uint8Array to B64 or B64url string
 *
 * B64CommonStringify 可以将 Uint8Array 编码为 B64 或 B64url 字符串
 *
 * @param {Uint8Array} input - Uint8Array
 * @param {boolean} url - 是否是 B64url 字符串
 */
function B64CommonStringify(input: Uint8Array, url: boolean) {
  let map = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
  map += url ? '-_' : '+/'
  let result = ''
  let i: number
  for (i = 0; i < input.length - 2; i += 3) {
    result += map[input[i] >> 2]
    result += map[((input[i] & 3) << 4) | (input[i + 1] >> 4)]
    result += map[((input[i + 1] & 15) << 2) | (input[i + 2] >> 6)]
    result += map[input[i + 2] & 63]
  }

  if (i === input.length - 2) {
    result += map[input[i] >> 2]
    result += map[((input[i] & 3) << 4) | (input[i + 1] >> 4)]
    result += map[(input[i + 1] & 15) << 2]
    result += url ? '' : '='
  }
  else if (i === input.length - 1) {
    result += map[input[i] >> 2]
    result += map[(input[i] & 3) << 4]
    result += url ? '' : '=='
  }
  return result
}

function CSVToU8(input: string) {
  const coreValueMap = new Map<string, number>()
  coreValueMap.set('富强', 0)
  coreValueMap.set('民主', 1)
  coreValueMap.set('文明', 2)
  coreValueMap.set('和谐', 3)
  coreValueMap.set('自由', 4)
  coreValueMap.set('平等', 5)
  coreValueMap.set('公正', 6)
  coreValueMap.set('法治', 7)
  coreValueMap.set('爱国', 8)
  coreValueMap.set('敬业', 9)
  coreValueMap.set('诚信', 10)
  coreValueMap.set('友善', 11)

  const from = (value: string) => {
    const nibble = coreValueMap.get(value)
    if (nibble === undefined) {
      throw new KitError('你竟然在社会主义核心价值观里夹带私货！')
    }
    return nibble
  }

  const coreValues = input.match(/(\S){2}/g)
  if (coreValues == null) {
    return new U8()
  }

  let h = 0
  let l = 0
  let count = 0
  const result: number[] = []
  for (let i = 0; i < coreValues.length; i++) {
    const isHigh = count % 2 === 0

    let nibble = from(coreValues[i])
    if (nibble === 10 || nibble === 11) {
      i++
      if (i === coreValues.length) {
        throw new KitError('你的社会主义核心价值观破碎了！')
      }
      nibble = nibble === 10
          ? 10 + from(coreValues[i])
          : 6 + from(coreValues[i])
    }
    if (isHigh) {
      h = nibble
    }
    else {
      l = nibble
    }

    if (!isHigh) {
      result.push(((h << 4) | l) & 0xFF)
    }
    count++
  }

  return new U8(result)
}
function U8ToCSV(input: Uint8Array) {
  const rand = () => Math.random() >= 0.5
  const map = ['富强', '民主', '文明', '和谐', '自由', '平等', '公正', '法治', '爱国', '敬业', '诚信', '友善']

  let result = ''
  input.forEach((byte) => {
    const h = (byte >> 4) & 0xF
    const l = byte & 0xF
    if (h < 10) {
      result += map[h]
    }
    else if (rand()) {
      result += map[11] + map[h - 6]
    }
    else {
      result += map[11] + map[h - 6]
    }

    if (l < 10) {
      result += map[l]
    }
    else if (rand()) {
      result += map[10] + map[l - 10]
    }
    else {
      result += map[11] + map[l - 6]
    }
  })

  return result
}
/** 社会主义核心价值观编解码器 / Core Socialist Values Codec */
export const CSV = createCodec(CSVToU8, U8ToCSV, 'core-socialist-values')

// * Math utility functions

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
 * - gcd: 最大公约数 / the greatest common divisor
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
  getWord(word_byte: number, index: number, little_endian: boolean = false): bigint {
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
  setWord(word_byte: number, index: number, word: bigint | Uint8Array, little_endian: boolean = false) {
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
  toBI(little_endian: boolean = false) {
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
   * Convert string to U8 (default encoding: UTF-8)
   *
   * 将 字符串 转换为 U8 (默认编码: UTF-8)
   *
   */
  static fromString(input: string, codec = UTF8): U8 {
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
   * @param little_endian
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
