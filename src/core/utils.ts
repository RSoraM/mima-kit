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

/** 求最大公约数 */
export function gcd(a: bigint, b: bigint): bigint {
  while (b !== 0n) {
    const t = a % b
    a = b
    b = t
  }
  return a
}

/** 求最小公倍数 */
export function lcm(a: bigint, b: bigint): bigint {
  return a * b / gcd(a, b)
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
  let r = 1n
  while (y > 0) {
    if ((y & 1n) === 1n)
      r = r * x % n
    y >>= 1n
    x = x * x % n
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
  let [modulus, inverse, current] = [n, 0n, 1n]

  if (n === 1n)
    return 0n

  while (x > 1n) {
    const quotient = x / n
    let temp = n

    n = x % n
    x = temp
    temp = inverse

    inverse = current - quotient * inverse
    current = temp
  }

  if (current < 0n)
    current += modulus

  return current
}

/** bigint 转换为 Uint8Array */
export function BIToU8(bigint: bigint): Uint8Array {
  // 计算所需的字节数
  let length = Math.ceil(bigint.toString(16).length >> 1)
  const uint8Array = new Uint8Array(length)

  // 将 bigint 转换为字节数组
  length--
  while (bigint > 0n) {
    uint8Array[length--] = Number(bigint & 0xFFn)
    bigint >>= 8n
  }

  return uint8Array
}

/** Uint8Array 转换为 bigint */
export function U8ToBI(uint8Array: Uint8Array): bigint {
  let bigint = 0n
  uint8Array.forEach(byte => bigint = (bigint << 8n) + BigInt(byte))
  return bigint
}

/**
 * @description
 * Merging multiple ArrayBuffers
 *
 * 合并多个 ArrayBuffer
 */
export function joinBuffer(...buffers: ArrayBuffer[]) {
  const byteTotal = buffers.reduce((acc, cur) => acc + cur.byteLength, 0)
  const result = new Uint8Array(byteTotal)
  let offset = 0
  for (const buffer of buffers) {
    result.set(new Uint8Array(buffer), offset)
    offset += buffer.byteLength
  }
  return result
}

/**
 * @description
 * resize ArrayBuffer
 *
 * 调整 ArrayBuffer 大小
 *
 * @param {ArrayBuffer} buffer
 * @param {number} size - byte
 */
export function resizeBuffer(buffer: ArrayBuffer, size: number) {
  const B = new Uint8Array(size)
  B.set(new Uint8Array(buffer))
  return B
}

export function wrap<T = any>(...args: any[]): T {
  if (args.length === 0) {
    return {} as T
  }
  // @ts-expect-error Object assign
  return Object.freeze(Object.assign(...args))
}

export class KitError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'mima-kit Error'
  }
}
