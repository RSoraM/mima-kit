/** 8-bit 循环左移 */
export function rotateL8(x: number, n: number) {
  x &= 0xFF
  n %= 8
  return (x << n) | (x >>> (8 - n))
}

/** 8-bit 循环右移 */
export function rotateR8(x: number, n: number) {
  x &= 0xFF
  n %= 8
  return (x >>> n) | (x << (8 - n))
}

/** 16-bit 循环左移 */
export function rotateL16(x: number, n: number) {
  x &= 0xFFFF
  n %= 16
  return (x << n) | (x >>> (16 - n))
}

/** 16-bit 循环右移 */
export function rotateR16(x: number, n: number) {
  x &= 0xFFFF
  n %= 16
  return (x >>> n) | (x << (16 - n))
}

/** 32-bit 循环左移 */
export function rotateL32(x: number, n: number) {
  x >>>= 0
  n %= 32
  return (x << n) | (x >>> (32 - n))
}

/** 32-bit 循环右移 */
export function rotateR32(x: number, n: number) {
  x >>>= 0
  n %= 32
  return (x >>> n) | (x << (32 - n))
}

/** 64-bit 循环左移 */
export function rotateL64(x: bigint, n: bigint) {
  x &= 0xFFFFFFFFFFFFFFFFn
  n %= 64n
  return ((x << n) | (x >> (64n - n))) & 0xFFFFFFFFFFFFFFFFn
}

/** 64-bit 循环右移 */
export function rotateR64(x: bigint, n: bigint) {
  x &= 0xFFFFFFFFFFFFFFFFn
  n %= 64n
  return ((x >> n) | (x << (64n - n))) & 0xFFFFFFFFFFFFFFFFn
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
