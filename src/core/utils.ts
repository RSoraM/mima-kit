/** 8-bit 循环左移 */
export function rotateL8(x: number, n: number) {
  return (x << n) | (x >>> (8 - n))
}

/** 8-bit 循环右移 */
export function rotateR8(x: number, n: number) {
  return (x >>> n) | (x << (8 - n))
}

/** 16-bit 循环左移 */
export function rotateL16(x: number, n: number) {
  return (x << n) | (x >>> (16 - n))
}

/** 16-bit 循环右移 */
export function rotateR16(x: number, n: number) {
  return (x >>> n) | (x << (16 - n))
}

/** 32-bit 循环左移 */
export function rotateL32(x: number, n: number) {
  return (x << n) | (x >>> (32 - n))
}

/** 32-bit 循环右移 */
export function rotateR32(x: number, n: number) {
  return (x >>> n) | (x << (32 - n))
}

/** 64-bit 循环左移 */
export function rotateL64(x: bigint, n: bigint) {
  return ((x << n) | (x >> (64n - n))) & 0xFFFFFFFFFFFFFFFFn
}

/** 64-bit 循环右移 */
export function rotateR64(x: bigint, n: bigint) {
  return ((x >> n) | (x << (64n - n))) & 0xFFFFFFFFFFFFFFFFn
}

/**
 * ### joinBuffer
 *
 * @description
 * 合并多个 ArrayBuffer
 */
export function joinBuffer(...buffers: ArrayBuffer[]) {
  const sigByte = buffers.reduce((acc, cur) => acc + cur.byteLength, 0)
  const result = new Uint8Array(sigByte)
  let offset = 0
  for (const buffer of buffers) {
    result.set(new Uint8Array(buffer), offset)
    offset += buffer.byteLength
  }
  return result
}
