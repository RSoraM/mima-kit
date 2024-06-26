/** 32-bit 循环左移 */
export function rotateL(x: number, n: number) {
  return (x << n) | (x >>> (32 - n))
}

/** 32-bit 循环右移 */
export function rotateR(x: number, n: number) {
  return (x >>> n) | (x << (32 - n))
}

/** 64-bit 循环右移 */
export function rotateRn(x: bigint, n: bigint) {
  return ((x >> n) | (x << (64n - n))) & 0xFFFFFFFFFFFFFFFFn
}

/** 64-bit 循环左移 */
export function rotateLn(x: bigint, n: bigint) {
  return ((x << n) | (x >> (64n - n))) & 0xFFFFFFFFFFFFFFFFn
}
