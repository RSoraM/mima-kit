import { Utf8 } from '../core/codec'
import { createHash, createTupleHash } from '../core/hash'
import { joinBuffer } from '../core/utils'
import { Keccak_c, shake128, shake256 } from './sha3'

// * Encode and Padding Function

/**
 * @description
 * SP.800-185 2.3.1:
 *
 * left_encode
 *
 * 左侧整数编码
 *
 * Inspired by https://github.com/paulmillr/noble-hashes
 *
 * @example
 * ```ts
 * leftEncode(0) // Uint8Array(2) [ 1, 0 ]
 * leftEncode(18446744073709551615n) // Uint8Array(9) [ 8, 255, 255, 255, 255, 255, 255, 255, 255 ]
 * ```
 *
 * @param {number | bigint} x - 输入
 */
function leftEncode(x: number | bigint): Uint8Array {
  const result = []
  do {
    let xi
    if (typeof x === 'bigint') {
      xi = x & 0xFFn
      x = x >> 8n
    }
    else {
      xi = x & 0xFF
      x = x >> 8
    }

    result.unshift(Number(xi))
  } while (x > 0)

  result.unshift(result.length)

  return new Uint8Array(result)
}

/**
 * @description
 * SP.800-185 2.3.1:
 *
 * right_encode
 *
 * 右侧整数编码
 *
 * Inspired by https://github.com/paulmillr/noble-hashes
 *
 * @example
 * ```ts
 * rightEncode(0) // Uint8Array(2) [ 0, 1 ]
 * rightEncode(18446744073709551615n) // Uint8Array(9) [ 255, 255, 255, 255, 255, 255, 255, 255, 8 ]
 * ```
 *
 * @param {number | bigint} x - 输入
 */
function rightEncode(x: number | bigint): Uint8Array {
  const result = []
  do {
    let xi
    if (typeof x === 'bigint') {
      xi = x & 0xFFn
      x = x >> 8n
    }
    else {
      xi = x & 0xFF
      x = x >> 8
    }

    result.unshift(Number(xi))
  } while (x > 0)

  result.push(result.length)

  return new Uint8Array(result)
}

/**
 * @description
 * SP.800-185 2.3.2:
 *
 * encode_string
 *
 * 字符编码
 *
 * Unlike the specification document, this implementation does not perform concatenation operations, but returns an array, and the concatenation operation is performed externally. See `bytepad` function for details.
 *
 * 与规范文档不同, 这个实现不会进行串接操作, 而是返回一个数组, 串接操作在外部进行. 详细见 `bytepad` 函数.
 *
 * @example
 * ```ts
 * encodeString(K) // [left_encode(len(K)), K]
 * ```
 *
 * @param {string | Uint8Array} input - 输入
 */
function encodeString(input: string | Uint8Array) {
  input = typeof input === 'string' ? Utf8.parse(input) : input
  return [leftEncode(input.byteLength << 3), input]
}

/**
 * @description
 * SP.800-185 2.3.3:
 *
 * The `bytePad` is used by many algorithms which involves many concatenation operations, but for `Javascript` implementation, each concatenation means creating a `Uint8Array` for merging. Frequent creation of `Uint8Array` may cause performance issues.
 *
 * 在算法中 `bytePad` 涉及很多串接操作, 但对 `Javascript` 实现来说, 每次串接都意味着创建 `Uint8Array` 进行合并. 频繁地创建 `Uint8Array` 有可能导致性能问题.
 *
 * This is an optimized implementation. The input `X` is changed to an array, and the final return is also an array. The merge operation is moved to the outside.
 *
 * 这是一个优化后的实现. 将输入 `X` 改为数组, 最后也返回数组, 将合并操作移动到外部.
 *
 * @example
 * ```ts
 * bytepad(X, w) = left_encode(w) || X0 || ... || Xn || 0^z
 * ```
 *
 * @param {Uint8Array} X - 输入数组
 * @param {number} w - 字节倍数
 */
function bytepad(X: Uint8Array[], w: number): Uint8Array[] {
  if (w <= 0) {
    throw new Error('Invalid w')
  }

  // 使用 leftEncode 函数编码 w
  const encodedW = leftEncode(w)

  // z = left_encode(w) || X0 || ... || Xn

  // 计算 z 的有效字节长度总和, 用于计算填充零字节的数量
  let zByteLength = encodedW.byteLength
  X.forEach(x => zByteLength += x.byteLength)

  // 计算需要填充的零字节的数量
  const zeroByteLength = w - (zByteLength % w)

  X.unshift(encodedW)
  X.push(new Uint8Array(zeroByteLength))

  return X
}

/**
 * @description
 * `cSHAKE` Padding
 *
 * `cSHAKE` 填充函数
 *
 * @example
 * ```
 * M || 00 || 10*1
 * ```
 *
 * @param {number} rByte - 处理速率
 * @param {number} sigBytes - 消息字节数
 */
function cShakePadding(rByte: number, sigBytes: number) {
  const q = rByte - (sigBytes % rByte)
  const p = new Uint8Array(q)

  if (q === 1) {
    p[0] = 0x84
    return p
  }

  p[0] = 0x04
  p[q - 1] = 0x80
  return p
}

// * cSHAKE

/**
 * @description
 * `cSHAKE128` is a customizable variant of `SHAKE128`
 *
 * `cSHAKE128` 是 `SHAKE128` 的可定制变体
 *
 * @example
 * ```ts
 * cSHAKE128(256, '', 'password')('hello') // 'd3ff6985c8016860b2e459d92968e8eee9a3843b5bf0658f5a9a2a7e34894380'
 * cSHAKE128(256, '', 'password')('hello', B64) // '0/9phcgBaGCy5FnZKWjo7umjhDtb8GWPWpoqfjSJQ4A='
 * ```
 *
 * @param {number} d - 输出长度 bit
 * @param {string | Uint8Array} N - function-name
 * @param {string | Uint8Array} S - customization
 */
export function cShake128(d: number, N: string | Uint8Array = '', S: string | Uint8Array = '') {
  N = typeof N === 'string' ? Utf8.parse(N) : N
  S = typeof S === 'string' ? Utf8.parse(S) : S

  if (N.byteLength === 0 && S.byteLength === 0) {
    return shake128(d)
  }

  return createHash(
    (M: Uint8Array) => {
      const P = bytepad([...encodeString(N), ...encodeString(S)], 168)
      P.push(M)
      return Keccak_c(256, d, cShakePadding)(joinBuffer(...P))
    },
    {
      ALGORITHM: `cSHAKE128/${d}`,
      BLOCK_SIZE: 168,
      DIGEST_SIZE: d >> 3,
    },
  )
}

/**
 * @description
 * `cSHAKE256` is a customizable variant of `SHAKE256`
 *
 * `cSHAKE256` 是 `SHAKE256` 的可定制变体
 *
 * @example
 * ```ts
 * cSHAKE256(512, '', 'password')('hello') // 'bf2fffa507ad934fcf169ec14f478e3b1227058e7154314fbadbf318b71bbf1d01b97559dbd43d80b448a24e4f79c7072806107d2ff59b832fb1b6cd215149f7'
 * cSHAKE256(512, '', 'password')('hello', B64) // 'vy//pQetk0/PFp7BT0eOOxInBY5xVDFPutvzGLcbvx0BuXVZ29Q9gLRIok5PeccHKAYQfS/1m4MvsbbNIVFJ9w=='
 * ```
 *
 * @param {number} d - 输出长度 bit
 * @param {string | Uint8Array} N - function-name
 * @param {string | Uint8Array} S - customization
 */
export function cShake256(d: number, N: string | Uint8Array = '', S: string | Uint8Array = '') {
  N = typeof N === 'string' ? Utf8.parse(N) : N
  S = typeof S === 'string' ? Utf8.parse(S) : S

  if (N.byteLength === 0 && S.byteLength === 0) {
    return shake256(d)
  }

  return createHash(
    (M: Uint8Array) => {
      const P = bytepad([...encodeString(N), ...encodeString(S)], 136)
      P.push(M)
      return Keccak_c(512, d, cShakePadding)(joinBuffer(...P))
    },
    {
      ALGORITHM: `cSHAKE256/${d}`,
      BLOCK_SIZE: 136,
      DIGEST_SIZE: d >> 3,
    },
  )
}

// * KMAC

/**
 * @description
 * The Keccak Message Authentication Code (KMAC) algorithm
 *
 * Keccak 消息认证码 (KMAC) 算法
 *
 * `KMAC128` is a variant of `KMAC`, build from `cSHAKE128`
 *
 * `KMAC128` 是 `KMAC` 的变体, 由 `cSHAKE128` 构建
 *
 * @example
 * ```ts
 * kmac128(256, 'password')('hello') // 'd114b588da4337c80455806f3d461768c27931bcb6977c25d4611fb78e95da04'
 * kmac128(256, 'password')('hello', B64) // '0RS1iNpDN8gEVYBvPUYXaMJ5Mby2l3wl1GEft46V2gQ='
 * ```
 *
 * @param {number} d - 输出长度 bit
 * @param {string | Uint8Array} K - key
 * @param {string | Uint8Array} S - customization
 */
export function kmac128(d: number, K: string | Uint8Array = '', S: string | Uint8Array = '') {
  return createHash(
    (M: Uint8Array) => {
      const X = bytepad([...encodeString('KMAC'), ...encodeString(S)], 168)
      X.push(...bytepad(encodeString(K), 168))
      X.push(M)
      X.push(rightEncode(d))

      return Keccak_c(256, d, cShakePadding)(joinBuffer(...X))
    },
    {
      ALGORITHM: `KMAC128/${d}`,
      BLOCK_SIZE: 168,
      DIGEST_SIZE: d >> 3,
    },
  )
}

/**
 * @description
 * The Keccak Message Authentication Code (KMAC) algorithm
 *
 * Keccak 消息认证码 (KMAC) 算法
 *
 * `KMAC256` is a variant of `KMAC`, build from `cSHAKE256`
 *
 * `KMAC256` 是 `KMAC` 的变体, 由 `cSHAKE256` 构建
 *
 * @example
 * ```ts
 * kmac128(256, 'password')('hello') // '430e760bc82ecf237af15141408fb68ddc507a6dccce0de478f23f6bdaba60ed608552ecdc371f5bf3445d2f2b54112813621b7436958e0087725212519f8a75'
 * kmac128(256, 'password')('hello', B64) // 'Qw52C8guzyN68VFBQI+2jdxQem3Mzg3kePI/a9q6YO1ghVLs3DcfW/NEXS8rVBEoE2IbdDaVjgCHclISUZ+KdQ=='
 * ```
 *
 * @param {number} d - 输出长度 bit
 * @param {string | Uint8Array} K - key
 * @param {string | Uint8Array} S - customization
 */
export function kmac256(d: number, K: string | Uint8Array = '', S: string | Uint8Array = '') {
  return createHash(
    (M: Uint8Array) => {
      const X = bytepad([...encodeString('KMAC'), ...encodeString(S)], 136)
      X.push(...bytepad(encodeString(K), 136))
      X.push(M)
      X.push(rightEncode(d))

      return Keccak_c(512, d, cShakePadding)(joinBuffer(...X))
    },
    {
      ALGORITHM: `KMAC256/${d}`,
      BLOCK_SIZE: 136,
      DIGEST_SIZE: d >> 3,
    },
  )
}

/**
 * @description
 * `KMAC` with Arbitrary-Length Output
 *
 * 可变长度输出的 `KMAC`
 *
 * `KMAC128XOF` is a XOF mode of `KMAC128`, build from `cSHAKE128`
 *
 * `KMAC128XOF` 是 `KMAC128` 的 XOF 模式, 由 `cSHAKE128` 构建
 *
 * @example
 * ```ts
 * kmac128(256, 'password')('hello') // 'd114b588da4337c80455806f3d461768c27931bcb6977c25d4611fb78e95da04'
 * kmac128(256, 'password')('hello', B64) // '0RS1iNpDN8gEVYBvPUYXaMJ5Mby2l3wl1GEft46V2gQ='
 * ```
 *
 * @param {number} d - 输出长度 bit
 * @param {string | Uint8Array} K - key
 * @param {string | Uint8Array} S - customization
 */
export function kmac128XOF(d: number, K: string | Uint8Array = '', S: string | Uint8Array = '') {
  return createHash(
    (M: Uint8Array) => {
      const X = bytepad([...encodeString('KMAC'), ...encodeString(S)], 168)
      X.push(...bytepad(encodeString(K), 168))
      X.push(M)
      X.push(rightEncode(0))

      return Keccak_c(256, d, cShakePadding)(joinBuffer(...X))
    },
    {
      ALGORITHM: `KMAC128XOF/${d}`,
      BLOCK_SIZE: 168,
      DIGEST_SIZE: d >> 3,
    },
  )
}

/**
 * @description
 * `KMAC` with Arbitrary-Length Output
 *
 * 可变长度输出的 `KMAC`
 *
 * `KMAC256XOF` is a XOF mode of `KMAC256`, build from `cSHAKE256`
 *
 * `KMAC256XOF` 是 `KMAC256` 的 XOF 模式, 由 `cSHAKE256` 构建
 *
 * @example
 * ```ts
 * kmac128(256, 'password')('hello') // '430e760bc82ecf237af15141408fb68ddc507a6dccce0de478f23f6bdaba60ed608552ecdc371f5bf3445d2f2b54112813621b7436958e0087725212519f8a75'
 * kmac128(256, 'password')('hello', B64) // 'Qw52C8guzyN68VFBQI+2jdxQem3Mzg3kePI/a9q6YO1ghVLs3DcfW/NEXS8rVBEoE2IbdDaVjgCHclISUZ+KdQ=='
 * ```
 *
 * @param {number} d - 输出长度 bit
 * @param {string | Uint8Array} K - key
 * @param {string | Uint8Array} S - customization
 */
export function kmac256XOF(d: number, K: string | Uint8Array = '', S: string | Uint8Array = '') {
  return createHash(
    (M: Uint8Array) => {
      const X = bytepad([...encodeString('KMAC'), ...encodeString(S)], 136)
      X.push(...bytepad(encodeString(K), 136))
      X.push(M)
      X.push(rightEncode(0))

      return Keccak_c(512, d, cShakePadding)(joinBuffer(...X))
    },
    {
      ALGORITHM: `KMAC256XOF/${d}`,
      BLOCK_SIZE: 136,
      DIGEST_SIZE: d >> 3,
    },
  )
}

// * TupleHash

/**
 * @description
 * `TupleHash` is a `SHA3` derived hash function with variable-length output that is designed to simply hash a tuple of input strings, any or all of which may be empty strings, in an unambiguous way.
 *
 * `TupleHash` 是一个具有可变长度输出的 `SHA3` 派生散列函数, 旨在以一种明确的方式简单地散列输入字符串的元组, 这些字符串中的任何一个或全部都可以是空字符串.
 *
 * @param {number} d - 输出长度 bit
 * @param {string | Uint8Array} S - customization
 */
export function tupleHash128(d: number, S: string | Uint8Array = '') {
  return createTupleHash(
    (M: Uint8Array[]) => {
      const X = bytepad([...encodeString('TupleHash'), ...encodeString(S)], 168)
      M.forEach(m => X.push(...encodeString(m)))
      X.push(rightEncode(d))

      return Keccak_c(256, d, cShakePadding)(joinBuffer(...X))
    },
    {
      ALGORITHM: `TupleHash128/${d}`,
      BLOCK_SIZE: 168,
      DIGEST_SIZE: d >> 3,
    },
  )
}

/**
 * @description
 * `TupleHash` is a `SHA3` derived hash function with variable-length output that is designed to simply hash a tuple of input strings, any or all of which may be empty strings, in an unambiguous way.
 *
 * `TupleHash` 是一个具有可变长度输出的 `SHA3` 派生散列函数, 旨在以一种明确的方式简单地散列输入字符串的元组, 这些字符串中的任何一个或全部都可以是空字符串.
 *
 * @param {number} d - 输出长度 bit
 * @param {string | Uint8Array} S - customization
 */
export function tupleHash256(d: number, S: string | Uint8Array = '') {
  return createTupleHash(
    (M: Uint8Array[]) => {
      const X = bytepad([...encodeString('TupleHash'), ...encodeString(S)], 136)
      M.forEach(m => X.push(...encodeString(m)))
      X.push(rightEncode(d))

      return Keccak_c(512, d, cShakePadding)(joinBuffer(...X))
    },
    {
      ALGORITHM: `TupleHash256/${d}`,
      BLOCK_SIZE: 136,
      DIGEST_SIZE: d >> 3,
    },
  )
}

/**
 * @description
 * `TupleHash` with Arbitrary-Length Output
 *
 * 可变长度输出的 `TupleHash`
 *
 * @param {number} d - 输出长度 bit
 * @param {string | Uint8Array} S - customization
 */
export function tupleHash128XOF(d: number, S: string | Uint8Array = '') {
  return createTupleHash(
    (M: Uint8Array[]) => {
      const X = bytepad([...encodeString('TupleHash'), ...encodeString(S)], 168)
      M.forEach(m => X.push(...encodeString(m)))
      X.push(rightEncode(0))

      return Keccak_c(256, d, cShakePadding)(joinBuffer(...X))
    },
    {
      ALGORITHM: `TupleHash128XOF/${d}`,
      BLOCK_SIZE: 168,
      DIGEST_SIZE: d >> 3,
    },
  )
}

/**
 * @description
 * `TupleHash` with Arbitrary-Length Output
 *
 * 可变长度输出的 `TupleHash`
 *
 * @param {number} d - 输出长度 bit
 * @param {string | Uint8Array} S - customization
 */
export function tupleHash256XOF(d: number, S: string | Uint8Array = '') {
  return createTupleHash(
    (M: Uint8Array[]) => {
      const X = bytepad([...encodeString('TupleHash'), ...encodeString(S)], 136)
      M.forEach(m => X.push(...encodeString(m)))
      X.push(rightEncode(0))

      return Keccak_c(512, d, cShakePadding)(joinBuffer(...X))
    },
    {
      ALGORITHM: `TupleHash256XOF/${d}`,
      BLOCK_SIZE: 136,
      DIGEST_SIZE: d >> 3,
    },
  )
}

// * ParallelHash

// ! Note: This ParallelHash does not actually perform parallel computation, because writing multi-threaded in JavaScript is not easy.
// ! 注意: 此 ParallelHash 实际上并不执行并行计算, 因为在 JavaScript 写多线程并不轻松.

// TODO 计划引入 `multithreading` 依赖, 实现真正的并行计算

/**
 * @description
 * The purpose of `ParallelHash` is to support the efficient hashing of very long strings, by taking advantage of the parallelism available in modern processors.
 *
 * `ParallelHash` 的目的是利用现代处理器中可用的并行性, 支持对非常长的字符串进行高效散列.
 *
 * ! Note: This `ParallelHash` does not actually perform parallel computation, because writing multi-threaded in `JavaScript` is not easy.
 *
 * ! 注意: 此 `ParallelHash` 实际上并不执行并行计算, 因为在 `JavaScript` 写多线程并不轻松.
 *
 * @param {number} b - 状态大小 bit
 * @param {number} d - 输出长度 bit
 * @param {string | Uint8Array} S - customization
 */
export function parallelHash128(b: number, d: number, S: string | Uint8Array = '') {
  const bByte = b >> 3
  return createHash(
    (M: Uint8Array) => {
      const n = Math.ceil(M.byteLength / bByte)
      const X = bytepad([...encodeString('ParallelHash'), ...encodeString(S)], 168)
      X.push(leftEncode(b))

      for (let i = 0; i < n; i++) {
        const B = M.slice(i * (b << 3), (i + 1) * (b << 3))
        X.push(shake128(256).digest(B))
      }

      X.push(rightEncode(n))
      X.push(rightEncode(d))

      return Keccak_c(256, d, cShakePadding)(joinBuffer(...X))
    },
    {
      ALGORITHM: `ParallelHash128/${d}`,
      BLOCK_SIZE: 168,
      DIGEST_SIZE: d >> 3,
    },
  )
}

/**
 * @description
 * The purpose of `ParallelHash` is to support the efficient hashing of very long strings, by taking advantage of the parallelism available in modern processors.
 *
 * `ParallelHash` 的目的是利用现代处理器中可用的并行性, 支持对非常长的字符串进行高效散列.
 *
 * ! Note: This `ParallelHash` does not actually perform parallel computation, because writing multi-threaded in `JavaScript` is not easy.
 *
 * ! 注意: 此 `ParallelHash` 实际上并不执行并行计算, 因为在 `JavaScript` 写多线程并不轻松.
 *
 * @param {number} b - 状态大小 bit
 * @param {number} d - 输出长度 bit
 * @param {string | Uint8Array} S - customization
 */
export function parallelHash256(b: number, d: number, S: string | Uint8Array = '') {
  const bByte = b >> 3
  return createHash(
    (M: Uint8Array) => {
      const n = Math.ceil(M.byteLength / bByte)
      const X = bytepad([...encodeString('ParallelHash'), ...encodeString(S)], 136)
      X.push(leftEncode(b))

      for (let i = 0; i < n; i++) {
        const B = M.slice(i * (b << 3), (i + 1) * (b << 3))
        X.push(shake256(512).digest(B))
      }

      X.push(rightEncode(n))
      X.push(rightEncode(d))

      return Keccak_c(512, d, cShakePadding)(joinBuffer(...X))
    },
    {
      ALGORITHM: `ParallelHash256/${d}`,
      BLOCK_SIZE: 136,
      DIGEST_SIZE: d >> 3,
    },
  )
}

/**
 * @description
 * `ParallelHash` with Arbitrary-Length Output
 *
 * 可变长度输出的 `ParallelHash`
 *
 * ! Note: This `ParallelHash` does not actually perform parallel computation, because writing multi-threaded in `JavaScript` is not easy.
 *
 * ! 注意: 此 `ParallelHash` 实际上并不执行并行计算, 因为在 `JavaScript` 写多线程并不轻松.
 *
 * @param {number} b - 状态大小 bit
 * @param {number} d - 输出长度 bit
 * @param {string | Uint8Array} S - customization
 */
export function parallelHash128XOF(b: number, d: number, S: string | Uint8Array = '') {
  const bByte = b >> 3
  return createHash(
    (M: Uint8Array) => {
      const n = Math.ceil(M.byteLength / bByte)
      const X = bytepad([...encodeString('ParallelHash'), ...encodeString(S)], 168)
      X.push(leftEncode(b))

      for (let i = 0; i < n; i++) {
        const B = M.slice(i * (b << 3), (i + 1) * (b << 3))
        X.push(shake128(256).digest(B))
      }

      X.push(rightEncode(n))
      X.push(rightEncode(0))

      return Keccak_c(256, d, cShakePadding)(joinBuffer(...X))
    },
    {
      ALGORITHM: `ParallelHash128XOF`,
      BLOCK_SIZE: 168,
      DIGEST_SIZE: 0,
    },
  )
}

/**
 * @description
 * `ParallelHash` with Arbitrary-Length Output
 *
 * 可变长度输出的 `ParallelHash`
 *
 * ! Note: This `ParallelHash` does not actually perform parallel computation, because writing multi-threaded in `JavaScript` is not easy.
 *
 * ! 注意: 此 `ParallelHash` 实际上并不执行并行计算, 因为在 `JavaScript` 写多线程并不轻松.
 *
 * @param {number} b - 状态大小 bit
 * @param {number} d - 输出长度 bit
 * @param {string | Uint8Array} S - customization
 */
export function parallelHash256XOF(b: number, d: number, S: string | Uint8Array = '') {
  const bByte = b >> 3
  return createHash(
    (M: Uint8Array) => {
      const n = Math.ceil(M.byteLength / bByte)
      const X = bytepad([...encodeString('ParallelHash'), ...encodeString(S)], 136)
      X.push(leftEncode(b))

      for (let i = 0; i < n; i++) {
        const B = M.slice(i * (b << 3), (i + 1) * (b << 3))
        X.push(shake256(512).digest(B))
      }

      X.push(rightEncode(n))
      X.push(rightEncode(0))

      return Keccak_c(512, d, cShakePadding)(joinBuffer(...X))
    },
    {
      ALGORITHM: `ParallelHash256XOF`,
      BLOCK_SIZE: 136,
      DIGEST_SIZE: 0,
    },
  )
}
