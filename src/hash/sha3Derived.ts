import type { Codec } from '../core/codec'
import { HEX, UTF8 } from '../core/codec'
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
  input = typeof input === 'string' ? UTF8.parse(input) : input
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

export interface cSHAKEConfig {
  /**
   * function-name
   *
   * 函数名称
   *
   * @default ''
   */
  N?: string | Uint8Array
  /**
   * @default UTF8
   */
  N_CODEC?: Codec
  /**
   * customization
   *
   * 自定义参数
   *
   * @default ''
   */
  S?: string | Uint8Array
  /**
   * @default UTF8
   */
  S_CODEC?: Codec
  /**
   * @default UTF8
   */
  INPUT_CODEC?: Codec
  /**
   * @default HEX
   */
  OUTPUT_CODEC?: Codec
}

/**
 * @description
 * `cSHAKE128` is a customizable variant of `SHAKE128`
 *
 * `cSHAKE128` 是 `SHAKE128` 的可定制变体
 *
 * @example
 * ```ts
 * const config: cSHAKEConfig = {
 *   S: 'password',
 * }
 * cSHAKE128(256, config)('hello')
 * cSHAKE128(256, config)('hello', B64)
 * ```
 *
 * @param {number} d - 输出长度 bit
 * @param {cSHAKEConfig} config - 配置
 */
export function cShake128(d: number, config: cSHAKEConfig = {}) {
  let { N = new Uint8Array(), S = new Uint8Array() } = config
  const { N_CODEC = UTF8, S_CODEC = UTF8 } = config
  N = typeof N === 'string' ? N_CODEC.parse(N) : N
  S = typeof S === 'string' ? S_CODEC.parse(S) : S

  const INPUT_CODEC = config.INPUT_CODEC || UTF8
  const OUTPUT_CODEC = config.OUTPUT_CODEC || HEX
  const _description = {
    ALGORITHM: `cSHAKE128/${d}`,
    BLOCK_SIZE: 168,
    DIGEST_SIZE: d >> 3,
  }

  if (N.byteLength === 0 && S.byteLength === 0) {
    return createHash(
      {
        digest: shake128(d).digest,
        INPUT_CODEC,
        OUTPUT_CODEC,
      },
      _description,
    )
  }

  return createHash(
    {
      digest: (M: Uint8Array) => {
        const P = bytepad([...encodeString(N), ...encodeString(S)], 168)
        P.push(M)
        return Keccak_c(256, d, cShakePadding)(joinBuffer(...P))
      },
      INPUT_CODEC,
      OUTPUT_CODEC,
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
 * const config: cSHAKEConfig = {
 *   S: 'password',
 * }
 * cSHAKE256(512, config)('hello')
 * cSHAKE256(512, config)('hello', B64)
 * ```
 *
 * @param {number} d - 输出长度 bit
 * @param {cSHAKEConfig} config - 配置
 */
export function cShake256(d: number, config: cSHAKEConfig = {}) {
  let { N = new Uint8Array(), S = new Uint8Array() } = config
  const { N_CODEC = UTF8, S_CODEC = UTF8 } = config
  N = typeof N === 'string' ? N_CODEC.parse(N) : N
  S = typeof S === 'string' ? S_CODEC.parse(S) : S

  const INPUT_CODEC = config.INPUT_CODEC || UTF8
  const OUTPUT_CODEC = config.OUTPUT_CODEC || HEX
  const _description = {
    ALGORITHM: `cSHAKE256/${d}`,
    BLOCK_SIZE: 136,
    DIGEST_SIZE: d >> 3,
  }

  if (N.byteLength === 0 && S.byteLength === 0) {
    return createHash(
      {
        digest: shake256(d).digest,
        INPUT_CODEC,
        OUTPUT_CODEC,
      },
      _description,
    )
  }

  return createHash(
    {
      digest: (M: Uint8Array) => {
        const P = bytepad([...encodeString(N), ...encodeString(S)], 136)
        P.push(M)
        return Keccak_c(512, d, cShakePadding)(joinBuffer(...P))
      },
      INPUT_CODEC,
      OUTPUT_CODEC,
    },
    {
      ALGORITHM: `cSHAKE256/${d}`,
      BLOCK_SIZE: 136,
      DIGEST_SIZE: d >> 3,
    },
  )
}

// * KMAC

export interface KMACConfig {
  /**
   * key
   *
   * 密钥
   *
   * @default ''
   */
  K?: string | Uint8Array
  /**
   * @default UTF8
   */
  K_CODEC?: Codec
  /**
   * customization
   *
   * 自定义参数
   *
   * @default ''
   */
  S?: string | Uint8Array
  /**
   * @default UTF8
   */
  S_CODEC?: Codec
  /**
   * @default UTF8
   */
  INPUT_CODEC?: Codec
  /**
   * @default HEX
   */
  OUTPUT_CODEC?: Codec
}

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
 * const config: KMACConfig = {
 *   K: 'password',
 * }
 * kmac128(256, config)('hello')
 * kmac128(256, config)('hello', B64)
 * ```
 *
 * @param {number} d - 输出长度 bit
 * @param {KMACConfig} config - 配置
 */
export function kmac128(d: number, config: KMACConfig = {}) {
  let { K = new Uint8Array(), S = new Uint8Array() } = config
  const { K_CODEC = UTF8, S_CODEC = UTF8 } = config
  K = typeof K === 'string' ? K_CODEC.parse(K) : K
  S = typeof S === 'string' ? S_CODEC.parse(S) : S

  const INPUT_CODEC = config.INPUT_CODEC || UTF8
  const OUTPUT_CODEC = config.OUTPUT_CODEC || HEX

  return createHash(
    {
      digest: (M: Uint8Array) => {
        const X = bytepad([...encodeString('KMAC'), ...encodeString(S)], 168)
        X.push(...bytepad(encodeString(K), 168))
        X.push(M)
        X.push(rightEncode(d))

        return Keccak_c(256, d, cShakePadding)(joinBuffer(...X))
      },
      INPUT_CODEC,
      OUTPUT_CODEC,
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
 * const config: KMACConfig = {
 *   K: 'password
 * }
 * kmac128(256, config)('hello')
 * kmac128(256, config)('hello', B64)
 * ```
 *
 * @param {number} d - 输出长度 bit
 * @param {KMACConfig} config - 配置
 */
export function kmac256(d: number, config: KMACConfig = {}) {
  let { K = new Uint8Array(), S = new Uint8Array() } = config
  const { K_CODEC = UTF8, S_CODEC = UTF8 } = config
  K = typeof K === 'string' ? K_CODEC.parse(K) : K
  S = typeof S === 'string' ? S_CODEC.parse(S) : S

  const INPUT_CODEC = config.INPUT_CODEC || UTF8
  const OUTPUT_CODEC = config.OUTPUT_CODEC || HEX

  return createHash(
    {
      digest: (M: Uint8Array) => {
        const X = bytepad([...encodeString('KMAC'), ...encodeString(S)], 136)
        X.push(...bytepad(encodeString(K), 136))
        X.push(M)
        X.push(rightEncode(d))

        return Keccak_c(512, d, cShakePadding)(joinBuffer(...X))
      },
      INPUT_CODEC,
      OUTPUT_CODEC,
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
 * const config: KMACConfig = {
 *   K: 'password
 * }
 * kmac128(256, config)('hello')
 * kmac128(256, config)('hello', B64)
 * ```
 *
 * @param {number} d - 输出长度 bit
 * @param {KMACConfig} config - 配置
 */
export function kmac128XOF(d: number, config: KMACConfig = {}) {
  let { K = new Uint8Array(), S = new Uint8Array() } = config
  const { K_CODEC = UTF8, S_CODEC = UTF8 } = config
  K = typeof K === 'string' ? K_CODEC.parse(K) : K
  S = typeof S === 'string' ? S_CODEC.parse(S) : S

  const INPUT_CODEC = config.INPUT_CODEC || UTF8
  const OUTPUT_CODEC = config.OUTPUT_CODEC || HEX

  return createHash(
    {
      digest: (M: Uint8Array) => {
        const X = bytepad([...encodeString('KMAC'), ...encodeString(S)], 168)
        X.push(...bytepad(encodeString(K), 168))
        X.push(M)
        X.push(rightEncode(0))

        return Keccak_c(256, d, cShakePadding)(joinBuffer(...X))
      },
      INPUT_CODEC,
      OUTPUT_CODEC,
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
 * const config: KMACConfig = {
 *   K: 'password
 * }
 * kmac128(256, config)('hello')
 * kmac128(256, config)('hello', B64)
 * ```
 *
 * @param {number} d - 输出长度 bit
 * @param {KMACConfig} config - 配置
 */
export function kmac256XOF(d: number, config: KMACConfig = {}) {
  let { K = new Uint8Array(), S = new Uint8Array() } = config
  const { K_CODEC = UTF8, S_CODEC = UTF8 } = config
  K = typeof K === 'string' ? K_CODEC.parse(K) : K
  S = typeof S === 'string' ? S_CODEC.parse(S) : S

  const INPUT_CODEC = config.INPUT_CODEC || UTF8
  const OUTPUT_CODEC = config.OUTPUT_CODEC || HEX

  return createHash(
    {
      digest: (M: Uint8Array) => {
        const X = bytepad([...encodeString('KMAC'), ...encodeString(S)], 136)
        X.push(...bytepad(encodeString(K), 136))
        X.push(M)
        X.push(rightEncode(0))

        return Keccak_c(512, d, cShakePadding)(joinBuffer(...X))
      },
      INPUT_CODEC,
      OUTPUT_CODEC,
    },
    {
      ALGORITHM: `KMAC256XOF/${d}`,
      BLOCK_SIZE: 136,
      DIGEST_SIZE: d >> 3,
    },
  )
}

// * TupleHash

export interface TupleHashConfig {
  /**
   * customization
   *
   * 自定义参数
   *
   * @default ''
   */
  S?: string | Uint8Array
  /**
   * @default UTF8
   */
  S_CODEC?: Codec
  /**
   * @default UTF8
   */
  INPUT_CODEC?: Codec
  /**
   * @default HEX
   */
  OUTPUT_CODEC?: Codec
}

/**
 * @description
 * `TupleHash` is a `SHA3` derived hash function with variable-length output that is designed to simply hash a tuple of input strings, any or all of which may be empty strings, in an unambiguous way.
 *
 * `TupleHash` 是一个具有可变长度输出的 `SHA3` 派生散列函数, 旨在以一种明确的方式简单地散列输入字符串的元组, 这些字符串中的任何一个或全部都可以是空字符串.
 *
 * @param {number} d - 输出长度 bit
 * @param {TupleHashConfig} config - 配置
 */
export function tupleHash128(d: number, config: TupleHashConfig = {}) {
  let { S = new Uint8Array() } = config
  const { S_CODEC = UTF8 } = config
  S = typeof S === 'string' ? S_CODEC.parse(S) : S

  const { INPUT_CODEC = UTF8, OUTPUT_CODEC = HEX } = config

  return createTupleHash(
    {
      digest: (M: Uint8Array[]) => {
        const X = bytepad([...encodeString('TupleHash'), ...encodeString(S)], 168)
        M.forEach(m => X.push(...encodeString(m)))
        X.push(rightEncode(d))

        return Keccak_c(256, d, cShakePadding)(joinBuffer(...X))
      },
      INPUT_CODEC,
      OUTPUT_CODEC,
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
 * @param {TupleHashConfig} config - 配置
 */
export function tupleHash256(d: number, config: TupleHashConfig = {}) {
  let { S = new Uint8Array() } = config
  const { S_CODEC = UTF8 } = config
  S = typeof S === 'string' ? S_CODEC.parse(S) : S

  const { INPUT_CODEC = UTF8, OUTPUT_CODEC = HEX } = config

  return createTupleHash(
    {
      digest: (M: Uint8Array[]) => {
        const X = bytepad([...encodeString('TupleHash'), ...encodeString(S)], 136)
        M.forEach(m => X.push(...encodeString(m)))
        X.push(rightEncode(d))

        return Keccak_c(512, d, cShakePadding)(joinBuffer(...X))
      },
      INPUT_CODEC,
      OUTPUT_CODEC,
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
 * @param {TupleHashConfig} config - 配置
 */
export function tupleHash128XOF(d: number, config: TupleHashConfig = {}) {
  let { S = new Uint8Array() } = config
  const { S_CODEC = UTF8 } = config
  S = typeof S === 'string' ? S_CODEC.parse(S) : S

  const { INPUT_CODEC = UTF8, OUTPUT_CODEC = HEX } = config

  return createTupleHash(
    {
      digest: (M: Uint8Array[]) => {
        const X = bytepad([...encodeString('TupleHash'), ...encodeString(S)], 168)
        M.forEach(m => X.push(...encodeString(m)))
        X.push(rightEncode(0))

        return Keccak_c(256, d, cShakePadding)(joinBuffer(...X))
      },
      INPUT_CODEC,
      OUTPUT_CODEC,
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
 * @param {TupleHashConfig} config - 配置
 */
export function tupleHash256XOF(d: number, config: TupleHashConfig = {}) {
  let { S = new Uint8Array() } = config
  const { S_CODEC = UTF8 } = config
  S = typeof S === 'string' ? S_CODEC.parse(S) : S

  const { INPUT_CODEC = UTF8, OUTPUT_CODEC = HEX } = config

  return createTupleHash(
    {
      digest: (M: Uint8Array[]) => {
        const X = bytepad([...encodeString('TupleHash'), ...encodeString(S)], 136)
        M.forEach(m => X.push(...encodeString(m)))
        X.push(rightEncode(0))

        return Keccak_c(512, d, cShakePadding)(joinBuffer(...X))
      },
      INPUT_CODEC,
      OUTPUT_CODEC,
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

export interface ParallelHashConfig extends TupleHashConfig { }

/**
 * @description
 * The purpose of `ParallelHash` is to support the efficient hashing of very long strings, by taking advantage of the parallelism available in modern processors.
 *
 * `ParallelHash` 的目的是利用现代处理器中可用的并行性, 支持对非常长的字符串进行高效散列.
 *
 * @param {number} b - 状态大小 bit
 * @param {number} d - 输出长度 bit
 * @param {ParallelHashConfig} config - 配置
 */
export function parallelHash128(b: number, d: number, config: ParallelHashConfig = {}) {
  let { S = new Uint8Array() } = config
  const { S_CODEC = UTF8 } = config
  S = typeof S === 'string' ? S_CODEC.parse(S) : S

  const { INPUT_CODEC = UTF8, OUTPUT_CODEC = HEX } = config

  const bByte = b >> 3
  return createHash(
    {
      digest: (M: Uint8Array) => {
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
      INPUT_CODEC,
      OUTPUT_CODEC,
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
 * @param {number} b - 状态大小 bit
 * @param {number} d - 输出长度 bit
 * @param {ParallelHashConfig} config - 配置
 */
export function parallelHash256(b: number, d: number, config: ParallelHashConfig = {}) {
  let { S = new Uint8Array() } = config
  const { S_CODEC = UTF8 } = config
  S = typeof S === 'string' ? S_CODEC.parse(S) : S

  const { INPUT_CODEC = UTF8, OUTPUT_CODEC = HEX } = config

  const bByte = b >> 3
  return createHash(
    {
      digest: (M: Uint8Array) => {
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
      INPUT_CODEC,
      OUTPUT_CODEC,
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
 * @param {number} b - 状态大小 bit
 * @param {number} d - 输出长度 bit
 * @param {ParallelHashConfig} config - 配置
 */
export function parallelHash128XOF(b: number, d: number, config: ParallelHashConfig = {}) {
  let { S = new Uint8Array() } = config
  const { S_CODEC = UTF8 } = config
  S = typeof S === 'string' ? S_CODEC.parse(S) : S

  const { INPUT_CODEC = UTF8, OUTPUT_CODEC = HEX } = config

  const bByte = b >> 3
  return createHash(
    {
      digest: (M: Uint8Array) => {
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
      INPUT_CODEC,
      OUTPUT_CODEC,
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
 * @param {number} b - 状态大小 bit
 * @param {number} d - 输出长度 bit
 * @param {ParallelHashConfig} config - 配置
 */
export function parallelHash256XOF(b: number, d: number, config: ParallelHashConfig = {}) {
  let { S = new Uint8Array() } = config
  const { S_CODEC = UTF8 } = config
  S = typeof S === 'string' ? S_CODEC.parse(S) : S

  const { INPUT_CODEC = UTF8, OUTPUT_CODEC = HEX } = config

  const bByte = b >> 3
  return createHash(
    {
      digest: (M: Uint8Array) => {
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
      INPUT_CODEC,
      OUTPUT_CODEC,
    },
    {
      ALGORITHM: `ParallelHash256XOF`,
      BLOCK_SIZE: 136,
      DIGEST_SIZE: 0,
    },
  )
}
