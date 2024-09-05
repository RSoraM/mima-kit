import { createHash } from '../core/hash'
import { joinBuffer } from '../core/utils'
import { PERMUTATION, Sponge_1600 } from './keccak1600'

// * SHA3 Padding Function

/**
 * @description
 * `SHA3` padding function interface
 *
 * `SHA3` 填充函数接口
 *
 * @param {number} rByte - 处理速率
 * @param {number} sigBytes - 消息字节数
 * @returns {Uint8Array} - 填充的内容
 */
interface Padding {
  (rByte: number, sigBytes: number): Uint8Array
}

/**
 * @description
 * FIPS.202 B.2:
 *
 * `SHA3` Padding
 *
 * `SHA3` 填充函数
 *
 * @example
 * ```
 * M || 01 || 10*1
 * ```
 *
 * @param {number} rByte - 处理速率
 * @param {number} sigBytes - 消息字节数
 */
const sha3Padding: Padding = (rByte: number, sigBytes: number) => {
  const q = rByte - (sigBytes % rByte)
  const p = new Uint8Array(q)

  if (q === 1) {
    p[0] = 0x86
    return p
  }

  p[0] = 0x06
  p[q - 1] = 0x80
  return p
}

/**
 * @description
 * FIPS.202 B.2:
 *
 * `SHAKE` Padding
 *
 * `SHAKE` 填充函数
 *
 * @example
 * ```
 * M || 1111 || 10*1
 * ```
 *
 * @param {number} rByte - 处理速率
 * @param {number} sigBytes - 消息字节数
 */
function shakePadding(rByte: number, sigBytes: number) {
  const q = rByte - (sigBytes % rByte)
  const p = new Uint8Array(q)

  if (q === 1) {
    p[0] = 0xF9
    return p
  }

  p[0] = 0x1F
  p[q - 1] = 0x80
  return p
}

// * SHA3 Function Specification

/**
 * @description
 * In the specification document, `Keccak[C]` is a specific configuration of `Keccak`. In different `SHA3` derivative algorithms, the input `M` will concatenate different bits, and perform `10*1` padding in the sponge function, such as `M || 01 || 10*1`. For byte-aligned programming languages, it is very difficult to implement this concatenation, so an additional `padding` function needs to be passed in to handle the padding of different algorithms.
 *
 * 在规范文档中, `Keccak[C]` 是 `Keccak` 的一种特定配置, 在不同的 `SHA3` 衍生算法中, 输入 `M` 会串接不同的比特位, 并在海绵函数中进行 `10*1` 填充, 比如 `M || 01 || 10*1`. 对于字节对齐的编程语言来说, 实现这种串接非常麻烦, 所以这里需要传入一个额外的 `padding` 函数, 以处理不同算法的填充.
 *
 * In other programming languages, `capacity c` and `rate r` may be equivalent as parameters. But from the perspective of `Javascript` implementation, we only need the parameter `rate r`, because the `capacity c` will not be used in the entire algorithm process. The only function of `capacity c` is to calculate the `rate r`. However, the algorithm description of `SHA3` in the specification document is based on `capacity c`, so here we follow the description of the specification document.
 *
 * 在别的编程语言中, `安全容量 c` 和 `处理速率 r` 作为参数可能是等效的. 但从 `Javascript` 实现的角度来说, 其实我们只需要参数 `处理速率 r`, 因为整个算法过程都不会用到 `安全容量 c`. `安全容量 c` 的唯一作用就是计算出 `处理速率 r`. 但规范文档中 `SHA3` 的算法描述都是以 `安全容量 c` 为基准的, 所以这里遵循规范文档的描述.
 *
 * @param {number} c - 安全容量 bit
 * @param {number} d - 输出长度 bit
 * @param {Padding} padding - 填充函数
 */
export function Keccak_c(c: number, d: number, padding: Padding) {
  const r = PERMUTATION.b - c
  const rByte = r >> 3
  return (M: Uint8Array) => {
    /** Padded Message */
    const P = joinBuffer(M, padding(rByte, M.byteLength))
    return Sponge_1600(rByte, d >> 3)(P)
  }
}

/**
 * @description
 * `SHA3-224` hash algorithm
 *
 * `SHA3-224` 散列算法
 *
 * @example
 * ```ts
 * sha3_224('hello') // 'b87f88c72702fff1748e58b87e9141a42c0dbedc29a78cb0d4a5cd81'
 * sha3_224('hello', B64) // 'uH+IxycC//F0jli4fpFBpCwNvtwpp4yw1KXNgQ=='
 * ```
 */
export const sha3_224 = createHash(
  {
    digest: (M: Uint8Array) => Keccak_c(448, 224, sha3Padding)(M),
  },
  {
    ALGORITHM: 'SHA3-224',
    BLOCK_SIZE: 144,
    DIGEST_SIZE: 28,
  },
)

/**
 * @description
 * `SHA3-256` hash algorithm
 *
 * `SHA3-256` 散列算法
 *
 * @example
 * ```ts
 * sha3_256('hello') // '3338be694f50c5f338814986cdf0686453a888b84f424d792af4b9202398f392'
 * sha3_256('hello', B64) // 'Mzi+aU9QxfM4gUmGzfBoZFOoiLhPQk15KvS5ICOY85I='
 * ```
 */
export const sha3_256 = createHash(
  {
    digest: (M: Uint8Array) => Keccak_c(512, 256, sha3Padding)(M),
  },
  {
    ALGORITHM: 'SHA3-256',
    BLOCK_SIZE: 136,
    DIGEST_SIZE: 32,
  },
)

/**
 * @description
 * `SHA3-384` hash algorithm
 *
 * `SHA3-384` 散列算法
 *
 * @example
 * ```ts
 * sha3_384('hello') // '720aea11019ef06440fbf05d87aa24680a2153df3907b23631e7177ce620fa1330ff07c0fddee54699a4c3ee0ee9d887'
 * sha3_384('hello', B64) // 'cgrqEQGe8GRA+/Bdh6okaAohU985B7I2MecXfOYg+hMw/wfA/d7lRpmkw+4O6diH'
 * ```
 */
export const sha3_384 = createHash(
  {
    digest: (M: Uint8Array) => Keccak_c(768, 384, sha3Padding)(M),
  },
  {
    ALGORITHM: 'SHA3-384',
    BLOCK_SIZE: 104,
    DIGEST_SIZE: 48,
  },
)

/**
 * @description
 * `SHA3-512` hash algorithm
 *
 * `SHA3-512` 散列算法
 *
 * @example
 * ```ts
 * sha3_512('hello') // '75d527c368f2efe848ecf6b073a36767800805e9eef2b1857d5f984f036eb6df891d75f72d9b154518c1cd58835286d1da9a38deba3de98b5a53e5ed78a84976'
 * sha3_512('hello', B64) // 'ddUnw2jy7+hI7Pawc6NnZ4AIBenu8rGFfV+YTwNutt+JHXX3LZsVRRjBzViDUobR2po43ro96YtaU+XteKhJdg=='
 * ```
 */
export const sha3_512 = createHash(
  {
    digest: (M: Uint8Array) => Keccak_c(1024, 512, sha3Padding)(M),
  },
  {
    ALGORITHM: 'SHA3-512',
    BLOCK_SIZE: 72,
    DIGEST_SIZE: 64,
  },
)

/**
 * @description
 * `SHAKE128` is one of the `SHA3` OXF hash algorithm
 *
 * `SHAKE128` 是 `SHA3` XOF 散列算法之一
 *
 * @example
 * ```ts
 * shake128(256)('hello') // '8eb4b6a932f280335ee1a279f8c208a349e7bc65daf831d3021c213825292463'
 * shake128(256)('hello', B64) // 'jrS2qTLygDNe4aJ5+MIIo0nnvGXa+DHTAhwhOCUpJGM='
 * ```
 *
 * @param {number} d - 输出长度 bit
 */
export function shake128(d: number) {
  return createHash(
    {
      digest: (M: Uint8Array) => Keccak_c(256, d, shakePadding)(M),
    },
    {
      ALGORITHM: `SHAKE128/${d}`,
      BLOCK_SIZE: 168,
      DIGEST_SIZE: d >> 3,
    },
  )
}

/**
 * @description
 * `SHAKE256` is one of the `SHA3` OXF hash algorithm
 *
 * `SHAKE256` 是 `SHA3` XOF 散列算法之一
 *
 * @example
 * ```ts
 * shake256(512)('hello') // '1234075ae4a1e77316cf2d8000974581a343b9ebbca7e3d1db83394c30f221626f594e4f0de63902349a5ea5781213215813919f92a4d86d127466e3d07e8be3'
 * shake256(512)('hello', B64) // 'EjQHWuSh53MWzy2AAJdFgaNDueu8p+PR24M5TDDyIWJvWU5PDeY5AjSaXqV4EhMhWBORn5Kk2G0SdGbj0H6L4w=='
 * ```
 *
 * @param {number} d - 输出长度 bit
 */
export function shake256(d: number) {
  return createHash(
    {
      digest: (M: Uint8Array) => Keccak_c(512, d, shakePadding)(M),
    },
    {
      ALGORITHM: `SHAKE256/${d}`,
      BLOCK_SIZE: 136,
      DIGEST_SIZE: d >> 3,
    },
  )
}
