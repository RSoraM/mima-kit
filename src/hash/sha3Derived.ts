import { UTF8 } from '../core/codec';
import type { Hash, KeyHash } from '../core/hash';
import { createHash, createKeyHash, createTupleHash } from '../core/hash';
import { joinBuffer, KitError, U8, u8 } from '../core/utils';
import type { Sha3Padding } from './sha3';
import { Keccak_c, shake128, shake256 } from './sha3';

// * Encode and Padding Function

/**
 * SP.800-185 2.3.1:
 *
 * 左侧整数编码 / left_encode
 *
 * Inspired by https://github.com/paulmillr/noble-hashes
 *
 * ```ts
 * leftEncode(0) // Uint8Array(2) [ 1, 0 ]
 * leftEncode(18446744073709551615n) // Uint8Array(9) [ 8, 255, 255, 255, 255, 255, 255, 255, 255 ]
 * ```
 *
 * @param {number} x - 输入 / input
 */
function leftEncode(x: number): Uint8Array {
  const result = [];
  do {
    result.unshift(x & 0xff);
    x = x >> 8;
  } while (x > 0);
  result.unshift(result.length);
  return Uint8Array.from(result);
}

/**
 * SP.800-185 2.3.1:
 *
 * 右侧整数编码 / right_encode
 *
 * Inspired by https://github.com/paulmillr/noble-hashes
 *
 * ```ts
 * rightEncode(0) // Uint8Array(2) [ 0, 1 ]
 * rightEncode(18446744073709551615n) // Uint8Array(9) [ 255, 255, 255, 255, 255, 255, 255, 255, 8 ]
 * ```
 *
 * @param {number | bigint} x - 输入 / input
 */
function rightEncode(x: number): Uint8Array {
  const result = [];
  do {
    result.unshift(x & 0xff);
    x = x >> 8;
  } while (x > 0);
  result.push(result.length);
  return Uint8Array.from(result);
}

/**
 * SP.800-185 2.3.2:
 *
 * 字符编码 / encode_string
 *
 * 与规范文档不同, 这个实现不会进行串接操作, 而是返回一个数组, 串接操作在外部进行. 详细见 `bytepad` 函数.
 *
 * Unlike the specification document, this implementation does not perform concatenation operations, but returns an array, and the concatenation operation is performed externally. See `bytepad` function for details.
 *
 * ```ts
 * encodeString(K) // [left_encode(len(K)), K]
 * ```
 *
 * @param {string | Uint8Array} input - 输入 / input
 */
function encodeString(input: string | Uint8Array) {
  input = typeof input === 'string' ? UTF8(input) : input;
  return [leftEncode(input.byteLength << 3), input];
}

/**
 * SP.800-185 2.3.3:
 *
 * 在算法中 `bytepad` 涉及很多串接操作, 但对 `Javascript` 实现来说, 每次串接都意味着创建 `Uint8Array` 进行合并. 频繁地创建 `Uint8Array` 有可能导致性能问题.
 * 这是一个优化后的实现. 将输入 `X` 改为数组, 最后也返回数组, 将合并操作移动到外部.
 *
 * The `bytepad` is used by many algorithms which involves many concatenation operations, but for `Javascript` implementation, each concatenation means creating a `Uint8Array` for merging. Frequent creation of `Uint8Array` may cause performance issues.
 * This is an optimized implementation. The input `X` is changed to an array, and the final return is also an array. The merge operation is moved to the outside.
 *
 *
 * ```ts
 * bytepad(X, w) = left_encode(w) || X0 || ... || Xn || 0^z
 * ```
 *
 * @param {Uint8Array} X - 输入数组 / input array
 * @param {number} w - 字节倍数 / byte multiple
 */
function bytepad(X: Uint8Array[], w: number): Uint8Array[] {
  if (w <= 0) {
    throw new KitError('w must be greater than 0');
  }

  // 使用 leftEncode 函数编码 w
  const left_encoded_w = leftEncode(w);

  // z = left_encode(w) || X0 || ... || Xn

  // 计算 z 的有效字节长度总和, 用于计算填充零字节的数量
  let z_byte = left_encoded_w.length;
  X.forEach((x) => {
    z_byte += x.length;
  });

  // 计算需要填充的零字节的数量
  const zero_byte = w - (z_byte % w);

  X.unshift(left_encoded_w);
  X.push(new Uint8Array(zero_byte));

  return X;
}

/**
 * `cSHAKE` 填充函数 / Padding Function
 *
 * ```ts
 * M || 00 || 10*1
 * ```
 *
 * @param {number} r_byte - 处理速率 / Rate
 */
const cshakePadding: Sha3Padding = (r_byte: number) => {
  return (M: Uint8Array) => {
    const sig_byte = M.length;
    const pad_byte = r_byte - (sig_byte % r_byte);
    const P = new U8(sig_byte + pad_byte);
    P.set(M);
    if (pad_byte === 1) {
      P[sig_byte] = 0x84;
    }
    P[sig_byte] = 0x04;
    P[P.length - 1] |= 0x80;
    return P;
  };
};

// * cSHAKE

/**
 * @param {number} d - 输出长度 / Digest Size (bit)
 * @param {Uint8Array} N - 函数名 / Function name
 * @param {Uint8Array} S - 自定义参数 / Customization
 * @param {number} c - 安全容量 / capacity (bit)
 * @param {number} r_byte - 处理速率 / Rate (byte)
 * @param {Hash} SHAKE - SHAKE 函数
 */
function cshake(
  d: number,
  N: Uint8Array,
  S: Uint8Array,
  c: number,
  r_byte: number,
  SHAKE: typeof shake128,
) {
  if (N.byteLength === 0 && S.byteLength === 0) {
    return (M: Uint8Array) => SHAKE(d)(M);
  }
  return (M: Uint8Array) => {
    const P = bytepad([...encodeString(N), ...encodeString(S)], r_byte);
    P.push(M);
    return Keccak_c(c, d, cshakePadding)(joinBuffer(...P));
  };
}

/**
 * `cSHAKE128` 是 `SHAKE128` 的可定制变体
 *
 * `cSHAKE128` is a customizable variant of `SHAKE128`
 *
 * @param {number} d - 输出长度 / Digest Size (bit)
 * @param {Uint8Array} [N] - 函数名 / Function name
 * @param {Uint8Array} [S] - 自定义参数 / Customization
 */
export function cshake128(d: number, N = new Uint8Array(), S = new Uint8Array()) {
  return createHash(cshake(d, N, S, 256, 168, shake128), {
    ALGORITHM: `cSHAKE128/${d}`,
    BLOCK_SIZE: 168,
    DIGEST_SIZE: d >> 3,
  });
}

/**
 * `cSHAKE256` 是 `SHAKE256` 的可定制变体
 *
 * `cSHAKE256` is a customizable variant of `SHAKE256`
 *
 * @param {number} d - 输出长度 / Digest Size (bit)
 * @param {Uint8Array} [N] - 函数名 / Function name
 * @param {Uint8Array} [S] - 自定义参数 / Customization
 */
export function cshake256(d: number, N = new Uint8Array(), S = new Uint8Array()) {
  return createHash(cshake(d, N, S, 512, 136, shake256), {
    ALGORITHM: `cSHAKE256/${d}`,
    BLOCK_SIZE: 136,
    DIGEST_SIZE: d >> 3,
  });
}

// * KMAC

/**
 * @param {number} d - 输出长度 / Digest Size (bit)
 * @param {Uint8Array} S - 自定义参数 / Customization
 * @param {number} c - 安全容量 / capacity (bit)
 * @param {number} r_byte - 处理速率 / Rate (byte)
 * @param {boolean} XOF - 是否为 XOF 模式 / XOF mode
 */
function kmac(d: number, S: Uint8Array, c: number, r_byte: number, XOF: boolean) {
  return (K: Uint8Array, M: Uint8Array) => {
    const X = bytepad([...encodeString('KMAC'), ...encodeString(S)], r_byte);
    X.push(...bytepad(encodeString(K), r_byte));
    X.push(M);
    X.push(rightEncode(XOF ? 0 : d));
    return Keccak_c(c, d, cshakePadding)(joinBuffer(...X));
  };
}

/**
 * Keccak 消息认证码 (KMAC) 算法
 * `KMAC128` 是 `KMAC` 的变体, 由 `cSHAKE128` 构建
 *
 * The Keccak Message Authentication Code (KMAC) algorithm
 * `KMAC128` is a variant of `KMAC`, build from `cSHAKE128`
 *
 * @param {number} d - 输出长度 / Digest Size (bit)
 * @param {Uint8Array} S - 自定义参数 / Customization
 * @param {number} k_size - 推荐密钥大小 / Recommended key size (bit)
 */
export function kmac128(d: number, S = new Uint8Array(0), k_size: number = 128): KeyHash {
  return createKeyHash(kmac(d, S, 256, 168, false), {
    ALGORITHM: `KMAC128/${d}`,
    BLOCK_SIZE: 168,
    DIGEST_SIZE: d >> 3,
    KEY_SIZE: k_size >> 3,
  });
}

/**
 * Keccak 消息认证码 (KMAC) 算法
 * `KMAC256` 是 `KMAC` 的变体, 由 `cSHAKE256` 构建
 *
 * The Keccak Message Authentication Code (KMAC) algorithm
 * `KMAC256` is a variant of `KMAC`, build from `cSHAKE256`
 *
 * @param {number} d - 输出长度 / Digest Size (bit)
 * @param {Uint8Array} S - 自定义参数 / Customization
 * @param {number} k_size - 推荐密钥大小 / Recommended key size (bit)
 */
export function kmac256(d: number, S = new Uint8Array(0), k_size: number = 256): KeyHash {
  return createKeyHash(kmac(d, S, 512, 136, false), {
    ALGORITHM: `KMAC256/${d}`,
    BLOCK_SIZE: 136,
    DIGEST_SIZE: d >> 3,
    KEY_SIZE: k_size >> 3,
  });
}

/**
 * 可变长度输出的 `KMAC`
 * `KMAC128XOF` 是 `KMAC128` 的 XOF 模式, 由 `cSHAKE128` 构建
 *
 * `KMAC` with Arbitrary-Length Output
 * `KMAC128XOF` is a XOF mode of `KMAC128`, build from `cSHAKE128`
 *
 * @param {number} d - 输出长度 / Digest Size (bit)
 * @param {Uint8Array} S - 自定义参数 / Customization
 * @param {number} k_size - 推荐密钥大小 / Recommended key size (bit)
 */
export function kmac128XOF(d: number, S = new Uint8Array(0), k_size: number = 128): KeyHash {
  return createKeyHash(kmac(d, S, 256, 168, true), {
    ALGORITHM: `KMAC128XOF/${d}`,
    BLOCK_SIZE: 168,
    DIGEST_SIZE: d >> 3,
    KEY_SIZE: k_size >> 3,
  });
}

/**
 * 可变长度输出的 `KMAC`
 * `KMAC256XOF` 是 `KMAC256` 的 XOF 模式, 由 `cSHAKE256` 构建
 *
 * `KMAC` with Arbitrary-Length Output
 * `KMAC256XOF` is a XOF mode of `KMAC256`, build from `cSHAKE256`
 *
 * @param {number} d - 输出长度 / Digest Size (bit)
 * @param {Uint8Array} S - 自定义参数 / Customization
 * @param {number} k_size - 推荐密钥大小 / recommended key size (bit)
 */
export function kmac256XOF(d: number, S = new Uint8Array(0), k_size: number = 256): KeyHash {
  return createKeyHash(kmac(d, S, 512, 136, true), {
    ALGORITHM: `KMAC256XOF/${d}`,
    BLOCK_SIZE: 136,
    DIGEST_SIZE: d >> 3,
    KEY_SIZE: k_size >> 3,
  });
}

// * TupleHash

/**
 * @param {number} d - 输出长度 / Digest Size (bit)
 * @param {Uint8Array} S - 自定义参数 / Customization
 * @param {number} c - 安全容量 / capacity (bit)
 * @param {number} r_byte - 处理速率 / Rate (byte)
 * @param {boolean} XOF - 是否为 XOF 模式 / XOF mode
 */
function tuplehash(d: number, S: Uint8Array, c: number, r_byte: number, XOF: boolean) {
  return (M: Uint8Array[]) => {
    const X = bytepad([...encodeString('TupleHash'), ...encodeString(S)], r_byte);
    M.forEach((m) => {
      X.push(...encodeString(m));
    });
    X.push(rightEncode(XOF ? 0 : d));
    return Keccak_c(c, d, cshakePadding)(joinBuffer(...X));
  };
}

/**
 * `TupleHash` 是一个具有可变长度输出的 `SHA3` 派生散列函数, 旨在以一种明确的方式简单地散列输入字符串的元组, 这些字符串中的任何一个或全部都可以是空字符串.
 *
 * `TupleHash` is a `SHA3` derived hash function with variable-length output that is designed to simply hash a tuple of input strings, any or all of which may be empty strings, in an unambiguous way.
 *
 * @param {number} d - 输出长度 / Digest Size (bit)
 * @param {Uint8Array} S - 自定义参数 / Customization
 */
export function tuplehash128(d: number, S: Uint8Array = new Uint8Array()) {
  return createTupleHash(tuplehash(d, S, 256, 168, false), {
    ALGORITHM: `TupleHash128/${d}`,
    BLOCK_SIZE: 168,
    DIGEST_SIZE: d >> 3,
  });
}

/**
 * `TupleHash` 是一个具有可变长度输出的 `SHA3` 派生散列函数, 旨在以一种明确的方式简单地散列输入字符串的元组, 这些字符串中的任何一个或全部都可以是空字符串.
 *
 * `TupleHash` is a `SHA3` derived hash function with variable-length output that is designed to simply hash a tuple of input strings, any or all of which may be empty strings, in an unambiguous way.
 *
 * @param {number} d - 输出长度 / Digest Size (bit)
 * @param {Uint8Array} S - 自定义参数 / Customization
 */
export function tuplehash256(d: number, S: Uint8Array = new Uint8Array()) {
  return createTupleHash(tuplehash(d, S, 512, 136, false), {
    ALGORITHM: `TupleHash256/${d}`,
    BLOCK_SIZE: 136,
    DIGEST_SIZE: d >> 3,
  });
}

/**
 * 可变长度输出的 `TupleHash`
 *
 * `TupleHash` with Arbitrary-Length Output
 *
 * @param {number} d - 输出长度 / Digest Size (bit)
 * @param {Uint8Array} S - 自定义参数 / Customization
 */
export function tuplehash128XOF(d: number, S: Uint8Array = new Uint8Array()) {
  return createTupleHash(tuplehash(d, S, 256, 168, true), {
    ALGORITHM: `TupleHash128XOF/${d}`,
    BLOCK_SIZE: 168,
    DIGEST_SIZE: d >> 3,
  });
}

/**
 * 可变长度输出的 `TupleHash`
 *
 * `TupleHash` with Arbitrary-Length Output
 *
 * @param {number} d - 输出长度 / Digest Size (bit)
 * @param {Uint8Array} S - 自定义参数 / Customization
 */
export function tuplehash256XOF(d: number, S: Uint8Array = new Uint8Array()) {
  return createTupleHash(tuplehash(d, S, 512, 136, true), {
    ALGORITHM: `TupleHash256XOF/${d}`,
    BLOCK_SIZE: 136,
    DIGEST_SIZE: d >> 3,
  });
}

// * ParallelHash

// ! Note: This ParallelHash does not actually perform parallel computation, because writing multi-threaded in JavaScript is not easy.
// ! 注意: 此 ParallelHash 实际上并不执行并行计算, 因为在 JavaScript 写多线程并不轻松.

// TODO 计划引入 `multithreading` 依赖, 实现真正的并行计算

/**
 * @param {number} b - 状态大小 / State size (bit)
 * @param {number} d - 输出长度 / Digest Size (bit)
 * @param {Uint8Array} S - 自定义参数 / Customization
 * @param {number} c - 安全容量 / capacity (bit)
 * @param {number} r_byte - 处理速率 / Rate (byte)
 * @param {boolean} XOF - 是否为 XOF 模式 / XOF mode
 */
function parallelhash(
  b: number,
  d: number,
  S: Uint8Array,
  c: number,
  r_byte: number,
  XOF: boolean,
  SHAKE: Hash,
) {
  const bByte = b >> 3;
  return (M: Uint8Array) => {
    M = u8(M);
    const n = Math.ceil(M.byteLength / bByte);
    const X = bytepad([...encodeString('ParallelHash'), ...encodeString(S)], r_byte);
    X.push(leftEncode(b));

    for (let i = 0; i < n; i++) {
      const B = M.slice(i * (b << 3), (i + 1) * (b << 3));
      X.push(SHAKE(B));
    }

    X.push(rightEncode(n));
    X.push(rightEncode(XOF ? 0 : d));

    return Keccak_c(c, d, cshakePadding)(joinBuffer(...X));
  };
}

/**
 * `ParallelHash` 的目的是利用现代处理器中可用的并行性, 支持对非常长的字符串进行高效散列.
 *
 * The purpose of `ParallelHash` is to support the efficient hashing of very long strings, by taking advantage of the parallelism available in modern processors.
 *
 * @param {number} b - 状态大小 / State size (bit)
 * @param {number} d - 输出长度 / Digest Size (bit)
 * @param {Uint8Array} S - 自定义参数 / Customization
 */
export function parallelhash128(b: number, d: number, S: Uint8Array = new Uint8Array()) {
  return createHash(parallelhash(b, d, S, 256, 168, false, shake128(256)), {
    ALGORITHM: `ParallelHash128/${d}`,
    BLOCK_SIZE: 168,
    DIGEST_SIZE: d >> 3,
  });
}

/**
 * `ParallelHash` 的目的是利用现代处理器中可用的并行性, 支持对非常长的字符串进行高效散列.
 *
 * The purpose of `ParallelHash` is to support the efficient hashing of very long strings, by taking advantage of the parallelism available in modern processors.
 *
 * @param {number} b - 状态大小 / State size (bit)
 * @param {number} d - 输出长度 / Digest Size (bit)
 * @param {Uint8Array} S - 自定义参数 / Customization
 */
export function parallelhash256(b: number, d: number, S: Uint8Array = new Uint8Array()) {
  return createHash(parallelhash(b, d, S, 512, 136, false, shake256(512)), {
    ALGORITHM: `ParallelHash256/${d}`,
    BLOCK_SIZE: 136,
    DIGEST_SIZE: d >> 3,
  });
}

/**
 * 可变长度输出的 `ParallelHash`
 *
 * `ParallelHash` with Arbitrary-Length Output
 *
 * @param {number} b - 状态大小 / State size (bit)
 * @param {number} d - 输出长度 / Digest Size (bit)
 * @param {Uint8Array} S - 自定义参数 / Customization
 */
export function parallelhash128XOF(b: number, d: number, S: Uint8Array = new Uint8Array()) {
  return createHash(parallelhash(b, d, S, 256, 168, true, shake128(256)), {
    ALGORITHM: `ParallelHash128XOF`,
    BLOCK_SIZE: 168,
    DIGEST_SIZE: d >> 3,
  });
}

/**
 * 可变长度输出的 `ParallelHash`
 *
 * `ParallelHash` with Arbitrary-Length Output
 *
 * @param {number} b - 状态大小 / State size (bit)
 * @param {number} d - 输出长度 / Digest Size (bit)
 * @param {Uint8Array} S - 自定义参数 / Customization
 */
export function parallelhash256XOF(b: number, d: number, S: Uint8Array = new Uint8Array()) {
  return createHash(parallelhash(b, d, S, 512, 136, true, shake256(512)), {
    ALGORITHM: `ParallelHash256XOF`,
    BLOCK_SIZE: 136,
    DIGEST_SIZE: d >> 3,
  });
}
