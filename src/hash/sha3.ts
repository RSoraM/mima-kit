import { createHash } from '../core/hash'
import { joinBuffer, rotateL64 } from '../core/utils'
import type { KeccakPermutation } from '../core/keccakUtils'
import { RCGen, Sponge } from '../core/keccakUtils'

// * Constants

const PERMUTATION: KeccakPermutation = {
  b: 1600,
  bByte: 200,
  w: 64,
  wByte: 8,
  l: 6,
  nr: 24,
}

// FIPS.202 3.2.2
// Algorithm 2: ρ(A) 位移表
const R = [
  [0, 36, 3, 41, 18],
  [1, 44, 10, 45, 2],
  [62, 6, 43, 15, 61],
  [28, 55, 25, 21, 56],
  [27, 20, 39, 8, 14],
]

// FIPS.202 3.2.5
// RC 由 Algorithm 5: rc(t) 生成
const RC = [
  0x0000000000000001n,
  0x0000000000008082n,
  0x800000000000808An,
  0x8000000080008000n,
  0x000000000000808Bn,
  0x0000000080000001n,
  0x8000000080008081n,
  0x8000000000008009n,
  0x000000000000008An,
  0x0000000000000088n,
  0x0000000080008009n,
  0x000000008000000An,
  0x000000008000808Bn,
  0x800000000000008Bn,
  0x8000000000008089n,
  0x8000000000008003n,
  0x8000000000008002n,
  0x8000000000000080n,
  0x000000000000800An,
  0x800000008000000An,
  0x8000000080008081n,
  0x8000000000008080n,
  0x0000000080000001n,
  0x8000000080008008n,
]

// * 3.1 State

type StateArray1600 = BigUint64Array[]

/**
 * ### createStateArray
 *
 * @description
 * 创建一个 5x5 State Array
 */
function createStateArray(): StateArray1600 {
  return Array.from({ length: 5 }).map(() => new BigUint64Array(5))
}

/**
 * ### toStateArray
 *
 * @description
 * 3.1.2 Converting State to State Arrays
 */
function toStateArray(S: Uint8Array) {
  const A = createStateArray()
  const view = new DataView(S.buffer)

  for (let x = 0; x < 5; x++) {
    for (let y = 0; y < 5; y++) {
      A[x][y] = view.getBigUint64((y * 5 + x) * PERMUTATION.wByte, true)
    }
  }

  return A
}

/**
 * ### toState
 *
 * @description
 * 3.1.3 Converting State Arrays to State
 */
function toState(A: StateArray1600) {
  const S = new Uint8Array(PERMUTATION.bByte)
  const view = new DataView(S.buffer)

  for (let x = 0; x < 5; x++) {
    for (let y = 0; y < 5; y++) {
      view.setBigUint64((y * 5 + x) * PERMUTATION.wByte, A[x][y], true)
    }
  }

  return S
}

// * 3.2 Step Mappings

/** Algorithm 1: θ(A) */
function theta(A: StateArray1600) {
  const C = new BigUint64Array(5)
  const D = new BigUint64Array(5)

  for (let x = 0; x < 5; x++) {
    C[x] = A[x][0] ^ A[x][1] ^ A[x][2] ^ A[x][3] ^ A[x][4]
  }

  for (let x = 0; x < 5; x++) {
    D[x] = C[(x + 4) % 5] ^ rotateL64(C[(x + 1) % 5], 1n)

    for (let y = 0; y < 5; y++) {
      A[x][y] = A[x][y] ^ D[x]
    }
  }

  return A
}

/** Algorithm 2: ρ(A) */
// eslint-disable-next-line unused-imports/no-unused-vars
function rho(A: StateArray1600) {
  const _A = createStateArray()
  for (let x = 0; x < 5; x++) {
    for (let y = 0; y < 5; y++) {
      _A[x][y] = rotateL64(A[x][y], BigInt(R[x][y]))
    }
  }
  return _A
}

/** Algorithm 3: π(A) */
// eslint-disable-next-line unused-imports/no-unused-vars
function pi(A: StateArray1600) {
  const _A = createStateArray()
  for (let x = 0; x < 5; x++) {
    for (let y = 0; y < 5; y++) {
      _A[y][(2 * x + 3 * y) % 5] = A[x][y]
    }
  }
  return _A
}

/** 合并执行 π(ρ(A)) */
function rhoPi(A: StateArray1600) {
  const _A = createStateArray()
  for (let x = 0; x < 5; x++) {
    for (let y = 0; y < 5; y++) {
      _A[y][(2 * x + 3 * y) % 5] = rotateL64(A[x][y], BigInt(R[x][y]))
    }
  }
  return _A
}

/** Algorithm 4: χ(A) */
function chi(A: StateArray1600) {
  const _A = createStateArray()
  for (let x = 0; x < 5; x++) {
    for (let y = 0; y < 5; y++) {
      _A[x][y] = A[x][y] ^ ((~A[(x + 1) % 5][y]) & A[(x + 2) % 5][y])
    }
  }
  return _A
}

/** Algorithm 6: ι(A, ir) */
function iota(A: StateArray1600, RC: bigint) {
  A[0][0] = A[0][0] ^ RC
  return A
}

// * Padding Function

/**
 * ### sha3Padding
 *
 * FIPS.202 B.2: <br>
 * SHA3 填充函数
 *
 * @param {number} rBit 吸收量(bit)
 * @param {number} sigByte 原始消息字节
 */
function sha3Padding(rBit: number, sigByte: number) {
  const rByte = rBit >> 3
  const q = rByte - (sigByte % rByte)
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
 * ### shakePadding
 *
 * @description
 * FIPS.202 B.2: <br>
 * SHAKE 填充函数
 *
 * @param {number} rBit 吸收量(bit)
 * @param {number} sigByte 原始消息字节
 */
function shakePadding(rBit: number, sigByte: number) {
  const rByte = rBit >> 3
  const q = rByte - (sigByte % rByte)
  const p = new Uint8Array(q)

  if (q === 1) {
    p[0] = 0xF9
    return p
  }

  p[0] = 0x1F
  p[q - 1] = 0x80
  return p
}

// * KECCAK-p[1600]

/**
 * ### Keccak-p[1600]
 *
 * @description
 * 吸收函数 f 生成器
 *
 * @param nr 轮数
 */
export function Keccak_p_1600(nr?: number) {
  nr = nr || PERMUTATION.nr

  // 当轮数非默认的情况下，重新生成 RC
  const _RC = nr === PERMUTATION.nr ? RC : RCGen(PERMUTATION, nr, true)

  /**
   * @param S 状态
   */
  return (S: Uint8Array) => {
    if (S.byteLength !== PERMUTATION.bByte) {
      throw new Error('Invalid state size')
    }

    let A = toStateArray(S)
    for (let i = 0; i < nr; i++) {
      A = iota(chi(rhoPi(theta(A))), _RC[i])
    }
    return toState(A)
  }
}

// * 6. SHA3 FUNCTION SPECIFICATIONS

/**
 * ### SHA3 生成函数
 *
 * @description
 * 对于 SHA3 系列函数, Keccak-p 使用固定参数 Keccak-p(b:1600, nr:24).
 * SHA3 和 SHA3 XOF 函数的区别只有 c, d, padding.
 * 因此生成函数只需要提供 c, d, padding.
 *
 * @param c 容量 bit
 * @param d 输出长度 bit
 * @param padding 填充函数
 */
function sha3(c: number, d: number, padding: typeof sha3Padding) {
  const r = PERMUTATION.b - c
  return (M: Uint8Array) => {
    /** Padded Message */
    const P = joinBuffer(M, padding(r, M.byteLength))

    return Sponge(Keccak_p_1600(), PERMUTATION.bByte, r >> 3)(P, d)
  }
}

/**
 * ### SHA3-224
 *
 * @description
 * SHA3-224 hash algorithm <br>
 * SHA3-224 散列算法
 *
 * @example
 * sha3_224('hello') // 'b87f88c72702fff1748e58b87e9141a42c0dbedc29a78cb0d4a5cd81'
 * sha3_224('hello', B64) // 'uH+IxycC//F0jli4fpFBpCwNvtwpp4yw1KXNgQ=='
 *
 * @param {string | Uint8Array} input 输入
 * @param {Codec} codec 输出编解码器
 */
export const sha3_224 = createHash(
  (M: Uint8Array) => sha3(448, 224, sha3Padding)(M),
  {
    ALGORITHM: 'SHA3-224',
    BLOCK_SIZE: 144,
    DIGEST_SIZE: 28,
  },
)

/**
 * ### SHA3-256
 *
 * @description
 * SHA3-256 hash algorithm <br>
 * SHA3-256 散列算法
 *
 * @example
 * sha3_256('hello') // '3338be694f50c5f338814986cdf0686453a888b84f424d792af4b9202398f392'
 * sha3_256('hello', B64) // 'Mzi+aU9QxfM4gUmGzfBoZFOoiLhPQk15KvS5ICOY85I='
 *
 * @param {string | Uint8Array} input 输入
 * @param {Codec} codec 输出编解码器
 */
export const sha3_256 = createHash(
  (M: Uint8Array) => sha3(512, 256, sha3Padding)(M),
  {
    ALGORITHM: 'SHA3-256',
    BLOCK_SIZE: 136,
    DIGEST_SIZE: 32,
  },
)

/**
 * ### SHA3-384
 *
 * @description
 * SHA3-384 hash algorithm <br>
 * SHA3-384 散列算法
 *
 * @example
 * sha3_384('hello') // '720aea11019ef06440fbf05d87aa24680a2153df3907b23631e7177ce620fa1330ff07c0fddee54699a4c3ee0ee9d887'
 * sha3_384('hello', B64) // 'cgrqEQGe8GRA+/Bdh6okaAohU985B7I2MecXfOYg+hMw/wfA/d7lRpmkw+4O6diH'
 *
 * @param {string | Uint8Array} input 输入
 * @param {Codec} codec 输出编解码器
 */
export const sha3_384 = createHash(
  (M: Uint8Array) => sha3(768, 384, sha3Padding)(M),
  {
    ALGORITHM: 'SHA3-384',
    BLOCK_SIZE: 104,
    DIGEST_SIZE: 48,
  },
)

/**
 * ### SHA3-512
 *
 * @description
 * SHA3-512 hash algorithm <br>
 * SHA3-512 散列算法
 *
 * @example
 * sha3_512('hello') // '75d527c368f2efe848ecf6b073a36767800805e9eef2b1857d5f984f036eb6df891d75f72d9b154518c1cd58835286d1da9a38deba3de98b5a53e5ed78a84976'
 * sha3_512('hello', B64) // 'ddUnw2jy7+hI7Pawc6NnZ4AIBenu8rGFfV+YTwNutt+JHXX3LZsVRRjBzViDUobR2po43ro96YtaU+XteKhJdg=='
 *
 * @param {string | Uint8Array} input 输入
 * @param {Codec} codec 输出编解码器
 */
export const sha3_512 = createHash(
  (M: Uint8Array) => sha3(1024, 512, sha3Padding)(M),
  {
    ALGORITHM: 'SHA3-512',
    BLOCK_SIZE: 72,
    DIGEST_SIZE: 64,
  },
)

/**
 * ### SHAKE128
 *
 * @description
 * SHAKE128 is one of the SHA3 OXF hash algorithm <br>
 * SHAKE128 是 SHA3 XOF 散列算法之一
 *
 * @example
 * shake128(256)('hello') // '8eb4b6a932f280335ee1a279f8c208a349e7bc65daf831d3021c213825292463'
 * shake128(256)('hello', B64) // 'jrS2qTLygDNe4aJ5+MIIo0nnvGXa+DHTAhwhOCUpJGM='
 *
 * @param {number} d 输出长度
 */
export function shake128(d: number) {
  return createHash(
    (M: Uint8Array) => sha3(256, d, shakePadding)(M),
    {
      ALGORITHM: `SHAKE128/${d}`,
      BLOCK_SIZE: 168,
      DIGEST_SIZE: d >> 3,
    },
  )
}

/**
 * ### SHAKE256
 *
 * @description
 * SHAKE256 is one of the SHA3 OXF hash algorithm <br>
 * SHAKE256 是 SHA3 XOF 散列算法之一
 *
 * @example
 * shake256(512)('hello') // '1234075ae4a1e77316cf2d8000974581a343b9ebbca7e3d1db83394c30f221626f594e4f0de63902349a5ea5781213215813919f92a4d86d127466e3d07e8be3'
 * shake256(512)('hello', B64) // 'EjQHWuSh53MWzy2AAJdFgaNDueu8p+PR24M5TDDyIWJvWU5PDeY5AjSaXqV4EhMhWBORn5Kk2G0SdGbj0H6L4w=='
 *
 * @param {number} d 输出长度
 */
export function shake256(d: number) {
  return createHash(
    (M: Uint8Array) => sha3(512, d, shakePadding)(M),
    {
      ALGORITHM: `SHAKE256/${d}`,
      BLOCK_SIZE: 136,
      DIGEST_SIZE: d >> 3,
    },
  )
}
