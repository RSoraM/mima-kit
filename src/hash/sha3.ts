import type { Codec } from '../core/codec'
import { Hex, Utf8 } from '../core/codec'
import { rotateLn } from '../core/utils'

// * Constants

// FIPS.202 3.1
// b is size of KECCAK-p PERMUTATIONS(aka. State size).
// w = b / 25
// l = log2(w)
// nr = 12 + 2 * l
//
// |  b | 25 | 50 | 100 | 200 | 400 | 800 | 1600 |
// |----|----|----|-----|-----|-----|-----|------|
// |  w |  1 |  2 |   4 |   8 |  16 |  32 |   64 |
// |  l |  0 |  1 |   2 |   3 |   4 |   5 |    6 |
// | nr | 12 | 14 |  16 |  18 |  20 |  22 |   24 |
//
const LEGAL_B = [25, 50, 100, 200, 400, 800, 1600]

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

type StateArray = Array<BigUint64Array>

/**
 * @function createStateArray
 * @description
 * 创建一个 5x5 State Array
 * @returns State Array
 */
function createStateArray(): StateArray {
  return Array.from({ length: 5 }).map(
    () => new BigUint64Array(5),
  )
}

/**
 * @function toStateArray
 * @description
 * 3.1.2 Converting State to State Arrays
 */
function toStateArray(S: ArrayBuffer) {
  const A: StateArray = createStateArray()
  const view = new BigUint64Array(S)

  for (let x = 0; x < 5; x++) {
    for (let y = 0; y < 5; y++) {
      A[x][y] = view[y * 5 + x]
    }
  }

  return A
}

/**
 * @function toState
 * @description
 * 3.1.3 Converting State Arrays to State
 */
function toState(A: StateArray) {
  const S = new ArrayBuffer(200)
  const view = new BigUint64Array(S)

  for (let y = 0; y < 5; y++) {
    for (let x = 0; x < 5; x++) {
      view[y * 5 + x] = A[x][y]
    }
  }

  return S
}

// * 3.2 Step Mappings

/**
 * Algorithm 1: θ(A)
 */
function theta(A: StateArray) {
  const _A = createStateArray()

  const C = new BigUint64Array(5)
  const D = new BigUint64Array(5)

  for (let x = 0; x < 5; x++) {
    C[x] = A[x][0] ^ A[x][1] ^ A[x][2] ^ A[x][3] ^ A[x][4]
  }

  for (let x = 0; x < 5; x++) {
    D[x] = C[(x + 4) % 5] ^ rotateLn(C[(x + 1) % 5], 1n)
  }

  for (let x = 0; x < 5; x++) {
    for (let y = 0; y < 5; y++) {
      _A[x][y] = A[x][y] ^ D[x]
    }
  }

  return _A
}

/**
 * Algorithm 2: ρ(A)
 */
// eslint-disable-next-line unused-imports/no-unused-vars
function rho(A: StateArray) {
  const _A = createStateArray()
  for (let x = 0; x < 5; x++) {
    for (let y = 0; y < 5; y++) {
      _A[x][y] = rotateLn(A[x][y], BigInt(R[x][y]))
    }
  }
  return _A
}

/**
 * Algorithm 3: π(A)
 */
// eslint-disable-next-line unused-imports/no-unused-vars
function pi(A: StateArray) {
  const _A = createStateArray()
  for (let x = 0; x < 5; x++) {
    for (let y = 0; y < 5; y++) {
      _A[y][(2 * x + 3 * y) % 5] = A[x][y]
    }
  }
  return _A
}

/**
 * 合并执行 π(ρ(A))
 */
function rhoPi(A: StateArray) {
  const _A = createStateArray()
  for (let x = 0; x < 5; x++) {
    for (let y = 0; y < 5; y++) {
      _A[y][(2 * x + 3 * y) % 5] = rotateLn(A[x][y], BigInt(R[x][y]))
    }
  }
  return _A
}

/**
 * Algorithm 4: χ(A)
 */
function chi(A: StateArray) {
  const _A = createStateArray()
  for (let x = 0; x < 5; x++) {
    for (let y = 0; y < 5; y++) {
      _A[x][y] = A[x][y] ^ ((~A[(x + 1) % 5][y]) & A[(x + 2) % 5][y])
    }
  }
  return _A
}

/**
 * Algorithm 6: ι(A, ir)
 */
function iota(A: StateArray, ir: number) {
  A[0][0] = A[0][0] ^ RC[ir]
  return A
}

// * Padding Function

/**
 * @function sha3Padding
 * FIPS.202 B.2:
 * SHA-3 填充函数
 * @param rBit 吸收量(bit)
 * @param sigByte 原始消息字节
 * @returns
 */
function sha3Padding(rBit: number, sigByte: number) {
  const rByte = rBit >> 3
  const q = rByte - (sigByte % rByte)
  const paddingBuffer = new ArrayBuffer(q)
  const paddingView = new Uint8Array(paddingBuffer)

  if (q === 1) {
    paddingView[0] = 0x86
    return paddingBuffer
  }

  paddingView[0] = 0x06
  paddingView[q - 1] = 0x80
  return paddingBuffer
}

/**
 * @function shakePadding
 * @description
 * FIPS.202 B.2:
 * SHAKE 填充函数
 * @param rBit 吸收量(bit)
 * @param sigByte 原始消息字节
 * @returns
 */
function shakePadding(rBit: number, sigByte: number) {
  const rByte = rBit >> 3
  const q = rByte - (sigByte % rByte)
  const paddingBuffer = new ArrayBuffer(q)
  const paddingView = new Uint8Array(paddingBuffer)

  if (q === 1) {
    paddingView[0] = 0xF9
    return paddingBuffer
  }

  paddingView[0] = 0x1F
  paddingView[q - 1] = 0x80
  return paddingBuffer
}

// * KECCAK family

/**
 * @function Keccak[c]
 * @description
 * FIPS.202 5.2:
 * Keccak 是 Sponge 函数家族.
 * 当 b = 1600, Keccak 家族表示为 Keccak[c];
 * @param c 容量(bit)
 */
function Keccak(c: number) {
  const b = 1600
  return Sponge(b - c)
}

/**
 * @function Sponge
 * @description
 * 除去填充功能的 Sponge 结构，用于 SHA-3 系列函数.
 * 对于 SHA-3 系列函数，映射函数 f 是 Keccak_p(b:1600, nr:24).
 * @param b 状态量(bit)
 * @param r 吸收量(bit): r = b - c
 */
function Sponge(r: number) {
  const b = 1600
  const nr = 24
  const bByte = b >> 3
  const rByte = r >> 3

  const f = Keccak_p(b, nr)

  /**
   * @param P 经过填充的消息
   * @param d 输出长度
   */
  return (P: ArrayBuffer, d: number) => {
    const dByte = d >> 3
    // n: 分块数
    const blockTotal = P.byteLength / rByte
    // c: 容量
    // const c = b - r

    let S = new ArrayBuffer(bByte)
    const SView = new Uint8Array(S)
    for (let i = 0; i < blockTotal; i++) {
      const Pi = new Uint8Array(P.slice(i * rByte, (i + 1) * rByte))
      SView.forEach((byte, index) => SView[index] = byte ^ Pi[index])
      S = f(S)
    }

    let Z = new Uint8Array(S.slice(0, rByte))

    while (Z.byteLength < dByte) {
      S = f(S)
      Z = new Uint8Array(Z.byteLength + rByte)
      Z.set(Z, 0)
    }

    return Z.buffer.slice(0, dByte)
  }
}

/**
 * @function Keccak-p
 * 吸收函数 f 生成器
 * @param b 状态量(bit)
 * @param nr 轮数
 */
function Keccak_p(b: number, nr: number) {
  if (!LEGAL_B.includes(b)) {
    throw new Error('Invalid state size')
  }

  /**
   * @param S 状态
   */
  return (S: ArrayBuffer) => {
    if (S.byteLength * 8 !== b) {
      throw new Error('Invalid state size')
    }

    let A = toStateArray(S)
    for (let i = 0; i < nr; i++) {
      // Rnd(A,ir) = iota(chi(rhoPi(theta(A))), ir)
      A = iota(chi(rhoPi(theta(A))), i)
    }
    return toState(A)
  }
}

// * 6. SHA-3 FUNCTION SPECIFICATIONS

/**
 * @function SHA-3 生成函数
 * @description
 * 对于 SHA-3 系列函数, Keccak-p 使用固定参数 Keccak-p(b:1600, nr:24).
 * SHA-3 和 SHA-3 XOF 函数的区别只有 c, d, padding.
 * 因此生成函数只需要提供 c, d, padding.
 * @param c 容量 bit
 * @param d 输出长度 bit
 * @param padding 填充函数
 * @param codec 编码器
 */
function sha3(c: number, d: number, padding: typeof sha3Padding, codec: Codec = Hex) {
  const b = 1600
  return (input: string | ArrayBufferLike) => {
    const M = typeof input == 'string' ? Utf8.parse(input) : input
    const paddingBuffer = padding(b - c, M.byteLength)

    /** Padded Message */
    const P = new ArrayBuffer(M.byteLength + paddingBuffer.byteLength)
    const PView = new Uint8Array(P)
    PView.set(new Uint8Array(M), 0)
    PView.set(new Uint8Array(paddingBuffer), M.byteLength)

    return codec.stringify(Keccak(c)(P, d))
  }
}

export function sha3_224(input: string, codec: Codec = Hex) {
  return sha3(448, 224, sha3Padding, codec)(input)
}

export function sha3_256(input: string, codec: Codec = Hex) {
  return sha3(512, 256, sha3Padding, codec)(input)
}

export function sha3_384(input: string, codec: Codec = Hex) {
  return sha3(768, 384, sha3Padding, codec)(input)
}

export function sha3_512(input: string, codec: Codec = Hex) {
  return sha3(1024, 512, sha3Padding, codec)(input)
}

export function shake128(input: string, d: number, codec: Codec = Hex) {
  return sha3(256, d, shakePadding, codec)(input)
}

export function shake256(input: string, d: number, codec: Codec = Hex) {
  return sha3(512, d, shakePadding, codec)(input)
}
