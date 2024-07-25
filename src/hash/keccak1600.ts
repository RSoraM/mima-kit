import { rotateL64 } from '../core/utils'
import type { Keccak, KeccakPermutation } from '../core/keccakUtils'
import { RCGen, Sponge } from '../core/keccakUtils'

// * Constants

export const PERMUTATION: KeccakPermutation = {
  b: 1600,
  bByte: 200,
  w: 64,
  wByte: 8,
  l: 6,
  nr: 24,
}

/**
 * FIPS.202 3.2.2
 * Algorithm 2: ρ(A) 位移表
 * 由 src/core/keccakUtils.ts 中的 RGen 函数生成
 */
const R = [
  [0, 36, 3, 41, 18],
  [1, 44, 10, 45, 2],
  [62, 6, 43, 15, 61],
  [28, 55, 25, 21, 56],
  [27, 20, 39, 8, 14],
]

/**
 * FIPS.202 3.2.5
 * RC 由 Algorithm 5: rc(t) 生成
 * 由 src/core/keccakUtils.ts 中的 RCGen 函数生成
 */
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

// * Permutation Function

type StateArray1600 = BigUint64Array[]

/**
 * @description
 * create a 5x5 State Array
 * 创建一个 5x5 State Array
 */
function createStateArray(): StateArray1600 {
  return Array.from({ length: 5 }).map(() => new BigUint64Array(5))
}

/**
 * @description
 * Converting State to State Arrays
 * 将状态转换为状态数组
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
 * @description
 * Converting State Arrays to State
 * 将状态数组转换为状态
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

// * Mapping Function

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

// * Keccak-p[1600]

/**
 * @description
 * Keccak-p[1600] Absorption Function
 * Keccak-p[1600] 吸收函数
 *
 * @param nr 轮数
 */
export function Keccak_p_1600(nr?: number) {
  nr = nr || PERMUTATION.nr

  // 当轮数非默认的情况下，重新生成 RC
  const _RC = nr === PERMUTATION.nr ? RC : RCGen(PERMUTATION, nr, true)

  /**
   * @description
   * Absorbing Function
   * 吸收函数
   *
   * @param {Uint8Array} S - 状态
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

/**
 * @description
 * Keccak-p[1600] Sponge Construction
 * Keccak-p[1600] 海绵构造
 *
 * @param {number} rByte - 吸收量的字节长度
 * @param {Keccak} f - Keccak 置换函数
 */
export function Sponge_1600(rByte: number, f: Keccak = Keccak_p_1600()) {
  return Sponge(f, PERMUTATION.bByte, rByte)
}
