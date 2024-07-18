import type { Keccak, KeccakPermutation } from '../core/keccakUtils'
import { RCGen, Sponge } from '../core/keccakUtils'
import { rotateL } from '../core/utils'

// * Constants

const PERMUTATION: KeccakPermutation = {
  b: 800,
  bByte: 100,
  w: 32,
  wByte: 4,
  l: 5,
  nr: 22,
}

// FIPS.202 3.2.2
// Algorithm 2: ρ(A) 位移表
// 由 src/core/keccakUtils.ts 中的 RGen 函数生成
const R = [
  [0, 4, 3, 9, 18],
  [1, 12, 10, 13, 2],
  [30, 6, 11, 15, 29],
  [28, 20, 24, 8, 23],
  [27, 20, 18, 2, 29],
]

// FIPS.202 3.2.5
// RC 由 Algorithm 5: rc(t) 生成
// 由 src/core/keccakUtils.ts 中的 RCGen 函数生成
const RC = [
  0x80000000,
  0x41010000,
  0x51010000,
  0x00010001,
  0xD1010000,
  0x80000001,
  0x81010001,
  0x90010000,
  0x51000000,
  0x11000000,
  0x90010001,
  0x50000001,
  0xD1010001,
  0xD1000000,
  0x91010000,
  0xC0010000,
  0x40010000,
  0x01000000,
  0x50010000,
  0x50000001,
  0x81010001,
  0x01010000,
]

// * 3.1 State

type StateArray800 = Uint32Array[]
function createStateArray(): StateArray800 {
  return Array.from({ length: 5 }).map(() => new Uint32Array(5))
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
      A[x][y] = view.getUint32((y * 5 + x) * PERMUTATION.wByte, true)
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
function toState(A: StateArray800) {
  const S = new Uint8Array(PERMUTATION.bByte)
  const view = new DataView(S.buffer)

  for (let x = 0; x < 5; x++) {
    for (let y = 0; y < 5; y++) {
      view.setUint32((y * 5 + x) * PERMUTATION.wByte, A[x][y], true)
    }
  }

  return S
}

// * 3.2 Step Mappings

/** Algorithm 1: θ(A) */
function theta(A: StateArray800) {
  const C = new Uint32Array(5)
  const D = new Uint32Array(5)

  for (let x = 0; x < 5; x++) {
    C[x] = A[x][0] ^ A[x][1] ^ A[x][2] ^ A[x][3] ^ A[x][4]
  }

  for (let x = 0; x < 5; x++) {
    D[x] = C[(x + 4) % 5] ^ rotateL(C[(x + 1) % 5], 1)

    for (let y = 0; y < 5; y++) {
      A[x][y] = A[x][y] ^ D[x]
    }
  }

  return A
}

/** Algorithm 2: ρ(A) */
// eslint-disable-next-line unused-imports/no-unused-vars
function rho(A: StateArray800) {
  const _A = createStateArray()
  for (let x = 0; x < 5; x++) {
    for (let y = 0; y < 5; y++) {
      _A[x][y] = rotateL(A[x][y], R[x][y])
    }
  }
  return _A
}

/** Algorithm 3: π(A) */
// eslint-disable-next-line unused-imports/no-unused-vars
function pi(A: StateArray800) {
  const _A = createStateArray()
  for (let x = 0; x < 5; x++) {
    for (let y = 0; y < 5; y++) {
      _A[y][(2 * x + 3 * y) % 5] = A[x][y]
    }
  }
  return _A
}

/** 合并执行 π(ρ(A)) */
function rhoPi(A: StateArray800) {
  const _A = createStateArray()
  for (let x = 0; x < 5; x++) {
    for (let y = 0; y < 5; y++) {
      _A[y][(2 * x + 3 * y) % 5] = rotateL(A[x][y], R[x][y])
    }
  }
  return _A
}

/** Algorithm 4: χ(A) */
function chi(A: StateArray800) {
  const _A = createStateArray()
  for (let x = 0; x < 5; x++) {
    for (let y = 0; y < 5; y++) {
      _A[x][y] = A[x][y] ^ ((~A[(x + 1) % 5][y]) & A[(x + 2) % 5][y])
    }
  }
  return _A
}

/** Algorithm 6: ι(A, ir) */
function iota(A: StateArray800, RC: number) {
  A[0][0] = A[0][0] ^ RC
  return A
}

// * KECCAK-p[800]

/**
 * ### Keccak-p[800]
 *
 * @description
 * 吸收函数 f 生成器
 *
 * @param nr 轮数
 */
export function Keccak_p_800(nr?: number) {
  nr = nr || PERMUTATION.nr

  // 当轮数非默认的情况下，重新生成 RC
  const _RC = nr === PERMUTATION.nr ? RC : RCGen(PERMUTATION, nr)

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

export function Sponge_800(rByte: number, f: Keccak = Keccak_p_800()) {
  return Sponge(f, PERMUTATION.bByte, rByte)
}
