import { KitError, joinBuffer, rotateL64 } from '../core/utils'

// * Constants

/**
 * ρ(A) 位移表 / Shift Table
 */
const R = [
  [0, 36, 3, 41, 18],
  [1, 44, 10, 45, 2],
  [62, 6, 43, 15, 61],
  [28, 55, 25, 21, 56],
  [27, 20, 39, 8, 14],
]
/**
 * https://datatracker.ietf.org/doc/draft-irtf-cfrg-kangarootwelve/
 */
const RC12 = [
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
/**
 * `RCGen(6, 24)`
 */
const RC24 = [
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

// * Keccak Utils

/**
 * RC Table Generation Function
 *
 * @param {number} l - log2(w)
 * @param {number} [nr] - 轮数
 */
export function RCGen(l = 6, nr = 24) {
  const RCTable = []
  for (let ir = 0; ir < nr; ir++) {
    let RC = 0n
    for (let j = 0; j <= l; j++) {
      const t = j + 7 * ir

      // rc(t)
      let rc: bigint
      if (t % 255 === 0) {
        rc = 1n
      }
      else {
        let R = 0x80n
        for (let i = 1; i <= t % 255; i++) {
          const b = R & 1n
          R ^= (b << 8n) | (b << 4n) | (b << 3n) | (b << 2n)
          R >>= 1n
        }
        rc = R >> 7n
      }

      // RC[2^j - 1] = rc(j + 7ir)
      RC |= (rc << BigInt(2 ** j - 1))
    }
    RCTable.push(RC)
  }
  return RCTable
}

/**
 * @param {number} w - 工作字长度 / Word Size
 */
export function RGen(w: number) {
  const R = [
    [0, 36, 3, 105, 210],
    [1, 300, 10, 45, 66],
    [190, 6, 171, 15, 253],
    [28, 276, 120, 136, 55],
    [91, 276, 210, 66, 253],
  ]

  return R.map(x => x.map(y => y % w))
}

// * Permutation Function

type StateArray1600 = BigUint64Array[]

/**
 * create a 5x5 `State Array`
 *
 * 创建一个 5x5 `状态矩阵`
 */
function createStateArray(): StateArray1600 {
  return Array.from({ length: 5 }).map(() => new BigUint64Array(5))
}

/**
 * Converting `State` to `State Arrays`
 *
 * 将 `状态` 转换为 `状态矩阵`
 */
function toStateArray(S: Uint8Array) {
  const A = createStateArray()
  const view = new DataView(S.buffer)

  for (let x = 0; x < 5; x++) {
    for (let y = 0; y < 5; y++) {
      A[x][y] = view.getBigUint64((y * 5 + x) << 3, true)
    }
  }

  return A
}

/**
 * Converting `State Arrays` to `State`
 *
 * 将 `状态矩阵` 转换为 `状态`
 */
function toState(A: StateArray1600) {
  const S = new Uint8Array(200)
  const view = new DataView(S.buffer)

  for (let x = 0; x < 5; x++) {
    for (let y = 0; y < 5; y++) {
      view.setBigUint64((y * 5 + x) << 3, A[x][y], true)
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
      _A[x][y] = A[(x + 3 * y) % 5][x]
    }
  }
  return _A
}

/**
 * Combining π(ρ(A))
 *
 * 合并执行 π(ρ(A))
 */
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
 * `Keccak-p` 置换函数 / Permutate Function
 */
export interface Keccak_p {
  /**
   * @param {Uint8Array} S - 状态 / State
   */
  (S: Uint8Array): Uint8Array
}

/**
 * `Keccak-p[1600, nr]` 置换函数 / Permutate Function
 *
 * @param {number} [nr] - 轮数 / Rounds (default: 24)
 */
export function keccak_p_1600(nr = 24): Keccak_p {
  // b = 1600
  const bByte = 200
  const l = 6

  // 当轮数非默认的情况下，重新生成 RC
  let RC: bigint[]
  if (nr === 12) {
    RC = RC12
  }
  else if (nr === 24) {
    RC = RC24
  }
  else {
    RC = RCGen(l, nr)
  }

  return (S: Uint8Array) => {
    if (S.byteLength !== bByte) {
      throw new KitError('Invalid state size')
    }

    let A = toStateArray(S)
    for (let i = 0; i < nr; i++) {
      A = iota(chi(rhoPi(theta(A))), RC[i])
    }
    return toState(A)
  }
}

// * Sponge Construction

/**
 * `SPONGE` 填充函数 / Padding Function
 */
export interface SpongePadding {
  /**
   * @param {Uint8Array} M - 消息 / Message
   */
  (M: Uint8Array): Uint8Array
}

/**
 * `SPONGE` & `Keccak-p[1600]`
 *
 * @param {number} r_byte - 处理速率 / Rate
 * @param {number} d_byte - 输出长度 / Digest Size
 * @param {SpongePadding} pad - 填充函数 / Padding Function
 * @param {Keccak_p} f - Keccak-p 置换函数 / Permutate Function
 */
export function sponge_1600(
  r_byte: number,
  d_byte: number,
  pad: SpongePadding,
  f: Keccak_p = keccak_p_1600(),
) {
  return (M: Uint8Array) => {
    // * 填充
    const P = pad(M)
    // * 吸收
    let S = new Uint8Array(200)
    let i = 0
    while (i < P.byteLength) {
      const Pi = P.slice(i, i += r_byte)
      S.forEach((byte, index) => S[index] = byte ^ Pi[index])
      S = f(S)
    }
    // * 挤出
    const z = [S.slice(0, r_byte)]
    let z_byte = r_byte
    while (z_byte < d_byte) {
      S = f(S)
      z.push(S.slice(0, r_byte))
      z_byte += r_byte
    }
    // * 截断输出
    return joinBuffer(...z).slice(0, d_byte)
  }
}
