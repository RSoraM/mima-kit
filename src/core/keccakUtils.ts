// FIPS.202 3.1
//
// KECCAK-p 置换组合
//
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

const LEGAL_B = [200, 400, 800, 1600]

/**
 * Keccak-p 排列接口
 */
export interface KeccakPermutation {
  b: number
  bByte: number
  w: number
  wByte: number
  l: number
  nr: number
}

/**
 * ### getKeccakPermutation
 *
 * @description
 * 获取 Keccak-p 排列
 *
 * @param {number} b 状态的比特长度
 */
export function getKeccakPermutation(b: number): KeccakPermutation {
  if (!LEGAL_B.includes(b)) {
    throw new Error('Invalid Permutation')
  }

  const w = b / 25
  const l = Math.log2(w)
  const nr = 12 + 2 * l

  return { b, bByte: b >> 3, w, wByte: w >> 3, l, nr }
}

// * State Utils

// FIPS.202 3.2.5
// RC 由 Algorithm 5: rc(t) 生成
/**
 * ### RCGen
 *
 * @description
 * RC 生成函数，底层实现使用文本转数字的方式 <br>
 * 性能非常差，对于已知不变的参数，可以使用预生成的表
 *
 * @param PERMUTATION Keccak 置换参数
 * @param nr 指定轮数
 * @param bigint 是否返回 BigInt
 */
export function RCGen(PERMUTATION: KeccakPermutation, nr?: number, bigint?: false): number[]
export function RCGen(PERMUTATION: KeccakPermutation, nr?: number, bigint?: true): bigint[]
export function RCGen(PERMUTATION: KeccakPermutation, nr?: number, bigint = false) {
  const RCTable = []

  nr = nr || PERMUTATION.nr
  for (let ir = 0; ir < nr; ir++) {
    const RC = Array.from({ length: PERMUTATION.w }).fill(0)

    for (let j = 0; j <= PERMUTATION.l; j++) {
      const t = j + 7 * ir
      let r = 0
      if (t % 255 === 0) {
        r = 1
      }
      else {
        const R = [1, 0, 0, 0, 0, 0, 0, 0]
        for (let i = 0; i < t % 255; i++) {
          R.unshift(0)
          R[0] = R[0] ^ R[8]
          R[4] = R[4] ^ R[8]
          R[5] = R[5] ^ R[8]
          R[6] = R[6] ^ R[8]
          R.pop()
        }
        r = R[0]
      }

      RC[2 ** j - 1] = r
    }

    const binary = `0b${RC.join('')}`

    RCTable.push(bigint ? BigInt(binary) : Number(binary))
  }
  return RCTable
}

// FIPS.202 3.2.2
// Algorithm 2: ρ(A) 位移表生成函数
/**
 * ### RGen
 *
 * @description
 * 生成 ρ(A) 位移表，对于已知不变的参数，可以使用预生成的表
 *
 * @param w 工作字长
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

// * Sponge Construction

export type Keccak = (S: Uint8Array) => Uint8Array

/**
 * ### Sponge
 *
 * @description
 * 海绵函数，与文档中的描述不同，这里的海绵函数不包含填充函数，请在调用时自行填充
 *
 * @param f Keccak 置换函数
 * @param bByte 状态的字节长度
 * @param rByte 吸收量的字节长度
 */
export function Sponge(f: Keccak, bByte: number, rByte: number) {
  /**
   * @param P 经过填充的消息
   * @param d 输出长度
   */
  return (P: Uint8Array, d: number) => {
    // n: 分块数
    const blockTotal = Math.ceil(P.byteLength / rByte)

    let S = new Uint8Array(bByte)
    for (let i = 0; i < blockTotal; i++) {
      const Pi = P.slice(i * rByte, (i + 1) * rByte)
      S.forEach((byte, index) => S[index] = byte ^ Pi[index])
      S = f(S)
    }

    let Z = S.slice(0, rByte)

    const dByte = d >> 3
    while (Z.byteLength < dByte) {
      const temp = new Uint8Array(Z.byteLength + rByte)
      temp.set(Z, 0)
      S = f(S)
      temp.set(S.slice(0, rByte), Z.byteLength)
      Z = temp
    }

    return Z.slice(0, dByte)
  }
}
