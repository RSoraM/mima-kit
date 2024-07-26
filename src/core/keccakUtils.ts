// FIPS.202 3.1
//
// Keccak 置换组合
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

/**
 * @description
 * Keccak Permutation Descration Interface
 * Keccak 置换描述接口
 */
export interface KeccakPermutation {
  b: number
  bByte: number
  w: number
  wByte: number
  l: number
  nr: number
}

// * Permutation Utils

/**
 * @description
 * FIPS.202 3.2.5
 *
 * ! Note: RC Generation Function, the implementation uses text-to-number conversion. The performance is very poor, for known and unchanged parameters, you should use pre-generated tables.
 * ! Note: RC 生成函数, 底层实现使用文本转数字的方式. 性能非常差, 对于已知不变的参数, 应使用预生成的表.
 *
 * @param {KeccakPermutation} PERMUTATION - Keccak 置换描述
 * @param {number} nr - 指定轮数
 * @param {boolean} bigint - 是否返回 BigInt
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

/**
 * @description
 * FIPS.202 3.2.2
 *
 * ! Note: Generate ρ(A) displacement table, for known and unchanged parameters, you should use pre-generated tables.
 * ! Note: 生成 ρ(A) 位移表, 对于已知不变的参数, 应使用预生成的表.
 *
 * @param {number} w - 工作字长
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

/**
 * @description
 * Keccak Permutation Function Interface
 * Keccak 置换函数接口
 */
export interface Keccak {
  (S: Uint8Array): Uint8Array
}

/**
 * @description
 * Sponge Construction, different from the document, this sponge function does not include the padding function, please fill it in before using.
 * 海绵构造, 与文档不同, 该海绵函数不包含填充函数, 请在使用前填充.
 *
 * @param {Keccak} f - Keccak 置换函数
 * @param {number} bByte - 状态的字节长度
 * @param {number} rByte - 吸收量的字节长度
 */
export function Sponge(f: Keccak, bByte: number, rByte: number) {
  /**
   * @param {Uint8Array} P - 经过填充的消息
   * @param {number} d - 输出长度 bit
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
