import { joinBuffer } from './utils'

// FIPS.202 3.1
//
// Keccak 配置预设
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
 * `Keccak` Config Descration Interface
 *
 * `Keccak` 配置描述接口
 */
export interface KeccakConfig {
  b: number
  bByte: number
  w: number
  wByte: number
  l: number
  nr: number
}

/**
 * @description
 * `Keccak-p` Function Interface
 *
 * `Keccak-p` 函数接口
 *
 * The `Keccak-p[b, nr]` in the specification document is more like a constructor. But since the parameter `b` will affect the data structure used by the implementation, and the parameter `b` only comes from 7 kinds of `Keccak` Config, multiple versions of the `Keccak-p` function are implemented by fixing the parameter `b`.
 *
 * 规范文档中 `Keccak-p[b, nr]` 更像是一个构造函数. 但由于参数 `b` 会影响实现使用的数据结构, 且参数 `b` 只来自 7 种 `Keccak` 配置, 所以实现时将 `b` 作为固定参数, 实现多个版本的 `Keccak-p` 函数.
 */
export interface Keccak_p {
  (S: Uint8Array): Uint8Array
}

// * Keccak Utils

/**
 * @description
 * FIPS.202 3.2.5
 *
 * ! Note: RC Generation Function, the implementation uses text-to-number conversion. The performance is very poor, for known and unchanged parameters, you should use pre-generated tables.
 *
 * ! Note: RC 生成函数, 底层实现使用文本转数字的方式. 性能非常差, 对于已知不变的参数, 应使用预生成的表.
 *
 * @param {KeccakConfig} PERMUTATION - `Keccak` 配置描述
 * @param {number} nr - 指定轮数
 * @param {boolean} bigint - 是否返回 BigInt
 */
export function RCGen(PERMUTATION: KeccakConfig, nr?: number, bigint?: false): number[]
export function RCGen(PERMUTATION: KeccakConfig, nr?: number, bigint?: true): bigint[]
export function RCGen(PERMUTATION: KeccakConfig, nr?: number, bigint = false) {
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
 *
 * ! Note: 生成 ρ(A) 位移表, 对于已知不变的参数, 应使用预生成的表.
 *
 * @param {number} w - 工作字长度
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
 * Different from the specification document, this sponge construction does not include the padding function, please pad it before use.
 *
 * 与规范文档不同, 该海绵构造不包含填充函数, 请在使用前填充.
 *
 * @param {Keccak_p} f - `Keccak-p` 函数
 * @param {number} bByte - 状态区块 byte
 * @param {number} rByte - 处理速率 byte
 * @param {number} dByte - 输出长度 byte
 */
export function Sponge(f: Keccak_p, bByte: number, rByte: number, dByte: number) {
  /**
   * @param {Uint8Array} P - 经过填充的消息
   */
  return (P: Uint8Array) => {
    let S = new Uint8Array(bByte)

    // * 吸收
    const blockTotal = P.byteLength / rByte
    for (let i = 0; i < blockTotal; i++) {
      const Pi = P.slice(i * rByte, (i + 1) * rByte)
      S.forEach((byte, index) => S[index] = byte ^ Pi[index])
      S = f(S)
    }

    // * 挤出
    const z = [S.slice(0, rByte)]
    let zByte = rByte
    while (zByte < dByte) {
      S = f(S)
      z.push(S.slice(0, rByte))
      zByte += rByte
    }

    // * 截断输出
    return joinBuffer(...z).slice(0, dByte)
  }
}
