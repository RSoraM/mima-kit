import { KitError } from '../core/utils'
import type { SpongePadding } from './keccak1600'
import { keccak_p_1600, sponge_1600 } from './keccak1600'

/**
 * turboSHAKE 填充函数 / Padding Function
 *
 * ```ts
 * M || D || 0x00*
 * ```
 *
 * @param {number} rByte - 处理速率 / Rate
 * @param {number} D - 域分隔符 / Domain Separator
 */
function turboShakePadding(rByte: number, D: number): SpongePadding {
  return (M: Uint8Array) => {
    const sig_byte = M.length + 1
    const block = Math.ceil(sig_byte / rByte)
    const P = new Uint8Array(block * rByte)
    P.set(M)
    P[M.length] = D
    P[P.length - 1] ^= 0x80
    return P
  }
}

export function turboSHAKE128(d: number, D = 0x1F) {
  if (D < 0x01 || D > 0x7F) {
    throw new KitError('Invalid Domain Separator')
  }
  const r_byte = 168
  const f = keccak_p_1600(12)
  const pad = turboShakePadding(r_byte, D)
  return (M: Uint8Array) => sponge_1600(r_byte, d, pad, f)(M)
}

export function turboSHAKE256(d: number, D = 0x1F) {
  if (D < 0x01 || D > 0x7F) {
    throw new KitError('Invalid Domain Separator')
  }
  const r_byte = 136
  const f = keccak_p_1600(12)
  const pad = turboShakePadding(r_byte, D)
  return (M: Uint8Array) => sponge_1600(r_byte, d, pad, f)(M)
}
