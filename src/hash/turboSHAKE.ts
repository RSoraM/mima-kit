import { createHash } from '../core/hash';
import { KitError, U8 } from '../core/utils';
import type { SpongePadding } from './keccak1600';
import { keccak_p_1600, sponge_1600 } from './keccak1600';

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
    const sig_byte = M.length + 1;
    const block = Math.ceil(sig_byte / rByte);
    const P = new U8(block * rByte);
    P.set(M);
    P[M.length] = D;
    P[P.length - 1] ^= 0x80;
    return P;
  };
}

/**
 * TurboSHAKE128
 *
 * @param {number} d - 输出长度 / Digest Size (bit)
 * @param {number} [D] - 域分隔符 / Domain Separator (range: 0x01 ~ 0x7F, default: 0x1F)
 */
export function turboshake128(d: number, D = 0x1f) {
  if (D < 0x01 || D > 0x7f) {
    throw new KitError('Invalid Domain Separator');
  }
  const d_byte = d >> 3;
  const r_byte = 168;
  const f = keccak_p_1600(12);
  const pad = turboShakePadding(r_byte, D);
  return createHash((M: Uint8Array) => sponge_1600(r_byte, d_byte, pad, f)(M), {
    ALGORITHM: `TurboSHAKE128/${d}`,
    BLOCK_SIZE: r_byte,
    DIGEST_SIZE: d_byte,
  });
}

/**
 * TurboSHAKE256
 *
 * @param {number} d - 输出长度 / Digest Size (bit)
 * @param {number} [D] - 域分隔符 / Domain Separator (range: 0x01 ~ 0x7F, default: 0x1F)
 */
export function turboshake256(d: number, D = 0x1f) {
  if (D < 0x01 || D > 0x7f) {
    throw new KitError('Invalid Domain Separator');
  }
  const d_byte = d >> 3;
  const r_byte = 136;
  const f = keccak_p_1600(12);
  const pad = turboShakePadding(r_byte, D);
  return createHash((M: Uint8Array) => sponge_1600(r_byte, d_byte, pad, f)(M), {
    ALGORITHM: `TurboSHAKE256/${d}`,
    BLOCK_SIZE: r_byte,
    DIGEST_SIZE: d_byte,
  });
}
