import type { Hash, KeyHash } from './hash'
import { hmac } from '../hash/hmac'
import { sha256 } from '../hash/sha256'
import { Counter, joinBuffer, KitError, rotateL32, U8, u32 } from './utils'

export interface KDF {
  /**
   * @param {number} k_byte - 期望的密钥长度 / output keying material length
   * @param {Uint8Array} ikm - 输入密钥材料 / input keying material
   * @param {Uint8Array} salt - 盐 / salt value
   */
  (k_byte: number, ikm: Uint8Array, salt?: Uint8Array): U8
}

/**
 * ANSI-X9.63 Key Derivation Function
 *
 * ANSI-X9.63 密钥派生函数
 */
export function x963kdf(hash: Hash, info = new Uint8Array(0)): KDF {
  const d_byte = hash.DIGEST_SIZE
  return (k_byte: number, ikm: Uint8Array) => {
    /** Output Keying Material */
    const okm: Uint8Array[] = []

    const counter = new Counter([0, 0, 0, 1])
    for (let okm_byte = 0; okm_byte < k_byte; okm_byte += d_byte) {
      const data = joinBuffer(ikm, counter, info)
      okm.push(hash(data))
      counter.inc()
    }

    return joinBuffer(...okm).slice(0, k_byte)
  }
}

/**
 * HMAC-based Key Derivation Function (HKDF), please combine `hmac` and `hash` externally to control the behavior of calling `hmac` inside the function.
 *
 * 基于 HMAC 的密钥派生函数 (HKDF), 请在外部组合 `hmac` 和 `hash` 函数, 以控制在函数内部调用 `hmac` 时的行为.
 */
export function hkdf(k_hash: KeyHash, info = new Uint8Array(0)): KDF {
  const d_byte = k_hash.DIGEST_SIZE
  return (k_byte: number, ikm: Uint8Array, salt = new Uint8Array(0)) => {
    /** Pseudo-Random Key */
    const prk = k_hash(salt, ikm)
    /** Output Keying Material */
    const okm: Uint8Array[] = []

    const counter = new Uint8Array([1])
    let prv = new Uint8Array(0)
    for (let okm_byte = 0; okm_byte < k_byte; okm_byte += d_byte) {
      prv = k_hash(prk, joinBuffer(prv, info, counter))
      okm.push(prv)
      counter[0]++
    }

    return joinBuffer(...okm).slice(0, k_byte)
  }
}

/**
 * Password-Based Key Derivation Function 2 (PBKDF2), please combine `hmac` and `hash` externally to control the behavior of calling `hmac` inside the function.
 *
 * PBKDF2 密码基础密钥派生函数 (PBKDF2), 请在外部组合 `hmac` 和 `hash` 函数, 以控制在函数内部调用 `hmac` 时的行为.
 */
export function pbkdf2(k_hash: KeyHash, iterations = 1000): KDF {
  const d_byte = k_hash.DIGEST_SIZE
  return (k_byte: number, ikm: Uint8Array, salt = new Uint8Array(0)) => {
    ikm = U8.from(ikm)

    /** Output Keying Material */
    const okm: Uint8Array[] = []

    let T: Uint8Array
    let U: Uint8Array
    const counter = new Counter([0, 0, 0, 1])
    for (let okm_byte = 0; okm_byte < k_byte; okm_byte += d_byte) {
      T = new Uint8Array(k_hash.DIGEST_SIZE)
      U = joinBuffer(salt, counter)
      for (let i = 0; i < iterations; i++) {
        U = k_hash(ikm, U)
        T.forEach((_, j) => T[j] ^= U[j])
      }
      okm.push(T)
      counter.inc()
    }

    return joinBuffer(...okm).slice(0, k_byte)
  }
}

interface ScryptConfig {
  /**
   * 开销因子 / Cost factor (default: 16384)
   *
   * 必须是 2 的幂
   *
   * Must be a power of 2
   */
  N?: number
  /**
   * 块数 / Block count (default: 8)
   */
  r?: number
  /**
   * 并行因子 / Parallelization factor (default: 1)
   */
  p?: number
  /**
   * 最大内存使用量 / Maximum memory usage
   *
   * 如果设置为 0，则不限制内存使用量
   *
   * If set to 0, there is no limit on memory usage
   *
   * (default: 0x40000400 bytes, 1GB + 1KB)
   */
  maxmem?: number
  /**
   * 密钥派生函数 / Key Derivation Function
   *
   * scrypt 标准使用了 `PBKDF2-HMAC-SHA256` 作为 KDF。
   * 该参数允许用户指定其他 KDF，改变 scrypt 的内部行为。
   *
   * 注意: 这不是 `scrypt` 的标准用法且缺乏相关的安全分析。
   *
   * The scrypt standard uses `PBKDF2-HMAC-SHA256` as the KDF.
   * This parameter allows users to specify a different KDF, changing the internal behavior of scrypt.
   *
   * Note: This is not the standard usage of `scrypt` and lacks relevant security analysis.
   *
   * (default: pbkdf2(hmac(sha256), 1))
   */
  kdf?: KDF
}

/**
 * Scrypt Key Derivation Function
 *
 * Scrypt 密钥派生函数
 *
 * Based on https://github.com/paulmillr/noble-hashes
 */
export function scrypt(config?: ScryptConfig): KDF {
  const {
    N = 16384,
    r = 8,
    p = 1,
    maxmem = 0x40000400,
    kdf = pbkdf2(hmac(sha256), 1),
  } = config ?? {}

  const BLOCK_SIZE = r << 7
  const BLOCK_SIZE_32 = r << 5
  const MAX_p = (0x1FFFFFFFE0 / BLOCK_SIZE) >>> 0
  const MEM_COST = BLOCK_SIZE * (N + p)
  const N_1 = N - 1

  if (N === 0 || (N & N_1) !== 0)
    throw new KitError(`N must be a power of 2`)
  if (p < 1 || p > MAX_p)
    throw new KitError(`p must be in range [1, ${MAX_p}]`)
  if (MEM_COST > maxmem)
    throw new KitError(`Memory cost exceeds maxmem: ${MEM_COST} > ${maxmem}`)

  // 内联 rotateL32 (神秘的黑魔法)
  const rotl = rotateL32

  function fast_xor_salsa_hash(
    prev: Uint32Array,
    pi: number,
    input: Uint32Array,
    ii: number,
    output: Uint32Array,
    oi: number,
  ) {
    const y00 = prev[pi++] ^ input[ii++]; const y01 = prev[pi++] ^ input[ii++]
    const y02 = prev[pi++] ^ input[ii++]; const y03 = prev[pi++] ^ input[ii++]
    const y04 = prev[pi++] ^ input[ii++]; const y05 = prev[pi++] ^ input[ii++]
    const y06 = prev[pi++] ^ input[ii++]; const y07 = prev[pi++] ^ input[ii++]
    const y08 = prev[pi++] ^ input[ii++]; const y09 = prev[pi++] ^ input[ii++]
    const y10 = prev[pi++] ^ input[ii++]; const y11 = prev[pi++] ^ input[ii++]
    const y12 = prev[pi++] ^ input[ii++]; const y13 = prev[pi++] ^ input[ii++]
    const y14 = prev[pi++] ^ input[ii++]; const y15 = prev[pi++] ^ input[ii++]
    // Save state to temporary variables (salsa)
    let x00 = y00; let x01 = y01; let x02 = y02; let x03 = y03
    let x04 = y04; let x05 = y05; let x06 = y06; let x07 = y07
    let x08 = y08; let x09 = y09; let x10 = y10; let x11 = y11
    let x12 = y12; let x13 = y13; let x14 = y14; let x15 = y15
    // Main loop (salsa)
    for (let i = 0; i < 8; i += 2) {
      x04 ^= rotl(x00 + x12 | 0,  7); x08 ^= rotl(x04 + x00 | 0,  9)
      x12 ^= rotl(x08 + x04 | 0, 13); x00 ^= rotl(x12 + x08 | 0, 18)
      x09 ^= rotl(x05 + x01 | 0,  7); x13 ^= rotl(x09 + x05 | 0,  9)
      x01 ^= rotl(x13 + x09 | 0, 13); x05 ^= rotl(x01 + x13 | 0, 18)
      x14 ^= rotl(x10 + x06 | 0,  7); x02 ^= rotl(x14 + x10 | 0,  9)
      x06 ^= rotl(x02 + x14 | 0, 13); x10 ^= rotl(x06 + x02 | 0, 18)
      x03 ^= rotl(x15 + x11 | 0,  7); x07 ^= rotl(x03 + x15 | 0,  9)
      x11 ^= rotl(x07 + x03 | 0, 13); x15 ^= rotl(x11 + x07 | 0, 18)
      x01 ^= rotl(x00 + x03 | 0,  7); x02 ^= rotl(x01 + x00 | 0,  9)
      x03 ^= rotl(x02 + x01 | 0, 13); x00 ^= rotl(x03 + x02 | 0, 18)
      x06 ^= rotl(x05 + x04 | 0,  7); x07 ^= rotl(x06 + x05 | 0,  9)
      x04 ^= rotl(x07 + x06 | 0, 13); x05 ^= rotl(x04 + x07 | 0, 18)
      x11 ^= rotl(x10 + x09 | 0,  7); x08 ^= rotl(x11 + x10 | 0,  9)
      x09 ^= rotl(x08 + x11 | 0, 13); x10 ^= rotl(x09 + x08 | 0, 18)
      x12 ^= rotl(x15 + x14 | 0,  7); x13 ^= rotl(x12 + x15 | 0,  9)
      x14 ^= rotl(x13 + x12 | 0, 13); x15 ^= rotl(x14 + x13 | 0, 18)
    }
    // Write output (salsa)
    output[oi++] = (y00 + x00) | 0; output[oi++] = (y01 + x01) | 0
    output[oi++] = (y02 + x02) | 0; output[oi++] = (y03 + x03) | 0
    output[oi++] = (y04 + x04) | 0; output[oi++] = (y05 + x05) | 0
    output[oi++] = (y06 + x06) | 0; output[oi++] = (y07 + x07) | 0
    output[oi++] = (y08 + x08) | 0; output[oi++] = (y09 + x09) | 0
    output[oi++] = (y10 + x10) | 0; output[oi++] = (y11 + x11) | 0
    output[oi++] = (y12 + x12) | 0; output[oi++] = (y13 + x13) | 0
    output[oi++] = (y14 + x14) | 0; output[oi++] = (y15 + x15) | 0
  }
  function block_mix(
    input: Uint32Array,
    input_index: number,
    output: Uint32Array,
    output_index: number,
    r: number,
  ) {
    let head = output_index
    let tail = output_index + (r << 4)
    const t = ((r << 1) - 1) << 4
    for (let i = 0; i < 16; i++) output[tail + i] = input[input_index + i + t]
    for (let i = 0; i < r; i++) {
      fast_xor_salsa_hash(output, tail, input, input_index, output, head)
      if (i > 0) { tail += 16 }
      input_index += 16
      fast_xor_salsa_hash(output, head, input, input_index, output, tail)
      head += 16
      input_index += 16
    }
  }

  return (k_byte: number, ikm: Uint8Array, salt = new Uint8Array(0)) => {
    const B = kdf(BLOCK_SIZE * p, ikm, salt)
    const B32 = u32(B)

    const V32 = u32(new Uint8Array(BLOCK_SIZE * N))
    const tmp = u32(new Uint8Array(BLOCK_SIZE))

    for (let pi = 0; pi < p; pi++) {
      const PI = BLOCK_SIZE_32 * pi
      V32.set(B32.subarray(PI, PI + BLOCK_SIZE_32), 0)
      let pos = 0
      for (let i = 0; i < N_1; i++) {
        block_mix(V32, pos, V32, pos + BLOCK_SIZE_32, r)
        pos += BLOCK_SIZE_32
      }
      block_mix(V32, N_1 * BLOCK_SIZE_32, B32, PI, r)

      for (let i = 0; i < N; i++) {
        const j = B32[PI + BLOCK_SIZE_32 - 16] % N
        for (let k = 0; k < BLOCK_SIZE_32; k++) {
          tmp[k] = B32[PI + k] ^ V32[j * BLOCK_SIZE_32 + k]
        }
        block_mix(tmp, 0, B32, PI, r)
      }
    }

    return kdf(k_byte, ikm, B)
  }
}
