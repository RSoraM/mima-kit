import { createKeyHash } from '../core/hash'
import { KitError, U8 } from '../core/utils'

function _poly1305(key: Uint8Array, message: Uint8Array): U8 {
  if (key.byteLength !== 32) {
    throw new KitError('Poly1305 key must be 32 bytes')
  }

  // Split key into r (clamped) and s
  const r = new Uint8Array(16)
  const s = new Uint8Array(16)
  r.set(key.subarray(0, 16))
  s.set(key.subarray(16, 32))

  // Clamp r
  r[3] &= 0x0f
  r[7] &= 0x0f
  r[11] &= 0x0f
  r[15] &= 0x0f
  r[4] &= 0xfc
  r[8] &= 0xfc
  r[12] &= 0xfc

  // Convert r and s to bigint (little-endian)
  let rVal = 0n
  let sVal = 0n
  for (let i = 15; i >= 0; i--) {
    rVal = (rVal << 8n) | BigInt(r[i])
    sVal = (sVal << 8n) | BigInt(s[i])
  }

  // Prime: 2^130 - 5
  const P = (1n << 130n) - 5n

  // Process message blocks
  let accumulator = 0n
  const paddedLen = Math.ceil(message.length / 16) * 16
  const padded = new Uint8Array(paddedLen)
  padded.set(message)

  for (let i = 0; i < paddedLen; i += 16) {
    // Read block as little-endian number
    let block = 0n
    for (let j = 15; j >= 0; j--) {
      block = (block << 8n) | BigInt(padded[i + j])
    }

    // Add high bit (2^128 for full blocks, 2^(8*remaining_bits) for last partial block)
    const remainingBytes = message.length - i
    const highBit = remainingBytes >= 16 ? 1n << 128n : 1n << BigInt(remainingBytes * 8)
    block += highBit

    // Accumulate
    accumulator = ((accumulator + block) * rVal) % P
  }

  // Add s
  let tag = (accumulator + sVal) % (1n << 128n)

  // Convert to bytes (little-endian)
  const result = new U8(16)
  for (let i = 0; i < 16; i++) {
    result[i] = Number(tag & 0xffn)
    tag >>= 8n
  }

  return result
}

/**
 * RFC8439: Poly1305 密码学消息验证码
 * 使用 Poly1305 算法计算一个 16 字节的认证标签
 *
 * RFC8439: Poly1305 one-time authenticator
 * Computes a 16-byte authentication tag using the Poly1305 algorithm
 */
export const poly1305 = createKeyHash(_poly1305, {
  ALGORITHM: 'Poly1305',
  BLOCK_SIZE: 16,
  DIGEST_SIZE: 16,
  KEY_SIZE: 32,
})
