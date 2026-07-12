import { createCipher } from '../../core/cipher'
import { KitError, resizeBuffer, rotateL32, U8, u8, u32 } from '../../core/utils'

// * Constants
// "expa" "nd 3" "2-by" "te k" in little-endian
const SIGMA = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]

// * Functions

/**
 * ChaCha20 Quarter Round
 *
 * The quarter round function transforms four 32-bit words:
 * a += b; d ^= a; d <<<= 16;
 * c += d; b ^= c; b <<<= 12;
 * a += b; d ^= a; d <<<= 8;
 * c += d; b ^= c; b <<<= 7;
 */
function quarterRound(state: Uint32Array, a: number, b: number, c: number, d: number) {
  state[a] = (state[a] + state[b]) >>> 0
  state[d] = rotateL32(state[d] ^ state[a], 16)

  state[c] = (state[c] + state[d]) >>> 0
  state[b] = rotateL32(state[b] ^ state[c], 12)

  state[a] = (state[a] + state[b]) >>> 0
  state[d] = rotateL32(state[d] ^ state[a], 8)

  state[c] = (state[c] + state[d]) >>> 0
  state[b] = rotateL32(state[b] ^ state[c], 7)
}

/**
 * ChaCha20 Block Function
 *
 * Creates a 64-byte keystream block from the state
 *
 * @param state - Initial state (16 x 32-bit words)
 * @param rounds - Number of rounds (default: 20)
 */
function block(state: Uint32Array, rounds: number = 20): Uint8Array {
  // Working state
  const working = new Uint32Array(state)

  // Perform rounds (each round consists of column and diagonal operations)
  for (let i = 0; i < rounds; i += 2) {
    // Column rounds
    quarterRound(working, 0, 4, 8, 12)
    quarterRound(working, 1, 5, 9, 13)
    quarterRound(working, 2, 6, 10, 14)
    quarterRound(working, 3, 7, 11, 15)

    // Diagonal rounds
    quarterRound(working, 0, 5, 10, 15)
    quarterRound(working, 1, 6, 11, 12)
    quarterRound(working, 2, 7, 8, 13)
    quarterRound(working, 3, 4, 9, 14)
  }

  // Add the initial state to the working state
  for (let i = 0; i < 16; i++) {
    working[i] = (working[i] + state[i]) >>> 0
  }

  // Convert to bytes (little-endian)
  return u8(working)
}

/**
 * Initialize ChaCha20 state
 *
 * State layout (16 x 32-bit words):
 * [0-3]:   Constants "expa", "nd 3", "2-by", "te k"
 * [4-11]:  256-bit key (8 words)
 * [12]:    32-bit block counter
 * [13-15]: 96-bit nonce (3 words)
 *
 * @param key - 32-byte (256-bit) key
 * @param nonce - 12-byte (96-bit) nonce
 * @param counter - Initial block counter (default: 0)
 */
function initState(key: Uint8Array, nonce: Uint8Array, counter: number = 0): Uint32Array {
  if (key.byteLength !== 32) {
    throw new KitError('ChaCha20 key must be 32 bytes (256 bits)')
  }
  if (nonce.byteLength !== 12) {
    throw new KitError('ChaCha20 nonce must be 12 bytes (96 bits)')
  }

  const state = new Uint32Array(16)
  const keyView = u32(key)
  const nonceView = u32(nonce)

  // Constants
  state[0] = SIGMA[0]
  state[1] = SIGMA[1]
  state[2] = SIGMA[2]
  state[3] = SIGMA[3]

  // Key (little-endian words)
  state[4] = keyView[0]
  state[5] = keyView[1]
  state[6] = keyView[2]
  state[7] = keyView[3]
  state[8] = keyView[4]
  state[9] = keyView[5]
  state[10] = keyView[6]
  state[11] = keyView[7]

  // Counter
  state[12] = counter >>> 0

  // Nonce (little-endian words)
  state[13] = nonceView[0]
  state[14] = nonceView[1]
  state[15] = nonceView[2]

  return state
}

// * ChaCha20 Algorithm

function _chacha20(key: Uint8Array, nonce: Uint8Array, counter: number = 1) {
  // Initialize state
  const state = initState(key, nonce, counter)

  // Pseudo Random Byte Stream
  let S = block(state)
  let currentBlock = 1

  const cipher = (M: Uint8Array) => {
    const BLOCK_TOTAL = (M.length >>> 6) + 1

    // If we already have enough keystream, just XOR
    if (currentBlock > BLOCK_TOTAL) {
      return u8(M).map((byte, i) => byte ^ S[i])
    }

    // Squeeze more keystream blocks
    S = resizeBuffer(S, BLOCK_TOTAL << 6)
    while (BLOCK_TOTAL > currentBlock) {
      // Increment counter (word at index 12)
      state[12] = (state[12] + 1) >>> 0
      S.set(block(state), currentBlock << 6)
      currentBlock++
    }

    return u8(M).map((byte, i) => byte ^ S[i])
  }

  return {
    encrypt: (M: Uint8Array) => cipher(M),
    decrypt: (C: Uint8Array) => cipher(C),
  }
}

/**
 * ChaCha20 流密码 / Stream Cipher
 *
 * ChaCha20 is a stream cipher designed by Daniel J. Bernstein.
 * It uses a 256-bit key and a 96-bit nonce to generate a keystream.
 *
 * @see RFC 8439 - ChaCha20 and Poly1305
 */
export const chacha20 = createCipher(_chacha20, {
  ALGORITHM: 'ChaCha20',
  KEY_SIZE: 32,
  MIN_KEY_SIZE: 32,
  MAX_KEY_SIZE: 32,
  IV_SIZE: 12,
  MIN_IV_SIZE: 12,
  MAX_IV_SIZE: 12,
})

// * ChaCha20-Poly1305 AEAD

/**
 * Poly1305 one-time authenticator
 *
 * Computes a 16-byte authentication tag using the Poly1305 algorithm
 * with r and s derived from a 32-byte one-time key.
 */
function poly1305(message: Uint8Array, key: Uint8Array): Uint8Array {
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
  const result = new Uint8Array(16)
  for (let i = 0; i < 16; i++) {
    result[i] = Number(tag & 0xffn)
    tag >>= 8n
  }

  return result
}

/**
 * ChaCha20-Poly1305 AEAD Interface
 */
export interface ChaCha20Poly1305Cipherable {
  /**
   * Encrypt plaintext with associated data
   * @param plaintext - Data to encrypt
   * @param aad - Additional authenticated data (not encrypted)
   * @returns Ciphertext with 16-byte authentication tag appended
   */
  encrypt: (plaintext: Uint8Array, aad?: Uint8Array) => Uint8Array
  /**
   * Decrypt ciphertext and verify authentication tag
   * @param ciphertext - Ciphertext with 16-byte tag appended
   * @param aad - Additional authenticated data
   * @returns Decrypted plaintext, or throws error if authentication fails
   */
  decrypt: (ciphertext: Uint8Array, aad?: Uint8Array) => Uint8Array
}

/**
 * ChaCha20-Poly1305 AEAD Cipher
 *
 * Authenticated Encryption with Associated Data using ChaCha20 and Poly1305.
 *
 * @see RFC 8439 - ChaCha20 and Poly1305
 */
export function chacha20poly1305(key: Uint8Array, nonce: Uint8Array): ChaCha20Poly1305Cipherable {
  if (key.byteLength !== 32) {
    throw new KitError('ChaCha20-Poly1305 key must be 32 bytes')
  }
  if (nonce.byteLength !== 12) {
    throw new KitError('ChaCha20-Poly1305 nonce must be 12 bytes')
  }

  // Generate Poly1305 one-time key from first keystream block
  const polyKeyState = initState(key, nonce, 0)
  const polyKey = block(polyKeyState).subarray(0, 32)

  // Initialize cipher with counter starting at 1
  const cipher = _chacha20(key, nonce, 1)

  const encrypt = (plaintext: Uint8Array, aad: Uint8Array = new Uint8Array(0)): U8 => {
    // Encrypt plaintext
    const ciphertext = cipher.encrypt(plaintext)

    // Compute authentication tag
    // Poly1305 input: aad || pad16(aad) || ciphertext || pad16(ciphertext) || len(aad) || len(ciphertext)
    const aadLen = aad.length
    const ctLen = ciphertext.length
    const aadPadLen = (16 - (aadLen % 16)) % 16
    const ctPadLen = (16 - (ctLen % 16)) % 16

    const polyInput = new Uint8Array(aadLen + aadPadLen + ctLen + ctPadLen + 16)

    let offset = 0
    polyInput.set(aad, offset)
    offset += aadLen + aadPadLen
    polyInput.set(ciphertext, offset)
    offset += ctLen + ctPadLen

    // Lengths in little-endian (64-bit each)
    const view = new DataView(polyInput.buffer, polyInput.byteOffset, polyInput.byteLength)
    view.setBigUint64(offset, BigInt(aadLen), true)
    view.setBigUint64(offset + 8, BigInt(ctLen), true)

    const tag = poly1305(polyInput, polyKey)

    // Return ciphertext || tag
    const result = new U8(ctLen + 16)
    result.set(ciphertext)
    result.set(tag, ctLen)

    return result
  }

  const decrypt = (ciphertext: Uint8Array, aad: Uint8Array = new Uint8Array(0)): U8 => {
    if (ciphertext.length < 16) {
      throw new KitError('Ciphertext too short (must include 16-byte tag)')
    }

    const ctLen = ciphertext.length - 16
    const ct = ciphertext.subarray(0, ctLen)
    const tag = ciphertext.subarray(ctLen)

    // Verify authentication tag
    const aadLen = aad.length
    const aadPadLen = (16 - (aadLen % 16)) % 16
    const ctPadLen = (16 - (ctLen % 16)) % 16

    const polyInput = new Uint8Array(aadLen + aadPadLen + ctLen + ctPadLen + 16)

    let offset = 0
    polyInput.set(aad, offset)
    offset += aadLen + aadPadLen
    polyInput.set(ct, offset)
    offset += ctLen + ctPadLen

    const view = new DataView(polyInput.buffer, polyInput.byteOffset, polyInput.byteLength)
    view.setBigUint64(offset, BigInt(aadLen), true)
    view.setBigUint64(offset + 8, BigInt(ctLen), true)

    const expectedTag = poly1305(polyInput, polyKey)

    // Constant-time comparison
    let diff = 0
    for (let i = 0; i < 16; i++) {
      diff |= tag[i] ^ expectedTag[i]
    }

    if (diff !== 0) {
      throw new KitError('Authentication failed')
    }

    // Decrypt ciphertext
    return cipher.decrypt(ct)
  }

  return { encrypt, decrypt }
}
