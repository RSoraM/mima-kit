import { createCipher } from '../../core/cipher'
import { KitError, resizeBuffer, rotateL32, type U8, u8, u32 } from '../../core/utils'
import { poly1305 } from '../../hash/poly1305'

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

export interface ChaCha20Poly1305AEAD {
  /**
   * @param {Uint8Array} plaintext - 明文 / plaintext
   */
  encrypt: (plaintext: Uint8Array) => U8
  /**
   * @param {Uint8Array} ciphertext - 密文 / ciphertext
   */
  decrypt: (ciphertext: Uint8Array) => U8
  /**
   * @param {Uint8Array} cipherText - 密文 / ciphertext
   * @param {Uint8Array} additional_data - 附加数据 / Additional data
   * @returns {Uint8Array} - 认证标签 / Authentication tag
   */
  sign: (ciphertext: Uint8Array, additional_data?: Uint8Array) => U8
  /**
   * @param {Uint8Array} auth_tag - 认证标签 / Authentication tag
   * @param {Uint8Array} ciphertext - 密文 / ciphertext
   * @param {Uint8Array} additional_data - 附加数据 / Additional data
   */
  verify: (auth_tag: Uint8Array, ciphertext: Uint8Array, additional_data?: Uint8Array) => boolean
}

/**
 * ChaCha20-Poly1305 AEAD
 */
export function chacha20poly1305(key: Uint8Array, nonce: Uint8Array): ChaCha20Poly1305AEAD {
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

  const sign = (ciphertext: Uint8Array, additional_data: Uint8Array = new Uint8Array(0)): U8 => {
    // Poly1305 input: aad || pad16(aad) || ciphertext || pad16(ciphertext) || len(aad) || len(ciphertext)
    const ctLen = ciphertext.length
    const aadLen = additional_data.length
    const aadPadLen = (16 - (aadLen % 16)) % 16
    const ctPadLen = (16 - (ctLen % 16)) % 16
    const polyInput = new Uint8Array(aadLen + aadPadLen + ctLen + ctPadLen + 16)

    let offset = 0
    polyInput.set(additional_data, offset)
    offset += aadLen + aadPadLen
    polyInput.set(ciphertext, offset)
    offset += ctLen + ctPadLen

    // Lengths in little-endian (64-bit each)
    const view = new DataView(polyInput.buffer, polyInput.byteOffset, polyInput.byteLength)
    view.setBigUint64(offset, BigInt(aadLen), true)
    view.setBigUint64(offset + 8, BigInt(ctLen), true)

    return poly1305(polyKey, polyInput)
  }

  const verify = (auth_tag: Uint8Array, ciphertext: Uint8Array, additional_data: Uint8Array = new Uint8Array(0)): boolean => {
    return sign(ciphertext, additional_data).every((_, i) => _ === auth_tag[i])
  }

  return {
    encrypt: cipher.encrypt,
    decrypt: cipher.decrypt,
    sign,
    verify,
  }
}
