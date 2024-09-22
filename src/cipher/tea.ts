import { createCipher } from '../core/cipher'

// * Constants

const DELTA_BE = 0x9E3779B9

// * Tiny Encryption Algorithm (TEA)

export const tea = createCipher(
  (K: Uint8Array) => {
    if (K.byteLength !== 16) {
      throw new Error('TEA requires a key of length 16 bytes')
    }
    const K32 = new Uint32Array(K.buffer)

    const encrypt = (M: Uint8Array) => {
      if (M.byteLength !== 8) {
        throw new Error('TEA requires a block of length 8 bytes')
      }
      const C = M.slice(0)
      const C32 = new Uint32Array(C.buffer)
      let sum = 0
      for (let i = 0; i < 32; i++) {
        sum += DELTA_BE
        C32[0] += ((C32[1] << 4) + K32[0]) ^ (C32[1] + sum) ^ ((C32[1] >>> 5) + K32[1])
        C32[1] += ((C32[0] << 4) + K32[2]) ^ (C32[0] + sum) ^ ((C32[0] >>> 5) + K32[3])
      }
      return C
    }
    const decrypt = (C: Uint8Array) => {
      if (C.byteLength !== 8) {
        throw new Error('TEA requires a block of length 8 bytes')
      }
      const M = C.slice(0)
      const M32 = new Uint32Array(M.buffer)
      let sum = 0xC6EF3720
      for (let i = 0; i < 32; i++) {
        M32[1] -= ((M32[0] << 4) + K32[2]) ^ (M32[0] + sum) ^ ((M32[0] >>> 5) + K32[3])
        M32[0] -= ((M32[1] << 4) + K32[0]) ^ (M32[1] + sum) ^ ((M32[1] >>> 5) + K32[1])
        sum -= DELTA_BE
      }
      return M
    }
    return { encrypt, decrypt }
  },
  {
    ALGORITHM: 'TEA',
    BLOCK_SIZE: 8,
    KEY_SIZE: 16,
  },
)

export const xtea = createCipher(
  (K: Uint8Array) => {
    if (K.byteLength !== 16) {
      throw new Error('TEA requires a key of length 16 bytes')
    }
    const K32 = new Uint32Array(K.buffer)

    const encrypt = (M: Uint8Array) => {
      if (M.byteLength !== 8) {
        throw new Error('TEA requires a block of length 8 bytes')
      }
      const C = M.slice(0)
      const C32 = new Uint32Array(C.buffer)
      let sum = 0
      for (let i = 0; i < 32; i++) {
        C32[0] += (C32[1] << 4 ^ C32[1] >>> 5) + C32[1] ^ sum + K32[sum & 3]
        sum += DELTA_BE
        C32[1] += (C32[0] << 4 ^ C32[0] >>> 5) + C32[0] ^ sum + K32[(sum >>> 11) & 3]
      }
      return C
    }
    const decrypt = (C: Uint8Array) => {
      if (C.byteLength !== 8) {
        throw new Error('TEA requires a block of length 8 bytes')
      }
      const M = C.slice(0)
      const M32 = new Uint32Array(M.buffer)
      let sum = DELTA_BE << 5
      for (let i = 0; i < 32; i++) {
        M32[1] -= ((M32[0] << 4 ^ M32[0] >>> 5) + M32[0]) ^ (sum + K32[(sum >>> 11) & 3])
        sum -= DELTA_BE
        M32[0] -= ((M32[1] << 4 ^ M32[1] >>> 5) + M32[1]) ^ (sum + K32[sum & 3])
      }
      return M
    }
    return { encrypt, decrypt }
  },
  {
    ALGORITHM: 'XTEA',
    BLOCK_SIZE: 8,
    KEY_SIZE: 16,
  },
)
