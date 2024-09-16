import { createIVStreamCipher } from '../core/cipher'
import { KitError, rotateL32 } from '../core/utils'

// * Constants

const A = new Uint32Array([0x4D34D34D, 0xD34D34D3, 0x34D34D34, 0x4D34D34D, 0xD34D34D3, 0x34D34D34, 0x4D34D34D, 0xD34D34D3])

// * Functions

function setupKey(K: Uint8Array, X: Uint8Array, C: Uint8Array) {
  const K16 = new Uint16Array(K.buffer)
  const X32 = new Uint32Array(X.buffer)
  const C32 = new Uint32Array(C.buffer)
  for (let i = 0; i < 8; i++) {
    if (i % 2 === 0) {
      const KH = K16[(i + 1) % 8]
      const KL = K16[i]
      X32[i] = (KH << 16) | KL
      const CH = K16[(i + 4) % 8]
      const CL = K16[(i + 5) % 8]
      C32[i] = (CH << 16) | CL
    }
    else {
      const KH = K16[(i + 5) % 8]
      const KL = K16[(i + 4) % 8]
      X32[i] = (KH << 16) | KL
      const CH = K16[i]
      const CL = K16[(i + 1) % 8]
      C32[i] = (CH << 16) | CL
    }
  }
}

function setupIV(iv: Uint8Array, C: Uint8Array) {
  const iv32 = new Uint32Array(iv.buffer)
  const iv16 = new Uint16Array(iv.buffer)
  const C32 = new Uint32Array(C.buffer)
  C32[0] ^= iv32[0]
  C32[1] ^= (iv16[3] << 16) | iv16[1]
  C32[2] ^= iv32[1]
  C32[3] ^= (iv16[2] << 16) | iv16[0]
  C32[4] ^= iv32[0]
  C32[5] ^= (iv16[3] << 16) | iv16[1]
  C32[6] ^= iv32[1]
  C32[7] ^= (iv16[2] << 16) | iv16[0]
}

// * Rabbit Algorithm

/**
 * @description
 * Rabbit stream cipher
 *
 * 兔子流密码
 *
 * @example
 * Note: Empty iv will skip iv setup
 *
 * 注意: 空 iv 将跳过 iv 配置
 * ```ts
 * const cipher = rabbit(k, iv)
 * cipher.encrypt(m)
 * cipher.decrypt(c)
 *
 * // Skip iv setup
 * const cipher = rabbit(k, '')
 * const cipher = rabbit(k, new Uint8Array(0))
 * ```
 */
export const rabbit = createIVStreamCipher(
  (K: Uint8Array, iv: Uint8Array) => {
    if (K.byteLength !== 16) {
      throw new KitError('rabbit requires a key of 16 bytes')
    }

    // 初始化变量
    let carray = 0
    const X = new Uint8Array(32)
    const C = new Uint8Array(32)
    const X32 = new Uint32Array(X.buffer)
    const C32 = new Uint32Array(C.buffer)
    const nextState = (skipExtract: boolean = false): Uint8Array => {
      // Counter System
      for (let i = 0; i < 8; i++) {
        const _C = C32[i]
        C32[i] = (C32[i] + A[i] + carray) | 0
        carray = C32[i] < _C ? 1 : 0
      }

      // G
      const G = new Uint32Array(8)
      G.forEach((_, i) => {
        const temp = (BigInt(X32[i]) + BigInt(C32[i])) & 0xFFFFFFFFn
        const square = temp * temp
        G[i] = Number((square ^ (square >> 32n)) & 0xFFFFFFFFn)
      })

      // Next State
      X32[0] = 0xFFFFFFFF & (G[0] + rotateL32(G[7], 16) + rotateL32(G[6], 16))
      X32[1] = 0xFFFFFFFF & (G[1] + rotateL32(G[0], 8) + G[7])
      X32[2] = 0xFFFFFFFF & (G[2] + rotateL32(G[1], 16) + rotateL32(G[0], 16))
      X32[3] = 0xFFFFFFFF & (G[3] + rotateL32(G[2], 8) + G[1])
      X32[4] = 0xFFFFFFFF & (G[4] + rotateL32(G[3], 16) + rotateL32(G[2], 16))
      X32[5] = 0xFFFFFFFF & (G[5] + rotateL32(G[4], 8) + G[3])
      X32[6] = 0xFFFFFFFF & (G[6] + rotateL32(G[5], 16) + rotateL32(G[4], 16))
      X32[7] = 0xFFFFFFFF & (G[7] + rotateL32(G[6], 8) + G[5])

      if (skipExtract) {
        return new Uint8Array()
      }

      // Extract Output
      const S = new Uint32Array(4)
      S[0] = X32[0] ^ (X32[5] >>> 16) ^ (X32[3] << 16)
      S[1] = X32[2] ^ (X32[7] >>> 16) ^ (X32[5] << 16)
      S[2] = X32[4] ^ (X32[1] >>> 16) ^ (X32[7] << 16)
      S[3] = X32[6] ^ (X32[3] >>> 16) ^ (X32[1] << 16)
      return new Uint8Array(S.buffer)
    }

    // 配置密钥
    setupKey(K, X, C)
    for (let i = 0; i < 4; i++) {
      nextState(true)
    }
    for (let i = 0; i < 8; i++) {
      C32[i] ^= X32[(i + 4) % 8]
    }

    // 配置 IV
    if (iv.byteLength === 8) {
      setupIV(iv, C)
      for (let i = 0; i < 4; i++) {
        nextState(true)
      }
    }
    else if (iv.byteLength !== 0 && iv.byteLength !== 8) {
      throw new KitError('rabbit requires a iv of 8 bytes')
    }

    // 密钥流
    let S = new Uint8Array(0)
    let current = 0
    const squeeze = (count: number) => {
      if (current >= count) {
        return S
      }
      const temp = new Uint8Array(count << 4)
      temp.set(S, 0)
      // console.log(temp.buffer)
      while (current < count) {
        temp.set(nextState(), current << 4)
        current++
      }
      S = temp
      return S
    }
    const cipher = (M: Uint8Array) => {
      const BLOCK_TOTAL = Math.ceil(M.byteLength >> 4) + 1
      S = squeeze(BLOCK_TOTAL)
      return M.map((byte, i) => byte ^ S[i])
    }

    return {
      encrypt: (M: Uint8Array) => cipher(M),
      decrypt: (C: Uint8Array) => cipher(C),
    }
  },
  {
    ALGORITHM: 'rabbit',
    KEY_SIZE: 16,
    IV_SIZE: 8,
  },
)
