import { createStreamCipher } from '../../core/cipher'
import { KitError } from '../../core/utils'

// * Functions

function KSA(K: Uint8Array) {
  const SBox = new Uint8Array(256)
  SBox.forEach((_, i) => SBox[i] = i)

  let j = 0
  for (let i = 0; i < 256; i++) {
    j = (j + SBox[i] + K[i % K.byteLength]) % 256;
    [SBox[i], SBox[j]] = [SBox[j], SBox[i]]
  }

  return SBox
}

// * RC4 Algorithm

function cipher(M: Uint8Array, SBox: Uint8Array) {
  SBox = SBox.slice(0)
  const result = new Uint8Array(M.byteLength)
  let i = 0
  let j = 0
  M.forEach((_, k) => {
    i = (i + 1) % 256
    j = (j + SBox[i]) % 256;
    [SBox[i], SBox[j]] = [SBox[j], SBox[i]]
    result[k] = M[k] ^ SBox[(SBox[i] + SBox[j]) % 256]
  })
  return result
}

/**
 * @description
 * ARC4 stream cipher
 *
 * ARC4 流密码
 *
 * ```ts
 * const cipher = arc4(k)
 * cipher.encrypt(m)
 * cipher.decrypt(c)
 * ```
 */
export const arc4 = createStreamCipher(
  (K: Uint8Array) => {
    if (K.byteLength < 1 || K.byteLength > 256) {
      throw new KitError(`RC4 requires a key of length 1 to 256 bytes`)
    }
    const SBox = KSA(K)
    return {
      encrypt: (M: Uint8Array) => cipher(M, SBox),
      decrypt: (M: Uint8Array) => cipher(M, SBox),
    }
  },
  {
    ALGORITHM: `ARC4`,
    KEY_SIZE: 256,
  },
)
