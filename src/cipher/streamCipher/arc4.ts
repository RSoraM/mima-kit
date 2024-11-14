import { createStreamCipher } from '../../core/cipher'
import { KitError, U8 } from '../../core/utils'

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
  const result = new U8(M.byteLength)
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

function _arc4(K: Uint8Array) {
  if (K.byteLength < 5 || K.byteLength > 256) {
    throw new KitError(`RC4 requires a key of length 5 to 256 bytes`)
  }
  const SBox = KSA(K)
  return {
    encrypt: (M: Uint8Array) => cipher(M, SBox),
    decrypt: (M: Uint8Array) => cipher(M, SBox),
  }
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
  _arc4,
  {
    ALGORITHM: `ARC4`,
    KEY_SIZE: 16,
    MIN_KEY_SIZE: 5,
    MAX_KEY_SIZE: 256,
  },
)
