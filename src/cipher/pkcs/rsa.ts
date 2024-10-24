import { genPrime, nextPrime } from '../../core/prime'
import { BIToU8, KitError, U8ToBI, gcd, lcm, modInverse, modPow } from '../../core/utils'

function genKeyPair(b: number): Required<KeyPair> {
  const p = genPrime(b)
  const q = genPrime(b)
  const n = p * q
  const λ = lcm(p - 1n, q - 1n)

  // public key
  let e = 65537n
  while (gcd(e, λ) !== 1n) {
    e = nextPrime(e)
  }

  // private key
  const d = modInverse(e, λ)

  return { p, q, n, d, e }
}

function encrypt(M: Uint8Array, n: bigint, e: bigint): Uint8Array {
  const m = U8ToBI(M)
  const c = modPow(m, e, n)
  return BIToU8(c)
}

function decrypt(C: Uint8Array, n: bigint, d: bigint): Uint8Array {
  const c = U8ToBI(C)
  const m = modPow(c, d, n)
  return BIToU8(m)
}

function sign(H: Uint8Array, n: bigint, d: bigint): Uint8Array {
  const h = U8ToBI(H)
  const s = modPow(h, d, n)
  return BIToU8(s)
}

function verify(H: Uint8Array, S: Uint8Array, n: bigint, e: bigint): boolean {
  const h = U8ToBI(H)
  const s = U8ToBI(S)
  const m = modPow(s, e, n)
  return m === h
}

function fromKeyPair(keyPair: KeyPair) {
  let { n, d, e } = keyPair
  return {
    encrypt: (M: Uint8Array) => {
      // 公钥加密
      if (e) {
        n = typeof n === 'bigint' ? n : U8ToBI(n)
        e = typeof e === 'bigint' ? e : U8ToBI(e)
        return encrypt(M, n, e)
      }

      // 不存在公钥时, 抛出错误
      throw new KitError('Missing necessary parameters to encrypt')
    },
    decrypt: (C: Uint8Array) => {
      // 私钥解密
      if (d) {
        n = typeof n === 'bigint' ? n : U8ToBI(n)
        d = typeof d === 'bigint' ? d : U8ToBI(d)
        return decrypt(C, n, d)
      }

      // 不存在私钥时, 抛出错误
      throw new KitError('Missing necessary parameters to decrypt')
    },
    sign: (H: Uint8Array) => {
      // 私钥签名
      if (d) {
        n = typeof n === 'bigint' ? n : U8ToBI(n)
        d = typeof d === 'bigint' ? d : U8ToBI(d)
        return sign(H, n, d)
      }

      // 不存在私钥时, 抛出错误
      throw new KitError('Missing necessary parameters to sign')
    },
    verify: (H: Uint8Array, S: Uint8Array) => {
      // 公钥验证
      if (e) {
        n = typeof n === 'bigint' ? n : U8ToBI(n)
        e = typeof e === 'bigint' ? e : U8ToBI(e)
        return verify(H, S, n, e)
      }

      // 不存在公钥时, 抛出错误
      throw new KitError('Missing necessary parameters to verify')
    },
  }
}

export const rsa: RSA = Object.assign(
  (b: number = 1024) => fromKeyPair(genKeyPair(b)),
  {
    fromKeyPair,
  },
)

interface KeyPair {
  n: bigint | Uint8Array
  d?: bigint | Uint8Array
  e?: bigint | Uint8Array
  p?: bigint | Uint8Array
  q?: bigint | Uint8Array
}

interface Encryptable {
  (M: Uint8Array): Uint8Array
}
interface Decryptable {
  (P: Uint8Array): Uint8Array
}
interface Signable {
  (H: Uint8Array): Uint8Array
}
interface Verifyable {
  (H: Uint8Array, S: Uint8Array): boolean
}

interface FromKeyPair {
  (keyPair: KeyPair): {
    encrypt: Encryptable
    decrypt: Decryptable
    sign: Signable
    verify: Verifyable
  }
}
interface RSA {
  (b: number): ReturnType<FromKeyPair>
  fromKeyPair: FromKeyPair
}
