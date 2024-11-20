import { genPrime } from '../../core/prime'
import { KitError, U8, gcd, lcm, modInverse, modPow, wrap } from '../../core/utils'

// * RSA Algorithm

function genKeyPair(b: number): Required<KeyPair> {
  const p = genPrime(b)
  const q = genPrime(b)
  const n = p * q
  const λ = lcm(p - 1n, q - 1n)

  // public key
  const e = 65537n
  if (gcd(e, λ) !== 1n) {
    throw new KitError('Invalid public exponent')
  }

  // private key
  const d = modInverse(e, λ)

  return { p, q, n, d, e }
}

function encrypt(M: Uint8Array, n: bigint, e: bigint): Uint8Array {
  const m = U8.from(M).toBI()
  const c = modPow(m, e, n)
  return U8.fromBI(c)
}

function decrypt(C: Uint8Array, n: bigint, d: bigint): Uint8Array {
  const c = U8.from(C).toBI()
  const m = modPow(c, d, n)
  return U8.fromBI(m)
}

function sign(H: Uint8Array, n: bigint, d: bigint): Uint8Array {
  const h = U8.from(H).toBI()
  const s = modPow(h, d, n)
  return U8.fromBI(s)
}

function verify(H: Uint8Array, S: Uint8Array, n: bigint, e: bigint): boolean {
  const h = U8.from(H).toBI()
  const s = U8.from(S).toBI()
  const m = modPow(s, e, n)
  return m === h
}

function fromKeyPair(keyPair: KeyPair) {
  let { n, d, e } = keyPair
  return {
    key: keyPair,
    encrypt: (M: Uint8Array) => {
      // 公钥加密
      if (e) {
        n = typeof n === 'bigint' ? n : U8.from(n).toBI()
        e = typeof e === 'bigint' ? e : U8.from(e).toBI()
        return encrypt(M, n, e)
      }

      // 不存在公钥时, 抛出错误
      throw new KitError('Missing necessary parameters to encrypt')
    },
    decrypt: (C: Uint8Array) => {
      // 私钥解密
      if (d) {
        n = typeof n === 'bigint' ? n : U8.from(n).toBI()
        d = typeof d === 'bigint' ? d : U8.from(d).toBI()
        return decrypt(C, n, d)
      }

      // 不存在私钥时, 抛出错误
      throw new KitError('Missing necessary parameters to decrypt')
    },
    sign: (H: Uint8Array) => {
      // 私钥签名
      if (d) {
        n = typeof n === 'bigint' ? n : U8.from(n).toBI()
        d = typeof d === 'bigint' ? d : U8.from(d).toBI()
        return sign(H, n, d)
      }

      // 不存在私钥时, 抛出错误
      throw new KitError('Missing necessary parameters to sign')
    },
    verify: (H: Uint8Array, S: Uint8Array) => {
      // 公钥验证
      if (e) {
        n = typeof n === 'bigint' ? n : U8.from(n).toBI()
        e = typeof e === 'bigint' ? e : U8.from(e).toBI()
        return verify(H, S, n, e)
      }

      // 不存在公钥时, 抛出错误
      throw new KitError('Missing necessary parameters to verify')
    },
  }
}

/**
 * @description
 * RSA Algorithm
 *
 * RSA 算法
 */
export const rsa = wrap<RSA>(
  (b: number = 1024) => fromKeyPair(genKeyPair(b)),
  {
    fromKeyPair,
  },
)

// * Interfaces

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
    key: KeyPair
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
