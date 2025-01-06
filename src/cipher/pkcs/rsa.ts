import type { RandomPrimeGenerator } from '../../core/prime'
import { genPrime } from '../../core/prime'
import { KitError, U8, gcd, lcm, mod, modInverse, modPow } from '../../core/utils'

// * Interfaces

export interface RSAPublicKey {
  /** 模数 / Modulus */
  n: bigint
  /** 公钥指数 / Public Exponent */
  e: bigint
}
export interface RSAPrivateKey extends RSAPublicKey {
  /** 模数 / Modulus */
  n: bigint
  /** 公钥指数 / Public Exponent */
  e: bigint
  /** 私钥指数 / Private Exponent */
  d: bigint
  p: bigint
  q: bigint
  dP: bigint
  dQ: bigint
  qInv: bigint
}

export interface RSACipherable {
  /**
   * 使用 RSA 加密原语加密消息
   *
   * Encrypt message using RSA encryption primitive
   */
  encrypt: (M: Uint8Array) => bigint
  /**
   * 使用 RSA 解密原语解密密文
   *
   * Decrypt ciphertext using RSA decryption primitive
   */
  decrypt: (C: Uint8Array) => bigint
}
export interface RSAVerifiable {
  /**
   * 使用 RSA 签名原语对消息签名
   *
   * Sign message using RSA signature primitive
   */
  sign: (M: Uint8Array) => bigint
  /**
   * 使用 RSA 验证原语验证签名
   *
   * Verify signature using RSA verification primitive
   */
  verify: (S: Uint8Array) => bigint
}

// * RSA Algorithm

/**
 * RSA 加密原语
 *
 * RSA encryption primitive
 */
function encryptionPrimitive(key: Partial<RSAPublicKey>, M: bigint | Uint8Array) {
  const { n, e } = key
  if (e === undefined || n === undefined) {
    throw new KitError('Invalid public key')
  }
  M = typeof M === 'bigint' ? M : U8.from(M).toBI()
  if (M >= n) {
    throw new KitError('Message representative out of range')
  }
  return modPow(M, e, n)
}

/**
 * RSA 解密原语
 *
 * RSA decryption primitive
 */
function decryptionPrimitive(key: Partial<RSAPrivateKey>, C: bigint | Uint8Array) {
  const { n, d } = key
  if (d === undefined || n === undefined) {
    throw new KitError('Invalid private key')
  }
  C = typeof C === 'bigint' ? C : U8.from(C).toBI()
  if (C >= n) {
    throw new KitError('Ciphertext representative out of range')
  }
  return modPow(C, d, n)
}

/**
 * RSA 签名原语
 *
 * RSA signature primitive
 */
function signaturePrimitive(key: Partial<RSAPrivateKey>, M: bigint | Uint8Array) {
  const { n, d } = key
  if (d === undefined || n === undefined) {
    throw new KitError('Invalid private key')
  }
  M = typeof M === 'bigint' ? M : U8.from(M).toBI()
  if (M >= n) {
    throw new KitError('Message representative out of range')
  }
  return modPow(M, d, n)
}

/**
 * RSA 验证原语
 *
 * RSA verification primitive
 */
function verificationPrimitive(key: Partial<RSAPublicKey>, S: bigint | Uint8Array) {
  const { n, e } = key
  if (e === undefined || n === undefined) {
    throw new KitError('Invalid public key')
  }
  S = typeof S === 'bigint' ? S : U8.from(S).toBI()
  if (S >= n) {
    throw new KitError('Signature is too long')
  }
  return modPow(S, e, n)
}

/**
 * RSA 密钥生成
 *
 * RSA key generation
 *
 * @param {number} b - RSA 私钥长度 / RSA private key length (bit)
 * @param {RandomPrimeGenerator} rpg - 随机素数生成器 / Random prime generator
 */
function genKey(b: number, rpg = genPrime): RSAPrivateKey {
  const p = rpg(b >> 1)
  const q = rpg(b >> 1)
  const n = p * q
  const λ = lcm(p - 1n, q - 1n)

  // public key
  const e = 65537n
  if (gcd(e, λ) !== 1n) {
    throw new KitError('Invalid public exponent')
  }

  // private key
  const d = modInverse(e, λ)

  const dP = mod(d, p - 1n)
  const dQ = mod(d, q - 1n)
  const qInv = modInverse(q, p)

  const privateKey: RSAPrivateKey = { n, e, d, p, q, dP, dQ, qInv }

  return privateKey
}

function fromKey(key: Partial<RSAPrivateKey>): RSACipherable & RSAVerifiable {
  const encrypt = (M: Uint8Array) => encryptionPrimitive(key, M)
  const decrypt = (C: Uint8Array) => decryptionPrimitive(key, C)
  const sign = (M: Uint8Array) => signaturePrimitive(key, M)
  const verify = (S: Uint8Array) => verificationPrimitive(key, S)
  return {
    ...key,
    encrypt,
    decrypt,
    sign,
    verify,
  }
}

/**
 * 根据 RSA 私钥长度生成 RSA 密钥对, 并返回 RSA 加密原语和签名原语
 *
 * Generate RSA key pair according to RSA private key length, and return RSA encryption primitive and signature primitive
 *
 * @param {number} b - RSA 私钥长度 / RSA private key length
 * @param {RandomPrimeGenerator} rpg - 随机素数生成器 / Random prime generator
 */
export function rsa(b: number, rpg?: RandomPrimeGenerator): RSACipherable & RSAVerifiable & RSAPrivateKey
/**
 * 根据 RSA 公钥或私钥生成 RSA 加密原语和验证原语
 *
 * Generate RSA encryption primitive and verification primitive according to RSA public or private key
 *
 * @param {RSAPrivateKey | RSAPublicKey} key - RSA 公钥或私钥 / RSA public or private key
 */
export function rsa<T extends RSAPrivateKey | RSAPublicKey>(key: T): RSACipherable & RSAVerifiable & T
export function rsa(b: number | RSAPrivateKey | RSAPublicKey, rpg = genPrime) {
  if (typeof b === 'number') {
    return fromKey(genKey(b, rpg))
  }
  return fromKey(b)
}
