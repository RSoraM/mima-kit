import * as asn from 'asn1js'
import type { Hash } from '../../core/hash'
import { genPrime } from '../../core/prime'
import { Counter, KitError, U8, gcd, getBIBits, joinBuffer, lcm, mod, modInverse, modPow } from '../../core/utils'

function mgf1(hash: Hash) {
  return (mdfSeed: bigint | Uint8Array, maskLen: number) => {
    mdfSeed = typeof mdfSeed === 'bigint' ? U8.fromBI(mdfSeed) : mdfSeed
    const T: Uint8Array[] = []
    const C = new Counter(joinBuffer(mdfSeed, new Uint8Array(4)))
    for (let i = 0; i < maskLen; i += hash.DIGEST_SIZE) {
      T.push(hash(C))
      C.inc(mdfSeed.length)
    }
    return joinBuffer(...T).slice(0, maskLen)
  }
}

// * RSA Algorithm

function genKey(b: number): RSAKeyPair {
  const p = genPrime(b >> 1)
  const q = genPrime(b >> 1)
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

  const publicKey: RSAPublicKey = { n, e }
  const privateKey: RSAPrivateKey = { n, d, p, q, dP, dQ, qInv }

  return {
    ...publicKey,
    ...privateKey,
    public_key: publicKey,
    private_key: privateKey,
  }
}

function exportKey(key: RSAKeyPair) {
  const { n, e, d, p, q, dP, dQ, qInv } = key
  const n_buffer = U8.fromBI(n, ((getBIBits(n) + 7) >> 3) + 1)
  const e_buffer = U8.fromBI(e)
  const d_buffer = U8.fromBI(d, ((getBIBits(d) + 7) >> 3) + 1)
  const p_buffer = U8.fromBI(p, ((getBIBits(p) + 7) >> 3) + 1)
  const q_buffer = U8.fromBI(q, ((getBIBits(q) + 7) >> 3) + 1)
  const dP_buffer = U8.fromBI(dP, ((getBIBits(dP) + 7) >> 3) + 1)
  const dQ_buffer = U8.fromBI(dQ, ((getBIBits(dQ) + 7) >> 3) + 1)
  const qInv_buffer = U8.fromBI(qInv, ((getBIBits(qInv) + 7) >> 3) + 1)

  const private_key = new asn.Sequence({
    value: [
      new asn.Integer({ value: 0 }),
      new asn.Integer({ valueHex: n_buffer, isHexOnly: true }),
      new asn.Integer({ valueHex: e_buffer, isHexOnly: true }),
      new asn.Integer({ valueHex: d_buffer, isHexOnly: true }),
      new asn.Integer({ valueHex: p_buffer, isHexOnly: true }),
      new asn.Integer({ valueHex: q_buffer, isHexOnly: true }),
      new asn.Integer({ valueHex: dP_buffer, isHexOnly: true }),
      new asn.Integer({ valueHex: dQ_buffer, isHexOnly: true }),
      new asn.Integer({ valueHex: qInv_buffer, isHexOnly: true }),
    ],
  })
  const public_key = new asn.Sequence({
    name: 'RSAPublicKey',
    value: [
      new asn.Sequence({
        value: [
          new asn.ObjectIdentifier({ value: '1.2.840.113549.1.1.1' }),
          new asn.Null(),
        ],
      }),
      new asn.BitString({
        valueHex: new asn.Sequence({
          value: [
            new asn.Integer({ valueHex: n_buffer, isHexOnly: true }),
            new asn.Integer({ valueHex: e_buffer, isHexOnly: true }),
          ],
        }).toBER(),
        isHexOnly: true,
      }),
    ],
  })
  return {
    private_key: new U8(private_key.toBER(false)),
    public_key: new U8(public_key.toBER(false)),
  }
}

function ePrim(key: RSAPublicKey, M: bigint | Uint8Array) {
  const { n, e } = key
  M = typeof M === 'bigint' ? M : U8.from(M).toBI()
  if (M >= n) {
    throw new KitError('Message representative out of range')
  }
  return modPow(M, e, n)
}

function dPrim(key: RSAPrivateKey, C: bigint | Uint8Array) {
  const { n, d } = key
  C = typeof C === 'bigint' ? C : U8.from(C).toBI()
  if (C >= n) {
    throw new KitError('Ciphertext representative out of range')
  }
  return modPow(C, d, n)
}

function sPrimV1(key: RSAPrivateKey, M: bigint | Uint8Array) {
  const { n, d } = key
  M = typeof M === 'bigint' ? M : U8.from(M).toBI()
  if (M >= n) {
    throw new KitError('Message representative out of range')
  }
  return modPow(M, d, n)
}

function vPrimV1(key: RSAPublicKey, S: bigint | Uint8Array) {
  const { n, e } = key
  S = typeof S === 'bigint' ? S : U8.from(S).toBI()
  if (S >= n) {
    throw new KitError('Signature is too long')
  }
  return modPow(S, e, n)
}

function ES_OAEP(hash: Hash) {
  const mgf = mgf1(hash)
  const encrypt = (key: RSAPublicKey, M: Uint8Array, label = new Uint8Array()) => {
    const k = (getBIBits(key.n) + 7) >> 3
    const mLen = M.length
    const hLen = hash.DIGEST_SIZE
    const dbLen = k - hLen - 1
    if (mLen > k - 2 * hLen - 2) {
      throw new KitError('Message too long')
    }

    // * EME-OAEP encoding

    // DB = lHash || PS || 0x01 || M
    const DB = new Uint8Array(dbLen)
    const lHash = hash(label)
    const mOffset = DB.length - mLen
    DB.set(lHash, 0)
    DB.set(M, mOffset)
    DB[mOffset - 1] = 0x01
    // EM = 0x00 || maskedSeed || maskedDB
    const seed = new Uint8Array(hLen)
    crypto.getRandomValues(seed)
    const dbMask = mgf(seed, dbLen)
    const maskedDB = DB.map((v, i) => v ^ dbMask[i])
    const seedMask = mgf(maskedDB, hLen)
    const maskedSeed = seed.map((v, i) => v ^ seedMask[i])
    const EM = joinBuffer(new Uint8Array([0x00]), maskedSeed, maskedDB)
    return U8.fromBI(ePrim(key, EM.toBI()), k)
  }
  const decrypt = (key: RSAPrivateKey, C: Uint8Array, label = new Uint8Array()) => {
    const k = (getBIBits(key.n) + 7) >> 3
    const hLen = hash.DIGEST_SIZE
    if (k !== C.length) {
      throw new KitError('Decryption error')
    }
    if (k < 2 * hLen + 2) {
      throw new KitError('Decryption error')
    }
    const EM = U8.fromBI(dPrim(key, C), k)
    if (EM[0] !== 0x00) {
      throw new KitError('Decryption error')
    }
    const lHash = hash(label)
    const maskedSeed = EM.subarray(1, hLen + 1)
    const maskedDB = EM.subarray(hLen + 1)
    const seedMask = mgf(maskedDB, hLen)
    const seed = maskedSeed.map((v, i) => v ^ seedMask[i])
    const dbMask = mgf(seed, maskedDB.length)
    const DB = maskedDB.map((v, i) => v ^ dbMask[i])
    const lHash_ = DB.subarray(0, hLen)
    if (lHash.some((v, i) => v !== lHash_[i])) {
      throw new KitError('Decryption error')
    }
    const PS = DB.subarray(hLen)
    const mOffset = PS.findIndex(v => v === 0x01)
    if (mOffset === -1) {
      throw new KitError('Decryption error')
    }
    if (PS.subarray(0, mOffset).some(v => v !== 0x00)) {
      throw new KitError('Decryption error')
    }
    const M = PS.subarray(mOffset + 1)
    return M
  }
  return { encrypt, decrypt }
}

const ES_PKCS1_1_5 = (() => {
  const encrypt = (key: RSAPublicKey, M: Uint8Array) => {
    const k = (getBIBits(key.n) + 7) >> 3
    if (M.length > k - 11) {
      throw new KitError('Message is too long')
    }

    const PS = new Uint8Array(k - M.length - 3)
    while (1) {
      crypto.getRandomValues(PS)
      if (!PS.includes(0x00)) {
        break
      }
    }
    const EM = joinBuffer(new U8([0x00, 0x02]), PS, new U8([0x00]), M)
    return U8.fromBI(ePrim(key, EM), k)
  }
  const decrypt = (key: RSAPrivateKey, C: Uint8Array) => {
    const k = (getBIBits(key.n) + 7) >> 3
    if (C.length !== k) {
      throw new KitError('Decryption error')
    }

    const EM = U8.fromBI(dPrim(key, C), k)
    if (EM[0] !== 0x00 || EM[1] !== 0x02) {
      throw new KitError('Decryption error')
    }
    const SeparatorIndex = EM.subarray(2).findIndex(v => v === 0x00)
    if (SeparatorIndex === -1) {
      throw new KitError('Decryption error')
    }
    const M = EM.subarray(SeparatorIndex + 3)
    return M
  }
  return { encrypt, decrypt }
})()

function EMSA_PSS(hash: Hash, sLen: number) {
  const mgf = mgf1(hash)
  const encode = (M: Uint8Array, emBits: number) => {
    const mHash = hash(M)
    const hLen = hash.DIGEST_SIZE
    const emLen = (emBits + 7) >> 3
    if (emLen < hLen + sLen + 2) {
      throw new KitError('Encoding error')
    }
    const salt = new U8(sLen)
    crypto.getRandomValues(salt)
    const M2 = joinBuffer(new U8(8), mHash, salt)
    const H = hash(M2)
    const PS = new U8(emLen - sLen - hLen - 2)
    const DB = joinBuffer(PS, new U8([0x01]), salt)
    const dbMask = mgf(H, DB.length)
    const maskedDB = DB.map((v, i) => v ^ dbMask[i])
    const bitMask = 0xFF >> (emLen << 3) - emBits
    maskedDB[0] &= bitMask
    const EM = joinBuffer(maskedDB, H, new U8([0xBC]))
    return EM
  }
  const verify = (M: Uint8Array, EM: Uint8Array, emBits: number) => {
    const mHash = hash(M)
    const hLen = hash.DIGEST_SIZE
    const emLen = (emBits + 7) >> 3
    if (emLen !== EM.length || emLen < hLen + sLen + 2) {
      return false
    }
    if (EM[emLen - 1] !== 0xBC) {
      return false
    }
    const maskedDB = EM.subarray(0, emLen - hLen - 1)
    const H = EM.subarray(maskedDB.length, emLen - 1)
    const bitMask = 0xFF >> (emLen << 3) - emBits
    if (maskedDB[0] > bitMask) {
      return false
    }
    const dbMask = mgf(H, maskedDB.length)
    const DB = maskedDB.map((v, i) => v ^ dbMask[i])
    DB[0] &= bitMask
    const PS = DB.subarray(0, DB.length - sLen - 1)
    if (PS.some(v => v !== 0x00)) {
      return false
    }
    if (DB[PS.length] !== 0x01) {
      return false
    }
    const salt = DB.subarray(PS.length + 1)
    const M2 = joinBuffer(new U8(8), mHash, salt)
    const H2 = hash(M2)
    return H2.every((v, i) => v === H[i])
  }
  return { encode, verify }
}

function SSA_PSS(hash: Hash, sLen: number) {
  const emsa = EMSA_PSS(hash, sLen)
  const sign = (key: RSAPrivateKey, M: Uint8Array) => {
    const modBits = getBIBits(key.n)
    const EM = emsa.encode(M, modBits - 1)
    const S = sPrimV1(key, EM)
    return U8.fromBI(S)
  }
  const verify = (key: RSAPublicKey, M: Uint8Array, S: Uint8Array) => {
    const modBits = getBIBits(key.n)
    const k = (modBits + 7) >> 3
    if (S.length !== k) {
      return false
    }
    const EM = U8.fromBI(vPrimV1(key, S))
    return emsa.verify(M, EM, modBits - 1)
  }
  return { sign, verify }
}

/**
 * @description
 * RSA Algorithm
 *
 * RSA 算法
 */
export const rsa = {
  genKey,
  exportKey,
  ePrim,
  dPrim,
  ES_OAEP,
  ES_PKCS1_1_5,
  SSA_PSS,
}

// * Interfaces

interface RSAPublicKey {
  /** 模数 / Modulus */
  n: bigint
  /** 公钥指数 / Public Exponent */
  e: bigint
}
interface RSAPrivateKey {
  /** 模数 / Modulus */
  n: bigint
  /** 私钥指数 / Private Exponent */
  d: bigint
  p: bigint
  q: bigint
  dP: bigint
  dQ: bigint
  qInv: bigint
}
interface RSAKeyPair extends RSAPublicKey, RSAPrivateKey {
  public_key: RSAPublicKey
  private_key: RSAPrivateKey
}
