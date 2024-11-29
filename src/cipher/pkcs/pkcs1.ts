import * as asn from 'asn1js'
import type { Hash } from '../../core/hash'
import { Counter, KitError, U8, getBIBits, joinBuffer } from '../../core/utils'
import { sha1 } from '../../hash/sha1'
import type { RSAPrivateKey, RSAPublicKey } from './rsa'
import { rsa } from './rsa'

// * MGF1

export interface MGF {
  (mdfSeed: Uint8Array, maskLen: number): Uint8Array
}
export function mgf1(hash: Hash): MGF {
  return (mdfSeed: Uint8Array, maskLen: number) => {
    const T: Uint8Array[] = []
    const C = new Counter(joinBuffer(mdfSeed, new Uint8Array(4)))
    for (let i = 0; i < maskLen; i += hash.DIGEST_SIZE) {
      T.push(hash(C))
      C.inc(mdfSeed.length)
    }
    return joinBuffer(...T).slice(0, maskLen)
  }
}

// * Encryption Scheme

/**
 * OAEP 1.2.840.113549.1.1.7
 */
export function pkcs1_es_oaep(
  key: RSAPublicKey | RSAPrivateKey,
  hash: Hash = sha1,
  mgf = mgf1(hash),
  label = new Uint8Array(),
) {
  const k = (getBIBits(key.n) + 7) >> 3
  const hLen = hash.DIGEST_SIZE
  const MAX_MESSAGE_LENGTH = k - 2 * hLen - 2
  if (MAX_MESSAGE_LENGTH <= 0) {
    throw new KitError('Invalid key or hash function')
  }
  const _rsa = rsa(key)
  const lHash = hash(label)
  const encrypt = (M: Uint8Array) => {
    const mLen = M.length
    if (mLen > MAX_MESSAGE_LENGTH) {
      throw new KitError('Message too long')
    }
    // DB = lHash || PS || 0x01 || M
    const PS = new U8(MAX_MESSAGE_LENGTH - mLen)
    const DB = joinBuffer(lHash, PS, new U8([0x01]), M)
    // EM = 0x00 || maskedSeed || maskedDB
    const seed = new U8(hLen)
    crypto.getRandomValues(seed)
    const dbMask = mgf(seed, DB.length)
    const maskedDB = DB.map((v, i) => v ^ dbMask[i])
    const seedMask = mgf(maskedDB, hLen)
    const maskedSeed = seed.map((v, i) => v ^ seedMask[i])
    const EM = joinBuffer(new U8([0x00]), maskedSeed, maskedDB)
    return U8.fromBI(_rsa.encrypt(EM), k)
  }
  const decrypt = (C: Uint8Array) => {
    if (k !== C.length) {
      throw new KitError('Decryption error')
    }
    const EM = U8.fromBI(_rsa.decrypt(C), k)
    if (EM[0] !== 0x00) {
      throw new KitError('Decryption error')
    }
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
    const M = PS.slice(mOffset + 1)
    return M
  }
  return { encrypt, decrypt }
}

/**
 * PKCS#1-v1.5 1.2.840.113549.1.1.1
 */
export function pkcs1_es_1_5(
  key: RSAPublicKey | RSAPrivateKey,
) {
  const k = (getBIBits(key.n) + 7) >> 3
  const MAX_MESSAGE_LENGTH = k - 11
  if (MAX_MESSAGE_LENGTH <= 0) {
    throw new KitError('Invalid key')
  }
  const _rsa = rsa(key)
  const encrypt = (M: Uint8Array) => {
    if (M.length > MAX_MESSAGE_LENGTH) {
      throw new KitError('Message is too long')
    }
    const PS = new Uint8Array(k - M.length - 3)
    do {
      crypto.getRandomValues(PS)
    } while (PS.includes(0x00))
    const EM = joinBuffer(new U8([0x00, 0x02]), PS, new U8([0x00]), M)
    return U8.fromBI(_rsa.encrypt(EM), k)
  }
  const decrypt = (C: Uint8Array) => {
    if (C.length !== k) {
      throw new KitError('Decryption error')
    }
    const EM = U8.fromBI(_rsa.decrypt(C), k)
    if (EM[0] !== 0x00 || EM[1] !== 0x02) {
      throw new KitError('Decryption error')
    }
    const SeparatorIndex = EM.subarray(2).findIndex(v => v === 0x00)
    if (SeparatorIndex === -1) {
      throw new KitError('Decryption error')
    }
    const M = EM.slice(SeparatorIndex + 3)
    return M
  }
  return { encrypt, decrypt }
}

// * Signature Scheme with Appendix

export function pkcs1_ssa_pss(
  key: RSAPublicKey | RSAPrivateKey,
  hash: Hash = sha1,
  mgf = mgf1(hash),
  sLen = hash.DIGEST_SIZE,
) {
  const modBits = getBIBits(key.n)
  const k = (modBits + 7) >> 3
  const emLen = (modBits + 6) >> 3
  const emsa = emsa_pss(hash, mgf, sLen)
  const _rsa = rsa(key)
  const sign = (M: Uint8Array) => {
    const EM = emsa.encode(M, modBits - 1)
    const S = _rsa.sign(EM)
    return U8.fromBI(S, k)
  }
  const verify = (M: Uint8Array, S: Uint8Array) => {
    if (S.length !== k) {
      return false
    }
    const EM = U8.fromBI(_rsa.verify(S), emLen)
    return emsa.verify(M, EM, modBits - 1)
  }
  return { sign, verify }
}

export function pkcs1_ssa_1_5(
  key: RSAPublicKey | RSAPrivateKey,
  hash: Hash = sha1,
) {
  const modBits = getBIBits(key.n)
  const k = (modBits + 7) >> 3
  const _rsa = rsa(key)
  const sign = (M: Uint8Array) => {
    const EM = emsa_1_5(M, k, hash)
    const S = _rsa.sign(EM)
    return U8.fromBI(S, k)
  }
  const verify = (M: Uint8Array, S: Uint8Array) => {
    if (S.length !== k) {
      return false
    }
    const EM = U8.fromBI(_rsa.verify(S), k)
    const EM2 = emsa_1_5(M, k, hash)
    return EM.every((v, i) => v === EM2[i])
  }
  return { sign, verify }
}

// * Encoding Method for Signatures with Appendix

function emsa_pss(
  hash: Hash = sha1,
  mgf = mgf1(hash),
  sLen = hash.DIGEST_SIZE,
) {
  const hLen = hash.DIGEST_SIZE
  const encode = (M: Uint8Array, emBits: number) => {
    const mHash = hash(M)
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

function emsa_1_5(
  M: Uint8Array,
  emLen: number,
  hash: Hash = sha1,
) {
  const H = hash(M)
  const digestAlgorithm = new asn.Sequence({
    value: [
      new asn.ObjectIdentifier({ value: hash.OID }),
      new asn.Null(),
    ],
  })
  const digest = new asn.OctetString({ valueHex: H })
  const DigestInfo = new asn.Sequence({
    value: [
      digestAlgorithm,
      digest,
    ],
  })
  const T = new U8(DigestInfo.toBER(false))
  const psLen = emLen - T.length - 3
  if (psLen < 8) {
    throw new KitError('intended encoded message length too short')
  }
  const PS = new U8(psLen).fill(0xFF)
  const EM = joinBuffer(new U8([0x00, 0x01]), PS, new U8([0x00]), T)
  return EM
}
