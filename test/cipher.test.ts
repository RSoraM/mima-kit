import { describe, expect, it } from 'vitest'
import { B64, HEX, UTF8 } from '../src/core/codec'
import * as cipherSuite from '../src/core/cipher'
import { sm4 } from '../src/cipher/blockCipher/sm4'
import { aes } from '../src/cipher/blockCipher/aes'
import { aria } from '../src/cipher/blockCipher/aria'
import { des, t_des } from '../src/cipher/blockCipher/des'
import { blowfish } from '../src/cipher/blockCipher/blowfish'
import { twofish } from '../src/cipher/blockCipher/twofish'
import { tea, xtea } from '../src/cipher/blockCipher/tea'
import { arc4 } from '../src/cipher/streamCipher/arc4'
import { arc5 } from '../src/cipher/blockCipher/arc5'
import { salsa20 } from '../src/cipher/streamCipher/salsa20'
import { rabbit } from '../src/cipher/streamCipher/rabbit'
import type { ZUCParams } from '../src/cipher/streamCipher/zuc'
import { eea3, eia3 } from '../src/cipher/streamCipher/zuc'
import { camellia } from '../src/cipher/blockCipher/camellia'
import { U8 } from '../src/core/utils'

const { ecb, cbc, pcbc, cfb, ofb, ctr, gcm } = cipherSuite
const { ANSI_X923, NoPadding } = cipherSuite

describe('stream cipher', () => {
  // * RC4
  it('arc4', () => {
    const k = UTF8.parse('Password')
    const m = UTF8.parse('Plaintext')
    const c = HEX.parse('70830E0E2C1AC34177')

    const cipher = arc4(k)
    expect(cipher.encrypt(m)).toMatchObject(c)
    expect(cipher.decrypt(c)).toMatchObject(m)
  })
  // * Salsa20
  it('salsa20', () => {
    const k = UTF8.parse('2b7e151628aed2a6abf7158809cf4f3c')
    const iv = UTF8.parse('cafebabe')
    const m = UTF8.parse('meowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeow')
    const c = B64.parse('heP0vh0o4kkRZVkf1R9CQ8VsUZEM8TIX1ZDra/1xbrp7nX4csbbLRcyFkofzddSqnjmP20LEQVLQy6kPMUOJuO8jb/soNNDmsS/AczPsUVJZ2MzRKFXwi2aeM1GEv1iuWJConhfqqEjVQXre7WGGSsh3CxnmUNN10r2mTzm/tNSarH8Wy4s4RmmWrHsPOY2WEiyAvMIdVq+X8UATk7GXtpL4Z8CXnrswFp7Cd+M28C8u9hjt6taYC9+4DJc=')

    const cipher = salsa20(k, iv)
    expect(cipher.encrypt(m)).toMatchObject(c)
    expect(cipher.decrypt(c)).toMatchObject(m)
  })
  // * Rabbit
  it('rabbit', () => {
    const k_0 = new U8(16)
    const iv_0 = new U8(8)
    const out_0 = new U8([0xED, 0xB7, 0x05, 0x67, 0x37, 0x5D, 0xCD, 0x7C, 0xD8, 0x95, 0x54, 0xF8, 0x5E, 0x27, 0xA7, 0xC6, 0x8D, 0x4A, 0xDC, 0x70, 0x32, 0x29, 0x8F, 0x7B, 0xD4, 0xEF, 0xF5, 0x04, 0xAC, 0xA6, 0x29, 0x5F, 0x66, 0x8F, 0xBF, 0x47, 0x8A, 0xDB, 0x2B, 0xE5, 0x1E, 0x6C, 0xDE, 0x29, 0x2B, 0x82, 0xDE, 0x2A])
    const cipher_0 = rabbit(k_0, iv_0)
    expect(cipher_0.encrypt(new U8(48))).toMatchObject(out_0)
    expect(cipher_0.decrypt(out_0)).toMatchObject(new U8(48))

    const iv_1 = new U8([0x27, 0x17, 0xF4, 0xD2, 0x1A, 0x56, 0xEB, 0xA6])
    const out_1 = new U8([0x4D, 0x10, 0x51, 0xA1, 0x23, 0xAF, 0xB6, 0x70, 0xBF, 0x8D, 0x85, 0x05, 0xC8, 0xD8, 0x5A, 0x44, 0x03, 0x5B, 0xC3, 0xAC, 0xC6, 0x67, 0xAE, 0xAE, 0x5B, 0x2C, 0xF4, 0x47, 0x79, 0xF2, 0xC8, 0x96, 0xCB, 0x51, 0x15, 0xF0, 0x34, 0xF0, 0x3D, 0x31, 0x17, 0x1C, 0xA7, 0x5F, 0x89, 0xFC, 0xCB, 0x9F])
    const cipher_1 = rabbit(k_0, iv_1)
    expect(cipher_1.encrypt(new U8(48))).toMatchObject(out_1)
    expect(cipher_1.decrypt(out_1)).toMatchObject(new U8(48))

    // Skip iv setup
    const k_2 = new U8([0x43, 0x00, 0x9B, 0xC0, 0x01, 0xAB, 0xE9, 0xE9, 0x33, 0xC7, 0xE0, 0x87, 0x15, 0x74, 0x95, 0x83])
    const out_2 = new U8([0x9B, 0x60, 0xD0, 0x02, 0xFD, 0x5C, 0xEB, 0x32, 0xAC, 0xCD, 0x41, 0xA0, 0xCD, 0x0D, 0xB1, 0x0C, 0xAD, 0x3E, 0xFF, 0x4C, 0x11, 0x92, 0x70, 0x7B, 0x5A, 0x01, 0x17, 0x0F, 0xCA, 0x9F, 0xFC, 0x95, 0x28, 0x74, 0x94, 0x3A, 0xAD, 0x47, 0x41, 0x92, 0x3F, 0x7F, 0xFC, 0x8B, 0xDE, 0xE5, 0x49, 0x96])
    const cipher_2 = rabbit(k_2, new U8())
    expect(cipher_2.encrypt(new U8(48))).toMatchObject(out_2)
    expect(cipher_2.decrypt(out_2)).toMatchObject(new U8(48))
  })
  // * ZUC
  it('zuc-eea3', () => {
    // source: https://www.gsma.com/get-involved/working-groups/wp-content/uploads/2014/12/eea3eia3testdatav11.pdf
    const k = new U8([0x17, 0x3D, 0x14, 0xBA, 0x50, 0x03, 0x73, 0x1D, 0x7A, 0x60, 0x04, 0x94, 0x70, 0xF0, 0x0A, 0x29])
    const m = new U8([0x6C, 0xF6, 0x53, 0x40, 0x73, 0x55, 0x52, 0xAB, 0x0C, 0x97, 0x52, 0xFA, 0x6F, 0x90, 0x25, 0xFE, 0x0B, 0xD6, 0x75, 0xD9, 0x00, 0x58, 0x75, 0xB2])
    const c = new U8([0xA6, 0xC8, 0x5F, 0xC6, 0x6A, 0xFB, 0x85, 0x33, 0xAA, 0xFC, 0x25, 0x18, 0xDF, 0xE7, 0x84, 0x94, 0x0E, 0xE1, 0xE4, 0xB0, 0x30, 0x23, 0x8C, 0xC8])
    const encrypt: ZUCParams = {
      KEY: k,
      M: m,
      COUNTER: 0x66035492,
      BEARER: 0xF,
      DIRECTION: 0,
      LENGTH: 0xC1,
    }
    const decrypt: ZUCParams = {
      KEY: k,
      M: c,
      COUNTER: 0x66035492,
      BEARER: 0xF,
      DIRECTION: 0,
      LENGTH: 0xC1,
    }
    expect(eea3(encrypt)).toMatchObject(c)
    expect(eea3(decrypt)).toMatchObject(m)
  })
  it('zuc-eia3', () => {
    const t1: ZUCParams = {
      KEY: new U8(16),
      M: new U8(4),
      COUNTER: 0,
      BEARER: 0,
      DIRECTION: 0,
      LENGTH: 1,
    }
    const r1 = new U8([0xC8, 0xA9, 0x59, 0x5E])
    const t2: ZUCParams = {
      KEY: new U8([0x47, 0x05, 0x41, 0x25, 0x56, 0x1E, 0xB2, 0xDD, 0xA9, 0x40, 0x59, 0xDA, 0x05, 0x09, 0x78, 0x50]),
      M: new U8(12),
      COUNTER: 0x561EB2DD,
      BEARER: 0x14,
      DIRECTION: 0,
      LENGTH: 90,
    }
    const r2 = new U8([0x67, 0x19, 0xA0, 0x88])
    const t3: ZUCParams = {
      KEY: new U8([0x6B, 0x8B, 0x08, 0xEE, 0x79, 0xE0, 0xB5, 0x98, 0x2D, 0x6D, 0x12, 0x8E, 0xA9, 0xF2, 0x20, 0xCB]),
      M: new U8([0x5B, 0xAD, 0x72, 0x47, 0x10, 0xBA, 0x1C, 0x56, 0xD5, 0xA3, 0x15, 0xF8, 0xD4, 0x0F, 0x6E, 0x09, 0x37, 0x80, 0xBE, 0x8E, 0x8D, 0xE0, 0x7B, 0x69, 0x92, 0x43, 0x20, 0x18, 0xE0, 0x8E, 0xD9, 0x6A, 0x57, 0x34, 0xAF, 0x8B, 0xAD, 0x8A, 0x57, 0x5D, 0x3A, 0x1F, 0x16, 0x2F, 0x85, 0x04, 0x5C, 0xC7, 0x70, 0x92, 0x55, 0x71, 0xD9, 0xF5, 0xB9, 0x4E, 0x45, 0x4A, 0x77, 0xC1, 0x6E, 0x72, 0x93, 0x6B, 0xF0, 0x16, 0xAE, 0x15, 0x74, 0x99, 0xF0, 0x54, 0x3B, 0x5D, 0x52, 0xCA, 0xA6, 0xDB, 0xEA, 0xB6, 0x97, 0xD2, 0xBB, 0x73, 0xE4, 0x1B, 0x80, 0x75, 0xDC, 0xE7, 0x9B, 0x4B, 0x86, 0x04, 0x4F, 0x66, 0x1D, 0x44, 0x85, 0xA5, 0x43, 0xDD, 0x78, 0x60, 0x6E, 0x04, 0x19, 0xE8, 0x05, 0x98, 0x59, 0xD3, 0xCB, 0x2B, 0x67, 0xCE, 0x09, 0x77, 0x60, 0x3F, 0x81, 0xFF, 0x83, 0x9E, 0x33, 0x18, 0x59, 0x54, 0x4C, 0xFB, 0xC8, 0xD0, 0x0F, 0xEF, 0x1A, 0x4C, 0x85, 0x10, 0xFB, 0x54, 0x7D, 0x6B, 0x06, 0xC6, 0x11, 0xEF, 0x44, 0xF1, 0xBC, 0xE1, 0x07, 0xCF, 0xA4, 0x5A, 0x06, 0xAA, 0xB3, 0x60, 0x15, 0x2B, 0x28, 0xDC, 0x1E, 0xBE, 0x6F, 0x7F, 0xE0, 0x9B, 0x05, 0x16, 0xF9, 0xA5, 0xB0, 0x2A, 0x1B, 0xD8, 0x4B, 0xB0, 0x18, 0x1E, 0x2E, 0x89, 0xE1, 0x9B, 0xD8, 0x12, 0x59, 0x30, 0xD1, 0x78, 0x68, 0x2F, 0x38, 0x62, 0xDC, 0x51, 0xB6, 0x36, 0xF0, 0x4E, 0x72, 0x0C, 0x47, 0xC3, 0xCE, 0x51, 0xAD, 0x70, 0xD9, 0x4B, 0x9B, 0x22, 0x55, 0xFB, 0xAE, 0x90, 0x65, 0x49, 0xF4, 0x99, 0xF8, 0xC6, 0xD3, 0x99, 0x47, 0xED, 0x5E, 0x5D, 0xF8, 0xE2, 0xDE, 0xF1, 0x13, 0x25, 0x3E, 0x7B, 0x08, 0xD0, 0xA7, 0x6B, 0x6B, 0xFC, 0x68, 0xC8, 0x12, 0xF3, 0x75, 0xC7, 0x9B, 0x8F, 0xE5, 0xFD, 0x85, 0x97, 0x6A, 0xA6, 0xD4, 0x6B, 0x4A, 0x23, 0x39, 0xD8, 0xAE, 0x51, 0x47, 0xF6, 0x80, 0xFB, 0xE7, 0x0F, 0x97, 0x8B, 0x38, 0xEF, 0xFD, 0x7B, 0x2F, 0x78, 0x66, 0xA2, 0x25, 0x54, 0xE1, 0x93, 0xA9, 0x4E, 0x98, 0xA6, 0x8B, 0x74, 0xBD, 0x25, 0xBB, 0x2B, 0x3F, 0x5F, 0xB0, 0xA5, 0xFD, 0x59, 0x88, 0x7F, 0x9A, 0xB6, 0x81, 0x59, 0xB7, 0x17, 0x8D, 0x5B, 0x7B, 0x67, 0x7C, 0xB5, 0x46, 0xBF, 0x41, 0xEA, 0xDC, 0xA2, 0x16, 0xFC, 0x10, 0x85, 0x01, 0x28, 0xF8, 0xBD, 0xEF, 0x5C, 0x8D, 0x89, 0xF9, 0x6A, 0xFA, 0x4F, 0xA8, 0xB5, 0x48, 0x85, 0x56, 0x5E, 0xD8, 0x38, 0xA9, 0x50, 0xFE, 0xE5, 0xF1, 0xC3, 0xB0, 0xA4, 0xF6, 0xFB, 0x71, 0xE5, 0x4D, 0xFD, 0x16, 0x9E, 0x82, 0xCE, 0xCC, 0x72, 0x66, 0xC8, 0x50, 0xE6, 0x7C, 0x5E, 0xF0, 0xBA, 0x96, 0x0F, 0x52, 0x14, 0x06, 0x0E, 0x71, 0xEB, 0x17, 0x2A, 0x75, 0xFC, 0x14, 0x86, 0x83, 0x5C, 0xBE, 0xA6, 0x53, 0x44, 0x65, 0xB0, 0x55, 0xC9, 0x6A, 0x72, 0xE4, 0x10, 0x52, 0x24, 0x18, 0x23, 0x25, 0xD8, 0x30, 0x41, 0x4B, 0x40, 0x21, 0x4D, 0xAA, 0x80, 0x91, 0xD2, 0xE0, 0xFB, 0x01, 0x0A, 0xE1, 0x5C, 0x6D, 0xE9, 0x08, 0x50, 0x97, 0x3B, 0xDF, 0x1E, 0x42, 0x3B, 0xE1, 0x48, 0xA2, 0x37, 0xB8, 0x7A, 0x0C, 0x9F, 0x34, 0xD4, 0xB4, 0x76, 0x05, 0xB8, 0x03, 0xD7, 0x43, 0xA8, 0x6A, 0x90, 0x39, 0x9A, 0x4A, 0xF3, 0x96, 0xD3, 0xA1, 0x20, 0x0A, 0x62, 0xF3, 0xD9, 0x50, 0x79, 0x62, 0xE8, 0xE5, 0xBE, 0xE6, 0xD3, 0xDA, 0x2B, 0xB3, 0xF7, 0x23, 0x76, 0x64, 0xAC, 0x7A, 0x29, 0x28, 0x23, 0x90, 0x0B, 0xC6, 0x35, 0x03, 0xB2, 0x9E, 0x80, 0xD6, 0x3F, 0x60, 0x67, 0xBF, 0x8E, 0x17, 0x16, 0xAC, 0x25, 0xBE, 0xBA, 0x35, 0x0D, 0xEB, 0x62, 0xA9, 0x9F, 0xE0, 0x31, 0x85, 0xEB, 0x4F, 0x69, 0x93, 0x7E, 0xCD, 0x38, 0x79, 0x41, 0xFD, 0xA5, 0x44, 0xBA, 0x67, 0xDB, 0x09, 0x11, 0x77, 0x49, 0x38, 0xB0, 0x18, 0x27, 0xBC, 0xC6, 0x9C, 0x92, 0xB3, 0xF7, 0x72, 0xA9, 0xD2, 0x85, 0x9E, 0xF0, 0x03, 0x39, 0x8B, 0x1F, 0x6B, 0xBA, 0xD7, 0xB5, 0x74, 0xF7, 0x98, 0x9A, 0x1D, 0x10, 0xB2, 0xDF, 0x79, 0x8E, 0x0D, 0xBF, 0x30, 0xD6, 0x58, 0x74, 0x64, 0xD2, 0x48, 0x78, 0xCD, 0x00, 0xC0, 0xEA, 0xEE, 0x8A, 0x1A, 0x0C, 0xC7, 0x53, 0xA2, 0x79, 0x79, 0xE1, 0x1B, 0x41, 0xDB, 0x1D, 0xE3, 0xD5, 0x03, 0x8A, 0xFA, 0xF4, 0x9F, 0x5C, 0x68, 0x2C, 0x37, 0x48, 0xD8, 0xA3, 0xA9, 0xEC, 0x54, 0xE6, 0xA3, 0x71, 0x27, 0x5F, 0x16, 0x83, 0x51, 0x0F, 0x8E, 0x4F, 0x90, 0x93, 0x8F, 0x9A, 0xB6, 0xE1, 0x34, 0xC2, 0xCF, 0xDF, 0x48, 0x41, 0xCB, 0xA8, 0x8E, 0x0C, 0xFF, 0x2B, 0x0B, 0xCC, 0x8E, 0x6A, 0xDC, 0xB7, 0x11, 0x09, 0xB5, 0x19, 0x8F, 0xEC, 0xF1, 0xBB, 0x7E, 0x5C, 0x53, 0x1A, 0xCA, 0x50, 0xA5, 0x6A, 0x8A, 0x3B, 0x6D, 0xE5, 0x98, 0x62, 0xD4, 0x1F, 0xA1, 0x13, 0xD9, 0xCD, 0x95, 0x78, 0x08, 0xF0, 0x85, 0x71, 0xD9, 0xA4, 0xBB, 0x79, 0x2A, 0xF2, 0x71, 0xF6, 0xCC, 0x6D, 0xBB, 0x8D, 0xC7, 0xEC, 0x36, 0xE3, 0x6B, 0xE1, 0xED, 0x30, 0x81, 0x64, 0xC3, 0x1C, 0x7C, 0x0A, 0xFC, 0x54, 0x1C, 0x00, 0x00, 0x00]),
      COUNTER: 0x561EB2DD,
      BEARER: 0x1C,
      DIRECTION: 0,
      LENGTH: 0x1626,
    }
    const r3 = new U8([0x0C, 0xA1, 0x27, 0x92])
    expect(eia3(t1)).toMatchObject(r1)
    expect(eia3(t2)).toMatchObject(r2)
    expect(eia3(t3)).toMatchObject(r3)
  })
})

describe('block cipher', () => {
  // * SM4
  it('sm4', () => {
    const k = new U8([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10])
    const m = new U8([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10])
    const c = new U8([0x68, 0x1E, 0xDF, 0x34, 0xD2, 0x06, 0x96, 0x5E, 0x86, 0xB3, 0xE9, 0x4F, 0x53, 0x6E, 0x42, 0x46])

    const cipher = sm4(k)
    expect(cipher.encrypt(m)).toMatchObject(c)
    expect(cipher.decrypt(c)).toMatchObject(m)
  })
  // * AES
  it('aes-128', () => {
    const k = new U8([0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C])
    const m = new U8([0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A])
    const c = new U8([0x3A, 0xD7, 0x7B, 0xB4, 0x0D, 0x7A, 0x36, 0x60, 0xA8, 0x9E, 0xCA, 0xF3, 0x24, 0x66, 0xEF, 0x97])

    const cipher = aes(128)(k)
    expect(cipher.encrypt(m)).toMatchObject(c)
    expect(cipher.decrypt(c)).toMatchObject(m)
  })
  it('aes-192', () => {
    const k = new U8([0x8E, 0x73, 0xB0, 0xF7, 0xDA, 0x0E, 0x64, 0x52, 0xC8, 0x10, 0xF3, 0x2B, 0x80, 0x90, 0x79, 0xE5, 0x62, 0xF8, 0xEA, 0xD2, 0x52, 0x2C, 0x6B, 0x7B])
    const m = new U8([0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A])
    const c = new U8([0xBD, 0x33, 0x4F, 0x1D, 0x6E, 0x45, 0xF2, 0x5F, 0xF7, 0x12, 0xA2, 0x14, 0x57, 0x1F, 0xA5, 0xCC])

    const cipher = aes(192)(k)
    expect(cipher.encrypt(m)).toMatchObject(c)
    expect(cipher.decrypt(c)).toMatchObject(m)
  })
  it('aes-256', () => {
    const k = new U8([0x60, 0x3D, 0xEB, 0x10, 0x15, 0xCA, 0x71, 0xBE, 0x2B, 0x73, 0xAE, 0xF0, 0x85, 0x7D, 0x77, 0x81, 0x1F, 0x35, 0x2C, 0x07, 0x3B, 0x61, 0x08, 0xD7, 0x2D, 0x98, 0x10, 0xA3, 0x09, 0x14, 0xDF, 0xF4])
    const m = new U8([0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A])
    const c = new U8([0xF3, 0xEE, 0xD1, 0xBD, 0xB5, 0xD2, 0xA0, 0x3C, 0x06, 0x4B, 0x5A, 0x7E, 0x3D, 0xB1, 0x81, 0xF8])

    const cipher = aes(256)(k)
    expect(cipher.encrypt(m)).toMatchObject(c)
    expect(cipher.decrypt(c)).toMatchObject(m)
  })
  // * ARIA
  it('aria-128', () => {
    const k = new U8([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F])
    const m = new U8([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])
    const c = new U8([0xD7, 0x18, 0xFB, 0xD6, 0xAB, 0x64, 0x4C, 0x73, 0x9D, 0xA9, 0x5F, 0x3B, 0xE6, 0x45, 0x17, 0x78])

    const cipher = aria(128)(k)
    expect(cipher.encrypt(m)).toMatchObject(c)
    expect(cipher.decrypt(c)).toMatchObject(m)
  })
  it('aria-192', () => {
    const k = new U8([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17])
    const m = new U8([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])
    const c = new U8([0x26, 0x44, 0x9C, 0x18, 0x05, 0xDB, 0xE7, 0xAA, 0x25, 0xA4, 0x68, 0xCE, 0x26, 0x3A, 0x9E, 0x79])

    const cipher = aria(192)(k)
    expect(cipher.encrypt(m)).toMatchObject(c)
    expect(cipher.decrypt(c)).toMatchObject(m)
  })
  it('aria-256', () => {
    const k = new U8([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F])
    const m = new U8([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])
    const c = new U8([0xF9, 0x2B, 0xD7, 0xC7, 0x9F, 0xB7, 0x2E, 0x2F, 0x2B, 0x8F, 0x80, 0xC1, 0x97, 0x2D, 0x24, 0xFC])

    const cipher = aria(256)(k)
    expect(cipher.encrypt(m)).toMatchObject(c)
    expect(cipher.decrypt(c)).toMatchObject(m)
  })
  // * Camellia
  it('camellia-128', () => {
    const k = new U8([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10])
    const m = new U8([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10])
    const c = new U8([0x67, 0x67, 0x31, 0x38, 0x54, 0x96, 0x69, 0x73, 0x08, 0x57, 0x06, 0x56, 0x48, 0xEA, 0xBE, 0x43])
    const cipher = camellia(128)(k)
    expect(cipher.encrypt(m)).toMatchObject(c)
    expect(cipher.decrypt(c)).toMatchObject(m)
  })
  it('camellia-192', () => {
    const k = new U8([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77])
    const m = new U8([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10])
    const c = new U8([0xB4, 0x99, 0x34, 0x01, 0xB3, 0xE9, 0x96, 0xF8, 0x4E, 0xE5, 0xCE, 0xE7, 0xD7, 0x9B, 0x09, 0xB9])
    const cipher = camellia(192)(k)
    expect(cipher.encrypt(m)).toMatchObject(c)
    expect(cipher.decrypt(c)).toMatchObject(m)
  })
  it('camellia-256', () => {
    const k = new U8([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])
    const m = new U8([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10])
    const c = new U8([0x9A, 0xCC, 0x23, 0x7D, 0xFF, 0x16, 0xD7, 0x6C, 0x20, 0xEF, 0x7C, 0x91, 0x9E, 0x3A, 0x75, 0x09])
    const cipher = camellia(256)(k)
    expect(cipher.encrypt(m)).toMatchObject(c)
    expect(cipher.decrypt(c)).toMatchObject(m)
  })
  // * DES
  it('des', () => {
    const k = new U8([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF])
    const m = new U8([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF])
    const c = new U8([0x56, 0xCC, 0x09, 0xE7, 0xCF, 0xDC, 0x4C, 0xEF])

    const cipher = des(k)
    expect(cipher.encrypt(m)).toMatchObject(c)
    expect(cipher.decrypt(c)).toMatchObject(m)
  })
  // * 3DES
  it('3des-128', () => {
    const k = new U8([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFF, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0xFF, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF])
    const m = new U8([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF])
    const c = new U8([0x40, 0x50, 0x77, 0x2A, 0xE7, 0x64, 0x22, 0x0A])

    const cipher128 = t_des(128)(k.subarray(0, 16))
    expect(cipher128.encrypt(m)).toMatchObject(c)
    expect(cipher128.decrypt(c)).toMatchObject(m)
  })
  it('3des-192', () => {
    const k = new U8([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFF, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0xFF, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF])
    const m = new U8([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF])
    const c = new U8([0xD2, 0x1E, 0x1E, 0xA1, 0x13, 0x0B, 0x42, 0x73])

    const cipher192 = t_des(192)(k)
    expect(cipher192.encrypt(m)).toMatchObject(c)
    expect(cipher192.decrypt(c)).toMatchObject(m)
  })
  // * ARC5
  it('arc5-8/12/4', () => {
    // source: https://datatracker.ietf.org/doc/html/draft-krovetz-rc6-rc5-vectors-00
    const k = new U8([0x00, 0x01, 0x02, 0x03])
    const m = new U8([0x00, 0x01])
    const c = new U8([0x21, 0x2A])
    const cipher = arc5(8, 12)(k)
    expect(cipher.encrypt(m)).toMatchObject(c)
    expect(cipher.decrypt(c)).toMatchObject(m)
  })
  it('arc5-16/16/8', () => {
    // source: https://datatracker.ietf.org/doc/html/draft-krovetz-rc6-rc5-vectors-00
    const k = new U8([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07])
    const m = new U8([0x00, 0x01, 0x02, 0x03])
    const c = new U8([0x23, 0xA8, 0xD7, 0x2E])
    const cipher = arc5(16, 16)(k)
    expect(cipher.encrypt(m)).toMatchObject(c)
    expect(cipher.decrypt(c)).toMatchObject(m)
  })
  it('arc5-32/20/16', () => {
    // source: https://datatracker.ietf.org/doc/html/draft-krovetz-rc6-rc5-vectors-00
    const k = new U8([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F])
    const m = new U8([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07])
    const c = new U8([0x2A, 0x0E, 0xDC, 0x0E, 0x94, 0x31, 0xFF, 0x73])
    const cipher = arc5(32, 20)(k)
    expect(cipher.encrypt(m)).toMatchObject(c)
    expect(cipher.decrypt(c)).toMatchObject(m)
  })
  it('arc5-64/24/24', () => {
    // source: https://datatracker.ietf.org/doc/html/draft-krovetz-rc6-rc5-vectors-00
    const k = new U8([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17])
    const m = new U8([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F])
    const c = new U8([0xA4, 0x67, 0x72, 0x82, 0x0E, 0xDB, 0xCE, 0x02, 0x35, 0xAB, 0xEA, 0x32, 0xAE, 0x71, 0x78, 0xDA])
    const cipher = arc5(64, 24)(k)
    expect(cipher.encrypt(m)).toMatchObject(c)
    expect(cipher.decrypt(c)).toMatchObject(m)
  })
  it('arc5-128/28/32', () => {
    // source: https://datatracker.ietf.org/doc/html/draft-krovetz-rc6-rc5-vectors-00
    const k = new U8([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F])
    const m = new U8([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F])
    const c = new U8([0xEC, 0xA5, 0x91, 0x09, 0x21, 0xA4, 0xF4, 0xCF, 0xDD, 0x7A, 0xD7, 0xAD, 0x20, 0xA1, 0xFC, 0xBA, 0x06, 0x8E, 0xC7, 0xA7, 0xCD, 0x75, 0x2D, 0x68, 0xFE, 0x91, 0x4B, 0x7F, 0xE1, 0x80, 0xB4, 0x40])
    const cipher = arc5(128, 28)(k)
    expect(cipher.encrypt(m)).toMatchObject(c)
    expect(cipher.decrypt(c)).toMatchObject(m)
  })
  // * Blowfish
  it('blowfish', () => {
    // source: https://www.schneier.com/wp-content/uploads/2015/12/vectors-2.txt
    const k = new U8(16)
    const m = new U8(8)
    const c = new U8(HEX.parse('4EF997456198DD78'))

    const bf = blowfish(k)
    expect(bf.encrypt(m)).toMatchObject(c)
    expect(bf.decrypt(c)).toMatchObject(m)
  })
  // * Twofish
  it('twofish', () => {
    // source: https://www.schneier.com/wp-content/uploads/2015/12/ecb_ival.txt
    const k = new U8(16)
    const m = new U8(16)
    const c = new U8(HEX.parse('9F589F5CF6122C32B6BFEC2F2AE8C35A'))
    const tf = twofish(128)(k)
    expect(tf.encrypt(m)).toMatchObject(c)
    expect(tf.decrypt(c)).toMatchObject(m)

    const k192 = new U8(HEX.parse('0123456789ABCDEFFEDCBA98765432100011223344556677'))
    const c192 = new U8(HEX.parse('CFD1D2E5A9BE9CDF501F13B892BD2248'))
    const tf192 = twofish(192)(k192)
    expect(tf192.encrypt(m)).toMatchObject(c192)
    expect(tf192.decrypt(c192)).toMatchObject(m)

    const k256 = new U8(HEX.parse('0123456789ABCDEFFEDCBA987654321000112233445566778899AABBCCDDEEFF'))
    const c256 = new U8(HEX.parse('37527BE0052334B89F0CFCCAE87CFA20'))
    const tf256 = twofish(256)(k256)
    expect(tf256.encrypt(m)).toMatchObject(c256)
    expect(tf256.decrypt(c256)).toMatchObject(m)
  })
  // * TEA
  it('tea', () => {
    // source: https://www.cix.co.uk/~klockstone/teavect.htm
    const k = new U8(16)
    const m = new U8(8)
    const c = new U8([0x0A, 0x3A, 0xEA, 0x41, 0x40, 0xA9, 0xBA, 0x94])
    const cipher = tea(32)(k)
    expect(cipher.encrypt(m)).toMatchObject(c)
    expect(cipher.decrypt(c)).toMatchObject(m)
  })
  // * XTEA
  it('xtea', () => {
    const k = new U8(16)
    const m = new U8(8)
    const c = new U8([0xD8, 0xD4, 0xE9, 0xDE, 0xD9, 0x1E, 0x13, 0xF7])
    const cipher = xtea(32)(k)
    expect(cipher.encrypt(m)).toMatchObject(c)
    expect(cipher.decrypt(c)).toMatchObject(m)
  })
})

describe('mode', () => {
  // * ECB-SM4
  it('ecb-sm4', () => {
    const k = HEX.parse('8586c1e4007b4ac8ea156616bb813986')
    const m = UTF8.parse('meow, 喵， 🐱')
    const c = HEX.parse('cd5a3e21a3c5fbeb05a819c67469703b49597aa5bc280694147d3145f8269bdb')

    const ecb_sm4 = ecb(sm4)(k)
    expect(ecb_sm4.encrypt(m)).toMatchObject(c)
    expect(ecb_sm4.decrypt(c)).toMatchObject(m)
  })
  // * CBC-SM4
  it('cbc-sm4', () => {
    const k = HEX.parse('8586c1e4007b4ac8ea156616bb813986')
    const iv = HEX.parse('060d358b88e62a5287b1df4dddf016b3')
    const m = UTF8.parse('meow, 喵， 🐱')
    const c = HEX.parse('ac1e00f787097325407c4686cf80273bd1ec1f8de32343df8d9b245b04e58014')

    const cbc_sm4 = cbc(sm4, ANSI_X923)(k, iv)
    expect(cbc_sm4.encrypt(m)).toMatchObject(c)
    expect(cbc_sm4.decrypt(c)).toMatchObject(m)
  })
  // * PCBC-SM4
  it('pcbc-sm4', () => {
    const k = HEX.parse('8586c1e4007b4ac8ea156616bb813986')
    const iv = HEX.parse('060d358b88e62a5287b1df4dddf016b3')
    const m = UTF8.parse('meow, 喵， 🐱')
    const c = HEX.parse('ac1e00f787097325407c4686cf80273b189865931ac1ce2d99577a2c8d685c77')

    const pcbc_sm4 = pcbc(sm4)(k, iv)
    expect(pcbc_sm4.encrypt(m)).toMatchObject(c)
    expect(pcbc_sm4.decrypt(c)).toMatchObject(m)
  })
  // * CFB-SM4
  it('cfb-sm4', () => {
    const k = HEX.parse('8586c1e4007b4ac8ea156616bb813986')
    const iv = HEX.parse('060d358b88e62a5287b1df4dddf016b3')
    const m = UTF8.parse('meow, 喵， 🐱')
    const c = HEX.parse('e38ec4c9fb65e1da9ba25c2f35840c123c171e4d8e26c1d54e7038aa4a8e9e65')

    const cfb_sm4 = cfb(sm4)(k, iv)
    expect(cfb_sm4.encrypt(m)).toMatchObject(c)
    expect(cfb_sm4.decrypt(c)).toMatchObject(m)
  })
  // * CFB-SM4-Stream
  it('cfb-sm4-stream', () => {
    const k = HEX.parse('8586c1e4007b4ac8ea156616bb813986')
    const iv = HEX.parse('060d358b88e62a5287b1df4dddf016b3')
    const m = UTF8.parse('meow, 喵， 🐱')
    const c = HEX.parse('e38ec4c9fb65e1da9ba25c2f35840c123c')

    const cfb_sm4 = cfb(sm4, NoPadding)(k, iv)
    expect(cfb_sm4.encrypt(m)).toMatchObject(c)
    expect(cfb_sm4.decrypt(c)).toMatchObject(m)
  })
  // * OFB-SM4
  it('ofb-sm4', () => {
    const k = HEX.parse('8586c1e4007b4ac8ea156616bb813986')
    const iv = HEX.parse('060d358b88e62a5287b1df4dddf016b3')
    const m = UTF8.parse('meow, 喵， 🐱')
    const c = HEX.parse('e38ec4c9fb65e1da9ba25c2f35840c1222d0dc374e57e74de38c562c8e0d2e3f')

    const ofb_sm4 = ofb(sm4)(k, iv)
    expect(ofb_sm4.encrypt(m)).toMatchObject(c)
    expect(ofb_sm4.decrypt(c)).toMatchObject(m)
  })
  // * OFB-SM4-Stream
  it('ofb-sm4-stream', () => {
    const k = HEX.parse('8586c1e4007b4ac8ea156616bb813986')
    const iv = HEX.parse('060d358b88e62a5287b1df4dddf016b3')
    const m = UTF8.parse('meow, 喵， 🐱')
    const c = HEX.parse('e38ec4c9fb65e1da9ba25c2f35840c1222')

    const ofb_sm4 = ofb(sm4, NoPadding)(k, iv)
    expect(ofb_sm4.encrypt(m)).toMatchObject(c)
    expect(ofb_sm4.decrypt(c)).toMatchObject(m)
  })
  // * CTR-SM4
  it('ctr-sm4', () => {
    const k = HEX.parse('8586c1e4007b4ac8ea156616bb813986')
    const iv = HEX.parse('060d358b88e62a5287b1df4dddf016b3')
    const m = UTF8.parse('meow, 喵， 🐱')
    const c = HEX.parse('e38ec4c9fb65e1da9ba25c2f35840c1226cd921b5c89efd7008b46c4a73c908a')

    const ctr_sm4 = ctr(sm4)(k, iv)
    expect(ctr_sm4.encrypt(m)).toMatchObject(c)
    expect(ctr_sm4.decrypt(c)).toMatchObject(m)
  })
  // * CTR-SM4-Stream
  it('ctr-sm4-stream', () => {
    const k = HEX.parse('8586c1e4007b4ac8ea156616bb813986')
    const iv = HEX.parse('060d358b88e62a5287b1df4dddf016b3')
    const m = UTF8.parse('meow, 喵， 🐱')
    const c = HEX.parse('e38ec4c9fb65e1da9ba25c2f35840c1226')

    const ctr_sm4 = ctr(sm4, NoPadding)(k, iv)
    expect(ctr_sm4.encrypt(m)).toMatchObject(c)
    expect(ctr_sm4.decrypt(c)).toMatchObject(m)
  })
  // * GCM-SM4
  it('gcm-sm4', () => {
    const k = HEX.parse('8586c1e4007b4ac8ea156616bb813986')
    const iv = HEX.parse('060d358b88e62a5287b1df4dddf016b3')
    const m = UTF8.parse('meow, 喵， 🐱')
    const a = HEX.parse('feedfacedeadbeeffeedfacedeadbeefabaddad2')
    const c = HEX.parse('1f5490b2105791a5ae8e5eff3fc75438d6a512a9f89a8b0afac8e7fdba78a331')
    const t = HEX.parse('082c1baa5c841297f6397d8b213a34e8')

    const gcm_sm4 = gcm(sm4)(k, iv)
    expect(gcm_sm4.encrypt(m)).toMatchObject(c)
    expect(gcm_sm4.decrypt(c)).toMatchObject(m)
    expect(gcm_sm4.sign(c, a)).toMatchObject(t)
    expect(gcm_sm4.verify(t, c, a)).toMatchInlineSnapshot(`${true}`)
  })
  // * GCM-SM4-Stream
  it('gcm-sm4-stream', () => {
    const k = HEX.parse('8586c1e4007b4ac8ea156616bb813986')
    const iv = HEX.parse('060d358b88e62a5287b1df4dddf016b3')
    const m = UTF8.parse('meow, 喵， 🐱')
    const a = HEX.parse('feedfacedeadbeeffeedfacedeadbeefabaddad2')
    const c = HEX.parse('1f5490b2105791a5ae8e5eff3fc75438d6')
    const t = HEX.parse('8dc65670d665f16a045c2931245fc639')

    const gcm_sm4 = gcm(sm4, NoPadding)(k, iv)
    expect(gcm_sm4.encrypt(m)).toMatchObject(c)
    expect(gcm_sm4.decrypt(c)).toMatchObject(m)
    expect(gcm_sm4.sign(c, a)).toMatchObject(t)
    expect(gcm_sm4.verify(t, c, a)).toMatchInlineSnapshot(`${true}`)
  })
})
