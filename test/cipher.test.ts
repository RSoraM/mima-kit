import { describe, expect, it } from 'vitest'
import { B64, HEX, UTF8 } from '../src/core/codec'
import * as cipherSuite from '../src/core/cipher'
import { sm4 } from '../src/cipher/sm4'
import { aes } from '../src/cipher/aes'
import { des, t_des } from '../src/cipher/des'
import { arc4 } from '../src/cipher/arc4'
import { salsa20 } from '../src/cipher/salsa20'
import { rabbit } from '../src/cipher/rabbit'
import { blowfish } from '../src/cipher/blowfish'

const { ecb, cbc, pcbc, cfb, ofb, ctr, gcm } = cipherSuite
const { ANSI_X923, NoPadding } = cipherSuite

describe('stream cipher', () => {
  // * RC4
  it('rc4', () => {
    const k = 'Key'
    const m = 'Plaintext'
    const c = 'bbf316e8d940af0ad3'
    const config: cipherSuite.StreamCipherConfig = {
      KEY_CODEC: UTF8,
    }

    const cipher = arc4(k, config)
    expect(cipher.encrypt(m)).toMatchInlineSnapshot(`"${c}"`)
    expect(cipher.decrypt(c)).toMatchInlineSnapshot(`"${m}"`)
  })
  // * Salsa20
  it('salsa20', () => {
    const k = UTF8.parse('2b7e151628aed2a6abf7158809cf4f3c')
    const iv = UTF8.parse('cafebabe')
    const m = UTF8.parse('meowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeow')
    const c = B64.parse('heP0vh0o4kkRZVkf1R9CQ8VsUZEM8TIX1ZDra/1xbrp7nX4csbbLRcyFkofzddSqnjmP20LEQVLQy6kPMUOJuO8jb/soNNDmsS/AczPsUVJZ2MzRKFXwi2aeM1GEv1iuWJConhfqqEjVQXre7WGGSsh3CxnmUNN10r2mTzm/tNSarH8Wy4s4RmmWrHsPOY2WEiyAvMIdVq+X8UATk7GXtpL4Z8CXnrswFp7Cd+M28C8u9hjt6taYC9+4DJc=')

    const cipher = salsa20(k, iv)
    expect(cipher.encrypt(m)).toMatchInlineSnapshot(`"${HEX.stringify(c)}"`)
    expect(cipher.decrypt(c)).toMatchInlineSnapshot(`"${UTF8.stringify(m)}"`)
  })
  // * Rabbit
  it('rabbit', () => {
    const k = '2b7e151628aed2a6abf7158809cf4f3c'
    const iv = 'cafebabecafebabe'
    const m = 'hello world'
    const c = '416710e6a92705a851d0ca'
    const m1 = 'meowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeowmeow'
    const c1 = '446713fdab621db04ed9c19eb655bfa7583f5fd58a15f7d32fcb7032e6d0e45a6bbed84d700d6e6f9d0ec98e9ec5017039ae24fbb53790087c6ccce37ac26fe95b708e1253753b66b763835374574eade94ec1bea87c2574c5c2c6a2874c6f19c4bd2f31b580e9a70af6969f68aeefd01d967db86f3b787096714c4d7d463bce600c749c1730acc2c1e4928be3a265dd1134f44e8dbe3a83b97127483a3ddcbafee6f410bcfa0f11a0e464c0e144ed79e29c48b4c22a51524cf7bbb5'

    const cipher = rabbit(k, iv)
    expect(cipher.encrypt(m)).toMatchInlineSnapshot(`"${c}"`)
    expect(cipher.decrypt(c)).toMatchInlineSnapshot(`"${m}"`)

    expect(cipher.encrypt(m1)).toMatchInlineSnapshot(`"${c1}"`)
    expect(cipher.decrypt(c1)).toMatchInlineSnapshot(`"${m1}"`)
  })
})

describe('block cipher', () => {
  // * SM4
  it('sm4', () => {
    const k = new Uint8Array([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10])
    const m = new Uint8Array([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10])
    const c = new Uint8Array([0x68, 0x1E, 0xDF, 0x34, 0xD2, 0x06, 0x96, 0x5E, 0x86, 0xB3, 0xE9, 0x4F, 0x53, 0x6E, 0x42, 0x46])

    const cipher = sm4(k)
    expect(cipher.encrypt(m)).toMatchObject(c)
    expect(cipher.decrypt(c)).toMatchObject(m)
  })
  // * AES
  it('aes-128', () => {
    const k = new Uint8Array([0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C])
    const m = new Uint8Array([0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A])
    const c = new Uint8Array([0x3A, 0xD7, 0x7B, 0xB4, 0x0D, 0x7A, 0x36, 0x60, 0xA8, 0x9E, 0xCA, 0xF3, 0x24, 0x66, 0xEF, 0x97])

    const cipher = aes(128)(k)
    expect(cipher.encrypt(m)).toMatchObject(c)
    expect(cipher.decrypt(c)).toMatchObject(m)
  })
  it('aes-192', () => {
    const k = new Uint8Array([0x8E, 0x73, 0xB0, 0xF7, 0xDA, 0x0E, 0x64, 0x52, 0xC8, 0x10, 0xF3, 0x2B, 0x80, 0x90, 0x79, 0xE5, 0x62, 0xF8, 0xEA, 0xD2, 0x52, 0x2C, 0x6B, 0x7B])
    const m = new Uint8Array([0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A])
    const c = new Uint8Array([0xBD, 0x33, 0x4F, 0x1D, 0x6E, 0x45, 0xF2, 0x5F, 0xF7, 0x12, 0xA2, 0x14, 0x57, 0x1F, 0xA5, 0xCC])

    const cipher = aes(192)(k)
    expect(cipher.encrypt(m)).toMatchObject(c)
    expect(cipher.decrypt(c)).toMatchObject(m)
  })
  it('aes-256', () => {
    const k = new Uint8Array([0x60, 0x3D, 0xEB, 0x10, 0x15, 0xCA, 0x71, 0xBE, 0x2B, 0x73, 0xAE, 0xF0, 0x85, 0x7D, 0x77, 0x81, 0x1F, 0x35, 0x2C, 0x07, 0x3B, 0x61, 0x08, 0xD7, 0x2D, 0x98, 0x10, 0xA3, 0x09, 0x14, 0xDF, 0xF4])
    const m = new Uint8Array([0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A])
    const c = new Uint8Array([0xF3, 0xEE, 0xD1, 0xBD, 0xB5, 0xD2, 0xA0, 0x3C, 0x06, 0x4B, 0x5A, 0x7E, 0x3D, 0xB1, 0x81, 0xF8])

    const cipher = aes(256)(k)
    expect(cipher.encrypt(m)).toMatchObject(c)
    expect(cipher.decrypt(c)).toMatchObject(m)
  })
  // * DES
  it('des', () => {
    const k = new Uint8Array([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF])
    const m = new Uint8Array([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF])
    const c = new Uint8Array([0x56, 0xCC, 0x09, 0xE7, 0xCF, 0xDC, 0x4C, 0xEF])

    const cipher = des(k)
    expect(cipher.encrypt(m)).toMatchObject(c)
    expect(cipher.decrypt(c)).toMatchObject(m)
  })
  // * 3DES
  it('3des-128', () => {
    const k = new Uint8Array([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFF, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0xFF, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF])
    const m = new Uint8Array([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF])
    const c = new Uint8Array([0x40, 0x50, 0x77, 0x2A, 0xE7, 0x64, 0x22, 0x0A])

    const cipher128 = t_des(128)(k.subarray(0, 16))
    expect(cipher128.encrypt(m)).toMatchObject(c)
    expect(cipher128.decrypt(c)).toMatchObject(m)
  })
  it('3des-192', () => {
    const k = new Uint8Array([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFF, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0xFF, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF])
    const m = new Uint8Array([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF])
    const c = new Uint8Array([0xD2, 0x1E, 0x1E, 0xA1, 0x13, 0x0B, 0x42, 0x73])

    const cipher192 = t_des(192)(k)
    expect(cipher192.encrypt(m)).toMatchObject(c)
    expect(cipher192.decrypt(c)).toMatchObject(m)
  })
  // * Blowfish
  it('blowfish', () => {
    const k = HEX.parse('0123456789ABCDEFFEDCBA9876543210')
    const m = HEX.parse('6D656F772C20E596')
    const c = HEX.parse('26A31048CF7C6953')

    const bf = blowfish(k)
    expect(bf.encrypt(m)).toMatchObject(c)
    expect(bf.decrypt(c)).toMatchObject(m)
  })
})

describe('mode', () => {
  // * ECB-SM4
  it('ecb-sm4', () => {
    const k = '8586c1e4007b4ac8ea156616bb813986'
    const m = 'meow, 喵， 🐱'
    const c = 'cd5a3e21a3c5fbeb05a819c67469703b49597aa5bc280694147d3145f8269bdb'

    const ecb_sm4 = ecb(sm4)(k)
    expect(ecb_sm4.encrypt(m)).toMatchInlineSnapshot(`"${c}"`)
    expect(ecb_sm4.decrypt(c)).toMatchInlineSnapshot(`"${m}"`)
  })
  // * CBC-SM4
  it('cbc-sm4', () => {
    const k = '8586c1e4007b4ac8ea156616bb813986'
    const iv = '060d358b88e62a5287b1df4dddf016b3'
    const m = 'meow, 喵， 🐱'
    const c = 'ac1e00f787097325407c4686cf80273bd1ec1f8de32343df8d9b245b04e58014'

    const cbc_sm4 = cbc(sm4, { PADDING: ANSI_X923 })(k, iv)
    expect(cbc_sm4.encrypt(m)).toMatchInlineSnapshot(`"${c}"`)
    expect(cbc_sm4.decrypt(c)).toMatchInlineSnapshot(`"${m}"`)
  })
  // * PCBC-SM4
  it('pcbc-sm4', () => {
    const k = '8586c1e4007b4ac8ea156616bb813986'
    const iv = '060d358b88e62a5287b1df4dddf016b3'
    const m = 'meow, 喵， 🐱'
    const c = 'ac1e00f787097325407c4686cf80273b189865931ac1ce2d99577a2c8d685c77'

    const pcbc_sm4 = pcbc(sm4)(k, iv)
    expect(pcbc_sm4.encrypt(m)).toMatchInlineSnapshot(`"${c}"`)
    expect(pcbc_sm4.decrypt(c)).toMatchInlineSnapshot(`"${m}"`)
  })
  // * CFB-SM4
  it('cfb-sm4', () => {
    const k = '8586c1e4007b4ac8ea156616bb813986'
    const iv = '060d358b88e62a5287b1df4dddf016b3'
    const m = 'meow, 喵， 🐱'
    const c = 'e38ec4c9fb65e1da9ba25c2f35840c123c171e4d8e26c1d54e7038aa4a8e9e65'

    const cfb_sm4 = cfb(sm4)(k, iv)
    expect(cfb_sm4.encrypt(m)).toMatchInlineSnapshot(`"${c}"`)
    expect(cfb_sm4.decrypt(c)).toMatchInlineSnapshot(`"${m}"`)
  })
  // * CFB-SM4-Stream
  it('cfb-sm4-stream', () => {
    const k = '8586c1e4007b4ac8ea156616bb813986'
    const iv = '060d358b88e62a5287b1df4dddf016b3'
    const m = 'meow, 喵， 🐱'
    const c = 'e38ec4c9fb65e1da9ba25c2f35840c123c'

    const cfb_sm4 = cfb(sm4, { PADDING: NoPadding })(k, iv)
    expect(cfb_sm4.encrypt(m)).toMatchInlineSnapshot(`"${c}"`)
    expect(cfb_sm4.decrypt(c)).toMatchInlineSnapshot(`"${m}"`)
  })
  // * OFB-SM4
  it('ofb-sm4', () => {
    const k = '8586c1e4007b4ac8ea156616bb813986'
    const iv = '060d358b88e62a5287b1df4dddf016b3'
    const m = 'meow, 喵， 🐱'
    const c = 'e38ec4c9fb65e1da9ba25c2f35840c1222d0dc374e57e74de38c562c8e0d2e3f'

    const ofb_sm4 = ofb(sm4)(k, iv)
    expect(ofb_sm4.encrypt(m)).toMatchInlineSnapshot(`"${c}"`)
    expect(ofb_sm4.decrypt(c)).toMatchInlineSnapshot(`"${m}"`)
  })
  // * OFB-SM4-Stream
  it('ofb-sm4-stream', () => {
    const k = '8586c1e4007b4ac8ea156616bb813986'
    const iv = '060d358b88e62a5287b1df4dddf016b3'
    const m = 'meow, 喵， 🐱'
    const c = 'e38ec4c9fb65e1da9ba25c2f35840c1222'

    const ofb_sm4 = ofb(sm4, { PADDING: NoPadding })(k, iv)
    expect(ofb_sm4.encrypt(m)).toMatchInlineSnapshot(`"${c}"`)
    expect(ofb_sm4.decrypt(c)).toMatchInlineSnapshot(`"${m}"`)
  })
  // * CTR-SM4
  it('ctr-sm4', () => {
    const k = '8586c1e4007b4ac8ea156616bb813986'
    const iv = '060d358b88e62a5287b1df4dddf016b3'
    const m = 'meow, 喵， 🐱'
    const c = 'e38ec4c9fb65e1da9ba25c2f35840c1226cd921b5c89efd7008b46c4a73c908a'

    const ctr_sm4 = ctr(sm4)(k, iv)
    expect(ctr_sm4.encrypt(m)).toMatchInlineSnapshot(`"${c}"`)
    expect(ctr_sm4.decrypt(c)).toMatchInlineSnapshot(`"${m}"`)
  })
  // * CTR-SM4-Stream
  it('ctr-sm4-stream', () => {
    const k = '8586c1e4007b4ac8ea156616bb813986'
    const iv = '060d358b88e62a5287b1df4dddf016b3'
    const m = 'meow, 喵， 🐱'
    const c = 'e38ec4c9fb65e1da9ba25c2f35840c1226'

    const ctr_sm4 = ctr(sm4, { PADDING: NoPadding })(k, iv)
    expect(ctr_sm4.encrypt(m)).toMatchInlineSnapshot(`"${c}"`)
    expect(ctr_sm4.decrypt(c)).toMatchInlineSnapshot(`"${m}"`)
  })
  // * GCM-SM4
  it('gcm-sm4', () => {
    const k = '8586c1e4007b4ac8ea156616bb813986'
    const iv = '060d358b88e62a5287b1df4dddf016b3'
    const m = 'meow, 喵， 🐱'
    const a = 'feedfacedeadbeeffeedfacedeadbeefabaddad2'
    const c = '1f5490b2105791a5ae8e5eff3fc75438d6a512a9f89a8b0afac8e7fdba78a331'
    const t = '082c1baa5c841297f6397d8b213a34e8'
    const config: cipherSuite.GCMConfig = {
      ADDITIONAL_DATA_CODEC: HEX,
    }

    const gcm_sm4 = gcm(sm4, config)(k, iv)
    expect(gcm_sm4.encrypt(m)).toMatchInlineSnapshot(`"${c}"`)
    expect(gcm_sm4.decrypt(c)).toMatchInlineSnapshot(`"${m}"`)
    expect(gcm_sm4.sign(c, a)).toMatchInlineSnapshot(`"${t}"`)
    expect(gcm_sm4.verify(t, c, a)).toMatchInlineSnapshot(`${true}`)
  })
  // * GCM-SM4-Stream
  it('gcm-sm4-stream', () => {
    const k = '8586c1e4007b4ac8ea156616bb813986'
    const iv = '060d358b88e62a5287b1df4dddf016b3'
    const m = 'meow, 喵， 🐱'
    const a = 'feedfacedeadbeeffeedfacedeadbeefabaddad2'
    const c = '1f5490b2105791a5ae8e5eff3fc75438d6'
    const t = 'ac82d2f3167f16466a95b8986d9a1659'
    const config: cipherSuite.GCMConfig = {
      PADDING: NoPadding,
    }

    const gcm_sm4 = gcm(sm4, config)(k, iv)
    expect(gcm_sm4.encrypt(m)).toMatchInlineSnapshot(`"${c}"`)
    expect(gcm_sm4.decrypt(c)).toMatchInlineSnapshot(`"${m}"`)
    expect(gcm_sm4.sign(c, a)).toMatchInlineSnapshot(`"${t}"`)
    expect(gcm_sm4.verify(t, c, a)).toMatchInlineSnapshot(`${true}`)
  })
})
