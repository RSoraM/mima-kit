import { describe, expect, it } from 'vitest'
import { HEX, UTF8 } from '../src/core/codec'
import { hkdf, pbkdf2, scrypt, x963kdf } from '../src/core/kdf'
import { hmac } from '../src/hash/hmac'
import { sha1 } from '../src/hash/sha1'
import { sha256 } from '../src/hash/sha256'

describe('kdf', () => {
  // vector source: http://rfc.nop.hu/secg/gec2.pdf
  it('x963kdf', () => {
    const kdf = x963kdf(sha1)
    const ikm = HEX('0499B502FC8B5BAFB0F4047E731D1F9FD8CD0D8881')
    expect(kdf(40, ikm)).toMatchObject(HEX('03C62280C894E103C680B13CD4B4AE740A5EF0C72547292F82DC6B1777F47D63BA9D1EA732DBF386'))
  })
  // vector source: https://www.rfc-editor.org/rfc/rfc5869
  it('hkdf', () => {
    const ikm = HEX('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f')
    const salt = HEX('606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf')
    const info = HEX('b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff')
    const L = 82
    const kdf_sha256 = hkdf(hmac(sha256), info)
    expect(kdf_sha256(L, ikm, salt)).toMatchObject(HEX('b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87'))
  })
  // vector source: https://www.dcode.fr/pbkdf2-hash
  it('pbkdf2', () => {
    const ikm = UTF8('password')
    const salt = UTF8('salt')
    const kdf = pbkdf2(hmac(sha1), 5000)
    expect(kdf(20, ikm, salt)).toMatchObject(HEX('edf738254821c55da61e6afa20efd0c657cb941c'))
  })
  // vector source: https://www.rfc-editor.org/rfc/rfc7914
  it('scrypt', () => {
    const ikm = UTF8('pleaseletmein')
    const salt = UTF8('SodiumChloride')
    const kdf = scrypt()
    expect(kdf(64, ikm, salt)).toMatchObject(HEX('7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887'))
  })
})
