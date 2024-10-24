import { describe, expect, it } from 'vitest'
import { UTF8 } from '../src/core/codec'
import { rsa } from '../src/cipher/pkcs/rsa'

describe('pkcs', () => {
  const m = UTF8.parse('meow, 喵， 🐱')
  it('rsa-1024', () => {
    const rsa_1024 = rsa(1024)
    const c = rsa_1024.encrypt(m)
    expect(rsa_1024.decrypt(c)).toMatchObject(m)
  })
  it.skip('rsa-2048', () => {
    const rsa_2048 = rsa(2048)
    const c = rsa_2048.encrypt(m)
    expect(rsa_2048.decrypt(c)).toMatchObject(m)
  })
  it.skip('rsa-4096', () => {
    const rsa_4096 = rsa(4096)
    const c = rsa_4096.encrypt(m)
    expect(rsa_4096.decrypt(c)).toMatchObject(m)
  })
})
