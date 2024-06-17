import { describe, expect, it } from 'vitest'
import { md5, sha1 } from '../src/index'
import { B64, B64url, Hex, Utf8 } from '../src/core/codec'
import { sha224, sha256 } from '../src/hash/sha256'
import { sha384, sha512, sha512t } from '../src/hash/sha512'

describe('hash', () => {
  it('md5', () => {
    expect(md5('')).toMatchInlineSnapshot('"d41d8cd98f00b204e9800998ecf8427e"')
    expect(md5('meow, 喵， 🐱')).toMatchInlineSnapshot('"49ac572e5f34b3e212e727fbd05df30c"')
  })
  it('sha1', () => {
    expect(sha1('')).toMatchInlineSnapshot('"da39a3ee5e6b4b0d3255bfef95601890afd80709"')
    expect(sha1('meow, 喵， 🐱')).toMatchInlineSnapshot('"d4af2eec98c3f9c25c53dd1304c5963ed80f48ff"')
  })
  it('sha224', () => {
    expect(sha224('')).toMatchInlineSnapshot('"d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"')
    expect(sha224('meow, 喵， 🐱')).toMatchInlineSnapshot('"b2b263f005ba9a07783a97269fcf79863657bc4dbe6716373d6a4744"')
  })
  it('sha256', () => {
    expect(sha256('')).toMatchInlineSnapshot('"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"')
    expect(sha256('meow, 喵， 🐱')).toMatchInlineSnapshot('"9325c5351e2c58f0c4f3b973bd48e6b8981c04c1a6474d35686d5fdce77aebca"')
  })
  it('sha384', () => {
    expect(sha384('')).toMatchInlineSnapshot('"38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"')
    expect(sha384('meow, 喵， 🐱')).toMatchInlineSnapshot('"51dcb8ca5e46938c2aa35956bf5fa2c24d0e8595720943f5fe0ac5d66190675af7a84ae14f6546b8bf2d86c29c214b0e"')
  })
  it('sha512', () => {
    expect(sha512('')).toMatchInlineSnapshot('"cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"')
    expect(sha512('meow, 喵， 🐱')).toMatchInlineSnapshot('"385e2b3fee115b4df04bf67f08861413637294b56586aa238b11806b315f9b626dba973338a9463631a11b9882a30a56fc9300ead6fe3dbcf0a5a5f12769d4df"')
  })
  it('sha512/224', () => {
    expect(sha512t(224)('')).toMatchInlineSnapshot('"6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4"')
    const sha512_224 = sha512t(224)
    expect(sha512_224('')).toMatchInlineSnapshot('"6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4"')
    expect(sha512_224('meow, 喵， 🐱')).toMatchInlineSnapshot('"988a78f176c3f4cb1b19b3a4e0ae4f6924df720a04068713a6ee519e"')
  })
})

describe('codec', () => {
  it('utf8', () => {
    expect(Utf8.stringify(Utf8.parse('cat, 猫, 🐱'))).toMatchInlineSnapshot(`"cat, 猫, 🐱"`)
  })
  it('hex', () => {
    expect(Hex.stringify(Utf8.parse('cat, 猫, 🐱'))).toMatchInlineSnapshot(`"6361742c20e78cab2c20f09f90b1"`)
    expect(Utf8.stringify(Hex.parse('6361742c20e78cab2c20f09f90b1'))).toMatchInlineSnapshot(`"cat, 猫, 🐱"`)
  })
  it('b64', () => {
    expect(B64.stringify(Utf8.parse('因为，Base64 将三个字节转化成四个字节，因此 Base64 编码后的文本，会比原文本大出三分之一左右。'))).toMatchInlineSnapshot(`"5Zug5Li677yMQmFzZTY0IOWwhuS4ieS4quWtl+iKgui9rOWMluaIkOWbm+S4quWtl+iKgu+8jOWboOatpCBCYXNlNjQg57yW56CB5ZCO55qE5paH5pys77yM5Lya5q+U5Y6f5paH5pys5aSn5Ye65LiJ5YiG5LmL5LiA5bem5Y+z44CC"`)
    expect(B64.stringify(Utf8.parse('a'))).toMatchInlineSnapshot(`"YQ=="`)
    expect(B64.stringify(Utf8.parse('cat, 猫, 🐱'))).toMatchInlineSnapshot(`"Y2F0LCDnjKssIPCfkLE="`)
    expect(Utf8.stringify(B64.parse('Y2F0LCDnjKssIPCfkLE'))).toMatchInlineSnapshot(`"cat, 猫, 🐱"`)
  })
  it('b64url', () => {
    expect(B64url.stringify(Utf8.parse('因为，Base64 将三个字节转化成四个字节，因此 Base64 编码后的文本，会比原文本大出三分之一左右。'))).toMatchInlineSnapshot(`"5Zug5Li677yMQmFzZTY0IOWwhuS4ieS4quWtl-iKgui9rOWMluaIkOWbm-S4quWtl-iKgu-8jOWboOatpCBCYXNlNjQg57yW56CB5ZCO55qE5paH5pys77yM5Lya5q-U5Y6f5paH5pys5aSn5Ye65LiJ5YiG5LmL5LiA5bem5Y-z44CC"`)
    expect(B64url.stringify(Utf8.parse('a'))).toMatchInlineSnapshot(`"YQ"`)
    expect(B64url.stringify(Utf8.parse('cat, 猫, 🐱'))).toMatchInlineSnapshot(`"Y2F0LCDnjKssIPCfkLE"`)
    expect(Utf8.stringify(B64url.parse('Y2F0LCDnjKssIPCfkLE'))).toMatchInlineSnapshot(`"cat, 猫, 🐱"`)
  })
})
