import { describe, expect, it } from 'vitest'
import { md5, sha1 } from '../src/index'
import { B64, B64url, Hex, Utf8 } from '../src/core/codec'

describe('hash', () => {
  it('md5', () => {
    expect(md5('')).toMatchInlineSnapshot('"d41d8cd98f00b204e9800998ecf8427e"')
    expect(md5('meow, 喵， 🐱')).toMatchInlineSnapshot('"49ac572e5f34b3e212e727fbd05df30c"')
  })
  it('sha1', () => {
    expect(sha1('')).toMatchInlineSnapshot('"da39a3ee5e6b4b0d3255bfef95601890afd80709"')
    expect(sha1('meow, 喵， 🐱')).toMatchInlineSnapshot('"d4af2eec98c3f9c25c53dd1304c5963ed80f48ff"')
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
