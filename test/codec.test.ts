import { describe, expect, it } from 'vitest'
import { B32, B64, B64URL, CSV, HEX, UTF8 } from '../src/core/codec'

describe('codec', () => {
  it('utf8', () => {
    expect(UTF8(UTF8('cat, 猫, 🐱'))).toMatchInlineSnapshot(`"cat, 猫, 🐱"`)
  })
  it('hex', () => {
    expect(HEX(UTF8('cat, 猫, 🐱'))).toMatchInlineSnapshot(`"6361742c20e78cab2c20f09f90b1"`)
    expect(UTF8(HEX('6361742c20e78cab2c20f09f90b1'))).toMatchInlineSnapshot(`"cat, 猫, 🐱"`)
  })
  it('b64', () => {
    expect(B64(UTF8('因为，Base64 将三个字节转化成四个字节，因此 Base64 编码后的文本，会比原文本大出三分之一左右。'))).toMatchInlineSnapshot(`"5Zug5Li677yMQmFzZTY0IOWwhuS4ieS4quWtl+iKgui9rOWMluaIkOWbm+S4quWtl+iKgu+8jOWboOatpCBCYXNlNjQg57yW56CB5ZCO55qE5paH5pys77yM5Lya5q+U5Y6f5paH5pys5aSn5Ye65LiJ5YiG5LmL5LiA5bem5Y+z44CC"`)
    expect(B64(UTF8('a'))).toMatchInlineSnapshot(`"YQ=="`)
    expect(B64(UTF8('cat, 猫, 🐱'))).toMatchInlineSnapshot(`"Y2F0LCDnjKssIPCfkLE="`)
    expect(UTF8(B64('Y2F0LCDnjKssIPCfkLE'))).toMatchInlineSnapshot(`"cat, 猫, 🐱"`)
  })
  it('b64url', () => {
    expect(B64URL(UTF8('因为，Base64 将三个字节转化成四个字节，因此 Base64 编码后的文本，会比原文本大出三分之一左右。'))).toMatchInlineSnapshot(`"5Zug5Li677yMQmFzZTY0IOWwhuS4ieS4quWtl-iKgui9rOWMluaIkOWbm-S4quWtl-iKgu-8jOWboOatpCBCYXNlNjQg57yW56CB5ZCO55qE5paH5pys77yM5Lya5q-U5Y6f5paH5pys5aSn5Ye65LiJ5YiG5LmL5LiA5bem5Y-z44CC"`)
    expect(B64URL(UTF8('a'))).toMatchInlineSnapshot(`"YQ"`)
    expect(B64URL(UTF8('cat, 猫, 🐱'))).toMatchInlineSnapshot(`"Y2F0LCDnjKssIPCfkLE"`)
    expect(UTF8(B64URL('Y2F0LCDnjKssIPCfkLE'))).toMatchInlineSnapshot(`"cat, 猫, 🐱"`)
    expect(UTF8(B64URL('5Zug5Li677yMQmFzZTY0IOWwhuS4ieS4quWtl-iKgui9rOWMluaIkOWbm-S4quWtl-iKgu-8jOWboOatpCBCYXNlNjQg57yW56CB5ZCO55qE5paH5pys77yM5Lya5q-U5Y6f5paH5pys5aSn5Ye65LiJ5YiG5LmL5LiA5bem5Y-z44CC'))).toMatchInlineSnapshot(`"因为，Base64 将三个字节转化成四个字节，因此 Base64 编码后的文本，会比原文本大出三分之一左右。"`)
  })
  it('b32', () => {
    const B32P = B32({ padding: true })

    expect(B32(UTF8('foobar'))).toMatchInlineSnapshot(`"MZXW6YTBOI"`)
    expect(B32P(UTF8('foobar'))).toMatchInlineSnapshot(`"MZXW6YTBOI======"`)
    expect(UTF8(B32('MZXW6YTBOI'))).toMatchInlineSnapshot(`"foobar"`)

    expect(B32(UTF8('cat, 猫, 🐱'))).toMatchInlineSnapshot(`"MNQXILBA46GKWLBA6CPZBMI"`)
    expect(UTF8(B32('MNQXILBA46GKWLBA6CPZBMI='))).toMatchInlineSnapshot(`"cat, 猫, 🐱"`)
  })
  it('b32-hex', () => {
    const B32HP = B32({ variant: 'rfc4648-hex', padding: true })
    const B32H = B32({ variant: 'rfc4648-hex', padding: false })

    expect(B32H(UTF8('foobar'))).toMatchInlineSnapshot(`"CPNMUOJ1E8"`)
    expect(B32HP(UTF8('foobar'))).toMatchInlineSnapshot(`"CPNMUOJ1E8======"`)

    expect(B32H(UTF8('cat, 猫, 🐱'))).toMatchInlineSnapshot(`"CDGN8B10SU6AMB10U2FP1C8"`)
    expect(B32HP(UTF8('cat, 猫, 🐱'))).toMatchInlineSnapshot(`"CDGN8B10SU6AMB10U2FP1C8="`)

    expect(UTF8(B32H('CDGN8B10SU6AMB10U2FP1C8='))).toMatchInlineSnapshot(`"cat, 猫, 🐱"`)
    expect(UTF8(B32H('CPNMUOJ1E8'))).toMatchInlineSnapshot(`"foobar"`)
  })
  it('b32-crockford', () => {
    const B32C = B32({ variant: 'crockford', padding: false })

    expect(B32C(UTF8('foobar'))).toMatchInlineSnapshot(`"CSQPYRK1E8"`)
    expect(UTF8(B32C('CSQPYRK1E8'))).toMatchInlineSnapshot(`"foobar"`)
    expect(UTF8(B32C('CSQPYRKLE8'))).toMatchInlineSnapshot(`"foobar"`)
    expect(B32C(UTF8('cat, 猫, 🐱'))).toMatchInlineSnapshot(`"CDGQ8B10WY6APB10Y2FS1C8"`)
    expect(UTF8(B32C('CDGQ8B10-WY6APB10-Y2FS1C8'))).toMatchInlineSnapshot(`"cat, 猫, 🐱"`)
    expect(UTF8(B32C('CDGQ8B1o-WY6APB1O-Y2FSLC8'))).toMatchInlineSnapshot(`"cat, 猫, 🐱"`)
    expect(UTF8(B32C('CDGQ8BI0-WY6APB1o-Y2FSlC8'))).toMatchInlineSnapshot(`"cat, 猫, 🐱"`)
  })
  it('csv', () => {
    expect(CSV(UTF8('cat'))).toMatchInlineSnapshot(`"公正和谐公正民主法治自由"`)
    expect(UTF8(CSV('公正和谐公正民主法治自由文明友善公正文明富强诚信自由法治爱国诚信文明诚信富强诚信民主文明友善公正文明富强诚信平等富强敬业友善敬业敬业富强友善平等民主'))).toMatchInlineSnapshot(`"cat, 猫, 🐱"`)
  })
})
