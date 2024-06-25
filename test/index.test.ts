import { describe, expect, it } from 'vitest'
import { md5, sha1 } from '../src/index'
import { B64, B64url, Hex, Utf8 } from '../src/core/codec'
import { sha224, sha256 } from '../src/hash/sha256'
import { sha384, sha512, sha512t } from '../src/hash/sha512'
import { sha3_224, sha3_256, sha3_384, sha3_512, shake128, shake256 } from '../src/hash/sha3'

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
  it('sha3', () => {
    expect(sha3_224('')).toMatchInlineSnapshot('"6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"')
    expect(sha3_224('meow, 喵， 🐱')).toMatchInlineSnapshot('"19b2d0e73d5e0ba70850be3714f651af047e50a66889a06cf3a23f37"')
    expect(sha3_256('')).toMatchInlineSnapshot('"a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"')
    expect(sha3_256('meow, 喵， 🐱')).toMatchInlineSnapshot('"11253eef825cfe6766c2e9afad051084bf60e5998823f3f6455b3a00e850dead"')
    expect(sha3_384('')).toMatchInlineSnapshot('"0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"')
    expect(sha3_384('meow, 喵， 🐱')).toMatchInlineSnapshot('"a240008e6a6899b793f2ab3fce4022eaa48b319ce1c4025e64b19c63f230ee8d57bb20f6c05b058e01781952f0b960c9"')
    expect(sha3_512('')).toMatchInlineSnapshot('"a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"')
    expect(sha3_512('meow, 喵， 🐱')).toMatchInlineSnapshot('"624e65a5587f89665d43f2c47de89df0bdb8b93d775ce950afd75aca9306630df3d1f27bf67c8a068f9f4724512d30520e19c0e9241138a4fe37a7267844f703"')

    expect(shake128('', 256)).toMatchInlineSnapshot('"7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26"')
    expect(shake128('meow, 喵， 🐱', 256)).toMatchInlineSnapshot('"5b6a7f04e608d48139e2b72aa4fc2d047fc1ae5c77aefec0fd822ad77dff56f1"')
    expect(shake256('', 512)).toMatchInlineSnapshot('"46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be"')
    expect(shake256('meow, 喵， 🐱', 512)).toMatchInlineSnapshot('"5db7c1ba86c680ac9d8442d18057f7bd28fb125e324271ca0327f2862173411b65ae4a9d454b31c52ab24a3b779bb67b2d9298e418d16ea737fc5d5d3fac760f"')
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
