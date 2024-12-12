<div align="center">
<!-- LOGO -->
<a href="https://github.com/RSoraM/mima-kit"><img src="./README/logo.svg" alt="logo" width="150"/></a>

<br>

<!-- LINKS -->
<a href="https://npmjs.com/package/mima-kit"><img src="https://img.shields.io/npm/v/mima-kit?style=for-the-badge" alt="npm version"/></a>
<a href="https://npmjs.com/package/mima-kit"><img src="https://img.shields.io/npm/dm/mima-kit?style=for-the-badge" alt="npm downloads"/></a>
<a href="https://bundlephobia.com/result?p=mima-kit"><img src="https://img.shields.io/bundlephobia/minzip/mima-kit?style=for-the-badge&label=minzip" alt="bundle"/></a>
<br>
<a href="https://www.jsdocs.io/package/mima-kit"><img src="https://img.shields.io/badge/jsDocs-reference-pink?style=for-the-badge" alt="jsdocs"/></a>
<a href="https://github.com/RSoraM/mima-kit/blob/main/LICENSE" alt="license"><img src="https://img.shields.io/github/license/RSoraM/mima-kit.svg?style=for-the-badge" alt="license"/></a>

[**简体中文**](./README.md) | [**English**](./README/README-en.md)

</div>
<br>

# mima-kit

`mima-kit` 是一个使用 `TypeScript` 实现的密码学套件。目标是提供一个简单易用的密码学库。`mima-kit` 尚处于早期开发阶段，API 可能会发生变化。

在线使用: https://rsoram.github.io/mima-live/

## 安装

```bash
npm install mima-kit
```

# 目录

<!-- 字符编码 -->
<a href="#字符编码" style="margin-left:1em">字符编码</a>
<!-- 字符编码 -->

<!-- 散列算法 -->
<details>
<summary>
<a href="#散列算法">散列算法</a>
</summary>
<ul style="list-style-type: none;">
  <li><a href="#加密散列算法">加密散列算法</a></li>
  <ul style="list-style-type: none; padding-left: 1em;">
    <li><a href="#sm3">SM3</a></li>
    <li><a href="#md5">MD5</a></li>
    <li><a href="#sha-1">SHA-1</a></li>
    <li><a href="#sha-2">SHA-2</a></li>
    <li><a href="#sha-3">SHA-3</a></li>
    <li><a href="#cshake">cSHAKE</a></li>
    <li><a href="#tuplehash">TupleHash</a></li>
    <li><a href="#parallelhash">ParallelHash</a></li>
    <li><a href="#turboshake">TurboSHAKE</a></li>
    <li><a href="#k12">K12</a></li>
  </ul>
  <li><a href="#带密钥的加密散列算法">带密钥的加密散列算法</a></li>
  <ul style="list-style-type: none;padding-left: 1em;">
    <li><a href="#hmac">HMAC</a></li>
    <li><a href="#kmac">KMAC</a></li>
  </ul>
  <li><a href="#包装您的加密散列算法">包装您的加密散列算法</a></li>
</ul>
</details>
<!-- 散列算法 -->

<!-- 对称密钥算法 -->
<details>
<summary>
<a href="#对称密钥算法">对称密钥算法</a>
</summary>
<ul style="list-style-type: none;">
  <li><a href="#分组密码算法">分组密码算法</a></li>
  <ul style="list-style-type: none; padding-left: 1em;">
    <li><a href="#sm4">SM4</a></li>
    <li><a href="#aes">AES</a></li>
    <li><a href="#aria">ARIA</a></li>
    <li><a href="#camellia">Camellia</a></li>
    <li><a href="#des">DES</a></li>
    <li><a href="#3des">3DES</a></li>
    <li><a href="#arc5">ARC5</a></li>
    <li><a href="#blowfish">Blowfish</a></li>
    <li><a href="#twofish">Twofish</a></li>
    <li><a href="#tea">TEA</a></li>
    <li><a href="#xtea">XTEA</a></li>
  </ul>
  <li><a href="#填充模式">填充模式</a></li>
  <li><a href="#工作模式">工作模式</a></li>
  <li><a href="#流密码算法">流密码算法</a></li>
  <ul style="list-style-type: none; padding-left: 1em;">
    <li><a href="#zuc">ZUC</a></li>
    <li><a href="#arc4">ARC4</a></li>
    <li><a href="#salsa20">Salsa20</a></li>
    <li><a href="#rabbit">Rabbit</a></li>
  </ul>
  <li><a href="#包装您的对称密钥算法">包装您的对称密钥算法</a></li>
</ul>
</details>
<!-- 对称密钥算法 -->

<!-- 非对称密钥算法 -->
<details>
<summary>
<a href="#非对称密钥算法">非对称密钥算法</a>
</summary>
<ul style="list-style-type: none;">
  <li><a href="#rsa">RSA</a></li>
  <ul style="list-style-type: none; padding-left: 1em;">
    <li><a href="#pkcs1-mgf1">PKCS1-MGF1</a></li>
    <li><a href="#rsaes-pkcs1-v1_5">RSAES-PKCS-v1_5</a></li>
    <li><a href="#rsaes-oaep">RSAES-OAEP</a></li>
    <li><a href="#rsassa-pkcs1-v1_5">RSASSA-PKCS-v1_5</a></li>
    <li><a href="#rsassa-pss">RSASSA-PSS</a></li>
  </ul>
  <li><a href="#ecc">ECC</a></li>
  <ul style="list-style-type: none; padding-left: 1em;">
    <li><a href="#point-compress">Point Compress</a></li>
    <li><a href="#ecdh">ECDH</a></li>
    <li><a href="#eccdh">ECCDH</a></li>
    <li><a href="#ecmqv">ECMQV</a></li>
    <li><a href="#ecdsa">ECDSA</a></li>
    <li><a href="#ecies">ECIES</a></li>
  </ul>
</ul>
</details>
<!-- 非对称密钥算法 -->

<!-- 其他组件 -->
<details>
<summary>
<a href="#其他组件">其他组件</a>
</summary>
<ul style="list-style-type: none;">
  <li><a href="#密钥派生">密钥派生</a></li>
  <ul style="list-style-type: none; padding-left: 1em;">
    <li><a href="#x963kdf">X9.63KDF</a></li>
    <li><a href="#hkdf">HKDF</a></li>
    <li><a href="#pbkdf2">PBKDF2</a></li>
  </ul>
  <li><a href="#椭圆曲线列表">椭圆曲线列表</a></li>
</ul>
</details>
<!-- 其他组件 -->

# 字符编码

- `UTF8` UTF-8 编码
- `HEX` 十六进制编码
- `B64` Base64 编码
- `B64URL` Base64URL 编码

密码学中的数据通常是二进制数据，在 `JS` 中通常以 `Uint8Array` 表示，`string` 和 `Uint8Array` 的转换需要 `字符编码`。

> 如果您使用 `Node.js` 这类支持 `Buffer` 的环境，那么您可以直接使用 `Buffer` 进行编解码。如果您使用的是浏览器环境，就可以使用 `mima-kit` 提供的解码器。

`mima-kit` 提供的编解码器会自动判断输入数据的类型。

- 输入 `Uint8Array` 类型的数据，会将其转换为 `string`
- 输入 `string` 类型的数据，会将其转换为 `Uint8Array`

```typescript
// convert utf-8 string to Uint8Array
const e = UTF8('mima-kit')
// convert Uint8Array to utf-8 string
const d = UTF8(e)
console.log(d) // 'mima-kit'
```

```typescript
interface Codec {
  /** Parse encoded string to Uint8Array */
  (input: string): U8
  /** Stringify Uint8Array to encoded string */
  (input: Uint8Array): string
  FORMAT: string
}
```

在上述代码中，您可能留意到了 `U8` 类型。`mima-kit` 中绝大多数函数都会返回 `U8` 类型，她是 `Uint8Array` 的子类，旨在提供一些额外的方法。绝大多数情况下，您可以放心地将 `U8` 类型传递给其他使用 `Uint8Array` 的函数。

```typescript
// Parse encoded string to U8
U8.fromSting('6D696D612D6B6974', HEX)

// Stringify U8 to encoded string
U8.fromSting('6D696D612D6B6974', HEX)
  .to(UTF8) // 'mima-kit'

// Convert BigInt to U8
U8.fromBI(0x12345678n) // [0x12, 0x34, 0x56, 0x78]

// Convert U8 to BigInt
U8.fromBI(0x12345678n)
  .toBI() // 305419896n (0x12345678n)
```

# 散列算法

`散列算法` 是一种将任意长度的数据映射为固定长度数据的算法。该定义非常宽泛，但在密码学中，通常讨论的是 `加密散列算法`。`带密钥的加密散列算法` 会额外使用一个密钥产生更安全的散列值。

## 加密散列算法

### SM3

Specification: [GM/T 0004-2012](https://oscca.gov.cn/sca/xxgk/2010-12/17/1002389/files/302a3ada057c4a73830536d03e683110.pdf)

```typescript
const m = UTF8('mima-kit')
sm3(m).to(HEX)
```

### MD5

Specification: [RFC 1321](https://www.rfc-editor.org/rfc/rfc1321.txt)

```typescript
const m = UTF8('mima-kit')
md5(m).to(HEX)
```

### SHA-1

Specification: [FIPS PUB 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf)

```typescript
const m = UTF8('mima-kit')
sha1(m).to(HEX)
```

### SHA-2

Specification: [FIPS PUB 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf)

```typescript
const m = UTF8('mima-kit')
sha224(m).to(HEX)
sha256(m).to(HEX)
sha384(m).to(HEX)
sha512(m).to(HEX)

const sha512_224 = sha512t(224)
sha512_224(m).to(HEX)
```

### SHA-3

Specification: [FIPS PUB 202](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf)

```typescript
const m = UTF8('mima-kit')
sha3_224(m).to(HEX)
sha3_256(m).to(HEX)
sha3_384(m).to(HEX)
sha3_512(m).to(HEX)

shake128(256)(m).to(HEX)
shake256(512)(m).to(HEX)
```

### cSHAKE

Specification: [NIST SP 800-185](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf)

```typescript
// optional function name
const n = UTF8('name')
// optional customization string
const s = UTF8('custom')
const m = UTF8('mima-kit')

cShake128(256, n, s)(m).to(HEX)
cShake256(512, n, s)(m).to(HEX)
```

### TupleHash

Specification: [NIST SP 800-185](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf)

```typescript
// optional customization string
const s = UTF8('custom')
const m = ['mima', '-', 'kit'].map(v => UTF8(v))
tupleHash128(256, s)(m).to(HEX)
tupleHash256(512, s)(m).to(HEX)
tupleHash128XOF(256, s)(m).to(HEX)
tupleHash256XOF(512, s)(m).to(HEX)
```

### ParallelHash

Specification: [NIST SP 800-185](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf)

> 注意：`mima-kit` 提供的 `ParallelHash` 算法并不能真正并行计算，只是将输入分块后分别计算，最后将结果拼接。

```typescript
// optional customization string
const s = UTF8('custom')
const m = UTF8('mima-kit')
const blockSize = 1024
parallelHash128(blockSize, 256, s)(m).to(HEX)
parallelHash256(blockSize, 512, s)(m).to(HEX)
parallelHash128XOF(blockSize, 256, s)(m).to(HEX)
parallelHash256XOF(blockSize, 512, s)(m).to(HEX)
```

### TurboSHAKE

Specification: [TurboSHAKE](https://keccak.team/files/TurboSHAKE.pdf)

```typescript
// optional Domain Separator
// range: 0x01 ~ 0x7F, default: 0x1F
const D = 0x0B
const m = UTF8('mima-kit')
turboSHAKE128(256, D)(m).to(HEX)
turboSHAKE256(512, D)(m).to(HEX)
```

### KangarooTwelve

Specification: [KangarooTwelve](https://keccak.team/files/KangarooTwelve.pdf)

```typescript
// optional customization string
const s = UTF8('custom')
const m = UTF8('mima-kit')
kt128(256, s)(m).to(HEX)
kt256(512, s)(m).to(HEX)
```

## 带密钥的加密散列算法

### HMAC

Specification: [RFC 2104](https://www.rfc-editor.org/rfc/rfc2104.txt)

> 密钥长度的参数 `k_size` 默认使用散列算法的 `DIGEST_SIZE`。该参数不会影响函数的结果，但会被其他函数使用，例如 `ECIES`。

```typescript
const key = UTF8('password')
const m = UTF8('mima-kit')
// HMAC-SM3
hmac(sm3)(key)(m).to(HEX)
// HMAC-SHA1-80 with 80-bit digest and 160-bit key
hmac(sha1, 80)(key)(m).to(HEX)
// HMAC-SHA1-160 with 160-bit digest and 80-bit key
hmac(sha1, 160, 80)(key)(m).to(HEX)
```

### KMAC

Specification: [NIST SP 800-185](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf)

```typescript
// customization string
const s = UTF8('custom')
const key = UTF8('password')
const m = UTF8('mima-kit')

kmac128(256, s)(key)(m).to(HEX)
kmac256(512, s)(key)(m).to(HEX)
kmac128XOF(256, s)(key)(m).to(HEX)
kmac256XOF(512, s)(key)(m).to(HEX)
```

## 包装您的加密散列算法

如果您已经实现了一个伟大而又神秘的散列算法，您可以使用 `createHash` 函数将其包装成一个可被调用的 `Hash` 对象。然后您就可以像使用其他 `加密散列算法` 一样，将您的算法和 `mima-kit` 中其他高级算法一起使用。

> 如果您熟悉 `JS`，您会发现 `createHash` 的本质不过是 `Object.assign` 的包装。您完全可以用 `Object.assign` 替代 `createHash`，但 `createHash` 会为您提供一些类型提示，避免发生恼人的拼写错误。

```typescript
const _greatHash: Digest = (M: Uint8Array) => new U8(M)
const greatHashDescription: HashDescription = {
  ALGORITHM: 'GreatHash',
  BLOCK_SIZE: 64,
  DIGEST_SIZE: 64,
}
const greatHash = createHash(_greatHash, greatHashDescription)
// HMAC-GreatHash
const hmac_gh = hmac(greatHash)
```

```typescript
interface Digest {
  (M: Uint8Array): U8
}
interface HashDescription {
  /** Algorithm name */
  ALGORITHM: string
  /** Block size (byte) */
  BLOCK_SIZE: number
  /** Digest size (byte) */
  DIGEST_SIZE: number
  OID?: string
}
```

# 对称密钥算法

`对称密钥算法` 是一种使用相同密钥进行 `加密` 和 `解密` 的加密算法。它可以分为 `分组密码算法` 和 `流密码算法`。`分组密码算法` 通常需要组合 `填充模式` 和 `工作模式` 一起使用。`分组密码算法` 可以通过特定的 `工作模式` 和 `NO_PAD` 转换为 `流密码算法`。

> 你可以在 `/test/cipher.test.ts` 中找到更多使用示例。

```typescript
const k = HEX('')
const iv = HEX('')
const p = UTF8('mima-kit')
// using SM4-CBC
const cbc_sm4 = cbc(sm4)(k, iv)
const c = cbc_sm4.encrypt(p)
const m = cbc_sm4.decrypt(c)
m.to(UTF8) // 'mima-kit'
// using SM4-CTR in stream mode
const ctr_sm4 = ctr(sm4, NO_PAD)(k, iv)
const c = ctr_sm4.encrypt(p)
const m = ctr_sm4.decrypt(c)
m.to(UTF8) // 'mima-kit'
```

## 分组密码算法

单独使用 `分组密码算法` 没有太大的意义，因为它只能对单个数据块进行加解密。

### SM4

Specification: [GM/T 0002-2012](https://www.sca.gov.cn/sca/c100061/201611/1002423/files/330480f731f64e1ea75138211ea0dc27.pdf)

```typescript
let k: Uint8Array
let m: Uint8Array
let c: Uint8Array

sm4(k).encrypt(m) // c
sm4(k).decrypt(c) // m
```

### AES

Specification: [FIPS PUB 197](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf)

```typescript
let k: Uint8Array
let m: Uint8Array
let c: Uint8Array

aes(128)(k).encrypt(m) // c
aes(128)(k).decrypt(x) // m

aes(192)(k).encrypt(m) // c
aes(192)(k).decrypt(c) // m

aes(256)(k).encrypt(m) // c
aes(256)(k).decrypt(c) // m
```

### ARIA

Specification: [RFC 5794](https://www.rfc-editor.org/rfc/rfc5794.txt)

```typescript
let k: Uint8Array
let m: Uint8Array
let c: Uint8Array

aria(128)(k).encrypt(m) // c
aria(128)(k).decrypt(c) // m

aria(192)(k).encrypt(m) // c
aria(192)(k).decrypt(c) // m

aria(256)(k).encrypt(m) // c
aria(256)(k).decrypt(c) // m
```

### Camellia

Specification: [RFC 3713](https://www.rfc-editor.org/rfc/rfc3713.txt)

```typescript
let k: Uint8Array
let m: Uint8Array
let c: Uint8Array

camellia(128)(k).encrypt(m) // c
camellia(128)(k).decrypt(c) // m

camellia(192)(k).encrypt(m) // c
camellia(192)(k).decrypt(c) // m

camellia(256)(k).encrypt(m) // c
camellia(256)(k).decrypt(c) // m
```

### DES

Specification: [FIPS PUB 46-3](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.46-3.pdf)

```typescript
let k: Uint8Array
let m: Uint8Array
let c: Uint8Array

des(k).encrypt(m) // c
des(k).decrypt(c) // m
```

### 3DES

Specification: [FIPS PUB 46-3](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.46-3.pdf)

```typescript
let k: Uint8Array
let m: Uint8Array
let c: Uint8Array

t_des(128)(k).encrypt(m) // c
t_des(128)(k).decrypt(c) // m

t_des(192)(k).encrypt(m) // c
t_des(192)(k).decrypt(c) // m
```

### ARC5

Specification: [ARC5](https://people.csail.mit.edu/rivest/pubs/Riv94.revised-1997-03-20.pdf)

`ARC5` 算法是一个参数化的算法，可以接受长度为 `0 < k.byteLength < 256` 的密钥。参数化后算法标记为 `ARC5-w/r`，其中 `w` 是工作字的比特长度，`r` 是轮数。

```typescript
// 推荐的参数化配置
// +-----+----+
// |   w |  r |
// +-----+----+
// |   8 |  8 |
// |  16 | 12 |
// |  32 | 16 | (default)
// |  64 | 20 |
// | 128 | 24 |
// +-----+----+

let k: Uint8Array
let m: Uint8Array
let c: Uint8Array

const spec8 = arc5(8, 8) // ARC5-8/8
const spec16 = arc5(16, 12) // ARC5-16/12
const spec32 = arc5(32, 16) // ARC5-32/16 (default)
const spec64 = arc5(64, 20) // ARC5-64/20
const spec128 = arc5(128, 24) // ARC5-128/24

spec32(k).encrypt(m) // c
spec32(k).decrypt(c) // m
```

### Blowfish

Specification: [Blowfish](https://www.schneier.com/academic/blowfish/)

```typescript
let k: Uint8Array
let m: Uint8Array
let c: Uint8Array

blowfish(k).encrypt(m) // c
blowfish(k).decrypt(c) // m
```

### Twofish

Specification: [Twofish](https://www.schneier.com/academic/twofish/)

```typescript
let k: Uint8Array
let m: Uint8Array
let c: Uint8Array

twofish(128)(k).encrypt(m) // c
twofish(128)(k).decrypt(x) // m

twofish(192)(k).encrypt(m) // c
twofish(192)(k).decrypt(c) // m

twofish(256)(k).encrypt(m) // c
twofish(256)(k).decrypt(c) // m
```

### TEA

Specification: [TEA](https://tayloredge.com/reference/Mathematics/TEA-XTEA.pdf)

向 `TEA` 算法传递一个代表 `轮数` 的参数。`TEA` 算法的 `轮数` 可以是任意正整数，默认使用 `32`。

```typescript
let k: Uint8Array
let m: Uint8Array
let c: Uint8Array

tea(32)(k).encrypt(m) // c
tea(32)(k).decrypt(c) // m
```

### XTEA

Specification: [XTEA](https://tayloredge.com/reference/Mathematics/TEA-XTEA.pdf)

向 `XTEA` 算法传递一个代表 `轮数` 的参数。`XTEA` 算法的 `轮数` 可以是任意正整数，默认使用 `32`。

```typescript
let k: Uint8Array
let m: Uint8Array
let c: Uint8Array

xtea(32)(k).encrypt(m) // c
xtea(32)(k).decrypt(c) // m
```

## 填充模式

- `PKCS7_PAD` PKCS#7 填充模式
- `X923_PAD` ANSI X9.23 填充模式
- `ISO7816_PAD` ISO/IEC 7816-4 填充模式
- `ZERO_PAD` 零填充模式
- `NO_PAD` 无填充模式

单独使用 `填充模式` 没有太大的意义，因为它只是对数据进行填充或者去填充。

```typescript
let block_size: number
let m = new Uint8Array()
let p = new Uint8Array()
// add padding
p = PKCS7_PAD(m, block_size)
// remove padding
m = PKCS7_PAD(p)
```

```typescript
interface Padding {
  /**
   * add padding
   * @param {Uint8Array} M - Message
   * @param {number} BLOCK_SIZE - Block size
   */
  (M: Uint8Array, BLOCK_SIZE: number): U8
  /**
   * remove padding
   * @param {Uint8Array} P - Padded message
   */
  (P: Uint8Array): U8
  ALGORITHM: string
}
```

### PKCS7_PAD

```typescript
const cbc_sm4 = cbc(sm4, PKCS7_PAD)
```

### X923_PAD

```typescript
const cbc_sm4 = cbc(sm4, X923_PAD)
```

### ISO7816_PAD

```typescript
const cbc_sm4 = cbc(sm4, ISO7816_PAD)
```

### ZERO_PAD

```typescript
const cbc_sm4 = cbc(sm4, ZERO_PAD)
```

### NO_PAD

> `NO_PAD` 模式不会对数据进行填充，这一模式仅用于将 `分组密码算法` 转换为 `流密码算法`。

```typescript
// run SM4-OFB in stream mode
const ofb_sm4 = ofb(sm4, NO_PAD)
```

## 工作模式

- `ecb` Electronic Codebook
- `cbc` Cipher Block Chaining
- `pcbc` Progressive Chaining Block Cipher
- `cfb` Cipher Feedback
- `ofb` Output Feedback
- `ctr` Counter Mode
- `gcm` Galois/Counter Mode

`mima-kit` 将 `工作模式` 与 `分组密码算法` 完全解偶，这意味着您可以将任意 `分组密码算法` 与任意 `工作模式` 结合使用。

### ECB

`Electronic Codebook` (ECB) 是最简单的工作模式。`ECB` 模式将明文分成固定长度的数据块，然后对每个数据块进行加密。

- `ECB` 模式不需要 `iv`。
- 向 `ECB` 模式传递的 `iv` 参数会被忽略。

```typescript
const k = HEX('')
const m = HEX('')
const c = HEX('')

const CIPHER = ecb(sm4)(k)
CIPHER.encrypt(m) // c
CIPHER.decrypt(c) // m
```

### CBC

`Cipher Block Chaining` (CBC) 是最常用的工作模式。`CBC` 模式每个明文块都会与前一个密文块进行异或操作，然后再进行加密。

- `CBC` 模式需要 `iv`。
- `iv` 的长度与加密算法的 `BLOCK_SIZE` 相同。

```typescript
const k = HEX('')
const iv = HEX('')
const m = HEX('')
const c = HEX('')

const CIPHER = cbc(sm4)(k, iv)
CIPHER.encrypt(m) // c
CIPHER.decrypt(c) // m
```

### PCBC

`Progressive Chaining Block Cipher` (PCBC) 是 `CBC` 的变种。`PCBC` 模式每个明文块都会与前一个明文和前一个密文块进行异或操作，然后再进行加密。`PCBC` 模式旨在将密文中的微小变化在加解密时无限传播。

- `PCBC` 模式需要 `iv`。
- `iv` 的长度与加密算法的 `BLOCK_SIZE` 相同。

```typescript
const k = HEX('')
const iv = HEX('')
const m = HEX('')
const c = HEX('')

const CIPHER = pcbc(sm4)(k, iv)
CIPHER.encrypt(m) // c
CIPHER.decrypt(c) // m
```

### CFB

`Cipher Feedback` (CFB) 将分组密码转换为流密码。`CFB` 模式通过加密前一个密文块获得加密数据流，然后与明文块进行异或操作，获得密文块。

- `CFB` 模式需要 `iv`。
- `iv` 的长度与加密算法的 `BLOCK_SIZE` 相同。
- `CFB` 可以通过 `NO_PAD` 转换为 `流密码算法`。

```typescript
const k = HEX('')
const iv = HEX('')
const m = HEX('')
const c = HEX('')

const CIPHER = cfb(sm4)(k, iv)
CIPHER.encrypt(m) // c
CIPHER.decrypt(c) // m
```

### OFB

`Output Feedback` (OFB) 将分组密码转换为流密码。`OFB` 模式通过加密 `iv` 获得加密数据流，然后与明文块进行异或操作，获得密文块。

- `OFB` 模式需要 `iv`。
- `iv` 的长度与加密算法的 `BLOCK_SIZE` 相同。
- `OFB` 可以通过 `NO_PAD` 转换为 `流密码算法`。

```typescript
const k = HEX('')
const iv = HEX('')
const m = HEX('')
const c = HEX('')

const CIPHER = ofb(sm4)(k, iv)
CIPHER.encrypt(m) // c
CIPHER.decrypt(c) // m
```

### CTR

`Counter Mode` (CTR) 将分组密码转换为流密码。`CTR` 模式将 `iv` 与计数器组合以生成唯一的 `计数器块`，通过加密 `计数器块` 获得加密数据流，然后与明文块进行异或操作，获得密文块。

- `CTR` 模式需要 `iv`。
- `iv` 的长度与加密算法的 `BLOCK_SIZE` 相同。
- `CTR` 可以通过 `NO_PAD` 转换为 `流密码算法`。

```typescript
const k = HEX('')
const iv = HEX('')
const m = HEX('')
const c = HEX('')

const CIPHER = ctr(sm4)(k, iv)
CIPHER.encrypt(m) // c
CIPHER.decrypt(c) // m
```

### GCM

`Galois/Counter Mode` (GCM) 将分组密码转换为流密码。`GCM` 模式可以看作是 `CTR` 模式的变种，它在 `CTR` 模式的基础上增加了 `认证` 功能。

- `GCM` 模式需要 `iv`。
- `iv` 的长度没有限制，但推荐使用 `96` 位长度的 `iv`。
- `GCM` 可以通过 `NO_PAD` 转换为 `流密码算法`。
- 签名生成的 `AUTH_TAG` 长度由 `AUTH_TAG_SIZE` 参数决定。`AUTH_TAG` 最大长度为 `128` 位，设置任意长度都不会影响程序的运行，但一般推荐使用 `128`、`120`、`112`、`104`、`96` 位长度，对于某些应用也可以使用 `64`、`32` 位长度。

`mima-kit` 实现的 `GCM` 模式并没有进行查表优化，因此性能可能会比较慢。

```typescript
const k = HEX('')
const iv = HEX('')
const m = HEX('')
const a = HEX('')
const c = HEX('')
const t = HEX('')

const CIPHER = gcm(aes(128))(k, iv)
CIPHER.encrypt(m) // c
CIPHER.decrypt(c) // m
CIPHER.sign(c, a) // auth tag
CIPHER.verify(t, c, a) // true or false
```

## 流密码算法

通常 `流密码算法` 不需要复杂的配置，一般只需要 `key` 和 `iv`。

```typescript
const k = HEX('')
const iv = HEX('')
const cipher = salsa20(k, iv)
const p = UTF8('mima-kit')
const c = cipher.encrypt(p)
const m = cipher.decrypt(c)
// p === m
```

### ZUC

`ZUC` 是 `3GPP` 规范中的流密码算法，它包含机密性算法 `128-EEA3` 和完整性算法 `128-EIA3`。由于 `ZUC` 算法主要用于移动通信，所以函数接口和其他流密码算法有所不同。

参考 `/test/cipher.test.ts` 以获取更多使用示例。

```typescript
const k = new Uint8Array(16)
const m = new Uint8Array(4)
const c = new Uint8Array([0x27, 0xBE, 0xDE, 0x74])
const mac = new Uint8Array([0xC8, 0xA9, 0x59, 0x5E])
const params: ZUCParams = {
  KEY: k,
  M: m,
  COUNTER: 0,
  BEARER: 0,
  DIRECTION: 0,
  LENGTH: 1,
}
// 128-EEA3 加密消息
eea3(params) // c
// 128-EIA3 计算消息认证码
eia3(params) // mac
// 128-EEA3 解密消息
params.M = c
eea3(params) // m
```

### ARC4

Specification: [ARC4](https://en.wikipedia.org/wiki/RC4)

`ARC4` 算法可以接受长度为 `0 < k.byteLength < 256` 的密钥，同时 `ARC4` 算法不需要 `iv`。

```typescript
const k = HEX('')
const cipher = arc4(k)
const c = cipher.encrypt(UTF8('mima-kit'))
const m = cipher.decrypt(c)
```

### Salsa20

Specification: [Salsa20](https://cr.yp.to/snuffle/spec.pdf)

`Salsa20` 算法可以接受长度为 `16` 或 `32` 字节的密钥和 `8` 字节的 `iv`。

```typescript
const k = HEX('')
const iv = HEX('')
const cipher = salsa20(k, iv)
const c = cipher.encrypt(UTF8('mima-kit'))
const m = cipher.decrypt(c)
```

### Rabbit

Specification: [Rabbit](https://www.rfc-editor.org/rfc/rfc4503.txt)

`Rabbit` 算法可以接受长度为 `16` 字节的密钥。对于 `iv`，`Rabbit` 算法可以接受长度为 `0` 或 `8` 字节的 `iv`。当 `iv` 长度为 `0` 字节时，`Rabbit` 算法会跳过 `iv Setup` 步骤。

```typescript
const p = UTF8('mima-kit')
const k = HEX('')
const iv = new Uint8Array(8)
const cipher = rabbit(k, iv)
const c = cipher.encrypt(p)
const m = cipher.decrypt(c)

// skip iv setup
const cipher = rabbit(k, new Uint8Array(0))
const c = cipher.encrypt(p)
const m = cipher.decrypt(c)
```

## 包装您的对称密钥算法

与 [`包装您的加密散列算法`](#包装您的加密散列算法) 一样，您可以使用 `createCipher` 函数将您的 `对称密钥算法` 包装成一个可被调用的 `Cipher` 对象。然后您就可以像使用其他 `对称密钥算法` 一样，将您的算法和 `mima-kit` 中其他高级算法一起使用。

> 如果您熟悉 `JS`，您会发现 `createCipher` 的本质不过是 `Object.assign` 的包装。您完全可以用 `Object.assign` 替代 `createCipher`，但 `createCipher` 会为您提供一些类型提示，避免发生恼人的拼写错误。

```typescript
const _greatCipher: Cipher = (k: Uint8Array) => {
  const cipher = {
    encrypt: (M: Uint8Array) => new U8(k.map((v, i) => v ^ M[i])),
    decrypt: (C: Uint8Array) => new U8(k.map((v, i) => v ^ C[i])),
  }
  return cipher
}
const greatCipherDescription: BlockCipherInfo = {
  ALGORITHM: 'GreatCipher',
  BLOCK_SIZE: 16,
  KEY_SIZE: 16,
  MIN_KEY_SIZE: 16,
  MAX_KEY_SIZE: 16,
}
const greatCipher = createCipher(_greatCipher, greatCipherDescription)
// GCM-GreatCipher
const gcm_gc = gcm(greatCipher)
```

```typescript
interface Cipher {
  (k: Uint8Array): Cipherable
}
interface Cipherable {
  encrypt: (M: Uint8Array) => U8
  decrypt: (C: Uint8Array) => U8
}
interface BlockCipherInfo {
  ALGORITHM: string
  /** Block size (byte) */
  BLOCK_SIZE: number
  /** Recommended key size (byte) */
  KEY_SIZE: number
  /** Minimum key size (byte) */
  MIN_KEY_SIZE: number
  /** Maximum key size (byte) */
  MAX_KEY_SIZE: number
}
```

# 非对称密钥算法

非对称密钥算法是一种使用不同密钥进行加密和解密的加密算法。非对称密钥算法通常包含 `公钥` 和 `私钥`，`公钥` 用于加密，`私钥` 用于解密。

> `mima-kit` 不支持也不打算支持 `ASN.1` 编码。如果您真的需要将密钥对导出为 `ASN.1` 编码，您可以使用 `asn1js` 这个库。
>
> 在 `Node.js` 环境中，`mima-kit` 使用本机 `crypto` 模块产生素数。而在浏览器环境中，`mima-kit` 使用 `Miller-Rabin` 算法产生素数。

## RSA

Specification: [RFC 8017](https://www.rfc-editor.org/rfc/rfc8017.html)

`RSA` 算法是一种基于大素数分解的非对称加密算法。`mima-kit` 提供的 `RSA` 算法支持大于 `256` 位的密钥。因为 `mima-kit` 内部实现的大数运算相关的函数在处理太小的数字时可能会产生错误的结果。且我并没有测试过小于 `256` 位的密钥，所以我无法保证小于 `256` 位的密钥是否能正常工作。

> 我想这个世界上应该没有人会使用这么小的密钥吧...

在 `PKCS#1` 中规定了 `RSA` 算法的 `密码学原语`，这些原语是实现规范中其他高级方案的基础。当传入 `number` 时，`rsa` 会生成一个带有 `原语` 能力的 `RSA` 密钥对。当传入 `RSAPrivateKey` 或 `RSAPublicKey` 时，会使用传入的对象作为密钥提供 `原语` 能力。

> 需要注意的是，`原语` 的 `encrypt`, `decrypt`, `sign`, `verify` 方法返回的是 `bigint` 类型，而不是 `U8` 类型。

```typescript
// Generate RSA key pair
const key = rsa(2048)
const p = UTF8('mima-kit')
const c = U8.fromBI(key.encrypt(p))
const m = U8.fromBI(key.decrypt(c))
// p === m
const s = U8.fromBI(key.sign(p))
const v = U8.fromBI(key.verify(s))
// v === m

// Using existing key pair
const k: RSAPrivateKey = {
  n: 82829320812173273978971929158153744899206558830123557057765054811547521644103n,
  e: 65537n,
  d: 2824085895826802885484730392051734790667622575612305367583022267256127084981n,
  p: 259507137283474348662341935422619692757n,
  q: 319179355447530963616684534587734455979n,
  dP: 244693883692716798906542597942783565521n,
  dQ: 232625874131426773839982556335858160883n,
  qInv: 143180457747603899913822528225463864868n,
}
const key = rsa(k)
```

### PKCS1-MGF1

`MGF1` 是 `PKCS#1` 标准中的一个函数组件，它用于生成 `OAEP` 和 `PSS` 等密码学方案中的 `Mask`。`MGF1` 需要组合 `Hash` 函数，通常 `MGF1` 不会直接使用，而是作为 `OAEP` 和 `PSS` 的一部分。

```typescript
const mgf = mgf1(sha1)
const seed = new U8()
const length = 32
const mask = mgf(seed, length)
```

```typescript
interface MGF {
  (mdfSeed: Uint8Array, maskLen: number): Uint8Array
}
```

### RSAES-PKCS1-v1_5

`RSAES-PKCS1-v1_5` 是 `PKCS#1` 标准中的一个加密方案。

```typescript
const p = UTF8('mima-kit')
const key = rsa(2048)
const cipher = pkcs1_es_1_5(key)
const c = cipher.encrypt(p)
const m = cipher.decrypt(c)
// p === m
```

### RSAES-OAEP

`RSAES-OAEP` 是 `PKCS#1` 标准中的一个加密方案。它需要组合 `Hash` 函数、`MGF` 函数和 `Label` 数据。

```typescript
const p = UTF8('mima-kit')
const key = rsa(2048)
// using SHA-256, MGF1-SHA-256, and empty label by default
const cipher = pkcs1_es_oaep(key)
// using SHA-1, MGF1-SHA-1, and empty label
const cipher = pkcs1_es_oaep(key, sha1)
// using SHA-1, MGF1-SHA-256, and label 'mima-kit'
const cipher = pkcs1_es_oaep(key, sha1, mgf1(sha256), UTF8('mima-kit'))

const c = cipher.encrypt(p)
const m = cipher.decrypt(c)
// p === m
```

### RSASSA-PKCS1-v1_5

`RSASSA-PKCS1-v1_5` 是 `PKCS#1` 标准中的一个签名方案。它需要组合 `Hash` 函数。

> `RSASSA-PKCS1-v1_5` 会用到 `Hash` 的 `OID`，`mima-kit` 中只有部份 `Hash` 函数记录了 `OID`，请务必在使用 `RSASSA-PKCS1-v1_5` 时检查 `Hash` 函数的 `OID` 是否正确。

```typescript
const p = UTF8('mima-kit')
const key = rsa(2048)
// check OID before using
sha256.OID = '2.16.840.1.101.3.4.2.1'
// using SHA-256 by default
const cipher = pkcs1_ssa_1_5(key)
// using SHA-1
const cipher = pkcs1_ssa_1_5(key, sha1)

const s = cipher.sign(p)
const v = cipher.verify(p, s)
// v === true
```

### RSASSA-PSS

`RSASSA-PSS` 是 `PKCS#1` 标准中的一个签名方案。它需要组合 `Hash` 函数、`MGF` 函数和 `Salt Length`。

```typescript
const p = UTF8('mima-kit')
const key = rsa(2048)
// using SHA-256, MGF1-SHA-256, and sha256.DIGEST_SIZE
const cipher = pkcs1_ssa_pss(key)
// using SHA-1, MGF1-SHA-1, and sha1.DIGEST_SIZE
const cipher = pkcs1_ssa_pss(key, sha1)
// using SHA-1, MGF1-SHA-256, and sha1.DIGEST_SIZE
const cipher = pkcs1_ssa_pss(key, sha1, mgf1(sha256))
// using SHA-1, MGF1-SHA-256, and 32
const cipher = pkcs1_ssa_pss(key, sha1, mgf1(sha256), 32)

const s = cipher.sign(p)
const v = cipher.verify(p, s)
// v === true
```

## ECC

Specification: [SEC 1](https://www.secg.org/sec1-v2.pdf)

`Elliptic-Curve Cryptography` 是一种基于椭圆曲线的非对称加密算法。`mima-kit` 目前仅支持基于素域 `Weierstrass` 椭圆曲线的 `ECC` 算法。

使用 `ECC` 算法前需要选择一个 `椭圆曲线`。参考 [椭圆曲线列表](#椭圆曲线列表)。

> 在 `mima-kit` 的仓库中有许多未导出到包外的 `椭圆曲线`，您可以在 `/src/core/ecParams.ts` 中找到这些 `椭圆曲线`。这些 `椭圆曲线` 大多是过于老旧且不常用的曲线，我也没有测试过是否能正常地工作。

```typescript
const ec = FpECC(secp256r1)
// Generate ECC key pair
const key = ec.genKey()
```

```typescript
interface FpECPoint {
  isInfinity?: boolean
  x: bigint
  y: bigint
}
interface ECPublicKey {
  /** Elliptic Curve Public Key */
  readonly Q: Readonly<FpECPoint>
}
interface ECPrivateKey {
  /** Elliptic Curve Private Key */
  readonly d: bigint
}
interface ECKeyPair extends ECPrivateKey, ECPublicKey {
}
```

### Point Compress

`Point Compress` 是 `ECC` 算法的公钥压缩方法，用于转换 `FpECPoint` 和 `U8`。

```typescript
const ec = FpECC(secp256r1)
const P = ec.genKey().Q
// will not compress by default
const U = ec.pointToU8(P)
// compress
const U = ec.pointToU8(P, true)
// decompress
const P = ec.U8ToPoint(U)
```

### ECDH

`Elliptic Curve Diffie-Hellman` 是 `ECC` 算法的一种密钥协商协议。在计算得到共享密钥后，通常会使用 `KDF` 从共享密钥中派生出一个或多个密钥。

```typescript
const ec = FpECC(secp256r1)
const keyA = ec.genKey()
const keyB = ec.genKey()
const secretA = ec.ecdh(keyA, keyB).x
const secretB = ec.ecdh(keyB, keyA).x
// secretA === secretB
```

### ECCDH

`Elliptic Curve Co-factor Diffie-Hellman` 是基于 `ECDH` 的一种密钥协商协议。对曲线参数中 `co-factor` 为 `1` 的曲线，`ECDH` 和 `ECCDH` 的结果是相同的。

```typescript
const ec = FpECC(w25519)
const keyA = ec.genKey()
const keyB = ec.genKey()
const secretAc = ec.eccdh(keyA, keyB).x
const secretBc = ec.eccdh(keyB, keyA).x
// secretAc === secretBc
```

### ECMQV

`Elliptic Curve Menezes-Qu-Vanstone` 是基于 `ECDH` 的一种密钥协商协议。

```typescript
const ec = FpECC(secp256r1)
const u_k1 = ec.genKey()
const u_k2 = ec.genKey()
const v_k1 = ec.genKey()
const v_k2 = ec.genKey()
const secretA = ec.ecmqv(u_k1, u_k2, v_k1, v_k2).x
const secretB = ec.ecmqv(v_k1, v_k2, u_k1, u_k2).x
// secretA === secretB
```

### ECDSA

`Elliptic Curve Digital Signature Algorithm` 是 `ECC` 算法的一种签名方案。

> 需要注意的是，`ECDSA` 的 `签名` 方法返回的是 `ECDSASignature` 类型，而不是 `U8` 类型。因为 `ECDSA` 签名的结果包含了 `r` 和 `s` 两个值。而在不同的标准下，对 `r` 和 `s` 的转换和拼接方式有可能不同。所以返回 `ECDSASignature` 可以提供更多的灵活性。

```typescript
const ec = FpECC(secp256r1)
const key = ec.genKey()
const p = UTF8('mima-kit')
// using SHA-256 by default
const cipher = ec.ecdsa()
// using SHA-1
const cipher = ec.ecdsa(sha1)
const s = cipher.sign(key, p)
const v = cipher.verify(key, p, s)
// v === true
```

```typescript
interface ECDSASignature {
  /** Temporary Public Key's x */
  r: bigint
  /** Signature Value */
  s: bigint
}
```

### ECIES

`ECIES` 是 `ECC` 算法的一种集成加密方案。`ECIES` 的配置内容比较多，请参考 `ECIESConfig` 接口。

```typescript
const ec = FpECC(secp256r1)
const key = ec.genKey()
const cipher = ec.ecies()
const p = UTF8('mima-kit')
const c = cipher.encrypt(key, p)
const m = cipher.decrypt(key, c)
// p === m
```

```typescript
interface ECIESConfig {
  /** Block Cipher Algorithm (default: AES-256-GCM) */
  cipher?: IVBlockCipher
  /** Key Hash Function (default: HMAC-SHA-256) */
  mac?: KeyHash
  /** Key Derivation Function (default: ANSI-X9.63-KDF with SHA-256) */
  kdf?: KDF
  /** Additional Data 1 (default: empty) */
  S1?: Uint8Array
  /** Additional Data 2 (default: empty) */
  S2?: Uint8Array
  /** Initialization Vector (default: Uint8Array(cipher.BLOCK_SIZE)) */
  iv?: Uint8Array
}
```

# 其他组件

## 密钥派生

密钥派生函数 (KDF) 是一种从一个密钥派生出另一个或多个密钥的算法。KDF 很少直接使用，而是作为其他算法方案的一部分。

```typescript
interface KDF {
  /**
   * @param {number} k_bit - 期望的密钥长度 / output keying material length
   * @param {Uint8Array} ikm - 输入密钥材料 / input keying material
   * @param {Uint8Array} info - 附加信息 / optional context and application specific information
   */
  (k_bit: number, ikm: Uint8Array, info?: Uint8Array): U8
}
```

### X9.63KDF

`X9.63KDF` 是 `ANSI-X9.63` 标准中的一个密钥派生函数。`X9.63KDF` 需要组合 `Hash` 函数。

```typescript
const kdf = x963kdf(sha256)
```

### HKDF

`HKDF` 是 `RFC 5869` 标准中的一个密钥派生函数。`HKDF` 需要组合 `KeyHash` 函数和一个可选的 `salt`

```typescript
const mac = hmac(sha256)
const kdf = hkdf(mac)
```

### PBKDF2

`PBKDF2` 是 `PKCS#5` 标准中的一个密钥派生函数。`PBKDF2` 需要组合 `KeyHash` 函数，指定 `iteration` 次数和一个可选的 `salt`。

```typescript
const mac = hmac(sha256)
const kdf = pbkdf2(mac, 1000)
```

## 椭圆曲线列表

`mima-kit` 并没有导出所有的 `椭圆曲线`，但是您可以在 `/src/core/ecParams.ts` 中找到所有的 `椭圆曲线`。

### `Weierstrass` 曲线

> 在表格之外，`sm2p256v1` 也是导出的 `Weierstrass` 曲线。它适用于所有 `ECC` 算法，但是它常用于 `SM2` 算法，所以不写入表格之中。

| SEC         | NIST     | X9.63        | RFC 5639  |
|-------------|----------|--------------|-----------|
| -           | `w25519` | -            | -         |
| -           | `w448`   | -            | -         |
| `secp192k1` | -        | -            | -         |
| `secp192r1` | `p192`   | `prime192v1` | -         |
| `secp224k1` | -        | -            | -         |
| `secp224r1` | `p224`   | -            | -         |
| `secp256r1` | `p256`   | `prime256v1` | -         |
| `secp256k1` | -        | -            | -         |
| `secp384r1` | `p384`   | -            | -         |
| `secp521r1` | `p521`   | -            | -         |
| -           | -        | -            | `bp192r1` |
| -           | -        | -            | `bp224r1` |
| -           | -        | -            | `bp256r1` |
| -           | -        | -            | `bp320r1` |
| -           | -        | -            | `bp384r1` |
| -           | -        | -            | `bp512r1` |

# License

[MIT](./LICENSE) License © 2023-PRESENT [RSoraM](https://github.com/RSoraM)

<!-- Badges -->

[npm-version-src]: https://img.shields.io/npm/v/mima-kit?style=for-the-badge
[npm-version-href]: https://npmjs.com/package/mima-kit

[npm-downloads-src]: https://img.shields.io/npm/dm/mima-kit?style=for-the-badge
[npm-downloads-href]: https://npmjs.com/package/mima-kit

[bundle-src]: https://img.shields.io/bundlephobia/minzip/mima-kit?style=for-the-badge&label=minzip
[bundle-href]: https://bundlephobia.com/result?p=mima-kit

[license-src]: https://img.shields.io/github/license/RSoraM/mima-kit.svg?style=for-the-badge
[license-href]: https://github.com/RSoraM/mima-kit/blob/main/LICENSE

[jsdocs-src]: https://img.shields.io/badge/jsDocs-reference-pink?style=for-the-badge
[jsdocs-href]: https://www.jsdocs.io/package/mima-kit
