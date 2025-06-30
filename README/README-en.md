<div align="center">
<!-- LOGO -->
<a href="https://github.com/RSoraM/mima-kit"><img src="./logo.svg" alt="logo" width="150"/></a>

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

`mima-kit` is a cryptographic suite implemented in `TypeScript`. The goal is to provide an easy-to-use cryptographic library. The name `mima` comes from the Chinese word `密码`, which means `password` or `cipher`. `mima-kit` is still in the early stages of development, and the API may change.

Try it -> https://rsoram.github.io/mima-live/

> Documents in other languages may be outdated. Please refer to the Simplified Chinese document for details.

## Install

```bash
npm install mima-kit
```

# Table of Contents

<!-- 字符编码 -->
<a href="#character-codec">
<!-- 字符编码 -->

<!-- 散列算法 -->
<details>
<summary>
<a href="#hash-algorithm">Hash Algorithm</a>
</summary>
<ul>
  <li><a href="#secure-hash-algorithm">Secure Hash Algorithm</a></li>
  <ul>
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
  <li><a href="#keyed-hash-algorithm">Keyed Hash Algorithm</a></li>
  <ul>
    <li><a href="#hmac">HMAC</a></li>
    <li><a href="#totp">TOTP</a></li>
    <li><a href="#kmac">KMAC</a></li>
  </ul>
  <li><a href="#wrap-your-hash-algorithm">Wrap Your Hash Algorithm</a></li>
</ul>
</details>
<!-- 散列算法 -->

<!-- 对称密钥算法 -->
<details>
<summary>
<a href="#symmetric-key-algorithm">Symmetric Key Algorithm</a>
</summary>
<ul>
  <li><a href="#block-cipher">Block Cipher</a></li>
  <ul>
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
    <li><a href="#xxtea">XXTEA</a></li>
  </ul>
  <li><a href="#padding-mode">Padding Mode</a></li>
  <li><a href="#operation-mode">Operation Mode</a></li>
  <li><a href="#stream-cipher">Stream Cipher</a></li>
  <ul>
    <li><a href="#zuc">ZUC</a></li>
    <li><a href="#arc4">ARC4</a></li>
    <li><a href="#salsa20">Salsa20</a></li>
    <li><a href="#rabbit">Rabbit</a></li>
  </ul>
  <li><a href="#wrap-your-symmetric-key-algorithm">Wrap Your Symmetric Key Algorithm</a></li>
</ul>
</details>
<!-- 对称密钥算法 -->

<!-- 非对称密钥算法 -->
<details>
<summary>
<a href="#asymmetric-key-algorithm">Asymmetric Key Algorithm</a>
</summary>
<ul>
  <li><a href="#rsa">RSA</a></li>
  <ul>
    <li><a href="#pkcs1-mgf1">PKCS1-MGF1</a></li>
    <li><a href="#rsaes-pkcs1-v1_5">RSAES-PKCS-v1_5</a></li>
    <li><a href="#rsaes-oaep">RSAES-OAEP</a></li>
    <li><a href="#rsassa-pkcs1-v1_5">RSASSA-PKCS-v1_5</a></li>
    <li><a href="#rsassa-pss">RSASSA-PSS</a></li>
  </ul>
  <li><a href="#ecc">ECC</a></li>
  <ul>
    <li><a href="#point-compress">Point Compress</a></li>
    <li><a href="#ecdh">ECDH</a></li>
    <li><a href="#eccdh">ECCDH</a></li>
    <li><a href="#ecmqv">ECMQV</a></li>
    <li><a href="#ecdsa">ECDSA</a></li>
    <li><a href="#ecies">ECIES</a></li>
  </ul>
  <li><a href="#sm2">SM2</a></li>
  <ul>
    <li><a href="#sm2-identifier">SM2-Identifier</a></li>
    <li><a href="#sm2-dh">SM2-DH</a></li>
    <li><a href="#sm2-dsa">SM2-DSA</a></li>
    <li><a href="#sm2-es">SM2-ES</a></li>
  </ul>
  <li><a href="#x25519">x25519</a></li>
  <ul>
    <li><a href="#x25519-dh">x25519-DH</a></li>
  </ul>
</ul>
</details>
<!-- 非对称密钥算法 -->

<!-- 其他组件 -->
<details>
<summary>
<a href="#other-components">Other Components</a>
</summary>
<ul>
  <li><a href="#key-derivation-function">Key Derivation Function</a></li>
  <ul>
    <li><a href="#x963kdf">X9.63KDF</a></li>
    <li><a href="#hkdf">HKDF</a></li>
    <li><a href="#pbkdf2">PBKDF2</a></li>
  </ul>
  <li><a href="#elliptic-curve-list">Elliptic Curve List</a></li>
</ul>
</details>
<!-- 其他组件 -->

# Character Codec

- `UTF8` UTF-8 Codec
- `HEX` Hexadecimal Codec
- `B32` Base32 Codec `RFC 4648` `RFC 4648-HEX` `Crockford`
- `B64` Base64 Codec
- `B64URL` Base64url Codec

Data in cryptography is usually binary data, which is usually represented by `Uint8Array` in `JS`. The conversion between `string` and `Uint8Array` requires `Character Codec`.

> If you are using an environment such as `Node.js` that supports `Buffer`, you can directly use `Buffer` as `codec`. If you are using a browser environment, you can use the `codec` provided by `mima-kit`.

The `codec` provided by `mima-kit` will automatically determine the type of the input data.

- Inputting data of type `Uint8Array` will convert it to `string`
- Inputting data of type `string` will convert it to `Uint8Array`

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

In the above code, you may have noticed the `U8` type. Most functions in `mima-kit` return the `U8` type, which is a subclass of `Uint8Array` and is designed to provide some additional methods. In most cases, you can safely pass the `U8` type to other functions that use `Uint8Array`.

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

There exist several de facto standards and variants of `B32` encoding, `mima-kit` provides three variants of `B32` codec, and `B32` is not padded by default.

```typescript
interface B32Params {
  variant?: 'rfc4648' | 'rfc4648-hex' | 'crockford'
  padding?: boolean
}
interface B32Codec extends Codec {
  /** Create a base32 codec */
  (params: B32Params): Codec
}

// RFC 4648 Base32 with no padding by default
B32(UTF8('cat, 猫, 🐱')) // MNQXILBA46GKWLBA6CPZBMI

// using RFC 4648 Base32-hex with padding
const B32HP = B32({ variant: 'rfc4648-hex', padding: true })
B32HP(UTF8('cat, 猫, 🐱')) // CDGN8B10SU6AMB10U2FP1C8=
```

# Hash Algorithm

`Hash Algorithm` is an algorithm that maps arbitrary-length data to fixed-length data. This definition is very broad, but in cryptography, we usually talk about `Secure Hash Algorithm`. `Keyed Hash Algorithm` will uses an additional key to produce a more secure hash value.

## Secure Hash Algorithm

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

cshake128(256, n, s)(m).to(HEX)
cshake256(512, n, s)(m).to(HEX)
```

### TupleHash

Specification: [NIST SP 800-185](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf)

```typescript
// optional customization string
const s = UTF8('custom')
const m = ['mima', '-', 'kit'].map(v => UTF8(v))
tuplehash128(256, s)(m).to(HEX)
tuplehash256(512, s)(m).to(HEX)
tuplehash128XOF(256, s)(m).to(HEX)
tuplehash256XOF(512, s)(m).to(HEX)
```

### ParallelHash

Specification: [NIST SP 800-185](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf)

> Note: The `ParallelHash` algorithm provided by `mima-kit` does not perform true parallel computation. It merely divides the input into blocks, computes them separately, and then concatenates the results.

```typescript
// optional customization string
const s = UTF8('custom')
const m = UTF8('mima-kit')
const blockSize = 1024
parallelhash128(blockSize, 256, s)(m).to(HEX)
parallelhash256(blockSize, 512, s)(m).to(HEX)
parallelhash128XOF(blockSize, 256, s)(m).to(HEX)
parallelhash256XOF(blockSize, 512, s)(m).to(HEX)
```

### TurboSHAKE

Specification: [TurboSHAKE](https://keccak.team/files/TurboSHAKE.pdf)

```typescript
// optional Domain Separator
// range: 0x01 ~ 0x7F, default: 0x1F
const D = 0x0B
const m = UTF8('mima-kit')
turboshake128(256, D)(m).to(HEX)
turboshake256(512, D)(m).to(HEX)
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

## Keyed Hash Algorithm

### HMAC

Specification: [RFC 2104](https://www.rfc-editor.org/rfc/rfc2104.txt)

> The key length parameter `k_size` defaults to the hash algorithm's `DIGEST_SIZE`. This parameter does not affect the result of this function, but is used by other functions, such as `ECIES`.

```typescript
const key = UTF8('password')
const m = UTF8('mima-kit')
// HMAC-SM3
hmac(sm3)(key, m).to(HEX)
// HMAC-SHA1-80 with 80-bit digest and 160-bit key
hmac(sha1, 80)(key, m).to(HEX)
// HMAC-SHA1-160 with 160-bit digest and 80-bit key
hmac(sha1, 160, 80)(key, m).to(HEX)
```

### TOTP

Specification: [RFC 6238](https://www.rfc-editor.org/rfc/rfc6238.txt)

> `TOTP` is an extension of `HMAC` that uses timestamps as counters to output one-time passwords with shared secret.

```typescript
const otp = totp(B32('4B7X5MEKEFIJMWWVBQMMCLY6JI3YOC7Y')) // '000000'

const totp_256 = totp({
  mac: hmac(sha256),
  step: 60_000, // 1 minute
  digits: 8, // 8 digits
})
const otp = totp_256(B32('4B7X5MEKEFIJMWWVBQMMCLY6JI3YOC7Y')) // '00000000'
```

```typescript
interface TOTPParams {
  /**
   * Keyed Hashing Algorithm (default: HMAC-SHA1)
   */
  mac?: KeyHash
  /**
   * Current timestamp (default: Date.now() milliseconds)
   *
   * When this parameter is specified, the current timestamp will not be obtained from `Date.now()`.
   */
  current?: number
  /**
   * Epoch timestamp (default: 0 milliseconds)
   */
  epoch?: number
  /**
   * Time step (default: 30000 milliseconds)
   */
  step?: number
  /**
   * `counter = (cuttent_time - epoch_time) / step`
   *
   * When this parameter is specified, the counter will not be calculated from the current timestamp.
   */
  counter?: number | bigint | Uint8Array
  /**
   * Number of digits in the returned OTP (default: 6)
   */
  digits?: number
}
```

### KMAC

Specification: [NIST SP 800-185](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf)

```typescript
// customization string
const s = UTF8('custom')
const key = UTF8('password')
const m = UTF8('mima-kit')

kmac128(256, s)(key, m).to(HEX)
kmac256(512, s)(key, m).to(HEX)
kmac128XOF(256, s)(key, m).to(HEX)
kmac256XOF(512, s)(key, m).to(HEX)
```

## Wrap Your Hash Algorithm

If you have implemented a great and mysterious hash algorithm, you can use the `createHash` function to wrap it into a callable `Hash` object. Then you can use your algorithm with other advanced algorithms in `mima-kit` just like others.

> If you are familiar with `JS`, you will find that the essence of `createHash` is just a wrapper of `Object.assign`. You can completely use `Object.assign` instead of `createHash`, but `createHash` will provide you with some type hints to avoid annoying spelling errors.

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
  /** 算法名称 / Algorithm name */
  ALGORITHM: string
  /** 分块大小 / Block size (byte) */
  BLOCK_SIZE: number
  /** 摘要大小 / Digest size (byte) */
  DIGEST_SIZE: number
  OID?: string
}
```

# Symmetric Key Algorithm

`Symmetric Key Algorithm` is an encryption algorithm that uses the same key for `encryption` and `decryption`. It can be divided into `Block Cipher` and `Stream Cipher`. `Block Cipher` usually need to be used in combination with `Padding Mode` and `Operation Mode`. `Block Cipher` can be converted to `Stream Cipher` by using a specific `Operation Mode` and `NO_PAD`.

> You can find more usage examples in `/test/cipher.test.ts`.

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

## Block Cipher

Using a `Block Cipher` alone does not make much sense because it can only encrypt and decrypt a single block of data.

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

`ARC5` is a parameterized algorithm that accepts keys of length `0 < k.byteLength < 256`. The parameterized algorithm is labeled `ARC5-w/r`, where `w` is the length of the workword in bits and `r` is the number of rounds.

```typescript
// Recommended parameterization configuration
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

You can pass a parameter representing the number of rounds to the `TEA` algorithm. The number of rounds for the `TEA` algorithm can be any positive integer, with a default of `32`.

```typescript
let k: Uint8Array
let m: Uint8Array
let c: Uint8Array

tea(32)(k).encrypt(m) // c
tea(32)(k).decrypt(c) // m
```

### XTEA

Specification: [XTEA](https://tayloredge.com/reference/Mathematics/TEA-XTEA.pdf)

You can pass a parameter representing the number of rounds to the `TEA` algorithm. The number of rounds for the `TEA` algorithm can be any positive integer, with a default of `32`.

```typescript
let k: Uint8Array
let m: Uint8Array
let c: Uint8Array

xtea(32)(k).encrypt(m) // c
xtea(32)(k).decrypt(c) // m
```

### XXTEA

Specification: [XXTEA](https://www.cix.co.uk/~klockstone/xxtea.pdf)

`XXTEA` is natively designed to encrypt any number of data blocks, where each data block is `4` byte.

```typescript
let k: Uint8Array
let m: Uint8Array
let c: Uint8Array

// using default config
xxtea()(k).encrypt(m) // c
xxtea()(k).decrypt(c) // m
```

By default, `XXTEA` performs `6 + 52/n` rounds of encryption on data, where `n` is the number of data blocks. You can set a fixed number of rounds with the `round` parameter.

```typescript
const config: XXTEAConfig = {
  round: 64,
}
xxtea(config)(k).encrypt(m) // c
xxtea(config)(k).decrypt(c) // m
```

In general use, data usually needs to be padded to ensure that the byte length of the data is a multiple of `4`. You can set the padding mode via the `padding` parameter. By default, `XXTEA` uses the `PKCS7` padding mode. If you determine that the byte length of the data is a multiple of `4`, you can skip padding by setting `padding` to `NO_PAD`.

```typescript
// using X923_PAD
const config: XXTEAConfig = {
  padding: X923_PAD,
}
// skip padding
const config: XXTEAConfig = {
  padding: NO_PAD,
}
xxtea(config)(k).encrypt(m) // c
xxtea(config)(k).decrypt(c) // m
```

If you want to use `XXTEA` like any other block cipher, for example in `GCM` mode

1. Set the `padding` to `NO_PAD` and let the `Operation Mode` handle the padding.
2. Set `BLOCK_SIZE` for `Operation Mode`
3. Since the data block size of `XXTEA` is `4` byte, please ensure that `BLOCK_SIZE` is a multiple of `4` and greater than `8`

> Note: This is not the standard usage of `XXTEA` and lacks relevant security analysis.

```typescript
const config: XXTEAConfig = {
  padding: NO_PAD,
  BLOCK_SIZE: 16,
}
const cipher = xxtea(config)

const k = HEX('')
const iv = HEX('')
const m = HEX('')
const c = HEX('')

const CIPHER = gcm(cipher)(k, iv)
CIPHER.encrypt(m) // c
CIPHER.decrypt(c) // m
```

```typescript
interface XXTEAConfig {
  /**
   * 分组大小 / Block size (default: 16)
   *
   * `XXTEA` 本身设计用于加密任意数量的数据块。单独使用 `XXTEA` 时，该选项不起作用。
   * 但是，如果需要将 `XXTEA` 用作分组密码和 `工作模式` 一起使用，则可以通过此选项设置分组大小。
   *
   * 注意: 这不是 `XXTEA` 的标准用法且缺乏相关的安全分析。
   *
   * `XXTEA` is natively designed to encrypt arbitrary amounts of data blocks.
   * When used alone, this option does not take effect.
   * However, if you need to use `XXTEA` as a block cipher and use it with `Operation Mode`,
   * you can set the `BLOCK_SIZE` through this option.
   *
   * Note: This is not the standard usage of `XXTEA` and lacks relevant security analysis.
   */
  BLOCK_SIZE?: number
  /**
   * 填充方式 / Padding method (default: PKCS7)
   *
   * 如果要像其他分组密码一样使用 `XXTEA`，例如使用 `CBC` 模式，
   * 应该将 `padding` 设置为 `NO_PAD` 并让 `工作模式` 处理填充。
   *
   * If you want to use `XXTEA` like other block ciphers, such as with `CBC` mode,
   * you should set the `padding` to `NO_PAD` and let the `Operation Mode` handle the padding.
   */
  padding?: Padding
  /**
   * 轮数 / Rounds (default: undefined)
   *
   * `XXTEA` 的轮数可以通过这个选项设置，如果不设置则使用默认的轮数计算方式。
   *
   * The rounds of `XXTEA` can be set through this option,
   * if not set, the default round calculation method will be used.
   */
  round?: number
}
```

## Padding Mode

- `PKCS7_PAD` PKCS#7 Padding
- `X923_PAD` ANSI X9.23 Padding
- `ISO7816_PAD` ISO/IEC 7816-4 Padding
- `ZERO_PAD` Zero Padding
- `NO_PAD` None Padding

Using `Padding` alone doesn't make much sense, as it just pads or unpads the data.

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
   * 添加填充 / Add padding
   * @param {Uint8Array} M - Message
   * @param {number} BLOCK_SIZE - Block size
   */
  (M: Uint8Array, BLOCK_SIZE: number): U8
  /**
   * 移除填充 / remove padding
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

> `NO_PAD` mode does not perform any operations on the data. This mode is only used to convert a `Block Cipher` to a `Stream Cipher`.

```typescript
// run SM4-OFB in stream mode
const ofb_sm4 = ofb(sm4, NO_PAD)
```

## Operation Mode

- `ecb` Electronic Codebook
- `cbc` Cipher Block Chaining
- `pcbc` Progressive Chaining Block Cipher
- `cfb` Cipher Feedback
- `ofb` Output Feedback
- `ctr` Counter Mode
- `gcm` Galois/Counter Mode

`mima-kit` completely decouples `Operation Mode` from `Block Cipher`, which means you can use any `Block Cipher` with any `Operation Mode`.

### ECB

Electronic Codebook (ECB) is the simplest block mode. `ECB` mode divides the plaintext into fixed-length data blocks, and then encrypts each data block.

- `ECB` mode does not require `iv`.
- `iv` passed to `ECB` mode will be ignored.

```typescript
const k = HEX('')
const m = HEX('')
const c = HEX('')

const CIPHER = ecb(sm4)(k)
CIPHER.encrypt(m) // c
CIPHER.decrypt(c) // m
```

### CBC

Cipher Block Chaining (CBC) is the most commonly used block mode. In `CBC` mode, each plaintext block is XORed with the previous ciphertext block before being encrypted.

- `CBC` mode requires an `iv`.
- The length of the `iv` is the same as the `BLOCK_SIZE` of the encryption algorithm.

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

Cipher Feedback (CFB) mode converts block ciphers into stream ciphers. `CFB` mode generates an encryption data stream by encrypting the previous ciphertext block, then XORs the data stream with the plaintext block to obtain the ciphertext block.

- `CFB` mode requires an `iv`.
- The length of the `iv` is the same as the `BLOCK_SIZE` of the encryption algorithm.
- `CFB` and `NO_PAD` can convert a `Block Cipher` to a `Stream Cipher`.

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

OFB mode converts block ciphers into stream ciphers. `OFB` mode generates an encryption data stream by encrypting the `iv`, then XORs the data stream with the plaintext block to obtain the ciphertext block.

- `OFB` mode requires an `iv`.
- The length of the `iv` is the same as the `BLOCK_SIZE` of the encryption algorithm.
- `OFB` and `NO_PAD` can convert a `Block Cipher` to a `Stream Cipher`.

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

Counter Mode (CTR) converts block ciphers into stream ciphers. `CTR` mode generates an encryption data stream by combining the `iv` with a counter to generate a unique `counter block`, encrypting the `counter block` to obtain the encryption data stream, and then XORing the data stream with the plaintext block to obtain the ciphertext block.

- `CTR` mode requires an `iv`.
- The length of the `iv` is the same as the `BLOCK_SIZE` of the encryption algorithm.
- `CTR` and `NO_PAD` can convert a `Block Cipher` to a `Stream Cipher`.

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

Galois/Counter Mode (GCM) converts block ciphers into stream ciphers. `GCM` mode can be seen as a variant of `CTR` mode, with the addition of `authentication` functionality.

- `GCM` Requires an `iv`.
- Length of `iv` is not limited, but it is recommended to use a `96` bit length `iv`.
- `GCM` and `NO_PAD` can convert a `Block Cipher` to a `Stream Cipher`.
- `AUTH_TAG` generated by the `GCM` mode is a `HEX` encoded string, and the `AUTH_TAG` length is determined by the `AUTH_TAG_SIZE` parameter. The maximum length of the `AUTH_TAG` is `128` bits. Setting any length will not affect the operation of the program, but it is generally recommended to use `128`, `120`, `112`, `104`, `96` bits, and for some applications, `64`, `32` bits can also be used.

The `GCM` mode implemented by `mima-kit` does not perform table lookup optimization, so the performance may be slower.

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

## Stream Cipher

Typically, `stream cipher` do not require complex configurations and generally only need a `key` and an `iv`.

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

`ZUC` is a stream cipher algorithm specified in the `3GPP` standard. It includes the confidentiality algorithm `128-EEA3` and the integrity algorithm `128-EIA3`. Since the `ZUC` algorithm is primarily used in mobile communications, its function interface differs from other stream cipher algorithms.

See `/test/cipher.test.ts` for more usage examples.

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
// 128-EEA3 encrypt message
eea3(params) // c
// 128-EIA3 generate mac
eia3(params) // mac
// 128-EEA3 decrypt message
params.M = c
eea3(params) // m
```

### ARC4

Specification: [ARC4](https://en.wikipedia.org/wiki/RC4)

The `ARC4` algorithm can accept keys with lengths of `0 < k.byteLength < 256`, and the `ARC4` algorithm does not require an `iv`.

```typescript
const k = HEX('')
const cipher = arc4(k)
const c = cipher.encrypt(UTF8('mima-kit'))
const m = cipher.decrypt(c)
```

### Salsa20

Specification: [Salsa20](https://cr.yp.to/snuffle/spec.pdf)

The `Salsa20` algorithm can accept keys of length `16` or `32` byte and an `iv` of `8` byte.

```typescript
const k = HEX('')
const iv = HEX('')
const cipher = salsa20(k, iv)
const c = cipher.encrypt(UTF8('mima-kit'))
const m = cipher.decrypt(c)
```

### Rabbit

Specification: [Rabbit](https://www.rfc-editor.org/rfc/rfc4503.txt)

The `Rabbit` algorithm can accept a key of length `16` byte. For the `iv`, the `Rabbit` algorithm can accept an `iv` of length `0` or `8` byte. When the `iv` length is `0` byte, the `Rabbit` algorithm will skip the `iv Setup` step.

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

## Wrap Your Symmetric Key Algorithm

Just like [`Wrap Your Hash Algorithm`](#wrap-your-hash-algorithm), you can use the `createCipher` function to wrap your `Symmetric Key Algorithm` into a callable `Cipher` object. Then you can use your algorithm with other advanced algorithms in `mima-kit` just like using others.

> If you are familiar with `JS`, you will find that the essence of `createCipher` is just a wrapper of `Object.assign`. You can completely use `Object.assign` instead of `createCipher`, but `createCipher` will provide you with some type hints to avoid annoying spelling errors.

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
  /** 分组大小 / Block size (byte) */
  BLOCK_SIZE: number
  /** 推荐的密钥大小 / Recommended key size (byte) */
  KEY_SIZE: number
  /** 最小密钥大小 / Minimum key size (byte) */
  MIN_KEY_SIZE: number
  /** 最大密钥大小 / Maximum key size (byte) */
  MAX_KEY_SIZE: number
}
```

# Asymmetric Key Algorithm

`Asymmetric Key Algorithm` is an encryption algorithm that uses different keys for `encryption` and `decryption`. `Asymmetric Key Algorithm` usually contains a `Public Key` and a `Private Key`, where `Public Key` is used for encryption and `Private Key` is used for decryption.

> `mima-kit` does not support and is not intended to support the `ASN.1` encoding. If you really need to export key pairs as `ASN.1` encoding, you can use the `asn1js` library.
>
> In the `Node.js` environment, `mima-kit` uses the native `crypto` module to generate prime numbers. In the browser environment, `mima-kit` uses the `Miller-Rabin` algorithm to generate prime numbers.

## RSA

Specification: [RFC 8017](https://www.rfc-editor.org/rfc/rfc8017.html)

`RSA` algorithm is an asymmetric encryption algorithm based on large prime number decomposition. `mima-kit` provides `RSA` algorithm that supports keys larger than `256` bits. Because `mima-kit` internally implements large number operations related functions that may produce incorrect results when processing too small numbers. And I have not tested keys smaller than `256` bits, so I cannot guarantee whether keys smaller than `256` bits can work properly.

> I don't think anyone in this world would use such a short key...

The `Cryptographic Primitive` for the `RSA` algorithm are specified in `PKCS#1`, which is the basis for implementing other advanced schemes in the specification. When `number` is passed, `rsa` generates an `RSA` key pair with `Primitive` capabilities. When `RSAPrivateKey` or `RSAPublicKey` is passed, `Primitive` capabilities are provided using the passed object as the key.

> `encrypt`, `decrypt`, `sign`, `verify` methods of `Primitive` return `bigint` instead of `U8`.

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

`MGF1` is a function component in the `PKCS#1`, which is used to generate `Mask` in cryptographic schemes such as `OAEP` and `PSS`. `MGF1` needs to be combined with the `Hash` function. Usually `MGF1` is not used directly, but as part of `OAEP` and `PSS`.

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

`RSAES-PKCS1-v1_5` is an encryption scheme in the `PKCS#1`.

```typescript
const p = UTF8('mima-kit')
const key = rsa(2048)
const cipher = pkcs1_es_1_5(key)
const c = cipher.encrypt(p)
const m = cipher.decrypt(c)
// p === m
```

### RSAES-OAEP

`RSAES-OAEP` is an encryption scheme in the `PKCS#1`. It needs to be combined with `Hash` function, `MGF` function and `Label` data.

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

`RSASSA-PKCS1-v1_5` is a signature scheme in the `PKCS#1`. It needs to be combined with `Hash` functions.

> `RSASSA-PKCS1-v1_5` will use the `OID` of `Hash`. Only some `Hash` functions in `mima-kit` record the `OID`. Please be sure to check whether the `OID` of the `Hash` function is correct when using `RSASSA-PKCS1-v1_5`.

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

`RSASSA-PSS` is a signature scheme in the `PKCS#1`. It needs to be combined with `Hash` function, `MGF` function and `Salt Length`.

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

`Elliptic-Curve Cryptography` is an asymmetric encryption algorithm based on elliptic curves. `mima-kit` currently only supports the `ECC` algorithm based on the prime field `Weierstrass` and `Montgomery` elliptic curve.

You need to select an `Elliptic Curve` before using the `ECC` algorithm. See [Elliptic Curve List](#elliptic-curve-list).

> There are many elliptic curve in the `mima-kit` repository that are not exported outside the package. You can find these `Elliptic Curve` in `/src/core/ecParams.ts`. Most of these `Elliptic Curve` are too old and uncommon curves, and I haven't tested whether they work properly.

```typescript
const ec = FpECC(secp256r1)
// Generate ECC key pair: ECKeyPair<U8>
const key = ec.gen()
const key = ec.gen('key_pair')
// Generate ECC private key: ECPrivateKey<U8>
const s_key = ec.gen('private_key')
// Generate ECC public key: ECKeypair<U8>
const p_key = ec.gen('public_key', s_key)
```

```typescript
/**
 * 伪射坐标表示的椭圆曲线的点
 *
 * Affine Coordinates of Elliptic Curve Point
 */
interface FpECPoint<T = bigint | Uint8Array> {
  isInfinity: boolean
  x: T
  y: T
}
interface ECPublicKey<T = bigint | Uint8Array> {
  /** 椭圆曲线公钥 / Elliptic Curve Public Key */
  readonly Q: Readonly<FpECPoint<T>>
}
interface ECPrivateKey<T = bigint | Uint8Array> {
  /** 椭圆曲线私钥 / Elliptic Curve Private Key */
  readonly d: T
}
/** 椭圆曲线密钥对 / Elliptic Curve Key Pair */
interface ECKeyPair<T = bigint | Uint8Array> extends ECPrivateKey<T>, ECPublicKey<T> {
}
```

### Point Compress

`Point Compress` is a public key compression method of the `ECC` algorithm, used to convert `FpECPoint` and `U8`.

```typescript
const ec = FpECC(secp256r1)
const { PointToU8, U8ToPoint } = ec.utils
const P = ec.gen().Q
// will not compress by default
const U = pointToU8(P)
// compress
const U = pointToU8(P, true)
// decompress: FpECPoint<U8>
const P = U8ToPoint(U)
```

### ECDH

`Elliptic Curve Diffie-Hellman` is a key agreement protocol for the `ECC` algorithm. After the shared key is calculated, a `KDF` is usually used to derive one or more keys from the shared key.

> The result of `ECDH` is an `FpECPoint<U8>`, which is typically used with `x` as key material for a `KDF`.

```typescript
const ec = FpECC(secp256r1)
const keyA = ec.gen()
const keyB = ec.gen()
const secretA = ec.dh(keyA, keyB).x
const secretB = ec.dh(keyB, keyA).x
// secretA === secretB
```

### ECCDH

`Elliptic Curve Co-factor Diffie-Hellman` is a key agreement protocol based on `ECDH`. For curves with `co-factor` equal to `1`, the results of `ECDH` and `ECCDH` are the same.

> The result of `ECDH` is an `FpECPoint<U8>`, which is typically used with `x` as key material for a `KDF`.

```typescript
const ec = FpECC(w25519)
const keyA = ec.gen()
const keyB = ec.gen()
const secretAc = ec.cdh(keyA, keyB).x
const secretBc = ec.cdh(keyB, keyA).x
// secretAc === secretBc
```

### ECMQV

`Elliptic Curve Menezes-Qu-Vanstone` is a key agreement protocol based on `ECDH`.

> The result of `ECDH` is an `FpECPoint<U8>`, which is typically used with `x` as key material for a `KDF`.

```typescript
const ec = FpECC(secp256r1)
const u_k1 = ec.gen()
const u_k2 = ec.gen()
const v_k1 = ec.gen()
const v_k2 = ec.gen()
const secretA = ec.mqv(u_k1, u_k2, v_k1, v_k2).x
const secretB = ec.mqv(v_k1, v_k2, u_k1, u_k2).x
// secretA === secretB
```

### ECDSA

`Elliptic Curve Digital Signature Algorithm` is a signature scheme for the `ECC` algorithm.

> The `signature` method of `ECDSA` returns the `ECDSASignature` type instead of the `U8` type. Because the result of `ECDSA` signature contains two values of `r` and `s`. Under different standards, the conversion and concatenation methods of `r` and `s` may be different. Therefore, returning `ECDSASignature` can provide more flexibility.

```typescript
const ec = FpECC(secp256r1)
const key = ec.gen()
const p = UTF8('mima-kit')
// using SHA-256 by default
const signer = ec.dsa()
// using SHA-1
const signer = ec.dsa(sha1)
// sign: ECDSASignature<U8>
const s = cipher.sign(key, p)
const v = cipher.verify(key, p, s)
// v === true
```

```typescript
interface ECDSASignature<T = bigint | Uint8Array> {
  /** 临时公钥 / Temporary Public Key */
  r: T
  /** 签名值 / Signature Value */
  s: T
}
```

### ECIES

`ECIES` is an integrated encryption scheme for the `ECC` algorithm. `ECIES` has a lot of configuration content, please refer to the `ECIESConfig` interface.

> The result of `ECIES` is an `ECIESCiphertext` type, which contains the `temporary public key`, the `ciphertext` and the `check value`.

```typescript
const ec = FpECC(secp256r1)
const key = ec.gen()
const cipher = ec.ies()
const p = UTF8('mima-kit')
const c = cipher.encrypt(key, p)
const m = cipher.decrypt(key, c)
// p === m
```

```typescript
interface ECIESConfig {
  /** 分组密码算法 / Block Cipher Algorithm (default: AES-256-GCM) */
  cipher?: IVBlockCipher
  /** 密钥哈希函数 / Key Hash Function (default: HMAC-SHA-256) */
  mac?: KeyHash
  /** 密钥派生函数 / Key Derivation Function (default: ANSI-X9.63-KDF with SHA-256) */
  kdf?: KDF
  /** 附加数据1 / Additional Data 1 (default: empty) */
  S1?: Uint8Array
  /** 附加数据2 / Additional Data 2 (default: empty) */
  S2?: Uint8Array
  /** 初始化向量 / Initialization Vector (default: Uint8Array(cipher.BLOCK_SIZE)) */
  iv?: Uint8Array
}
interface ECIESCiphertext {
  /** 临时公钥 / Temporary Public Key */
  R: ECPublicKey
  /** 密文 / Ciphertext */
  C: Uint8Array
  /** 校验值 / Check Value */
  D: Uint8Array
}
```

## SM2

Specification: [GB/T 35276-2017](https://www.oscca.gov.cn/sca/xxgk/2010-12/17/1002386/files/b791a9f908bb4803875ab6aeeb7b4e03.pdf)

The `SM2` algorithm is an asymmetric encryption algorithm based on the `elliptic curve` released by the State Cryptography Administration of China. In theory, the `SM2` algorithm can use any `elliptic curve`, but in practice, the `SM2` algorithm usually uses the `sm2p256v1` curve, so `mima-kit` uses the `sm2p256v1` curve as the default curve for the `SM2` algorithm.

```typescript
const sm2ec = sm2()
// Generate SM2 key pair
const key = sm2ec.gen()
const key = sm2ec.gen('key_pair')
// Generate SM2 private key
const s_key = sm2ec.gen('private_key')
// Generate SM2 public key
const p_key = sm2ec.gen('public_key', s_key)
```

### SM2-Identifier

`SM2` adds the concept of `Distinguishing Identifier` to `ECC`. `Distinguishing Identifier` uses user ID, public key and some parameters of the curve to unambiguously identify the identity information of an entity.

```typescript
const sm2ec = sm2()
const ID = UTF8('alice@rabbit.panic')
const KA = sm2ec.gen()
const ZA = sm2ec.di(ID, KA)
```

```typescript
interface SM2DI {
  /**
   * @param {Uint8Array} id - 用户标识 / User Identity
   * @param {ECPublicKey} key - 公钥 / Public Key
   * @param {Hash} hash - 哈希算法 / Hash Algorithm (default: SM3)
   */
  (id: Uint8Array, key: ECPublicKey, hash?: Hash): U8
}
```

### SM2-DH

Key agreement protocol for the `SM2` algorithm. Unlike the standard, `SM2-DH` from `mima-kit` directly returns a `shared secret`. You need to use a `KDF` to derive keys from the `shared secret`. The `KDF` used by the `SM2` standard is `ANSI-X9.63-KDF with SM3`. Both `ANSI-X9.63-KDF` and `SM3` are algorithms supported by `mima-kit`, and you can use them directly.

```typescript
const sm2ec = sm2()
const kdf = x963kdf(sm3)
// Initiator: Alice
// Responder: Bob

// Step 1: Alice
const KA = sm2ec.gen()
const KX = sm2ec.gen()
const ka = { Q: KA.Q } // public key of Alice
const kx = { Q: KX.Q } // temporary public key of Alice
const ID_A = UTF8('alice@rabbit.panic')
const ZA = sm2ec.di(ID_A, KA) // Alice's distinguishable identifier
// send ZA, ka, kx to Bob

// Step 2: Bob
const KB = sm2ec.gen()
const KY = sm2ec.gen()
const kb = { Q: KB.Q } // public key of Bob
const ky = { Q: KY.Q } // temporary public key of Bo
const ID_B = UTF8('bob@rolling.stone')
const ZB = sm2ec.di(ID_B, KB) // Bob's distinguishable identifier
const SB = sm2ec.dh(KB, KY, ka, kx, ZA, ZB) // shared secret key
const DKB = kdf(256, S) // derive key
// send ZB, kb, ky to Alice

// Step 3: Alice
const SA = sm2ec.dh(KA, KX, kb, ky, ZA, ZB) // shared secret key
const DKA = kdf(256, S) // derive key

SA === SB
DKA === DKB
```

```typescript
interface SM2DH {
  /**
   * @param {ECKeyPair} KA - 己方密钥对 / Self Key Pair
   * @param {ECPublicKey} KX - 己方临时密钥对 / Self Temporary Key Pair
   * @param {ECPublicKey} KB - 对方公钥 / Opposite Public Key
   * @param {ECPublicKey} KY - 对方临时公钥 / Opposite Temporary Public Key
   * @param [Uint8Array] ZA - 发起方标识派生值 / Initiator Identity Derived Value
   * @param [Uint8Array] ZB - 接收方标识派生值 / Receiver Identity Derived Value
   * @returns {U8} - 密钥材料 / Keying Material
   */
  (KA: ECKeyPair, KX: ECKeyPair, KB: ECPublicKey, KY: ECPublicKey, ZA?: Uint8Array, ZB?: Uint8Array): U8
}
```

### SM2-DSA

`SM2 Digital Signature Algorithm` is a signature scheme for the `SM2` algorithm. It accepts a `Hash` function as a parameter, and `SM2-DSA` uses `SM3` as the default `Hash` function.

> The `sign` method of `SM2-DSA` returns the `SM2DSASignature` type instead of the `U8` type. The result of the `SM2-DSA` signature contains two values, `r` and `s`.

```typescript
const sm2ec = sm2()
const ID = UTF8('alice@rabbit.panic')
const KA = sm2ec.gen()
const ZA = sm2ec.di(ID, KA)
const M = UTF8('mima-kit')

const signer = sm2ec.dsa() // using SM3 by default
const signature = signer.sign(ZA, KA, M)
signer.verify(ZA, KA, M, signature) // true
```

```typescript
interface SM2DSASignature<T = bigint | Uint8Array> {
  r: T
  s: T
}
interface SM2DSA {
  /**
   * @param {Hash} hash - 哈希算法 / Hash Algorithm (default: SM3)
   */
  (hash?: Hash): {
    /**
     * @param {Uint8Array} Z - 标识派生值 / Identity Derived Value
     * @param {ECPrivateKey} key - 签名方私钥 / Signer Private Key
     * @param {Uint8Array} M - 消息 / Message
     */
    sign: (Z: Uint8Array, key: ECPrivateKey, M: Uint8Array) => SM2DSASignature<U8>
    /**
     * @param {Uint8Array} Z - 标识派生值 / Identity Derived Value
     * @param {ECPublicKey} key - 签名方公钥 / Signer Public Key
     * @param {Uint8Array} M - 消息 / Message
     * @param {SM2DSASignature} S - 签名 / Signature
     */
    verify: (Z: Uint8Array, key: ECPublicKey, M: Uint8Array, S: SM2DSASignature) => boolean
  }
}
```

### SM2-ES

`SM2-ES` is an encryption scheme for the `SM2` algorithm.

```typescript
const sm2ec = sm2(curve)
const M = UTF8('The king\'s ears are donkey ears')

const key = sm2ec.gen()
const cipher = sm2ec.es()
const C = cipher.encrypt(key, M)
cipher.decrypt(key, C) // M
```

```typescript
interface SM2Encrypt {
  /**
   * @param {ECPublicKey} p_key - 接收方公钥 / Receiver Public Key
   * @param {Uint8Array} M - 明文 / Plaintext
   */
  (p_key: ECPublicKey, M: Uint8Array): U8
}
interface SM2Decrypt {
  /**
   * @param {ECPrivateKey} s_key - 解密方私钥 / Decryptor Private Key
   * @param {Uint8Array} C - 密文 / Ciphertext
   */
  (s_key: ECPrivateKey, C: Uint8Array): U8
}
interface SM2EncryptionScheme {
  /**
   * @param {Hash} hash - 哈希算法 / Hash Algorithm (default: SM3)
   * @param {KDF} kdf - 密钥派生函数 / Key Derivation Function (default: X9.63 KDF with SM3)
   * @param {'c1c2c3' | 'c1c3c2'} order - 密文分段顺序 / Ciphertext Segment Order (default: 'c1c3c2')
   */
  (hash?: Hash, kdf?: KDF, order?: 'c1c2c3' | 'c1c3c2'): {
    encrypt: SM2Encrypt
    decrypt: SM2Decrypt
  }
}
```

## x25519

Specification: [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748.html)

`x25519` and `x448` are `ECC` algorithms based on the `Montgomery` curve. They are not instances of `FpECC`, but separate algorithms.

> Note that `x25519` and `x448` provided by `mima-kit` may not be fully compatible with other implementations. This is because `RFC 7748` specifies `little-endian` as the encoding method, while `mima-kit` uses `big-endian` as the encoding method. By converting the `endian`, it should be compatible with other implementations.

> Although `FpECC` can also perform calculations on the `Montgomery` curve, the `x25519` and `x448` algorithms only require the `x` coordinate, and their algorithm implementations will `clamp` the private key, so their underlying algorithms are more efficient independent algorithms.

```typescript
// Generate key pair: X25519KeyPair<U8>
const key = x25519.gen()
const key = x25519.gen('key_pair')
// Generate private key: X25519PrivateKey<U8>
const s_key = x25519.gen('private_key')
// Generate public key: X25519KeyPair<U8>
const p_key = x25519.gen('public_key', s_key)
```

```typescript
interface X25519PrivateKey<T = bigint | Uint8Array> {
  /** 私钥 / Private Key */
  d: T
}
interface X25519PublicKey<T = bigint | Uint8Array> {
  /** 公钥 / Public Key */
  Q: T
}
interface X25519KeyPair<T = bigint | Uint8Array> extends X25519PrivateKey<T>, X25519PublicKey<T> {
}
```

### X25519-DH

Key agreement protocol for the `x25519` and `x448` algorithms. Unlike the standard, they return a `shared secret` directly. You need to derive keys from the `shared secret` separately using a `KDF`.

```typescript
const keyA = x25519.gen()
const keyB = x25519.gen()
const secretA = x25519.dh(keyA, keyB)
const secretB = x25519.dh(keyB, keyA)
// secretA === secretB
```

# Other Components

## Key Derivation Function

A key derivation function (KDF) is an algorithm that derives one or more keys from a key. KDFs are rarely used directly, but rather as part of other algorithmic schemes.

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

`X9.63KDF` is a key derivation function in the `ANSI-X9.63`. `X9.63KDF` needs to be combined with a `Hash` function.

```typescript
const kdf = x963kdf(sha256)
```

### HKDF

`HKDF` is a key derivation function in the `RFC 5869`. `HKDF` needs to be combined with the `KeyHash` function and an optional `salt`

```typescript
const mac = hmac(sha256)
const kdf = hkdf(mac)
```

### PBKDF2

`PBKDF2` is a key derivation function in the `PKCS#5`. `PBKDF2` needs to be combined with the `KeyHash` function, a `iteration` number and an optional `salt`.

```typescript
const mac = hmac(sha256)
const kdf = pbkdf2(mac, 1000)
```

## Elliptic Curve List

`mima-kit` does not export all `Elliptic Curves`, but you can find them in `/src/core/ecParams.ts`.

### `Weierstrass` Curves

> Outside the table, `sm2p256v1` is also a exported `Weierstrass` curve. It is applicable to all `ECC` algorithms, but it is commonly used in the `SM2` algorithm, so it is not included in the table.

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

### `Montgomery` Curves

| NIST       |
|------------|
| Curve25519 |
| Curve448   |

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
