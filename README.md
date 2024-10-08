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

- [mima-kit](#mima-kit)
  - [安装](#安装)
- [散列算法](#散列算法)
  - [散列方案（createHash）](#散列方案createhash)
    - [散列算法的默认行为](#散列算法的默认行为)
  - [加密散列算法](#加密散列算法)
    - [MD5](#md5)
    - [SM3](#sm3)
    - [SHA-1](#sha-1)
    - [SHA-2](#sha-2)
    - [SHA-3](#sha-3)
    - [cSHAKE](#cshake)
    - [TupleHash](#tuplehash)
    - [ParallelHash](#parallelhash)
  - [带密钥的加密散列算法](#带密钥的加密散列算法)
    - [HMAC](#hmac)
    - [KMAC](#kmac)
- [对称密钥算法](#对称密钥算法)
  - [分组密码算法](#分组密码算法)
    - [SM4](#sm4)
    - [AES](#aes)
    - [ARIA](#aria)
    - [Camellia](#camellia)
    - [DES](#des)
    - [3DES](#3des)
    - [ARC5](#arc5)
    - [Blowfish](#blowfish)
    - [Twofish](#twofish)
    - [TEA](#tea)
    - [XTEA](#xtea)
  - [填充模式](#填充模式)
    - [PKCS#7](#pkcs7)
    - [ANSI X9.23](#ansi-x923)
    - [ISO/IEC 7816-4](#isoiec-7816-4)
    - [Zero Padding](#zero-padding)
  - [分组模式](#分组模式)
    - [ECB](#ecb)
    - [CBC](#cbc)
    - [PCBC](#pcbc)
    - [CFB](#cfb)
    - [OFB](#ofb)
    - [CTR](#ctr)
    - [GCM](#gcm)
  - [流密码算法](#流密码算法)
    - [ZUC](#zuc)
    - [ARC4](#arc4)
    - [Salsa20](#salsa20)
    - [Rabbit](#rabbit)
- [License](#license)

## 安装

```bash
npm install mima-kit
```

# 散列算法

## 散列方案（createHash）

`mima-kit` 原生实现的散列算法都是基于 `Uint8Array`。为了方便使用，`mima-kit` 使用 `createHash` 函数对原生实现进行包装。

```typescript
import type { HashScheme } from 'mima-kit'
import { B64URL, createHash, sm3 } from 'mima-kit'

const scheme: HashScheme = {
  digest: sm3.digest,
  INPUT_CODEC: B64URL,
  OUTPUT_CODEC: B64URL,
}
const _sm3 = createHash(
  scheme,
  {
    ALGORITHM: sm3.ALGORITHM,
    BLOCK_SIZE: sm3.BLOCK_SIZE,
    DIGEST_SIZE: sm3.DIGEST_SIZE,
  }
)

console.log(_sm3('bWltYS1raXQ')) // Base64url string
```

```typescript
type Digest = (M: Uint8Array) => Uint8Array
interface HashScheme {
  digest: Digest
  /**
   * @default UTF8
   */
  INPUT_CODEC?: Codec
  /**
   * @default HEX
   */
  OUTPUT_CODEC?: Codec
}
interface HashDescription {
  /**
   * 算法名称
   */
  ALGORITHM: string
  /**
   * 分块大小 (byte)
   */
  BLOCK_SIZE: number
  /**
   * 摘要大小 (byte)
   */
  DIGEST_SIZE: number
}
```

### 散列算法的默认行为

通过 `createHash` 包装的散列算法有一些默认行为：

1. `digest` 函数是算法的原生实现，其输入输出均为 `Uint8Array` 类型。
2. 除了调用 `digest` 函数外，还可以直接调用签名函数。签名函数接受 `string` 或 `Uint8Array` 类型的输入，并会自动对 `string` 类型的输入进行 `UTF8` 编码。
3. 签名函数默认输出为 `HEX` 编码字符串，可以通过传递第二个参数来更改输出编码。只要编码器实现了 `Codec` 接口，理论上可以使用任何编码。
4. 算法不仅提供了丰富的调用方式和可自由组合的编码器，还记录了许多有用的信息，如算法名称、分块大小、输出长度以及输入输出的编解码器等。你可以通过 `console.log` 查看这些信息。

```typescript
import { B64, sm3 } from 'mima-kit'

let M: string | Uint8Array

// When M is Uint8Array
M = new Uint8Array()
console.log(sm3(M)) // Hex string
console.log(sm3(M, B64)) // Base64 string
console.log(sm3.digest(M)) // Uint8Array

// When M is string
M = 'utf-8 string'
console.log(sm3(M)) // Hex string
console.log(sm3(M, B64)) // Base64 string
console.log(sm3.digest(M)) // Error

// Algorithm Information
console.log(sm3)
```

## 加密散列算法

### MD5

```typescript
md5('mima-kit')
```

### SM3

```typescript
sm3('mima-kit')
```

### SHA-1

```typescript
sha1('mima-kit')
```

### SHA-2

```typescript
sha224('mima-kit')
sha256('mima-kit')
sha384('mima-kit')
sha512('mima-kit')

const sha512_224 = sha512t(224)
sha512_224('mima-kit')
```

### SHA-3

```typescript
sha3_224('mima-kit')
sha3_256('mima-kit')
sha3_384('mima-kit')
sha3_512('mima-kit')

shake128(256)('mima-kit')
shake256(512)('mima-kit')
```

### cSHAKE

```typescript
import type { cSHAKEConfig } from 'mima-kit'
const config: cSHAKEConfig = {
  N: 'name', // function name
  S: 'custom', // customization string
}

cShake128(256, config)('mima-kit')
cShake256(512, config)('mima-kit')
```

### TupleHash

```typescript
import type { TupleHashConfig } from 'mima-kit'
const config: TupleHashConfig = {
  S: 'custom', // customization string
}

tupleHash128(256, config)(['mima', '-', 'kit'])
tupleHash256(512, config)(['mima', '-', 'kit'])
tupleHash128XOF(256, config)(['mima', '-', 'kit'])
tupleHash256XOF(512, config)(['mima', '-', 'kit'])
```

### ParallelHash

> 注意：`mima-kit` 提供的 `ParallelHash` 算法并不能真正并行计算，只是将输入分块后分别计算，最后将结果拼接。

```typescript
import type { ParallelHashConfig } from 'mima-kit'
const config: ParallelHashConfig = {
  S: 'custom', // customization string
}
const blockSize = 1024
parallelHash128(blockSize, 256, config)('mima-kit')
parallelHash256(blockSize, 512, config)('mima-kit')
parallelHash128XOF(blockSize, 256, config)('mima-kit')
parallelHash256XOF(blockSize, 512, config)('mima-kit')
```

## 带密钥的加密散列算法

### HMAC

```typescript
import type { HMACScheme } from 'mima-kit'
const scheme: HMACScheme = {
  hash: sm3,
  key: 'password',
}
hmac(scheme)('mima-kit')
```

### KMAC

```typescript
import type { KMACConfig } from 'mima-kit'
const config: KMACConfig = {
  K: 'password', // key
  S: 'custom', // customization string
}

kmac128(256, config)('mima-kit')
kmac256(512, config)('mima-kit')
kmac128XOF(256, config)('mima-kit')
kmac256XOF(512, config)('mima-kit')
```

# 对称密钥算法

对称密钥算法是一种使用相同密钥进行加密和解密的加密算法。大致可以分为：`分组密码算法` 和 `流密码算法`。

## 分组密码算法

通常，我们会将 `分组密码算法`、 `填充模式` 和 `分组模式` 组合在一起，形成一个完整的 `分组密码方案`。因为单独的 `分组密码算法` 只能对单个数据块进行加解密，所以它们在单独使用时并没有太大的意义。

`mima-kit` 将 `组合` 这一行为放在了 `分组模式` 中，以达到灵活复用的目的。查看 [分组模式](#分组模式) 将 `分组密码算法`、`分组模式` 和 `填充模式` 组合在一起。

```typescript
const k = ''
const iv = ''
const config: CBCConfig = { }
const cbc_sm4 = cbc(sm4, config)(k, iv)
const c = cbc_sm4.encrypt('mima-kit') // c: Hex string
const m = cbc_sm4.decrypt(c) // m: UTF8 string
```

### SM4

```typescript
let k: Uint8Array
let m: Uint8Array
let c: Uint8Array

sm4(k).encrypt(m) // c
sm4(k).decrypt(c) // m
```

### AES

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

```typescript
let k: Uint8Array
let m: Uint8Array
let c: Uint8Array

des(k).encrypt(m) // c
des(k).decrypt(c) // m
```

### 3DES

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

```typescript
let k: Uint8Array
let m: Uint8Array
let c: Uint8Array

blowfish(k).encrypt(m) // c
blowfish(k).decrypt(c) // m
```

### Twofish

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

可以向 `TEA` 算法传递一个代表 `轮数` 的参数。`TEA` 算法的 `轮数` 可以任意正整数，默认使用 `32`。

```typescript
let k: Uint8Array
let m: Uint8Array
let c: Uint8Array

tea(32)(k).encrypt(m) // c
tea(32)(k).decrypt(c) // m
```

### XTEA

可以向 `XTEA` 算法传递一个代表 `轮数` 的参数。`XTEA` 算法的 `轮数` 可以任意正整数，默认使用 `32`。

```typescript
let k: Uint8Array
let m: Uint8Array
let c: Uint8Array

xtea(32)(k).encrypt(m) // c
xtea(32)(k).decrypt(c) // m
```

## 填充模式

单独使用 `填充模式` 并没有太大的意义。查看 [分组模式](#分组模式) 将 `分组密码算法`、`分组模式` 和 `填充模式` 组合在一起。

### PKCS#7

```typescript
let block_size: number
let m: Uint8Array
let p: Uint8Array
PKCS7(m, block_size) // p
PKCS7(p) // m
```

### ANSI X9.23

```typescript
let block_size: number
let m: Uint8Array
let p: Uint8Array
ANSI_X923(m, block_size) // p
ANSI_X923(p) // m
```

### ISO/IEC 7816-4

```typescript
let block_size: number
let m: Uint8Array
let p: Uint8Array
ISO7816_4(m, block_size) // p
ISO7816_4(p) // m
```

### Zero Padding

```typescript
let block_size: number
let m: Uint8Array
let p: Uint8Array
ZERO_PAD(m, block_size) // p
ZERO_PAD(p) // m
```

## 分组模式

查看 `/test/cipher.test.ts` 以获取更多使用示例。

### ECB

Electronic Codebook (ECB) 是最简单的分组模式。`ECB` 模式将明文分成固定长度的数据块，然后对每个数据块进行加密。

- `ECB` 模式不需要 `iv`。

```typescript
const k = '' // hex string
const m = '' // utf8 string
const c = '' // hex string
const config: ECBConfig = { }

const CIPHER = ecb(sm4, config)(k)
CIPHER.encrypt(m) // c
CIPHER.decrypt(c) // m
```

```typescript
interface ECBConfig {
  /**
   * @default PKCS7
   */
  PADDING?: Padding
  /**
   * @default HEX
   */
  KEY_CODEC?: Codec
  /**
   * @default UTF8
   */
  ENCRYPT_INPUT_CODEC?: Codec
  /**
   * @default HEX
   */
  ENCRYPT_OUTPUT_CODEC?: Codec
  /**
   * @default HEX
   */
  DECRYPT_INPUT_CODEC?: Codec
  /**
   * @default UTF8
   */
  DECRYPT_OUTPUT_CODEC?: Codec
}
```

### CBC

Cipher Block Chaining (CBC) 是最常用的分组模式。`CBC` 模式每个明文块都会与前一个密文块进行异或操作，然后再进行加密。

- `CBC` 模式需要 `iv`。
- `iv` 的长度与加密算法的 `BLOCK_SIZE` 相同。

```typescript
const k = '' // hex string
const iv = '' // hex string
const m = '' // utf8 string
const c = '' // hex string
const config: CBCConfig = { }

const CIPHER = cbc(sm4, config)(k, iv)
CIPHER.encrypt(m) // c
CIPHER.decrypt(c) // m
```

```typescript
interface CBCConfig {
  /**
   * @default PKCS7
   */
  PADDING?: Padding
  /**
   * @default HEX
   */
  KEY_CODEC?: Codec
  /**
   * @default HEX
   */
  IV_CODEC?: Codec
  /**
   * @default UTF8
   */
  ENCRYPT_INPUT_CODEC?: Codec
  /**
   * @default HEX
   */
  ENCRYPT_OUTPUT_CODEC?: Codec
  /**
   * @default HEX
   */
  DECRYPT_INPUT_CODEC?: Codec
  /**
   * @default UTF8
   */
  DECRYPT_OUTPUT_CODEC?: Codec
}
```

### PCBC

Progressive Chaining Block Cipher (PCBC) 是 `CBC` 的变种。`PCBC` 模式每个明文块都会与前一个明文和前一个密文块进行异或操作，然后再进行加密。`PCBC` 模式旨在将密文中的微小变化在加解密时无限传播。

- `PCBC` 模式需要 `iv`。
- `iv` 的长度与加密算法的 `BLOCK_SIZE` 相同。

```typescript
const k = '' // hex string
const iv = '' // hex string
const m = '' // utf8 string
const c = '' // hex string
const config: PCBCConfig = { }

const CIPHER = pcbc(sm4, config)(k, iv)
CIPHER.encrypt(m) // c
CIPHER.decrypt(c) // m
```

```typescript
interface PCBCConfig {
  /**
   * @default PKCS7
   */
  PADDING?: Padding
  /**
   * @default HEX
   */
  KEY_CODEC?: Codec
  /**
   * @default HEX
   */
  IV_CODEC?: Codec
  /**
   * @default UTF8
   */
  ENCRYPT_INPUT_CODEC?: Codec
  /**
   * @default HEX
   */
  ENCRYPT_OUTPUT_CODEC?: Codec
  /**
   * @default HEX
   */
  DECRYPT_INPUT_CODEC?: Codec
  /**
   * @default UTF8
   */
  DECRYPT_OUTPUT_CODEC?: Codec
}
```

### CFB

Cipher Feedback (CFB) 将分组密码转换为流密码。`CFB` 模式通过加密前一个密文块获得加密数据流，然后与明文块进行异或操作，获得密文块。

- `CFB` 模式需要 `iv`。
- `iv` 的长度与加密算法的 `BLOCK_SIZE` 相同。

```typescript
const k = '' // hex string
const iv = '' // hex string
const m = '' // utf8 string
const c = '' // hex string
const config: CFBConfig = { }

const CIPHER = cfb(sm4, config)(k, iv)
CIPHER.encrypt(m) // c
CIPHER.decrypt(c) // m
```

```typescript
interface CFBConfig {
  /**
   * @default PKCS7
   */
  PADDING?: Padding
  /**
   * @default HEX
   */
  KEY_CODEC?: Codec
  /**
   * @default HEX
   */
  IV_CODEC?: Codec
  /**
   * @default UTF8
   */
  ENCRYPT_INPUT_CODEC?: Codec
  /**
   * @default HEX
   */
  ENCRYPT_OUTPUT_CODEC?: Codec
  /**
   * @default HEX
   */
  DECRYPT_INPUT_CODEC?: Codec
  /**
   * @default UTF8
   */
  DECRYPT_OUTPUT_CODEC?: Codec
}
```

### OFB

Output Feedback (OFB) 将分组密码转换为流密码。`OFB` 模式通过加密 `iv` 获得加密数据流，然后与明文块进行异或操作，获得密文块。

- `OFB` 模式需要 `iv`。
- `iv` 的长度与加密算法的 `BLOCK_SIZE` 相同。

```typescript
const k = '' // hex string
const iv = '' // hex string
const m = '' // utf8 string
const c = '' // hex string
const config: OFBConfig = { }

const CIPHER = ofb(sm4, config)(k, iv)
CIPHER.encrypt(m) // c
CIPHER.decrypt(c) // m
```

```typescript
interface OFBConfig {
  /**
   * @default PKCS7
   */
  PADDING?: Padding
  /**
   * @default HEX
   */
  KEY_CODEC?: Codec
  /**
   * @default HEX
   */
  IV_CODEC?: Codec
  /**
   * @default UTF8
   */
  ENCRYPT_INPUT_CODEC?: Codec
  /**
   * @default HEX
   */
  ENCRYPT_OUTPUT_CODEC?: Codec
  /**
   * @default HEX
   */
  DECRYPT_INPUT_CODEC?: Codec
  /**
   * @default UTF8
   */
  DECRYPT_OUTPUT_CODEC?: Codec
}
```

### CTR

- `CTR` 模式需要 `iv`。
- `iv` 的长度与加密算法的 `BLOCK_SIZE` 相同。

Counter Mode (CTR) 将分组密码转换为流密码。`CTR` 模式将 `iv` 与计数器组合以生成唯一的 `计数器块`，通过加密 `计数器块` 获得加密数据流，然后与明文块进行异或操作，获得密文块。

```typescript
const k = '' // hex string
const iv = '' // hex string
const m = '' // utf8 string
const c = '' // hex string
const config: CTRConfig = { }

const CIPHER = ctr(sm4, config)(k, iv)
CIPHER.encrypt(m) // c
CIPHER.decrypt(c) // m
```

```typescript
interface CTRConfig {
  /**
   * @default PKCS7
   */
  PADDING?: Padding
  /**
   * @default HEX
   */
  KEY_CODEC?: Codec
  /**
   * @default HEX
   */
  IV_CODEC?: Codec
  /**
   * @default UTF8
   */
  ENCRYPT_INPUT_CODEC?: Codec
  /**
   * @default HEX
   */
  ENCRYPT_OUTPUT_CODEC?: Codec
  /**
   * @default HEX
   */
  DECRYPT_INPUT_CODEC?: Codec
  /**
   * @default UTF8
   */
  DECRYPT_OUTPUT_CODEC?: Codec
}
```

### GCM

Galois/Counter Mode (GCM) 将分组密码转换为流密码。`GCM` 模式可以看作是 `CTR` 模式的变种，它在 `CTR` 模式的基础上增加了 `认证` 功能。

- `GCM` 模式需要 `iv`。
- `iv` 的长度没有限制，但推荐使用 `96` 位长度的 `iv`。
- 签名生成的 `AUTH_TAG` 长度由 `AUTH_TAG_SIZE` 参数决定。`AUTH_TAG` 最大长度为 `128` 位，设置任意长度都不会影响程序的运行，但一般推荐使用 `128`、`120`、`112`、`104`、`96` 位长度，对于某些应用也可以使用 `64`、`32` 位长度。

`mima-kit` 实现的 `GCM` 模式并没有进行查表优化，因此性能可能会比较慢。

```typescript
const k = '' // hex string
const iv = '' // hex string
const m = '' // utf8 string
const a = '' // utf8 string
const c = '' // hex string
const t = '' // hex string
const config: GCMConfig = { }

const CIPHER = gcm(aes(128), config)(k, iv)
CIPHER.encrypt(m) // c
CIPHER.decrypt(c) // m
CIPHER.sign(c, a) // auth tag
CIPHER.verify(t, c, a) // true or false
```

```typescript
interface GCMConfig {
  /**
   * @default PKCS7
   */
  PADDING?: Padding
  /**
   * @default HEX
   */
  KEY_CODEC?: Codec
  /**
   * @default HEX
   */
  IV_CODEC?: Codec
  /**
   * @default UTF8
   */
  ENCRYPT_INPUT_CODEC?: Codec
  /**
   * @default HEX
   */
  ENCRYPT_OUTPUT_CODEC?: Codec
  /**
   * @default HEX
   */
  DECRYPT_INPUT_CODEC?: Codec
  /**
   * @default UTF8
   */
  DECRYPT_OUTPUT_CODEC?: Codec
  /**
   * @default UTF8
   */
  ADDITIONAL_DATA_CODEC?: Codec
  /**
   * 认证标签长度 (byte)
   * @default 16
   */
  AUTH_TAG_SIZE?: number
  /**
   * @default HEX
   */
  AUTH_TAG_CODEC?: Codec
}
```

## 流密码算法

通常 `流密码算法` 不需要复杂的配置，一般只需要 `key` 和 `iv`。

```typescript
const k = ''
const iv = ''
const config: IVStreamCipherConfig = { }
const cipher = salsa20(k, iv, config)
const c = cipher.encrypt('mima-kit') // c: Hex string
const m = cipher.decrypt(c) // m: UTF8 string
```

```typescript
interface IVStreamCipherConfig {
  /**
   * @default HEX
   */
  KEY_CODEC?: Codec
  /**
   * @default HEX
   */
  IV_CODEC?: Codec
  /**
   * @default UTF8
   */
  ENCRYPT_INPUT_CODEC?: Codec
  /**
   * @default HEX
   */
  ENCRYPT_OUTPUT_CODEC?: Codec
  /**
   * @default HEX
   */
  DECRYPT_INPUT_CODEC?: Codec
  /**
   * @default UTF8
   */
  DECRYPT_OUTPUT_CODEC?: Codec
}
```

### ZUC

`ZUC` 是 `3GPP` 规范中的流密码算法，它包含机密性算法 `128-EEA3` 和完整性算法 `128-EIA3`。由于 `ZUC` 算法主要用于移动通信，所以函数接口和其他流密码算法有所不同。

查看 `/test/cipher.test.ts` 以获取更多使用示例。

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
const config: ZUCConfig = { }
// 128-EEA3 加密消息
eea3(params, config) // c
// 128-EIA3 计算消息认证码
eia3(params, config) // mac
// 128-EEA3 解密消息
params.M = c
eea3(params, config) // m
```

### ARC4

`ARC4` 算法可以接受长度为 `0 < k.byteLength < 256` 的密钥，同时 `ARC4` 算法不需要 `iv`。

```typescript
const k = ''
const config: StreamCipherConfig = { }
const cipher = arc4(k, config)
const c = cipher.encrypt('mima-kit') // c: Hex string
const m = cipher.decrypt(c) // m: UTF8 string
```

```typescript
interface StreamCipherConfig {
  /**
   * @default HEX
   */
  KEY_CODEC?: Codec
  /**
   * @default UTF8
   */
  ENCRYPT_INPUT_CODEC?: Codec
  /**
   * @default HEX
   */
  ENCRYPT_OUTPUT_CODEC?: Codec
  /**
   * @default HEX
   */
  DECRYPT_INPUT_CODEC?: Codec
  /**
   * @default UTF8
   */
  DECRYPT_OUTPUT_CODEC?: Codec
}
```

### Salsa20

`Salsa20` 算法可以接受长度为 `16` 或 `32` 字节的密钥和 `8` 字节的 `iv`。

```typescript
const k = ''
const iv = ''
const cipher = salsa20(k, iv)
const c = cipher.encrypt('mima-kit') // c: Hex string
const m = cipher.decrypt(c) // m: UTF8 string
```

### Rabbit

`Rabbit` 算法可以接受长度为 `16` 字节的密钥。对于 `iv`，`Rabbit` 算法可以接受长度为 `0` 或 `8` 字节的 `iv`。当 `iv` 长度为 `0` 字节时，`Rabbit` 算法会跳过 `iv Setup` 步骤。

```typescript
const k = ''
const iv = new Uint8Array(8)
const cipher = rabbit(k, iv)
const c = cipher.encrypt('mima-kit') // c: Hex string
const m = cipher.decrypt(c) // m: UTF8 string

// skip iv setup
const cipher = rabbit(k, new Uint8Array(0))
const c = cipher.encrypt('mima-kit') // c: Hex string
const m = cipher.decrypt(c) // m: UTF8 string
```

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
