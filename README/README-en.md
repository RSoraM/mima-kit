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

> Documents in other languages may be outdated. Please refer to the Simplified Chinese document for details.

- [mima-kit](#mima-kit)
  - [Install](#install)
- [Hash Algorithm](#hash-algorithm)
  - [Hash Scheme (createHash)](#hash-scheme-createhash)
    - [Default behavior of hash algorithms](#default-behavior-of-hash-algorithms)
  - [Secure Hash Algorithm](#secure-hash-algorithm)
    - [MD5](#md5)
    - [SM3](#sm3)
    - [SHA-1](#sha-1)
    - [SHA-2](#sha-2)
    - [SHA-3](#sha-3)
    - [cSHAKE](#cshake)
    - [TupleHash](#tuplehash)
    - [ParallelHash](#parallelhash)
  - [Keyed Hash Algorithm](#keyed-hash-algorithm)
    - [HMAC](#hmac)
    - [KMAC](#kmac)
- [Block Cipher Algorithm](#block-cipher-algorithm)
  - [Cipher Algorithm](#cipher-algorithm)
    - [SM4](#sm4)
    - [AES](#aes)
    - [DES](#des)
    - [3DES](#3des)
  - [Padding Mode](#padding-mode)
    - [PKCS#7](#pkcs7)
    - [ANSI X9.23](#ansi-x923)
    - [ISO/IEC 7816-4](#isoiec-7816-4)
    - [Zero Padding](#zero-padding)
  - [Block Mode](#block-mode)
    - [ECB](#ecb)
    - [CBC](#cbc)
    - [PCBC](#pcbc)
    - [CFB](#cfb)
    - [OFB](#ofb)
    - [CTR](#ctr)
    - [GCM](#gcm)
- [License](#license)

## Install

```bash
npm install mima-kit
```

# Hash Algorithm

## Hash Scheme (createHash)

The hash algorithms natively implemented by `mima-kit` are all based on `Uint8Array`. For ease of use, `mima-kit` wraps the native implementations with the `createHash` function.

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
   * Algorithm name
   */
  ALGORITHM: string
  /**
   * Block size (byte)
   */
  BLOCK_SIZE: number
  /**
   * Digest size (byte)
   */
  DIGEST_SIZE: number
}
```

### Default behavior of hash algorithms

The hash algorithms wrapped by `createHash` have some default behaviors:

1. The `digest` function is the native implementation of the algorithm, with both input and output being of type `Uint8Array`.
2. In addition to calling the `digest` function, you can also directly call the hash function. The hash function accepts inputs of type `string` or `Uint8Array` and will automatically encode `string` inputs to `UTF8`.
3. The hash function outputs a `HEX` encoded string by default, but you can change the output encoding by passing a second parameter. As long as the encoder implements the `Codec` interface, any encoding can theoretically be used.
4. The algorithm not only provides a variety of calling methods and freely combinable encoders but also records a lot of useful information, such as the algorithm name, block size, output length, and input/output codecs. You can view this information via `console.log`.

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

## Secure Hash Algorithm

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

> Note: The `ParallelHash` algorithm provided by `mima-kit` does not perform true parallel computation. It merely divides the input into blocks, computes them separately, and then concatenates the results.

```typescript
import type { ParallelHashConfig } from 'mima-kit'
const config: ParallelHashConfig = {
  S: 'custom', // customization string
}

parallelHash128(256, config)('mima-kit')
parallelHash256(512, config)('mima-kit')
parallelHash128XOF(256, config)('mima-kit')
parallelHash256XOF(512, config)('mima-kit')
```

## Keyed Hash Algorithm

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

# Block Cipher Algorithm

Typically, we combine `encryption algorithms`, `padding modes`, and `block modes` to form a complete `encryption scheme`. Since standalone `encryption algorithms` can only encrypt or decrypt single data blocks, they are not very meaningful when used alone.

`mima-kit` places the `combination` behavior within the `block modes` to achieve flexible reuse.

## Cipher Algorithm

Using the `cipher algorithm` alone does not make much sense. See [Block Mode](#block-mode) to learn how to combine `cipher algorithm`, `padding mode`, and `block mode`.

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

## Padding Mode

Using the `padding mode` alone does not make much sense. See [Block Mode](#block-mode) to learn how to combine `cipher algorithm`, `padding mode`, and `block mode`.

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

## Block Mode

See `/test/index.test.ts` for more usage examples.

### ECB

Electronic Codebook (ECB) is the simplest block mode. `ECB` mode divides the plaintext into fixed-length data blocks, and then encrypts each data block.

- `ECB` mode does not require `iv`.

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

Cipher Block Chaining (CBC) is the most commonly used block mode. In `CBC` mode, each plaintext block is XORed with the previous ciphertext block before being encrypted.

- `CBC` mode requires an `iv`.
- The length of the `iv` is the same as the `BLOCK_SIZE` of the encryption algorithm.

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

Progressive Chaining Block Cipher (PCBC) is a variant of `CBC`. In `PCBC` mode, each plaintext block is XORed with the previous plaintext and previous ciphertext blocks before being encrypted. `PCBC` mode aims to propagate small changes in the ciphertext infinitely during encryption and decryption.

- `PCBC` mode requires an `iv`.
- The length of the `iv` is the same as the `BLOCK_SIZE` of the encryption algorithm.

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

Cipher Feedback (CFB) mode converts block ciphers into stream ciphers. `CFB` mode generates an encryption data stream by encrypting the previous ciphertext block, then XORs the data stream with the plaintext block to obtain the ciphertext block.

- `CFB` mode requires an `iv`.
- The length of the `iv` is the same as the `BLOCK_SIZE` of the encryption algorithm.

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

OFB mode converts block ciphers into stream ciphers. `OFB` mode generates an encryption data stream by encrypting the `iv`, then XORs the data stream with the plaintext block to obtain the ciphertext block.

- `OFB` mode requires an `iv`.
- The length of the `iv` is the same as the `BLOCK_SIZE` of the encryption algorithm.

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

Counter Mode (CTR) converts block ciphers into stream ciphers. `CTR` mode generates an encryption data stream by combining the `iv` with a counter to generate a unique `counter block`, encrypting the `counter block` to obtain the encryption data stream, and then XORing the data stream with the plaintext block to obtain the ciphertext block.

- `CTR` mode requires an `iv`.
- The length of the `iv` is the same as the `BLOCK_SIZE` of the encryption algorithm.

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

Galois/Counter Mode (GCM) converts block ciphers into stream ciphers. `GCM` mode can be seen as a variant of `CTR` mode, with the addition of `authentication` functionality.

- `GCM` Requires an `iv`.
- Length of `iv` is not limited, but it is recommended to use a `96` bit length `iv`.
- `AUTH_TAG` generated by the `GCM` mode is a `HEX` encoded string, and the `AUTH_TAG` length is determined by the `AUTH_TAG_SIZE` parameter. The maximum length of the `AUTH_TAG` is `128` bits. Setting any length will not affect the operation of the program, but it is generally recommended to use `128`, `120`, `112`, `104`, `96` bits, and for some applications, `64`, `32` bits can also be used.

The `GCM` mode implemented by `mima-kit` does not perform table lookup optimization, so the performance may be slower.

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
   * Authentication tag size (byte)
   * @default 16
   */
  AUTH_TAG_SIZE?: number
  /**
   * @default HEX
   */
  AUTH_TAG_CODEC?: Codec
}
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