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

`mima-kit` is a cryptographic suite implemented in `TypeScript`. The goal is to provide an easy-to-use cryptographic library. `mima-kit` is still in the early stages of development, and the API may change.

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
  - [Encryption Scheme (createCipher)](#encryption-scheme-createcipher)
    - [Default behavior of encryption schemes](#default-behavior-of-encryption-schemes)
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
    - [CFB](#cfb)
    - [OFB](#ofb)
    - [CTR](#ctr)
    - [PCBC](#pcbc)
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

## Encryption Scheme (createCipher)

Usually, we combine the `cipher algorithm`, `blocking mode` and `padding mode` to form a complete `encryption scheme`. Because a single `cipher algorithm` can only encrypt and decrypt a single block of data, they do not make much sense when used alone.

```typescript
const k = ''
const iv = ''
const config: CipherConfig = { }
const cbc_aes = createCipher(aes(256), cbc, config)(k, iv)
```

```ts
interface CipherConfig {
  /**
   * @default PKCS7
   */
  PADDING?: Padding
  /**
   * @default Hex
   */
  KEY_CODEC?: Codec
  /**
   * @default Hex
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

### Default behavior of encryption schemes
Similar to `createHash`, encryption schemes created with `createCipher` also have some default behaviors:

1. The `_encrypt` and `_decrypt` functions are the native implementations of the encryption scheme, with both input and output being of type `Uint8Array`.
2. For encryption, in addition to calling the `_encrypt` function, you can also directly call the `encrypt` function. The `encrypt` function accepts inputs of type `string` or `Uint8Array` and will automatically encode `string` inputs to `UTF8`.
3. For decryption, in addition to calling the `_decrypt` function, you can also directly call the `decrypt` function. The `decrypt` function accepts inputs of type `string` or `Uint8Array` and will automatically encode `string` inputs to `HEX`.
4. Both `encrypt` and `decrypt` can change the output encoding by passing a second parameter. As long as the encoder implements the `Codec` interface, any encoding can theoretically be used.
5. The encryption scheme not only provides a variety of calling methods and freely combinable encoders but also records a lot of useful information, which you can view via `console.log`.

```typescript
const config: CipherConfig = { }
const cipher = createCipher(sm4, ofb, config)(k, iv)

let M: string | Uint8Array
let C: string | Uint8Array

// When M is Uint8Array
M = new Uint8Array()
C = cipher._encrypt(M) // c: Uint8Array
M = cipher._decrypt(C) // m: Uint8Array

// When M is string
M = 'utf-8 string'
C = cipher.encrypt(M) // c: Hex string
M = cipher.decrypt(C) // m: UTF8 string

// Cipher Information
console.log(cipher)
```

## Cipher Algorithm

Using the `cipher algorithm` alone does not make much sense. See [Encryption Scheme](#encryption-scheme-createcipher) to learn how to combine `cipher algorithm`, `blocking mode`, and `padding mode`.

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

Using the `padding mode` alone does not make much sense. See [Encryption Scheme](#encryption-scheme-createcipher) to learn how to combine `cipher algorithm`, `blocking mode`, and `padding mode`.

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

Using the `block mode` alone does not make much sense. See [Encryption Scheme](#encryption-scheme-createcipher) to learn how to combine `cipher algorithm`, `blocking mode`, and `padding mode`.

### ECB

```typescript
let k: Uint8Array
let m: Uint8Array
let c: Uint8Array

const CIPHER = ecb(aes(128))(k)
CIPHER.encrypt(m) // c
CIPHER.decrypt(c) // m
```

### CBC

```typescript
let k: Uint8Array
let iv: Uint8Array
let m: Uint8Array
let c: Uint8Array

const CIPHER = cbc(aes(128))(k, iv)
CIPHER.encrypt(m) // c
CIPHER.decrypt(c) // m
```

### CFB

```typescript
let k: Uint8Array
let iv: Uint8Array
let m: Uint8Array
let c: Uint8Array

const CIPHER = cfb(aes(128))(k, iv)
CIPHER.encrypt(m) // c
CIPHER.decrypt(c) // m
```

### OFB

```typescript
let k: Uint8Array
let iv: Uint8Array
let m: Uint8Array
let c: Uint8Array

const CIPHER = ofb(aes(128))(k, iv)
CIPHER.encrypt(m) // c
CIPHER.decrypt(c) // m
```

### CTR

```typescript
let k: Uint8Array
let nonce: Uint8Array
let m: Uint8Array
let c: Uint8Array

const CIPHER = ctr(aes(128))(k, nonce)
CIPHER.encrypt(m) // c
CIPHER.decrypt(c) // m
```

### PCBC

```typescript
let k: Uint8Array
let iv: Uint8Array
let m: Uint8Array
let c: Uint8Array

const CIPHER = pcbc(aes(128))(k, iv)
CIPHER.encrypt(m) // c
CIPHER.decrypt(c) // m
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
