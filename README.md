# mima-kit

[![npm version][npm-version-src]][npm-version-href]
[![npm downloads][npm-downloads-src]][npm-downloads-href]
[![bundle][bundle-src]][bundle-href]

[![JSDocs][jsdocs-src]][jsdocs-href]
[![License][license-src]][license-href]

`mima-kit` 是一个使用 `TypeScript` 实现的密码学套件。目标是提供一个简单易用的密码学库。

`mima-kit` is a cryptographic suite implemented using TypeScript. The goal is to provide a simple and easy-to-use cryptographic library.

## 安装 - Installation

```bash
npm install mima-kit
```

## 使用 - Usage

```typescript
import { B64, Utf8, sm3 } from 'mima-kit'

sm3.digest(Utf8.parse('mima-kit')) // Uint8Array
sm3('mima-kit') // Hex string
sm3('mima-kit', B64) // Base64 string
```

## 加密散列算法 - Cryptographic Hash Function

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

// SHA-3 Derived Functions

cShake128(256, 'name', 'custom')('mima-kit')
cShake256(512, 'name', 'custom')('mima-kit')

tupleHash128(256, 'name', 'custom')(['mima', '-', 'kit'])
tupleHash256(512, 'name', 'custom')(['mima', '-', 'kit'])
tupleHash128XOF(256, 'name', 'custom')(['mima', '-', 'kit'])
tupleHash256XOF(512, 'name', 'custom')(['mima', '-', 'kit'])

parallelHash128(256, 'name', 'custom')('mima-kit')
parallelHash256(512, 'name', 'custom')('mima-kit')
parallelHash128XOF(256, 'name', 'custom')('mima-kit')
parallelHash256XOF(512, 'name', 'custom')('mima-kit')
```

## 带密钥的加密散列算法 - Keyed Cryptographic Hash Function

### HMAC

```typescript
hmac(sm3, 'password')('mima-kit')
hmac(sha512t(256), 'password')('mima-kit')
```

### KMAC

```typescript
kmac128(256, 'password', 'custom')('mima-kit')
kmac256(512, 'password', 'custom')('mima-kit')
kmac128XOF(256, 'password', 'custom')('mima-kit')
kmac256XOF(512, 'password', 'custom')('mima-kit')
```

## License

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
