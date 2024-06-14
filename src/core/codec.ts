// eslint-disable-next-line unicorn/prefer-node-protocol
import { Buffer } from 'buffer'

// * Codec

export interface Codec {
  parse: (input: string) => Buffer
  stringify: (input: ArrayBufferLike) => string
}

// * Utf8 Codec

export const Utf8: Codec = {
  parse(Utf8String) {
    return Buffer.from(Utf8String, 'utf-8')
  },
  stringify(buffer) {
    return Buffer.from(buffer).toString('utf-8')
  },
}

// * Hex Codec

export const Hex: Codec = {
  parse(HexString) {
    return Buffer.from(HexString, 'hex')
  },
  stringify(buffer) {
    return Buffer.from(buffer).toString('hex')
  },
}

// * B64 Codec

export const B64: Codec = {
  parse(B64String) {
    return Buffer.from(B64String, 'base64')
  },
  stringify(buffer) {
    return Buffer.from(buffer).toString('base64')
  },
}

export const B64url: Codec = {
  parse(B64urlString) {
    return Buffer.from(B64urlString, 'base64url')
  },
  stringify(buffer) {
    return Buffer.from(buffer).toString('base64url')
  },
}
