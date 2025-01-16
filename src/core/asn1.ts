import { U8 } from './utils'

export const ASN1 = {
  // 0x04
  OCTET_STRING: (value: Uint8Array) => {
    const buffer = new U8(value.length + 2)
    buffer.set([0x04, value.length], 0)
    buffer.set(value, 2)
    return buffer
  },
  // 0x05
  NULL: () => new U8([0x05, 0x00]),
  // 0x06
  OBJECT_IDENTIFIER: (id: string = '') => {
    const node = id.split('.').map(Number)
    const buffer: number[] = []
    buffer.push(node[0] * 40 + node[1])
    for (let i = 2; i < node.length; i++) {
      let n = node[i]
      if (n < 128) {
        buffer.push(n)
      }
      else {
        const bytes: number[] = [n & 0x7F]
        n >>= 7
        while (n > 0) {
          bytes.unshift((n & 0x7F) | 0x80)
          n >>= 7
        }
        buffer.push(...bytes)
      }
    }
    return new U8([0x06, buffer.length, ...buffer])
  },
  // 0x30
  SEQUENCE: (value: Uint8Array[]) => {
    const length = value.reduce((sum, v) => sum + v.length, 0)
    const buffer = new U8(length + 2)
    buffer.set([0x30, length], 0)
    let offset = 2
    for (const v of value) {
      buffer.set(v, offset)
      offset += v.length
    }
    return buffer
  },
}
