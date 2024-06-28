/**
 * @interface Codec
 *
 * @description
 * Codec interface provides two methods: parse and stringify <br>
 * 编解码器接口提供两个方法：parse 和 stringify
 */
export interface Codec {
  parse: (input: string) => Uint8Array
  stringify: (input: Uint8Array) => string
}

/**
 * ### Utf8 Codec
 *
 * @description
 * Utf8 codec provides conversion between Utf8 string and Uint8Array <br>
 * Utf8 编解码器提供 UTF-8字符串 与 Uint8Array相互转换
 *
 * @example
 * Utf8.parse('hello') // Uint8Array(5) [ 104, 101, 108, 108, 111 ]
 * Utf8.stringify(Uint8Array(5) [ 104, 101, 108, 108, 111 ]) // 'hello'
 */
export const Utf8: Codec = {
  parse(input) {
    return new TextEncoder().encode(input)
  },
  stringify(input) {
    return new TextDecoder('utf-8').decode(input)
  },
}

/**
 * ### Hex Codec
 *
 * @description
 * Hex codec provides conversion between Hex string and Uint8Array <br>
 * Hex 编解码器提供 HEX字符串 与 Uint8Array相互转换
 *
 * @example
 * Hex.parse('deadbeef') // Uint8Array(4) [ 222, 173, 190, 239 ]
 * Hex.stringify(Uint8Array(4) [ 222, 173, 190, 239 ]) // 'deadbeef'
 */
export const Hex: Codec = {
  parse(input) {
    const arr = input.match(/[\da-f]{2}/gi)
    if (arr == null) {
      return new Uint8Array()
    }
    return new Uint8Array(arr.map(h => Number.parseInt(h, 16)))
  },
  stringify(input) {
    const view = new DataView(input.buffer)
    let result = ''
    for (let i = 0; i < view.byteLength; i++) {
      result += view.getUint8(i).toString(16).padStart(2, '0')
    }
    return result
  },
}

/**
 * ### B64 Codec
 *
 * @description
 * B64 codec provides conversion between Base64 string and Uint8Array <br>
 * B64 编解码器提供 Base64字符串 与 Uint8Array相互转换
 *
 * @example
 * B64.parse('aGVsbG8=') // Uint8Array(5) [ 104, 101, 108, 108, 111 ]
 * B64.stringify(Uint8Array(5) [ 104, 101, 108, 108, 111 ]) // 'aGVsbG8='
 */
export const B64: Codec = {
  parse(input) {
    return B64CommonParse(input, false)
  },
  stringify(input) {
    return B64CommonStringify(input, false)
  },
}

/**
 * ### B64url Codec
 *
 * @description
 * B64url codec provides conversion between Base64url string and Uint8Array <br>
 * B64url 编解码器提供 Base64url字符串 与 Uint8Array相互转换
 *
 * @example
 * B64url.parse('aGVsbG8') // Uint8Array(5) [ 104, 101, 108, 108, 111 ]
 * B64url.stringify(Uint8Array(5) [ 104, 101, 108, 108, 111 ]) // 'aGVsbG8'
 */
export const B64url: Codec = {
  parse(input) {
    return B64CommonParse(input, true)
  },
  stringify(input) {
    return B64.stringify(input).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
  },
}

/** parse b64 string to uint8array */
function B64CommonParse(input: string, url: boolean) {
  if (url) {
    input = input.replace(/-/g, '+').replace(/_/g, '/')
    while (input.length % 4) {
      input += '='
    }
  }
  const binary = atob(input)
  const view = new Uint8Array(binary.length)

  for (let i = 0; i < binary.length; i++) {
    view[i] = binary.charCodeAt(i)
  }

  return view
}

/** stringify Uint8Array to b64 string */
export function B64CommonStringify(input: Uint8Array, url: boolean) {
  const view = new DataView(input.buffer)

  let map = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
  map += url ? '-_' : '+/'
  let result = ''
  let i = 0
  for (i = 0; i < view.byteLength - 2; i += 3) {
    result += map[view.getUint8(i) >> 2]
    result += map[((view.getUint8(i) & 3) << 4) | (view.getUint8(i + 1) >> 4)]
    result += map[((view.getUint8(i + 1) & 15) << 2) | (view.getUint8(i + 2) >> 6)]
    result += map[view.getUint8(i + 2) & 63]
  }

  if (i === view.byteLength - 2) {
    result += map[view.getUint8(i) >> 2]
    result += map[((view.getUint8(i) & 3) << 4) | (view.getUint8(i + 1) >> 4)]
    result += map[(view.getUint8(i + 1) & 15) << 2]
    result += url ? '' : '='
  }
  else if (i === view.byteLength - 1) {
    result += map[view.getUint8(i) >> 2]
    result += map[(view.getUint8(i) & 3) << 4]
    result += url ? '' : '=='
  }
  return result
}
