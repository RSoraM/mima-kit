import { KitError } from './utils'

/**
 * @description
 * Codec interface provides two methods: parse and stringify
 *
 * 编解码器接口提供两个方法：parse 和 stringify
 *
 * @example
 * ```ts
 * codec.parse('') // Uint8Array
 * codec.stringify(new Uint8Array()) // string
 * ```
 */
export interface Codec {
  /**
   * @description
   * Parse encoded string to Uint8Array
   *
   * 将编码字符串解析为 Uint8Array
   *
   * @param {string} input - 输入字符串
   */
  parse: (input: string) => Uint8Array

  /**
   * @description
   * Stringify Uint8Array to encoded string
   *
   * 将 Uint8Array 编码为字符串
   *
   * @param {Uint8Array} input - 输入 Uint8Array
   */
  stringify: (input: Uint8Array) => string
  FORMAT: string
}

/**
 * @description
 * Utf8 codec provides conversion between Utf8 string and Uint8Array
 *
 * Utf8 编解码器提供 UTF-8 字符串 与 Uint8Array 相互转换
 *
 * @example
 * ```ts
 * Utf8.parse('hello') // Uint8Array(5) [ 104, 101, 108, 108, 111 ]
 * Utf8.stringify(new Uint8Array([ 104, 101, 108, 108, 111 ])) // 'hello'
 * ```
 */
export const UTF8: Codec = {
  parse(input: string) {
    return new TextEncoder().encode(input)
  },
  stringify(input: Uint8Array) {
    return new TextDecoder('utf-8').decode(input)
  },
  FORMAT: 'utf-8',
}

/**
 * @description
 * Hex codec provides conversion between Hex string and Uint8Array
 *
 * Hex 编解码器提供 HEX 字符串 与 Uint8Array 相互转换
 *
 * @example
 * ```ts
 * Hex.parse('deadbeef') // Uint8Array(4) [ 222, 173, 190, 239 ]
 * Hex.stringify(new Uint8Array([ 222, 173, 190, 239 ])) // 'deadbeef'
 * ```
 */
export const HEX: Codec = {
  parse(input: string) {
    const arr = input.match(/[\da-f]{2}/gi)
    if (arr == null) {
      return new Uint8Array()
    }
    return new Uint8Array(arr.map(h => Number.parseInt(h, 16)))
  },
  stringify(input: Uint8Array) {
    const view = new DataView(input.buffer)
    let result = ''
    for (let i = 0; i < view.byteLength; i++) {
      result += view.getUint8(i).toString(16).padStart(2, '0')
    }
    return result
  },
  FORMAT: 'hex',
}

/**
 * @description
 * B64 codec provides conversion between Base64 string and Uint8Array
 *
 * B64 编解码器提供 Base64 字符串 与 Uint8Array 相互转换
 *
 * @example
 * ```ts
 * B64.parse('aGVsbG8=') // Uint8Array(5) [ 104, 101, 108, 108, 111 ]
 * B64.stringify(new Uint8Array([ 104, 101, 108, 108, 111 ])) // 'aGVsbG8='
 * ```
 */
export const B64: Codec = {
  parse(input: string) {
    return B64CommonParse(input, false)
  },
  stringify(input: Uint8Array) {
    return B64CommonStringify(input, false)
  },
  FORMAT: 'base64',
}

/**
 * @description
 * B64url codec provides conversion between Base64url string and Uint8Array
 *
 * B64url 编解码器提供 Base64url 字符串 与 Uint8Array 相互转换
 *
 * @example
 * ```ts
 * B64url.parse('aGVsbG8') // Uint8Array(5) [ 104, 101, 108, 108, 111 ]
 * B64url.stringify(new Uint8Array([ 104, 101, 108, 108, 111 ])) // 'aGVsbG8'
 * ```
 */
export const B64URL: Codec = {
  parse(input: string) {
    return B64CommonParse(input, true)
  },
  stringify(input: Uint8Array) {
    return B64.stringify(input).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
  },
  FORMAT: 'base64url',
}

/**
 * @description
 * B64CommonParse can parse B64 or B64url string to Uint8Array
 *
 * B64CommonParse 可以将 B64 或者 B64url 字符串解析为 Uint8Array
 *
 * @param {string} input - B64 或 B64url 字符串
 * @param {boolean} url - 是否是 B64url 字符串
 */
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

/**
 * @description
 * B64CommonStringify can stringify Uint8Array to B64 or B64url string
 *
 * B64CommonStringify 可以将 Uint8Array 编码为 B64 或 B64url 字符串
 *
 * @param {Uint8Array} input - Uint8Array
 * @param {boolean} url - 是否是 B64url 字符串
 */
function B64CommonStringify(input: Uint8Array, url: boolean) {
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

/**
 * @description
 * Core Socialist Values codec
 *
 * 社会主义核心价值观编解码器
 */
export const CSV: Codec = {
  parse(input: string) {
    const coreValueMap = new Map<string, number>()
    coreValueMap.set('富强', 0)
    coreValueMap.set('民主', 1)
    coreValueMap.set('文明', 2)
    coreValueMap.set('和谐', 3)
    coreValueMap.set('自由', 4)
    coreValueMap.set('平等', 5)
    coreValueMap.set('公正', 6)
    coreValueMap.set('法治', 7)
    coreValueMap.set('爱国', 8)
    coreValueMap.set('敬业', 9)
    coreValueMap.set('诚信', 10)
    coreValueMap.set('友善', 11)

    const from = (value: string) => {
      const nibble = coreValueMap.get(value)
      if (nibble === undefined) {
        throw new KitError('你竟然在社会主义核心价值观里夹带私货！')
      }
      return nibble
    }

    const coreValues = input.match(/(\S){2}/g)
    if (coreValues == null) {
      return new Uint8Array()
    }

    let h = 0
    let l = 0
    let count = 0
    const result: number[] = []
    for (let i = 0; i < coreValues.length; i++) {
      const isHigh = count % 2 === 0

      let nibble = from(coreValues[i])
      if (nibble === 10 || nibble === 11) {
        i++
        if (i === coreValues.length) {
          throw new KitError('你的社会主义核心价值观破碎了！')
        }
        nibble = nibble === 10
          ? 10 + from(coreValues[i])
          : 6 + from(coreValues[i])
      }
      isHigh ? h = nibble : l = nibble

      if (!isHigh) {
        result.push(((h << 4) | l) & 0xFF)
      }
      count++
    }

    return new Uint8Array(result)
  },
  stringify(input: Uint8Array) {
    const rand = () => Math.random() >= 0.5
    const map = ['富强', '民主', '文明', '和谐', '自由', '平等', '公正', '法治', '爱国', '敬业', '诚信', '友善']

    let result = ''
    input.forEach((byte) => {
      const h = (byte >> 4) & 0xF
      const l = byte & 0xF
      h < 10
        ? result += map[h]
        : rand()
          ? result += map[10] + map[h - 10]
          : result += map[11] + map[h - 6]
      l < 10
        ? result += map[l]
        : rand()
          ? result += map[10] + map[l - 10]
          : result += map[11] + map[l - 6]
    })

    return result
  },
  FORMAT: 'core-socialist-values',
}
