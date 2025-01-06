import { KitError, U8, wrap } from './utils'

/**
 * String Codec
 *
 * 字符编解码器
 */
export interface Codec {
  /**
   * Parse encoded string to Uint8Array
   *
   * 将编码字符串解析为 Uint8Array
   */
  (input: string): U8
  /**
   * Stringify Uint8Array to encoded string
   *
   * 将 Uint8Array 编码为字符串
   */
  (input: Uint8Array): string
  FORMAT: string
}
function createCodec(
  parse: (input: string) => U8,
  stringify: (input: Uint8Array) => string,
  format: string,
): Codec {
  function codec(input: string): U8
  function codec(input: Uint8Array): string
  function codec(input: string | Uint8Array) {
    if (typeof input === 'string') {
      return parse(input)
    }
    else {
      return stringify(input)
    }
  }
  return wrap(codec, { FORMAT: format })
}

function UTF8ToU8(input: string) {
  const utf8 = []
  for (let i = 0; i < input.length; i++) {
    const charCode = input.codePointAt(i) as number
    if (charCode < 0x80) {
      utf8.push(charCode)
    }
    else if (charCode < 0x800) {
      utf8.push(0xC0 | (charCode >> 6))
      utf8.push(0x80 | (charCode & 0x3F))
    }
    else if (charCode < 0x10000) {
      utf8.push(0xE0 | (charCode >> 12))
      utf8.push(0x80 | ((charCode >> 6) & 0x3F))
      utf8.push(0x80 | (charCode & 0x3F))
    }
    else if (charCode < 0x110000) {
      utf8.push(0xF0 | (charCode >> 18))
      utf8.push(0x80 | ((charCode >> 12) & 0x3F))
      utf8.push(0x80 | ((charCode >> 6) & 0x3F))
      utf8.push(0x80 | (charCode & 0x3F))
      i++
    }
  }
  return new U8(utf8)
}
function U8ToUTF8(input: Uint8Array) {
  const str = []
  let i = 0
  while (i < input.length) {
    const byte1 = input[i++]
    if (byte1 < 0x80) {
      str.push(String.fromCharCode(byte1))
    }
    else if (byte1 >= 0xC0 && byte1 < 0xE0) {
      const byte2 = input[i++]
      const codePoint = ((byte1 & 0x1F) << 6) | (byte2 & 0x3F)
      str.push(String.fromCharCode(codePoint))
    }
    else if (byte1 >= 0xE0 && byte1 < 0xF0) {
      const byte2 = input[i++]
      const byte3 = input[i++]
      const codePoint = ((byte1 & 0x0F) << 12) | ((byte2 & 0x3F) << 6) | (byte3 & 0x3F)
      str.push(String.fromCharCode(codePoint))
    }
    else if (byte1 >= 0xF0 && byte1 < 0xF8) {
      const byte2 = input[i++]
      const byte3 = input[i++]
      const byte4 = input[i++]
      const codePoint = ((byte1 & 0x07) << 18) | ((byte2 & 0x3F) << 12) | ((byte3 & 0x3F) << 6) | (byte4 & 0x3F)
      str.push(String.fromCodePoint(codePoint))
    }
  }
  return str.join('')
}
/**
 * utf-8 codec
 *
 * utf-8 编解码器
 */
export const UTF8 = createCodec(UTF8ToU8, U8ToUTF8, 'utf-8')

function HEXToU8(input: string) {
  const arr = input.match(/[\da-f]{2}/gi)
  if (arr == null) {
    return new U8()
  }
  return new U8(arr.map(h => Number.parseInt(h, 16)))
}
function U8ToHEX(input: Uint8Array) {
  let result = ''
  for (let i = 0; i < input.length; i++) {
    result += input[i].toString(16).padStart(2, '0')
  }
  return result
}
/**
 * hex codec
 *
 * hex 编解码器
 */
export const HEX = createCodec(HEXToU8, U8ToHEX, 'hex')

function B64ToU8(input: string) {
  return new U8(B64CommonParse(input, false))
}
function U8ToB64(input: Uint8Array) {
  return B64CommonStringify(input, false)
}
/**
 * base64 codec
 *
 * base64 编解码器
 */
export const B64 = createCodec(B64ToU8, U8ToB64, 'base64')

function B64URLToU8(input: string) {
  return new U8(B64CommonParse(input, true))
}
function U8ToB64URL(input: Uint8Array) {
  return B64(input).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
}
/**
 * base64url codec
 *
 * base64url 编解码器
 */
export const B64URL = createCodec(B64URLToU8, U8ToB64URL, 'base64url')

/**
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
  const base64Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
  input = input.replace(/[^A-Z0-9+/]/gi, '')

  const length = input.length * 0.75
  const uint8Array = new Uint8Array(length)

  let i = 0
  let j = 0
  while (i < input.length) {
    const a = base64Chars.indexOf(input.charAt(i++))
    const b = base64Chars.indexOf(input.charAt(i++))
    const c = base64Chars.indexOf(input.charAt(i++))
    const d = base64Chars.indexOf(input.charAt(i++))

    const combined = (a << 18) | (b << 12) | (c << 6) | d

    uint8Array[j++] = (combined >> 16) & 0xFF
    uint8Array[j++] = (combined >> 8) & 0xFF
    uint8Array[j++] = combined & 0xFF
  }
  return uint8Array
}

/**
 * B64CommonStringify can stringify Uint8Array to B64 or B64url string
 *
 * B64CommonStringify 可以将 Uint8Array 编码为 B64 或 B64url 字符串
 *
 * @param {Uint8Array} input - Uint8Array
 * @param {boolean} url - 是否是 B64url 字符串
 */
function B64CommonStringify(input: Uint8Array, url: boolean) {
  let map = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
  map += url ? '-_' : '+/'
  let result = ''
  let i: number
  for (i = 0; i < input.length - 2; i += 3) {
    result += map[input[i] >> 2]
    result += map[((input[i] & 3) << 4) | (input[i + 1] >> 4)]
    result += map[((input[i + 1] & 15) << 2) | (input[i + 2] >> 6)]
    result += map[input[i + 2] & 63]
  }

  if (i === input.length - 2) {
    result += map[input[i] >> 2]
    result += map[((input[i] & 3) << 4) | (input[i + 1] >> 4)]
    result += map[(input[i + 1] & 15) << 2]
    result += url ? '' : '='
  }
  else if (i === input.length - 1) {
    result += map[input[i] >> 2]
    result += map[(input[i] & 3) << 4]
    result += url ? '' : '=='
  }
  return result
}

function CSVToU8(input: string) {
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
    return new U8()
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
    if (isHigh) {
      h = nibble
    }
    else {
      l = nibble
    }

    if (!isHigh) {
      result.push(((h << 4) | l) & 0xFF)
    }
    count++
  }

  return new U8(result)
}
function U8ToCSV(input: Uint8Array) {
  const rand = () => Math.random() >= 0.5
  const map = ['富强', '民主', '文明', '和谐', '自由', '平等', '公正', '法治', '爱国', '敬业', '诚信', '友善']

  let result = ''
  input.forEach((byte) => {
    const h = (byte >> 4) & 0xF
    const l = byte & 0xF
    if (h < 10) {
      result += map[h]
    }
    else if (rand()) {
      result += map[11] + map[h - 6]
    }
    else {
      result += map[11] + map[h - 6]
    }

    if (l < 10) {
      result += map[l]
    }
    else if (rand()) {
      result += map[10] + map[l - 10]
    }
    else {
      result += map[11] + map[l - 6]
    }
  })

  return result
}
/**
 * Core Socialist Values codec
 *
 * 社会主义核心价值观编解码器
 */
export const CSV = createCodec(CSVToU8, U8ToCSV, 'core-socialist-values')
