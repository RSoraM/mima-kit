// * Codec

export interface Codec {
  parse: (input: string) => Uint8Array
  stringify: (input: ArrayBufferLike) => string
}

// * Utf8 Codec

export const Utf8: Codec = {
  parse(Utf8String) {
    return new TextEncoder().encode(Utf8String)
  },
  stringify(buffer) {
    return new TextDecoder('utf-8').decode(buffer)
  },
}

// * Hex Codec

export const Hex: Codec = {
  parse(HexString) {
    const arr = HexString.match(/[\da-f]{2}/gi)
    if (arr == null) {
      return new Uint8Array()
    }
    return new Uint8Array(arr.map(h => Number.parseInt(h, 16)))
  },
  stringify(buffer) {
    const view = new DataView(new Uint8Array(buffer).buffer)
    let result = ''
    for (let i = 0; i < view.byteLength; i++) {
      result += view.getUint8(i).toString(16).padStart(2, '0')
    }
    return result
  },
}

// * B64 Codec

export const B64: Codec = {
  parse(B64String) {
    return B64CommonParse(B64String, false)
  },
  stringify(buffer) {
    return B64CommonStringify(buffer, false)
  },
}

export const B64url: Codec = {
  parse(B64urlString) {
    return B64CommonParse(B64urlString, true)
  },
  stringify(buffer) {
    return B64.stringify(buffer).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
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

/** stringify ArrayBuffer to b64 string */
export function B64CommonStringify(buffer: ArrayBufferLike, url: boolean) {
  const view = new DataView(new Uint8Array(buffer).buffer)

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
