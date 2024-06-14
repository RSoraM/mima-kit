import type { Codec } from '../core/codec'
import { Hex, Utf8 } from '../core/codec'

export function md5(input: string, codec: Codec = Hex) {
  // TODO: Implement md5
  return codec.stringify(Utf8.parse(input))
}
