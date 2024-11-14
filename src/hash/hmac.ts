import type { Hash, HashDescription } from '../core/hash'
import { createHash } from '../core/hash'
import { joinBuffer, wrap } from '../core/utils'

export interface HMAC {
  (hash: Hash): HashDescription & {
    (K: Uint8Array): Hash
  }
  ALGORITHM: string
}

function _hmac(hash: Hash, K: Uint8Array, M: Uint8Array) {
  const { BLOCK_SIZE } = hash

  const K0 = new Uint8Array(BLOCK_SIZE)
  K0.set(K.byteLength > BLOCK_SIZE ? hash(K) : K)
  const iPad = K0.map(byte => (byte ^ 0x36))
  const oPad = K0.map(byte => (byte ^ 0x5C))

  const innerBuffer = hash(joinBuffer(iPad, M))
  const outerBuffer = hash(joinBuffer(oPad, innerBuffer))

  return outerBuffer
}

/**
 * @description
 * FIPS.198-1: The Keyed-Hash Message Authentication Code (HMAC).
 *
 * FIPS.198-1: 散列消息认证码 (HMAC).
 *
 * @param {HMACConfig} scheme - HMAC scheme
 */
export const hmac: HMAC = wrap(
  (hash: Hash) => {
    const { ALGORITHM, BLOCK_SIZE, DIGEST_SIZE } = hash
    const description: HashDescription = {
      ALGORITHM: `HMAC-${ALGORITHM}`,
      BLOCK_SIZE,
      DIGEST_SIZE,
    }
    return wrap(
      (K: Uint8Array) => createHash((M: Uint8Array) => _hmac(hash, K, M), description),
      description,
    )
  },
  {
    ALGORITHM: 'HMAC',
  },
)
