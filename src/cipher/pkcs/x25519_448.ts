import { curve25519, curve448 } from '../../core/ecParams'
import { KitError } from '../../core/utils'
import type { ECDH, ECKeyPair, ECPrivateKey, ECPublicKey, FpECCrypto } from './ecc'
import { FpECC } from './ecc'

// * X25519 & X448

interface X25519 {
  /**
   * 生成 x25519 椭圆曲线密钥
   *
   * Generate x25519 Elliptic Curve Key
   */
  gen: FpECCrypto['gen']
  /**
   * x25519 椭圆曲线密钥协商算法
   *
   * x25519 Elliptic Curve Diffie-Hellman Key Agreement Algorithm
   */
  ecdh: ECDH
}

interface X448 {
  /**
   * 生成 x25519 椭圆曲线密钥
   *
   * Generate x25519 Elliptic Curve Key
   */
  gen: FpECCrypto['gen']
  /**
   * x25519 椭圆曲线密钥协商算法
   *
   * x25519 Elliptic Curve Diffie-Hellman Key Agreement Algorithm
   */
  ecdh: ECDH
}

/**
 * x25519 椭圆曲线算法 / Elliptic Curve Algorithm
 */
export const x25519: X25519 = (() => {
  const { G } = curve25519
  const ec = FpECC(curve25519)
  const { mulPoint } = ec.utils

  function clamp(d: bigint) {
    d = d & 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF8n
    d = d | 0x4000000000000000000000000000000000000000000000000000000000000000n
    return d
  }

  function gen(type?: 'key_pair'): ECKeyPair
  function gen(type: 'private_key'): ECPrivateKey
  function gen(type: 'public_key', s_key: ECPrivateKey): ECKeyPair
  function gen(
    type: 'key_pair' | 'private_key' | 'public_key' = 'key_pair',
    s_key?: ECPrivateKey,
  ) {
    let d = 0n
    if (type === 'key_pair') {
      // private key
      d = ec.gen('private_key').d
      // public key
      const Q = mulPoint(G, clamp(d))
      return { Q, d }
    }
    else if (type === 'private_key') {
      d = ec.gen('private_key').d
      return { d }
    }
    else if (type === 'public_key') {
      d = s_key?.d ?? 0n
      if (d === 0n) {
        throw new KitError('Invalid private key')
      }
      const Q = mulPoint(G, clamp(d))
      return { Q, d }
    }
  }

  const ecdh: ECDH = (s_key: ECPrivateKey, p_key: ECPublicKey) => {
    const Q = p_key.Q
    const d = s_key.d
    const S = mulPoint(Q, clamp(d))
    if (S.isInfinity) {
      throw new KitError('the result of ECDH is the point at infinity')
    }
    return S
  }
  return { gen, ecdh }
})()

/**
 * x448 椭圆曲线算法 / Elliptic Curve Algorithm
 */
export const x448: X448 = (() => {
  const { G } = curve448
  const ec = FpECC(curve448)
  const { mulPoint } = ec.utils

  function clamp(d: bigint) {
    d = d & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFCn
    d = d | 0x8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000n
    return d
  }

  function gen(type?: 'key_pair'): ECKeyPair
  function gen(type: 'private_key'): ECPrivateKey
  function gen(type: 'public_key', s_key: ECPrivateKey): ECKeyPair
  function gen(
    type: 'key_pair' | 'private_key' | 'public_key' = 'key_pair',
    s_key?: ECPrivateKey,
  ) {
    let d = 0n
    if (type === 'key_pair') {
      // private key
      d = ec.gen('private_key').d
      // public key
      const Q = mulPoint(G, clamp(d))
      return { Q, d }
    }
    else if (type === 'private_key') {
      d = ec.gen('private_key').d
      return { d }
    }
    else if (type === 'public_key') {
      d = s_key?.d ?? 0n
      if (d === 0n) {
        throw new KitError('Invalid private key')
      }
      const Q = mulPoint(G, clamp(d))
      return { Q, d }
    }
  }

  const ecdh: ECDH = (s_key: ECPrivateKey, p_key: ECPublicKey) => {
    const Q = p_key.Q
    const d = s_key.d
    const S = mulPoint(Q, clamp(d))
    if (S.isInfinity) {
      throw new KitError('the result of ECDH is the point at infinity')
    }
    return S
  }
  return { gen, ecdh }
})()
