import { Fp } from '../../core/ec'
import { curve25519, curve448 } from '../../core/ecParams'
import { KitError, U8, genRandomBI, getBIBits } from '../../core/utils'

// * Interfaces

export interface X25519PrivateKey<T = bigint | Uint8Array> {
  /** 私钥 / Private Key */
  d: T
}
export interface X25519PublicKey<T = bigint | Uint8Array> {
  /** 公钥 / Public Key */
  Q: T
}
export interface X25519KeyPair<T = bigint | Uint8Array> extends X25519PrivateKey<T>, X25519PublicKey<T> {
}

export interface X448PrivateKey<T = bigint | Uint8Array> extends X25519PrivateKey<T> {
}
export interface X448PublicKey<T = bigint | Uint8Array> extends X25519PublicKey<T> {
}
export interface X448KeyPair<T = bigint | Uint8Array> extends X25519KeyPair<T> {
}

export interface X25519 {
  /**
   * 生成 x25519 椭圆曲线密钥
   *
   * Generate x25519 Elliptic Curve Key
   */
  gen: {
    /** 生成密钥对 / Generate Key Pair */
    (type?: 'key_pair'): X25519KeyPair<U8>
    /** 生成私钥 / Generate Private Key */
    (type: 'private_key'): X25519PrivateKey<U8>
    /** 生成公钥 / Generate Public Key */
    (type: 'public_key', s_key: X25519PrivateKey): X25519KeyPair<U8>
  }
  /**
   * x25519 椭圆曲线密钥协商算法
   *
   * x25519 Elliptic Curve Diffie-Hellman Key Agreement Algorithm
   */
  dh: {
    /**
     * @param {X25519PrivateKey} s_key - 己方私钥 / Self Private Key
     * @param {X25519PublicKey} p_key - 对方公钥 / Counterparty Public Key
     */
    (s_key: X25519PrivateKey, p_key: X25519PublicKey): U8
  }
}

export interface X448 {
  /**
   * 生成 x448 椭圆曲线密钥
   *
   * Generate x448 Elliptic Curve Key
   */
  gen: {
    /** 生成密钥对 / Generate Key Pair */
    (type?: 'key_pair'): X448KeyPair<U8>
    /** 生成私钥 / Generate Private Key */
    (type: 'private_key'): X448PrivateKey<U8>
    /** 生成公钥 / Generate Public Key */
    (type: 'public_key', s_key: X448PrivateKey): X448KeyPair<U8>
  }
  /**
   * x448 椭圆曲线密钥协商算法
   *
   * x448 Elliptic Curve Diffie-Hellman Key Agreement Algorithm
   */
  dh: {
    /**
     * @param {X448PrivateKey} s_key - 己方私钥 / Self Private Key
     * @param {X448PublicKey} p_key - 对方公钥 / Counterparty Public Key
     */
    (s_key: X448PrivateKey, p_key: X448PublicKey): U8
  }
}

// * X25519 & X448 Algorithms

function cSwap(swap: bigint, x_2: bigint, x_3: bigint) {
  const mask = -swap
  const dummy = mask & (x_2 ^ x_3)
  x_2 ^= dummy
  x_3 ^= dummy
  return [x_2, x_3]
}
/** 蒙哥马利梯子算法 / Montgomery Ladder Algorithm */
function ladder(k: bigint, u: bigint, p: bigint, a24: bigint, bit: number) {
  const { plus, subtract, pow, multiply } = Fp(p)
  let x_2 = 1n
  let z_2 = 0n
  let x_3 = u
  let z_3 = 1n
  let swap = 0n
  const bit_array = k.toString(2).padStart(bit, '0').split('').map(BigInt)
  for (const bit of bit_array) {
    swap ^= bit;
    [x_2, x_3] = cSwap(swap, x_2, x_3);
    [z_2, z_3] = cSwap(swap, z_2, z_3)
    swap = bit

    const A = plus(x_2, z_2)
    const AA = pow(A, 2n)
    const B = subtract(x_2, z_2)
    const BB = pow(B, 2n)
    const E = subtract(AA, BB)
    const C = plus(x_3, z_3)
    const D = subtract(x_3, z_3)
    const DA = multiply(D, A)
    const CB = multiply(C, B)
    x_3 = pow(plus(DA, CB), 2n)
    z_3 = multiply(u, pow(subtract(DA, CB), 2n))
    x_2 = multiply(AA, BB)
    z_2 = multiply(E, plus(AA, multiply(E, a24)))
  }
  [x_2, x_3] = cSwap(swap, x_2, x_3);
  [z_2, z_3] = cSwap(swap, z_2, z_3)
  return multiply(x_2, pow(z_2, p - 2n))
}

/** x25519 椭圆曲线算法 / Elliptic Curve Algorithm */
export const x25519: X25519 = (() => {
  const { p, G, n } = curve25519
  const p_bit = getBIBits(p)
  const p_byte = (p_bit + 7) >> 3

  const a24 = 121665n
  const Gx = typeof G.x === 'bigint' ? G.x : U8.from(G.x).toBI()

  function clamp(d: bigint) {
    d = d & 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF8n
    d = d | 0x4000000000000000000000000000000000000000000000000000000000000000n
    return d
  }
  function gen(type?: 'key_pair'): X25519KeyPair<U8>
  function gen(type: 'private_key'): X25519PrivateKey<U8>
  function gen(type: 'public_key', s_key: X25519PrivateKey): X25519KeyPair<U8>
  function gen(
    type: 'key_pair' | 'private_key' | 'public_key' = 'key_pair',
    s_key?: X25519PrivateKey,
  ) {
    if (type === 'key_pair') {
      // private key
      const t = genRandomBI(n, p_byte)
      const d_buffer = t.buffer
      const d = t.result
      // public key
      const x = ladder(clamp(d), Gx, p, a24, 255)
      const Q = U8.fromBI(x, p_byte)
      return { Q, d: d_buffer }
    }
    else if (type === 'private_key') {
      return { d: genRandomBI(n, p_byte).buffer }
    }
    else if (type === 'public_key') {
      const d_buffer = typeof s_key!.d === 'bigint' ? U8.fromBI(s_key!.d) : U8.from(s_key!.d)
      const d = typeof s_key!.d === 'bigint' ? s_key!.d : d_buffer.toBI()
      if (d === 0n) {
        throw new KitError('Invalid private key')
      }
      const x = ladder(clamp(d), Gx, p, a24, 255)
      const Q = U8.fromBI(x, p_byte)
      return { Q, d: d_buffer }
    }
  }
  const ecdh: X25519['dh'] = (s_key: X25519PrivateKey, p_key: X25519PublicKey): U8 => {
    const u = typeof p_key.Q === 'bigint' ? p_key.Q : U8.from(p_key.Q).toBI()
    const k = typeof s_key.d === 'bigint' ? s_key.d : U8.from(s_key.d).toBI()
    const x = ladder(clamp(k), u, p, a24, 255)
    return U8.fromBI(x, p_byte)
  }
  return { gen, dh: ecdh }
})()

/** x448 椭圆曲线算法 / Elliptic Curve Algorithm */
export const x448: X448 = (() => {
  const { p, G, n } = curve448
  const p_bit = getBIBits(p)
  const p_byte = (p_bit + 7) >> 3

  const a24 = 39081n
  const Gx = typeof G.x === 'bigint' ? G.x : U8.from(G.x).toBI()

  function clamp(d: bigint) {
    d = d & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFCn
    d = d | 0x8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000n
    return d
  }
  function gen(type?: 'key_pair'): X448KeyPair<U8>
  function gen(type: 'private_key'): X448PrivateKey<U8>
  function gen(type: 'public_key', s_key: X448PrivateKey): X448KeyPair<U8>
  function gen(
    type: 'key_pair' | 'private_key' | 'public_key' = 'key_pair',
    s_key?: X448PrivateKey,
  ) {
    if (type === 'key_pair') {
      // private key
      const t = genRandomBI(n, p_byte)
      const d_buffer = t.buffer
      const d = t.result
      // public key
      const x = ladder(clamp(d), Gx, p, a24, 448)
      const Q = U8.fromBI(x, p_byte)
      return { Q, d: d_buffer }
    }
    else if (type === 'private_key') {
      return { d: genRandomBI(n, p_byte).buffer }
    }
    else if (type === 'public_key') {
      const d_buffer = typeof s_key!.d === 'bigint' ? U8.fromBI(s_key!.d) : U8.from(s_key!.d)
      const d = typeof s_key!.d === 'bigint' ? s_key!.d : d_buffer.toBI()
      if (d === 0n) {
        throw new KitError('Invalid private key')
      }
      const x = ladder(clamp(d), Gx, p, a24, 448)
      const Q = U8.fromBI(x, p_byte)
      return { Q, d: d_buffer }
    }
  }
  const ecdh: X448['dh'] = (s_key: X448PrivateKey, p_key: X448PublicKey): U8 => {
    const u = typeof p_key.Q === 'bigint' ? p_key.Q : U8.from(p_key.Q).toBI()
    const k = typeof s_key.d === 'bigint' ? s_key.d : U8.from(s_key.d).toBI()
    const x = ladder(clamp(k), u, p, a24, 448)
    return U8.fromBI(x, p_byte)
  }
  return { gen, dh: ecdh }
})()
