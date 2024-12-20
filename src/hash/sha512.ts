import { UTF8 } from '../core/codec'
import { createHash } from '../core/hash'
import { KitError, U8, genBitMask, rotateR } from '../core/utils'

// * Constants

const K = new BigUint64Array([0x428A2F98D728AE22n, 0x7137449123EF65CDn, 0xB5C0FBCFEC4D3B2Fn, 0xE9B5DBA58189DBBCn, 0x3956C25BF348B538n, 0x59F111F1B605D019n, 0x923F82A4AF194F9Bn, 0xAB1C5ED5DA6D8118n, 0xD807AA98A3030242n, 0x12835B0145706FBEn, 0x243185BE4EE4B28Cn, 0x550C7DC3D5FFB4E2n, 0x72BE5D74F27B896Fn, 0x80DEB1FE3B1696B1n, 0x9BDC06A725C71235n, 0xC19BF174CF692694n, 0xE49B69C19EF14AD2n, 0xEFBE4786384F25E3n, 0x0FC19DC68B8CD5B5n, 0x240CA1CC77AC9C65n, 0x2DE92C6F592B0275n, 0x4A7484AA6EA6E483n, 0x5CB0A9DCBD41FBD4n, 0x76F988DA831153B5n, 0x983E5152EE66DFABn, 0xA831C66D2DB43210n, 0xB00327C898FB213Fn, 0xBF597FC7BEEF0EE4n, 0xC6E00BF33DA88FC2n, 0xD5A79147930AA725n, 0x06CA6351E003826Fn, 0x142929670A0E6E70n, 0x27B70A8546D22FFCn, 0x2E1B21385C26C926n, 0x4D2C6DFC5AC42AEDn, 0x53380D139D95B3DFn, 0x650A73548BAF63DEn, 0x766A0ABB3C77B2A8n, 0x81C2C92E47EDAEE6n, 0x92722C851482353Bn, 0xA2BFE8A14CF10364n, 0xA81A664BBC423001n, 0xC24B8B70D0F89791n, 0xC76C51A30654BE30n, 0xD192E819D6EF5218n, 0xD69906245565A910n, 0xF40E35855771202An, 0x106AA07032BBD1B8n, 0x19A4C116B8D2D0C8n, 0x1E376C085141AB53n, 0x2748774CDF8EEB99n, 0x34B0BCB5E19B48A8n, 0x391C0CB3C5C95A63n, 0x4ED8AA4AE3418ACBn, 0x5B9CCA4F7763E373n, 0x682E6FF3D6B2B8A3n, 0x748F82EE5DEFB2FCn, 0x78A5636F43172F60n, 0x84C87814A1F0AB72n, 0x8CC702081A6439ECn, 0x90BEFFFA23631E28n, 0xA4506CEBDE82BDE9n, 0xBEF9A3F7B2C67915n, 0xC67178F2E372532Bn, 0xCA273ECEEA26619Cn, 0xD186B8C721C0C207n, 0xEADA7DD6CDE0EB1En, 0xF57D4F7FEE6ED178n, 0x06F067AA72176FBAn, 0x0A637DC5A2C898A6n, 0x113F9804BEF90DAEn, 0x1B710B35131C471Bn, 0x28DB77F523047D84n, 0x32CAAB7B40C72493n, 0x3C9EBE0A15C9BEBCn, 0x431D67C49C100D4Cn, 0x4CC5D4BECB3E42B6n, 0x597F299CFC657E2An, 0x5FCB6FAB3AD6FAECn, 0x6C44198C4A475817n])

// * Function
const mask64 = genBitMask(64)
const rotateR64 = (x: bigint, n: bigint) => rotateR(64, x, n, mask64)

const Ch = (x: bigint, y: bigint, z: bigint) => (x & y) ^ ((~x) & z)
const Maj = (x: bigint, y: bigint, z: bigint) => (x & y) ^ (x & z) ^ (y & z)
const Sigma0 = (x: bigint) => rotateR64(x, 28n) ^ rotateR64(x, 34n) ^ rotateR64(x, 39n)
const Sigma1 = (x: bigint) => rotateR64(x, 14n) ^ rotateR64(x, 18n) ^ rotateR64(x, 41n)
const sigma0 = (x: bigint) => rotateR64(x, 1n) ^ rotateR64(x, 8n) ^ (x >> 7n)
const sigma1 = (x: bigint) => rotateR64(x, 19n) ^ rotateR64(x, 61n) ^ (x >> 6n)

/**
 * SHA-512/t IV 生成函数 / generator
 *
 * ```ts
 * (0 < t < 512) && (t !== 384)
 * ```
 *
 * @param {number} t - 截断长度 / truncation length (bit)
 */
function IVGen(t: number) {
  if (t <= 0) {
    throw new KitError('SHA-512 truncation must be greater than 0')
  }
  if (t >= 512) {
    throw new KitError('SHA-512 truncation must be less than 512')
  }
  if (t === 384) {
    throw new KitError('SHA-512 truncation must not be 384')
  }

  const state = new U8(64)
  const state_view = state.view(8)
  state_view.set(0, 0x6A09E667F3BCC908n ^ 0xA5A5A5A5A5A5A5A5n)
  state_view.set(1, 0xBB67AE8584CAA73Bn ^ 0xA5A5A5A5A5A5A5A5n)
  state_view.set(2, 0x3C6EF372FE94F82Bn ^ 0xA5A5A5A5A5A5A5A5n)
  state_view.set(3, 0xA54FF53A5F1D36F1n ^ 0xA5A5A5A5A5A5A5A5n)
  state_view.set(4, 0x510E527FADE682D1n ^ 0xA5A5A5A5A5A5A5A5n)
  state_view.set(5, 0x9B05688C2B3E6C1Fn ^ 0xA5A5A5A5A5A5A5A5n)
  state_view.set(6, 0x1F83D9ABFB41BD6Bn ^ 0xA5A5A5A5A5A5A5A5n)
  state_view.set(7, 0x5BE0CD19137E2179n ^ 0xA5A5A5A5A5A5A5A5n)

  return digest(state, UTF8(`SHA-512/${t}`))
}

// * Algorithm

function digest(state: U8, message: Uint8Array) {
  // * 初始化
  state = state.slice(0)
  const state_view = state.view(8)

  const m_byte = message.byteLength
  const m_bit = BigInt(m_byte) << 3n
  const block_size = 128
  // ceil((m_byte + 17) / 128)
  const block_total = (m_byte + 17 + 127) >> 7

  // * 填充
  const p = new U8(block_total * block_size)
  p.set(message)

  // appending the bit '1' to the message
  p[m_byte] = 0x80

  // appending length
  const p_view = new DataView(p.buffer)
  p_view.setBigUint64(p.byteLength - 16, m_bit >> 32n)
  p_view.setBigUint64(p.byteLength - 8, m_bit & 0xFFFFFFFFFFFFFFFFn)

  // * 分块处理
  for (let offset = 0; offset < p.length; offset += block_size) {
    /** B(n) = p[offset:offset + block_size] */

    // 准备状态字
    const H0 = state_view.get(0)
    const H1 = state_view.get(1)
    const H2 = state_view.get(2)
    const H3 = state_view.get(3)
    const H4 = state_view.get(4)
    const H5 = state_view.get(5)
    const H6 = state_view.get(6)
    const H7 = state_view.get(7)
    let a = H0
    let b = H1
    let c = H2
    let d = H3
    let e = H4
    let f = H5
    let g = H6
    let h = H7

    // 合并执行 扩展 & 压缩
    const W = new BigUint64Array(80)
    for (let i = 0; i < W.length; i++) {
      // 扩展
      if (i < 16)
        // W[i] = B(n)[i]
        W[i] = p_view.getBigUint64(offset + (i << 3))
      else
        W[i] = sigma1(W[i - 2]) + W[i - 7] + sigma0(W[i - 15]) + W[i - 16]

      // 压缩
      const T1 = h + Sigma1(e) + Ch(e, f, g) + K[i] + W[i]
      const T2 = Sigma0(a) + Maj(a, b, c)
      h = g
      g = f
      f = e
      e = (d + T1) & 0xFFFFFFFFFFFFFFFFn
      d = c
      c = b
      b = a
      a = (T1 + T2) & 0xFFFFFFFFFFFFFFFFn
    }

    // 更新状态字
    state_view.set(0, H0 + a)
    state_view.set(1, H1 + b)
    state_view.set(2, H2 + c)
    state_view.set(3, H3 + d)
    state_view.set(4, H4 + e)
    state_view.set(5, H5 + f)
    state_view.set(6, H6 + g)
    state_view.set(7, H7 + h)
  }

  // * 返回状态
  return state
}

function sha384Digest(M: Uint8Array) {
  // * 初始化 SHA-384 状态
  const state = new U8(64)
  const state_view = state.view(8)
  state_view.set(0, 0xCBBB9D5DC1059ED8n)
  state_view.set(1, 0x629A292A367CD507n)
  state_view.set(2, 0x9159015A3070DD17n)
  state_view.set(3, 0x152FECD8F70E5939n)
  state_view.set(4, 0x67332667FFC00B31n)
  state_view.set(5, 0x8EB44A8768581511n)
  state_view.set(6, 0xDB0C2E0D64F98FA7n)
  state_view.set(7, 0x47B5481DBEFA4FA4n)

  return digest(state, M).slice(0, 48)
}

function sha512Digest(M: Uint8Array) {
  // * 初始化 SHA-512 状态
  const state = new U8(64)
  const state_view = state.view(8)
  state_view.set(0, 0x6A09E667F3BCC908n)
  state_view.set(1, 0xBB67AE8584CAA73Bn)
  state_view.set(2, 0x3C6EF372FE94F82Bn)
  state_view.set(3, 0xA54FF53A5F1D36F1n)
  state_view.set(4, 0x510E527FADE682D1n)
  state_view.set(5, 0x9B05688C2B3E6C1Fn)
  state_view.set(6, 0x1F83D9ABFB41BD6Bn)
  state_view.set(7, 0x5BE0CD19137E2179n)

  return digest(state, M)
}

export const sha384 = createHash(
  sha384Digest,
  {
    ALGORITHM: 'SHA-384',
    BLOCK_SIZE: 128,
    DIGEST_SIZE: 48,
    OID: '2.16.840.1.101.3.4.2.2',
  },
)

export const sha512 = createHash(
  sha512Digest,
  {
    ALGORITHM: 'SHA-512',
    BLOCK_SIZE: 128,
    DIGEST_SIZE: 64,
    OID: '2.16.840.1.101.3.4.2.3',
  },
)

/**
 * @param {number} t - 截断长度 / truncation length (bit)
 */
export function sha512t(t: number) {
  // * 初始化 SHA-512/t 状态
  const status = IVGen(t)

  let OID: string | undefined
  if (t === 224)
    OID = '2.16.840.1.101.3.4.2.5'
  if (t === 256)
    OID = '2.16.840.1.101.3.4.2.6'

  return createHash(
    (M: Uint8Array) => digest(status, M).slice(0, t >> 3),
    {
      ALGORITHM: `SHA-512/${t}`,
      BLOCK_SIZE: 128,
      DIGEST_SIZE: t >> 3,
      OID,
    },
  )
}
