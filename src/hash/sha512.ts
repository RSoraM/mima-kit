import { UTF8 } from '../core/codec';
import { createHash } from '../core/hash';
import { genBitMask, KitError, rotateR, U8 } from '../core/utils';

// * Constants

const K = new BigUint64Array([
  0x428a2f98d728ae22n,
  0x7137449123ef65cdn,
  0xb5c0fbcfec4d3b2fn,
  0xe9b5dba58189dbbcn,
  0x3956c25bf348b538n,
  0x59f111f1b605d019n,
  0x923f82a4af194f9bn,
  0xab1c5ed5da6d8118n,
  0xd807aa98a3030242n,
  0x12835b0145706fben,
  0x243185be4ee4b28cn,
  0x550c7dc3d5ffb4e2n,
  0x72be5d74f27b896fn,
  0x80deb1fe3b1696b1n,
  0x9bdc06a725c71235n,
  0xc19bf174cf692694n,
  0xe49b69c19ef14ad2n,
  0xefbe4786384f25e3n,
  0x0fc19dc68b8cd5b5n,
  0x240ca1cc77ac9c65n,
  0x2de92c6f592b0275n,
  0x4a7484aa6ea6e483n,
  0x5cb0a9dcbd41fbd4n,
  0x76f988da831153b5n,
  0x983e5152ee66dfabn,
  0xa831c66d2db43210n,
  0xb00327c898fb213fn,
  0xbf597fc7beef0ee4n,
  0xc6e00bf33da88fc2n,
  0xd5a79147930aa725n,
  0x06ca6351e003826fn,
  0x142929670a0e6e70n,
  0x27b70a8546d22ffcn,
  0x2e1b21385c26c926n,
  0x4d2c6dfc5ac42aedn,
  0x53380d139d95b3dfn,
  0x650a73548baf63den,
  0x766a0abb3c77b2a8n,
  0x81c2c92e47edaee6n,
  0x92722c851482353bn,
  0xa2bfe8a14cf10364n,
  0xa81a664bbc423001n,
  0xc24b8b70d0f89791n,
  0xc76c51a30654be30n,
  0xd192e819d6ef5218n,
  0xd69906245565a910n,
  0xf40e35855771202an,
  0x106aa07032bbd1b8n,
  0x19a4c116b8d2d0c8n,
  0x1e376c085141ab53n,
  0x2748774cdf8eeb99n,
  0x34b0bcb5e19b48a8n,
  0x391c0cb3c5c95a63n,
  0x4ed8aa4ae3418acbn,
  0x5b9cca4f7763e373n,
  0x682e6ff3d6b2b8a3n,
  0x748f82ee5defb2fcn,
  0x78a5636f43172f60n,
  0x84c87814a1f0ab72n,
  0x8cc702081a6439ecn,
  0x90befffa23631e28n,
  0xa4506cebde82bde9n,
  0xbef9a3f7b2c67915n,
  0xc67178f2e372532bn,
  0xca273eceea26619cn,
  0xd186b8c721c0c207n,
  0xeada7dd6cde0eb1en,
  0xf57d4f7fee6ed178n,
  0x06f067aa72176fban,
  0x0a637dc5a2c898a6n,
  0x113f9804bef90daen,
  0x1b710b35131c471bn,
  0x28db77f523047d84n,
  0x32caab7b40c72493n,
  0x3c9ebe0a15c9bebcn,
  0x431d67c49c100d4cn,
  0x4cc5d4becb3e42b6n,
  0x597f299cfc657e2an,
  0x5fcb6fab3ad6faecn,
  0x6c44198c4a475817n,
]);

// * Function
const mask64 = genBitMask(64);
const rotateR64 = (x: bigint, n: bigint) => rotateR(64, x, n, mask64);

const Ch = (x: bigint, y: bigint, z: bigint) => (x & y) ^ (~x & z);
const Maj = (x: bigint, y: bigint, z: bigint) => (x & y) ^ (x & z) ^ (y & z);
const Sigma0 = (x: bigint) => rotateR64(x, 28n) ^ rotateR64(x, 34n) ^ rotateR64(x, 39n);
const Sigma1 = (x: bigint) => rotateR64(x, 14n) ^ rotateR64(x, 18n) ^ rotateR64(x, 41n);
const sigma0 = (x: bigint) => rotateR64(x, 1n) ^ rotateR64(x, 8n) ^ (x >> 7n);
const sigma1 = (x: bigint) => rotateR64(x, 19n) ^ rotateR64(x, 61n) ^ (x >> 6n);

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
    throw new KitError('SHA-512 truncation must be greater than 0');
  }
  if (t >= 512) {
    throw new KitError('SHA-512 truncation must be less than 512');
  }
  if (t === 384) {
    throw new KitError('SHA-512 truncation must not be 384');
  }

  const state = new U8(64);
  const state_view = state.view(8);
  state_view.set(0, 0x6a09e667f3bcc908n ^ 0xa5a5a5a5a5a5a5a5n);
  state_view.set(1, 0xbb67ae8584caa73bn ^ 0xa5a5a5a5a5a5a5a5n);
  state_view.set(2, 0x3c6ef372fe94f82bn ^ 0xa5a5a5a5a5a5a5a5n);
  state_view.set(3, 0xa54ff53a5f1d36f1n ^ 0xa5a5a5a5a5a5a5a5n);
  state_view.set(4, 0x510e527fade682d1n ^ 0xa5a5a5a5a5a5a5a5n);
  state_view.set(5, 0x9b05688c2b3e6c1fn ^ 0xa5a5a5a5a5a5a5a5n);
  state_view.set(6, 0x1f83d9abfb41bd6bn ^ 0xa5a5a5a5a5a5a5a5n);
  state_view.set(7, 0x5be0cd19137e2179n ^ 0xa5a5a5a5a5a5a5a5n);

  return digest(state, UTF8(`SHA-512/${t}`));
}

// * Algorithm

function digest(state: U8, message: Uint8Array) {
  // * 初始化
  state = state.slice(0);
  const state_view = state.view(8);

  const m_byte = message.byteLength;
  const m_bit = BigInt(m_byte) << 3n;
  const block_size = 128;
  // ceil((m_byte + 17) / 128)
  const block_total = (m_byte + 17 + 127) >> 7;

  // * 填充
  const p = new U8(block_total * block_size);
  p.set(message);

  // appending the bit '1' to the message
  p[m_byte] = 0x80;

  // appending length
  const p_view = new DataView(p.buffer);
  p_view.setBigUint64(p.byteLength - 16, m_bit >> 32n);
  p_view.setBigUint64(p.byteLength - 8, m_bit & 0xffffffffffffffffn);

  // * 分块处理
  for (let offset = 0; offset < p.length; offset += block_size) {
    /** B(n) = p[offset:offset + block_size] */

    // 准备状态字
    const H0 = state_view.get(0);
    const H1 = state_view.get(1);
    const H2 = state_view.get(2);
    const H3 = state_view.get(3);
    const H4 = state_view.get(4);
    const H5 = state_view.get(5);
    const H6 = state_view.get(6);
    const H7 = state_view.get(7);
    let a = H0;
    let b = H1;
    let c = H2;
    let d = H3;
    let e = H4;
    let f = H5;
    let g = H6;
    let h = H7;

    // 合并执行 扩展 & 压缩
    const W = new BigUint64Array(80);
    for (let i = 0; i < W.length; i++) {
      // 扩展
      if (i < 16)
        // W[i] = B(n)[i]
        W[i] = p_view.getBigUint64(offset + (i << 3));
      else W[i] = sigma1(W[i - 2]) + W[i - 7] + sigma0(W[i - 15]) + W[i - 16];

      // 压缩
      const T1 = h + Sigma1(e) + Ch(e, f, g) + K[i] + W[i];
      const T2 = Sigma0(a) + Maj(a, b, c);
      h = g;
      g = f;
      f = e;
      e = (d + T1) & 0xffffffffffffffffn;
      d = c;
      c = b;
      b = a;
      a = (T1 + T2) & 0xffffffffffffffffn;
    }

    // 更新状态字
    state_view.set(0, H0 + a);
    state_view.set(1, H1 + b);
    state_view.set(2, H2 + c);
    state_view.set(3, H3 + d);
    state_view.set(4, H4 + e);
    state_view.set(5, H5 + f);
    state_view.set(6, H6 + g);
    state_view.set(7, H7 + h);
  }

  // * 返回状态
  return state;
}

function sha384Digest(M: Uint8Array) {
  // * 初始化 SHA-384 状态
  const state = new U8(64);
  const state_view = state.view(8);
  state_view.set(0, 0xcbbb9d5dc1059ed8n);
  state_view.set(1, 0x629a292a367cd507n);
  state_view.set(2, 0x9159015a3070dd17n);
  state_view.set(3, 0x152fecd8f70e5939n);
  state_view.set(4, 0x67332667ffc00b31n);
  state_view.set(5, 0x8eb44a8768581511n);
  state_view.set(6, 0xdb0c2e0d64f98fa7n);
  state_view.set(7, 0x47b5481dbefa4fa4n);

  return digest(state, M).slice(0, 48);
}

function sha512Digest(M: Uint8Array) {
  // * 初始化 SHA-512 状态
  const state = new U8(64);
  const state_view = state.view(8);
  state_view.set(0, 0x6a09e667f3bcc908n);
  state_view.set(1, 0xbb67ae8584caa73bn);
  state_view.set(2, 0x3c6ef372fe94f82bn);
  state_view.set(3, 0xa54ff53a5f1d36f1n);
  state_view.set(4, 0x510e527fade682d1n);
  state_view.set(5, 0x9b05688c2b3e6c1fn);
  state_view.set(6, 0x1f83d9abfb41bd6bn);
  state_view.set(7, 0x5be0cd19137e2179n);

  return digest(state, M);
}

export const sha384 = createHash(sha384Digest, {
  ALGORITHM: 'SHA-384',
  BLOCK_SIZE: 128,
  DIGEST_SIZE: 48,
  OID: '2.16.840.1.101.3.4.2.2',
});

export const sha512 = createHash(sha512Digest, {
  ALGORITHM: 'SHA-512',
  BLOCK_SIZE: 128,
  DIGEST_SIZE: 64,
  OID: '2.16.840.1.101.3.4.2.3',
});

/**
 * @param {number} t - 截断长度 / truncation length (bit)
 */
export function sha512t(t: number) {
  // * 初始化 SHA-512/t 状态
  const status = IVGen(t);

  let OID: string | undefined;
  if (t === 224) OID = '2.16.840.1.101.3.4.2.5';
  if (t === 256) OID = '2.16.840.1.101.3.4.2.6';

  return createHash((M: Uint8Array) => digest(status, M).slice(0, t >> 3), {
    ALGORITHM: `SHA-512/${t}`,
    BLOCK_SIZE: 128,
    DIGEST_SIZE: t >> 3,
    OID,
  });
}
