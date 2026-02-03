import { createHash } from '../core/hash';
import { rotateR32, U8 } from '../core/utils';

// * Constants

const K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

// * Function

const Ch = (x: number, y: number, z: number) => (x & y) ^ (~x & z);
const Maj = (x: number, y: number, z: number) => (x & y) ^ (x & z) ^ (y & z);
const Sigma0 = (x: number) => rotateR32(x, 2) ^ rotateR32(x, 13) ^ rotateR32(x, 22);
const Sigma1 = (x: number) => rotateR32(x, 6) ^ rotateR32(x, 11) ^ rotateR32(x, 25);
const sigma0 = (x: number) => rotateR32(x, 7) ^ rotateR32(x, 18) ^ (x >>> 3);
const sigma1 = (x: number) => rotateR32(x, 17) ^ rotateR32(x, 19) ^ (x >>> 10);

// * Algorithm

function digest(state: U8, message: Uint8Array) {
  // * 初始化
  state = state.slice(0);
  const state_view = state.view(4);

  const m_byte = message.length;
  const m_bit = BigInt(m_byte) << 3n;
  const block_size = 64;
  // ceil((m_byte + 9) / 64)
  const block_total = (m_byte + 9 + 63) >> 6;

  // * 填充
  const p = new U8(block_total * block_size);
  p.set(message);

  // appending the bit '1' to the message
  p[m_byte] = 0x80;

  // appending length
  const p_view = new DataView(p.buffer);
  p_view.setBigUint64(p.length - 8, m_bit);

  // * 分块处理
  for (let offset = 0; offset < p.length; offset += block_size) {
    /** B(n) = p[offset:offset + block_size] */

    // 准备状态字
    const h0 = Number(state_view.get(0));
    const h1 = Number(state_view.get(1));
    const h2 = Number(state_view.get(2));
    const h3 = Number(state_view.get(3));
    const h4 = Number(state_view.get(4));
    const h5 = Number(state_view.get(5));
    const h6 = Number(state_view.get(6));
    const h7 = Number(state_view.get(7));
    let a = h0;
    let b = h1;
    let c = h2;
    let d = h3;
    let e = h4;
    let f = h5;
    let g = h6;
    let h = h7;

    // 合并执行 扩展 & 压缩
    const W = new Uint32Array(64);
    for (let i = 0; i < W.length; i++) {
      // 扩展
      if (i < 16)
        // W[i] = B(n)[i]
        W[i] = p_view.getUint32(offset + (i << 2));
      else W[i] = sigma1(W[i - 2]) + W[i - 7] + sigma0(W[i - 15]) + W[i - 16];

      // 压缩
      const T1 = h + Sigma1(e) + Ch(e, f, g) + K[i] + W[i];
      const T2 = Sigma0(a) + Maj(a, b, c);
      h = g;
      g = f;
      f = e;
      e = d + T1;
      d = c;
      c = b;
      b = a;
      a = T1 + T2;
    }

    // 更新状态字
    state_view.set(0, BigInt(h0 + a));
    state_view.set(1, BigInt(h1 + b));
    state_view.set(2, BigInt(h2 + c));
    state_view.set(3, BigInt(h3 + d));
    state_view.set(4, BigInt(h4 + e));
    state_view.set(5, BigInt(h5 + f));
    state_view.set(6, BigInt(h6 + g));
    state_view.set(7, BigInt(h7 + h));
  }

  // * 返回状态
  return state;
}

function sha224Digest(M: Uint8Array) {
  // * 初始化 SHA-224 状态
  const state = new U8(32);
  const state_view = state.view(4);
  state_view.set(0, 0xc1059ed8n);
  state_view.set(1, 0x367cd507n);
  state_view.set(2, 0x3070dd17n);
  state_view.set(3, 0xf70e5939n);
  state_view.set(4, 0xffc00b31n);
  state_view.set(5, 0x68581511n);
  state_view.set(6, 0x64f98fa7n);
  state_view.set(7, 0xbefa4fa4n);

  return digest(state, M).slice(0, 28);
}

function sha256Digest(M: Uint8Array) {
  // * 初始化 SHA-256 状态
  const state = new U8(32);
  const state_view = state.view(4);
  state_view.set(0, 0x6a09e667n);
  state_view.set(1, 0xbb67ae85n);
  state_view.set(2, 0x3c6ef372n);
  state_view.set(3, 0xa54ff53an);
  state_view.set(4, 0x510e527fn);
  state_view.set(5, 0x9b05688cn);
  state_view.set(6, 0x1f83d9abn);
  state_view.set(7, 0x5be0cd19n);

  return digest(state, M);
}

export const sha224 = createHash(sha224Digest, {
  ALGORITHM: 'SHA-224',
  BLOCK_SIZE: 64,
  DIGEST_SIZE: 28,
  OID: '2.16.840.1.101.3.4.2.4',
});

export const sha256 = createHash(sha256Digest, {
  ALGORITHM: 'SHA-256',
  BLOCK_SIZE: 64,
  DIGEST_SIZE: 32,
  OID: '2.16.840.1.101.3.4.2.1',
});
