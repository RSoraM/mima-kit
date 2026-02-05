import { createCipher } from '../../core/cipher';
import { KitError, resizeBuffer, rotateL32, U8 } from '../../core/utils';

// * Constants

const A = new Uint32Array([
  0x4d34d34d, 0xd34d34d3, 0x34d34d34, 0x4d34d34d, 0xd34d34d3, 0x34d34d34, 0x4d34d34d, 0xd34d34d3,
]);

// * Rabbit Algorithm

function _rabbit(key: Uint8Array, iv: Uint8Array) {
  if (key.length !== 16) {
    throw new KitError('Rabbit key must be 16 byte');
  }

  // 内部状态
  let carry = 0;
  const X = new Uint8Array(32);
  const C = new Uint8Array(32);
  const X32 = new Uint32Array(X.buffer);
  const C32 = new Uint32Array(C.buffer);
  const nextState = (skipExtract: boolean = false): Uint8Array => {
    // Counter System
    for (let i = 0; i < 8; i++) {
      const T = C32[i] + A[i] + carry;
      C32[i] = T | 0;
      carry = T > 0xffffffff ? 1 : 0;
    }

    // G
    const G = new Uint32Array(8);
    for (let i = 0; i < 8; i++) {
      const T = (BigInt(X32[i]) + BigInt(C32[i])) & 0xffffffffn;
      const S = T * T;
      G[i] = Number((S ^ (S >> 32n)) & 0xffffffffn);
    }

    // Next State
    X32[0] = 0xffffffff & (G[0] + rotateL32(G[7], 16) + rotateL32(G[6], 16));
    X32[1] = 0xffffffff & (G[1] + rotateL32(G[0], 8) + G[7]);
    X32[2] = 0xffffffff & (G[2] + rotateL32(G[1], 16) + rotateL32(G[0], 16));
    X32[3] = 0xffffffff & (G[3] + rotateL32(G[2], 8) + G[1]);
    X32[4] = 0xffffffff & (G[4] + rotateL32(G[3], 16) + rotateL32(G[2], 16));
    X32[5] = 0xffffffff & (G[5] + rotateL32(G[4], 8) + G[3]);
    X32[6] = 0xffffffff & (G[6] + rotateL32(G[5], 16) + rotateL32(G[4], 16));
    X32[7] = 0xffffffff & (G[7] + rotateL32(G[6], 8) + G[5]);

    if (skipExtract) {
      return new Uint8Array();
    }

    // Extract Output
    const S = new Uint32Array(4);
    S[0] = X32[0] ^ (X32[5] >>> 16) ^ (X32[3] << 16);
    S[1] = X32[2] ^ (X32[7] >>> 16) ^ (X32[5] << 16);
    S[2] = X32[4] ^ (X32[1] >>> 16) ^ (X32[7] << 16);
    S[3] = X32[6] ^ (X32[3] >>> 16) ^ (X32[1] << 16);
    return new Uint8Array(S.buffer, S.byteOffset, 16);
  };

  // 初始化
  (() => {
    // 配置密钥
    const K16 = new Uint16Array(key.buffer, key.byteOffset, key.byteLength >> 1);
    for (let i = 0; i < 8; i++) {
      if ((i & 1) === 0) {
        const KH = K16[(i + 1) % 8];
        const KL = K16[i];
        X32[i] = (KH << 16) | KL;
        const CH = K16[(i + 4) % 8];
        const CL = K16[(i + 5) % 8];
        C32[i] = (CH << 16) | CL;
      } else {
        const KH = K16[(i + 5) % 8];
        const KL = K16[(i + 4) % 8];
        X32[i] = (KH << 16) | KL;
        const CH = K16[i];
        const CL = K16[(i + 1) % 8];
        C32[i] = (CH << 16) | CL;
      }
    }
    for (let i = 0; i < 4; i++) {
      nextState(true);
    }
    for (let i = 0; i < 8; i++) {
      C32[i] ^= X32[(i + 4) % 8];
    }

    // 配置 IV
    if (iv.length === 8) {
      const iv32 = new Uint32Array(iv.buffer, iv.byteOffset, iv.byteLength >> 2);
      const iv16 = new Uint16Array(iv.buffer, iv.byteOffset, iv.byteLength >> 1);
      C32[0] ^= iv32[0];
      C32[1] ^= (iv16[3] << 16) | iv16[1];
      C32[2] ^= iv32[1];
      C32[3] ^= (iv16[2] << 16) | iv16[0];
      C32[4] ^= iv32[0];
      C32[5] ^= (iv16[3] << 16) | iv16[1];
      C32[6] ^= iv32[1];
      C32[7] ^= (iv16[2] << 16) | iv16[0];
      for (let i = 0; i < 4; i++) {
        nextState(true);
      }
    } else if (iv.length !== 0 && iv.length !== 8) {
      throw new KitError('Rabbit iv must be 8 byte');
    }
  })();

  // 密钥流
  let S = nextState();
  let current = 1;
  const squeeze = (count: number) => {
    if (current >= count) return S;
    S = resizeBuffer(S, count << 4);
    while (current < count) {
      S.set(nextState(), current << 4);
      current++;
    }
    return S;
  };
  const cipher = (M: Uint8Array) => {
    const BLOCK_TOTAL = Math.ceil(M.length >> 4) || 1;
    S = squeeze(BLOCK_TOTAL);
    return U8.from(M).map((_, i) => _ ^ S[i]);
  };

  return {
    encrypt: (M: Uint8Array) => cipher(M),
    decrypt: (C: Uint8Array) => cipher(C),
  };
}

/**
 * Rabbit 流密码 / stream cipher
 */
export const rabbit = createCipher(_rabbit, {
  ALGORITHM: 'rabbit',
  KEY_SIZE: 16,
  MIN_KEY_SIZE: 16,
  MAX_KEY_SIZE: 16,
  IV_SIZE: 8,
  MIN_IV_SIZE: 0,
  MAX_IV_SIZE: 8,
});
