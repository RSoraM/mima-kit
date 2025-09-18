import { describe, expect, it } from 'vitest'
import { ECC, es_xor } from '../src/cipher/ecc/ecc'
import { sm2 } from '../src/cipher/ecc/sm2'
import { x448, x25519 } from '../src/cipher/ecc/x25519_448'
import { ecb, NO_PAD } from '../src/core/cipher'
import { HEX, UTF8 } from '../src/core/codec'
import { secp160r1, sect163k1 } from '../src/core/ec_params'
import { x963kdf } from '../src/core/kdf'
import { U8 } from '../src/core/utils'
import { hmac } from '../src/hash/hmac'
import { sha1 } from '../src/hash/sha1'
import { sm3 } from '../src/hash/sm3'

describe('ecc-GF(p)', () => {
  // vector source: http://rfc.nop.hu/secg/gec2.pdf
  const ecc = ECC(secp160r1)
  const kdf = x963kdf(sha1)
  it('secp160r1-keygen', () => {
    const d = 971761939728640320549601132085879836204587084162n
    const Q = {
      type: 'affine' as const,
      isInfinity: false,
      x: 466448783855397898016055842232266600516272889280n,
      y: 1110706324081757720403272427311003102474457754220n,
    }
    const key = ecc.gen('public_key', { d })
    expect(key.d).toBe(d)
    expect(key.Q.x).toBe(Q.x)
    expect(key.Q.y).toBe(Q.y)
  })
  it('secp160r1-ecdh', () => {
    const u_k = {
      d: 971761939728640320549601132085879836204587084162n,
      Q: {
        type: 'affine' as const,
        isInfinity: false,
        x: 466448783855397898016055842232266600516272889280n,
        y: 1110706324081757720403272427311003102474457754220n,
      },
    }
    const v_k = {
      d: 399525573676508631577122671218044116107572676710n,
      Q: {
        type: 'affine' as const,
        isInfinity: false,
        x: 420773078745784176406965940076771545932416607676n,
        y: 221937774842090227911893783570676792435918278531n,
      },
    }
    const s_u = ecc.dh(u_k, v_k)
    const s_v = ecc.dh(v_k, u_k)
    const s_outside = U8.fromBI(1155982782519895915997745984453282631351432623114n)
    expect(s_u.x).toBe(s_v.x)
    expect(s_u.x).toBe(1155982782519895915997745984453282631351432623114n)

    const K = kdf(20 << 3, s_outside)
    const K_outside = HEX('744AB703F5BC082E59185F6D049D2D367DB245C2')
    expect(K_outside.every((v, i) => v === K[i])).toBe(true)
  })
  it('secp160r1-ecmqv', () => {
    const u_k1 = {
      d: 971761939728640320549601132085879836204587084162n,
      Q: {
        type: 'affine' as const,
        isInfinity: false,
        x: 466448783855397898016055842232266600516272889280n,
        y: 1110706324081757720403272427311003102474457754220n,
      },
    }
    const u_k2 = {
      d: 117720748206090884214100397070943062470184499100n,
      Q: {
        type: 'affine' as const,
        isInfinity: false,
        x: 1242349848876241038961169594145217616154763512351n,
        y: 1228723083615049968259530566733073401525145323751n,
      },
    }
    const v_k1 = {
      d: 399525573676508631577122671218044116107572676710n,
      Q: {
        type: 'affine' as const,
        isInfinity: false,
        x: 420773078745784176406965940076771545932416607676n,
        y: 221937774842090227911893783570676792435918278531n,
      },
    }
    const v_k2 = {
      d: 141325380784931851783969312377642205317371311134n,
      Q: {
        type: 'affine' as const,
        isInfinity: false,
        x: 641868187219485959973483930084949222543277290421n,
        y: 560813476551307469487939594456722559518188737232n,
      },
    }
    const s_u = ecc.mqv(u_k1, u_k2, v_k1, v_k2)
    const s_v = ecc.mqv(v_k1, v_k2, u_k1, u_k2)
    const s_outside = U8.fromBI(516158222599696982690660648801682584432269985196n)
    expect(s_u.x).toBe(s_v.x)
    expect(s_u.x).toBe(516158222599696982690660648801682584432269985196n)

    const K = kdf(20 << 3, s_outside)
    const K_outside = HEX('C06763F8C3D2452C1CC5D29BD61918FB485063F6')
    expect(K_outside.every((v, i) => v === K[i])).toBe(true)
  })
  it('secp160r1-ecdsa', () => {
    const dsa = ecc.dsa(sha1)
    const key = {
      d: 971761939728640320549601132085879836204587084162n,
      Q: {
        type: 'affine' as const,
        isInfinity: false,
        x: 466448783855397898016055842232266600516272889280n,
        y: 1110706324081757720403272427311003102474457754220n,
      },
    }
    const msg = UTF8('abc')
    const sig = dsa.sign(key, msg)
    const sig_outside = {
      r: 0xCE2873E5BE449563391FEB47DDCBA2DC16379191n,
      s: 0x3480EC1371A091A464B31CE47DF0CB8AA2D98B54n,
    }
    expect(dsa.verify(key, msg, sig)).toBe(true)
    expect(dsa.verify(key, msg, sig_outside)).toBe(true)
  })
  it('secp160r1-ecies', () => {
    const cipher = ecb(es_xor, NO_PAD)
    /** HMAC-SHA-1-160 with 20 bytes keys */
    const mac = hmac(sha1, 160, 160)
    const ecies = ecc.ies({ cipher, mac, kdf })

    const key = {
      d: 399525573676508631577122671218044116107572676710n,
      Q: {
        type: 'affine' as const,
        isInfinity: false,
        x: 420773078745784176406965940076771545932416607676n,
        y: 221937774842090227911893783570676792435918278531n,
      },
    }
    const msg = UTF8('abcdefghijklmnopqrst')
    const cip = ecies.encrypt(key, msg)
    const cip_outside = {
      R: {
        Q: {
          type: 'affine' as const,
          isInfinity: false,
          x: 1176954224688105769566774212902092897866168635793n,
          y: 1130322298812061698910820170565981471918861336822n,
        },
      },
      C: HEX('7123C870A31A81EA7583290D1BA17BC8759435ED'),
      D: HEX('1CCDA9EB4ED27360BE896729AD185493622591E5'),
    }
    expect(ecies.decrypt(key, cip)).toMatchObject(msg)
    expect(ecies.decrypt(key, cip_outside)).toMatchObject(msg)
  })
  it('secp160r1-point-compress', () => {
    const { PointToU8, U8ToPoint } = ecc.utils
    const R = {
      type: 'affine' as const,
      isInfinity: false,
      x: 1176954224688105769566774212902092897866168635793n,
      y: 1130322298812061698910820170565981471918861336822n,
    }
    const P = PointToU8(R, true)
    const P_outside = HEX('02CE2873E5BE449563391FEB47DDCBA2DC16379191')
    const Q = U8ToPoint(P_outside)
    expect(P).toMatchObject(P_outside)
    expect(Q.y).toBe(R.y)
  })
})

describe('ecc-GF(2^m)', () => {
  // vector source: http://rfc.nop.hu/secg/gec2.pdf
  const ecc = ECC(sect163k1)
  const kdf = x963kdf(sha1)
  it('sect163k1-keygen', () => {
    const d = 5321230001203043918714616464614664646674949479949n
    const Q = {
      type: 'affine' as const,
      isInfinity: false,
      x: 0x037D529FA37E42195F10111127FFB2BB38644806BCn,
      y: 0x0447026EEE8B34157F3EB51BE5185D2BE0249ED776n,
    }
    const key = ecc.gen('public_key', { d })
    expect(key.d).toBe(d)
    expect(key.Q.x).toBe(Q.x)
    expect(key.Q.y).toBe(Q.y)
  })
  it('sect163k1-ecdh', () => {
    const u_k = {
      d: 5321230001203043918714616464614664646674949479949n,
      Q: {
        type: 'affine' as const,
        isInfinity: false,
        x: 0x037D529FA37E42195F10111127FFB2BB38644806BCn,
        y: 0x0447026EEE8B34157F3EB51BE5185D2BE0249ED776n,
      },
    }
    const v_k = {
      d: 501870566195266176721440888203272826969530834326n,
      Q: {
        type: 'affine' as const,
        isInfinity: false,
        x: 0x072783FAAB9549002B4F13140B88132D1C75B3886Cn,
        y: 0x05A976794EA79A4DE26E2E19418F097942C08641C7n,
      },
    }
    const s_u = ecc.dh(u_k, v_k)
    const s_v = ecc.dh(v_k, u_k)
    const s_outside = U8.fromBI(0x0357C3DCD1DF3E27BD8885170EE4975B5081DA7FA7n)
    expect(s_u.x).toBe(s_v.x)
    expect(s_u.x).toBe(0x0357C3DCD1DF3E27BD8885170EE4975B5081DA7FA7n)

    const K = kdf(20 << 3, s_outside)
    const K_outside = HEX('6655A9C8F9E593149DB24C91CE621641035C9282')
    expect(K_outside.every((v, i) => v === K[i])).toBe(true)
  })
  it('sect163k1-ecmqv', () => {
    const u_k1 = {
      d: 5321230001203043918714616464614664646674949479949n,
      Q: {
        type: 'affine' as const,
        isInfinity: false,
        x: 0x037D529FA37E42195F10111127FFB2BB38644806BCn,
        y: 0x0447026EEE8B34157F3EB51BE5185D2BE0249ED776n,
      },
    }
    const u_k2 = {
      d: 4657215681533189829603817817038616871919531441490n,
      Q: {
        type: 'affine' as const,
        isInfinity: false,
        x: 0x015198E74BC2F1E5C9A62B80248DF0D62B9ADF8429n,
        y: 0x046B206B42773565749F123911C50992F41E5CB048n,
      },
    }
    const v_k1 = {
      d: 501870566195266176721440888203272826969530834326n,
      Q: {
        type: 'affine' as const,
        isInfinity: false,
        x: 0x072783FAAB9549002B4F13140B88132D1C75B3886Cn,
        y: 0x05A976794EA79A4DE26E2E19418F097942C08641C7n,
      },
    }
    const v_k2 = {
      d: 4002572202383399431900003559390459361505597843791n,
      Q: {
        type: 'affine' as const,
        isInfinity: false,
        x: 0x067E3AEA3510D69E8EDD19CB2A703DDC6CF5E56E32n,
        y: 0x0676C1358A4EEA8050564C6E828385DCE1427152EBn,
      },
    }
    const s_u = ecc.mqv(u_k1, u_k2, v_k1, v_k2)
    const s_v = ecc.mqv(v_k1, v_k2, u_k1, u_k2)
    const s_outside = U8.fromBI(0x038359FFD30C0D5FC1E6154F483B73D43E5CF2B503n)
    expect(s_u.x).toBe(s_v.x)
    expect(s_u.x).toBe(0x038359FFD30C0D5FC1E6154F483B73D43E5CF2B503n)

    const K = kdf(20 << 3, s_outside)
    const K_outside = HEX('49111524921C90333A317C3D04A5FCD3D45B2880')
    expect(K_outside.every((v, i) => v === K[i])).toBe(true)
  })
  it('sect163k1-ecdsa', () => {
    const key = {
      d: 5321230001203043918714616464614664646674949479949n,
      Q: {
        type: 'affine' as const,
        isInfinity: false,
        x: 0x037D529FA37E42195F10111127FFB2BB38644806BCn,
        y: 0x0447026EEE8B34157F3EB51BE5185D2BE0249ED776n,
      },
    }
    const dsa = ecc.dsa(sha1)
    const msg = UTF8('abc')
    const sig = dsa.sign(key, msg)
    const sig_outside = {
      r: 875196600601491789979810028167552198674202899628n,
      s: 1935199835333115956886966454901154618180070051199n,
    }
    expect(dsa.verify(key, msg, sig)).toBe(true)
    expect(dsa.verify(key, msg, sig_outside)).toBe(true)
  })
  it('sect163k1-ecies', () => {
    const cipher = ecb(es_xor, NO_PAD)
    /** HMAC-SHA-1-160 with 20 bytes keys */
    const mac = hmac(sha1, 160, 160)
    const ecies = ecc.ies({ cipher, mac, kdf })

    const key = {
      d: 501870566195266176721440888203272826969530834326n,
      Q: {
        type: 'affine' as const,
        isInfinity: false,
        x: 0x072783FAAB9549002B4F13140B88132D1C75B3886Cn,
        y: 0x05A976794EA79A4DE26E2E19418F097942C08641C7n,
      },
    }
    const msg = UTF8('abcdefghijklmnopqrst')
    const cip = ecies.encrypt(key, msg)
    const cip_outside = {
      R: {
        Q: {
          type: 'affine' as const,
          isInfinity: false,
          x: 0x04994D2C41AA30E52952B0A94EC6511328C502DA9Bn,
          y: 0x031FC936D73163B858BBC5326D77C1983946405264n,
        },
      },
      C: HEX('62A441E4ADF2866BAFEADA50B9DAC1047B2C83B3'),
      D: HEX('183301B414C82DFA91A58311369DF0E2A6F9642C'),
    }
    expect(ecies.decrypt(key, cip)).toMatchObject(msg)
    expect(ecies.decrypt(key, cip_outside)).toMatchObject(msg)
  })
  it('sect163k1-point-compress', () => {
    const { PointToU8, U8ToPoint } = ecc.utils
    const R = {
      type: 'affine' as const,
      isInfinity: false,
      x: 0x037D529FA37E42195F10111127FFB2BB38644806BCn,
      y: 0x0447026EEE8B34157F3EB51BE5185D2BE0249ED776n,
    }
    const P = PointToU8(R, true)
    const P_outside = HEX('03037D529FA37E42195F10111127FFB2BB38644806BC')
    const Q = U8ToPoint(P_outside)
    expect(P).toMatchObject(P_outside)
    expect(Q.x).toBe(R.x)
    expect(Q.y).toBe(R.y)
  })
})

describe('x25519 & x448', () => {
  // vector source: https://tools.ietf.org/html/rfc7748
  it('x25519', () => {
    const k_a_d = HEX('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a').toReversed()
    const k_a = x25519.gen('public_key', { d: k_a_d })
    const k_b_d = HEX('5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb').toReversed()
    const k_b = x25519.gen('public_key', { d: k_b_d })
    const s_a = x25519.dh(k_a, k_b)
    const s_b = x25519.dh(k_b, k_a)
    const s_outside = HEX('4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742').toReversed()
    expect(s_a).toMatchObject(s_b)
    expect(s_a).toMatchObject(s_outside)
  })
  it('x448', () => {
    const k_a_d = HEX('9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b').toReversed()
    const k_a = x448.gen('public_key', { d: k_a_d })
    const k_b_d = HEX('1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d').toReversed()
    const k_b = x448.gen('public_key', { d: k_b_d })
    const s_a = x448.dh(k_a, k_b)
    const s_b = x448.dh(k_b, k_a)
    const s_outside = HEX('07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282bb60c0b56fd2464c335543936521c24403085d59a449a5037514a879d').toReversed()
    expect(s_a).toMatchObject(s_b)
    expect(s_a).toMatchObject(s_outside)
  })
})

describe('sm2', () => {
  const curve: typeof secp160r1 = {
    type: 'Weierstrass',
    p: HEX('8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3').toBI(),
    a: HEX('787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498').toBI(),
    b: HEX('63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A').toBI(),
    G: {
      type: 'affine',
      isInfinity: false,
      x: HEX('421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D').toBI(),
      y: HEX('0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2').toBI(),
    },
    n: HEX('8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7').toBI(),
    h: 1n,
  }
  const ID_A = UTF8('ALICE123@YAHOO.COM')
  const ID_B = UTF8('BILL456@YAHOO.COM')
  it('dsa', () => {
    const sm2ec = sm2(curve)
    const M = UTF8('message digest')

    const key = sm2ec.gen()
    const Z = sm2ec.di(ID_A, key)
    const signer = sm2ec.dsa()
    const signature = signer.sign(Z, key, M)
    expect(signer.verify(Z, key, M, signature)).toBe(true)
  })
  it('dsa-vector', () => {
    const sm2ec = sm2(curve)
    const M = UTF8('message digest')

    // Vector Source: SM2椭圆曲线公钥密码算法 第2部分：数字签名算法
    const key_from_outside = {
      d: HEX('128B2FA8BD433C6C068C8D803DFF79792A519A55171B1B650C23661D15897263').toBI(),
      Q: {
        type: 'affine' as const,
        isInfinity: false,
        x: HEX('0AE4C7798AA0F119471BEE11825BE46202BB79E2A5844495E97C04FF4DF2548A').toBI(),
        y: HEX('7C0240F88F1CD4E16352A73C17B7F16F07353E53A176D684A9FE0C6BB798E857').toBI(),
      },
    }
    const Z_from_outside = sm2ec.di(ID_A, key_from_outside)
    const signer_from_outside = sm2ec.dsa()
    const sign_from_outside = {
      r: HEX('40F1EC59 F793D9F4 9E09DCEF 49130D41 94F79FB1 EED2CAA5 5BACDB49 C4E755D1').toBI(),
      s: HEX('6FC6DAC3 2C5D5CF1 0C77DFB2 0F7C2EB6 67A45787 2FB09EC5 6327A67E C7DEEBE7').toBI(),
    }
    expect(signer_from_outside.verify(Z_from_outside, key_from_outside, M, sign_from_outside)).toBe(true)
  })
  it('dh', () => {
    const sm2ec = sm2(curve)
    const ka = sm2ec.gen()
    const kx = sm2ec.gen()
    const ZA = sm2ec.di(ID_A, ka)
    const kb = sm2ec.gen()
    const ky = sm2ec.gen()
    const ZB = sm2ec.di(ID_B, kb)
    const sA = sm2ec.dh(ka, kx, kb, ky, ZA, ZB)
    const sB = sm2ec.dh(kb, ky, ka, kx, ZA, ZB)
    expect(sA.buffer).toMatchObject(sB.buffer)
  })
  it('dh-vector', () => {
    const sm2ec = sm2(curve)

    // Vector Source: SM2椭圆曲线公钥密码算法 第3部分：数字证书
    const ka_from_outside = {
      d: HEX('6FCBA2EF 9AE0AB90 2BC3BDE3 FF915D44 BA4CC78F 88E2F8E7 F8996D3B 8CCEEDEE').toBI(),
      Q: {
        type: 'affine' as const,
        isInfinity: false,
        x: HEX('3099093B F3C137D8 FCBBCDF4 A2AE50F3 B0F216C3 122D7942 5FE03A45 DBFE1655').toBI(),
        y: HEX('3DF79E8D AC1CF0EC BAA2F2B4 9D51A4B3 87F2EFAF 48233908 6A27A8E0 5BAED98B').toBI(),
      },
    }
    const kx_from_outside = {
      d: HEX('83A2C9C8 B96E5AF7 0BD480B4 72409A9A 327257F1 EBB73F5B 073354B2 48668563').toBI(),
      Q: {
        type: 'affine' as const,
        isInfinity: false,
        x: HEX('6CB56338 16F4DD56 0B1DEC45 8310CBCC 6856C095 05324A6D 23150C40 8F162BF0').toBI(),
        y: HEX('0D6FCF62 F1036C0A 1B6DACCF 57399223 A65F7D7B F2D9637E 5BBBEB85 7961BF1A').toBI(),
      },
    }
    const ZA_from_outside = sm2ec.di(ID_A, ka_from_outside)
    const kb_from_outside = {
      d: HEX('5E35D7D3 F3C54DBA C72E6181 9E730B01 9A84208C A3A35E4C 2E353DFC CB2A3B53').toBI(),
      Q: {
        type: 'affine' as const,
        isInfinity: false,
        x: HEX('245493D4 46C38D8C C0F11837 4690E7DF 633A8A4B FB3329B5 ECE604B2 B4F37F43').toBI(),
        y: HEX('53C0869F 4B9E1777 3DE68FEC 45E14904 E0DEA45B F6CECF99 18C85EA0 47C60A4C').toBI(),
      },
    }
    const ky_from_outside = {
      d: HEX('33FE2194 0342161C 55619C4A 0C060293 D543C80A F19748CE 176D8347 7DE71C80').toBI(),
      Q: {
        type: 'affine' as const,
        isInfinity: false,
        x: HEX('1799B2A2 C7782953 00D9A232 5C686129 B8F2B533 7B3DCF45 14E8BBC1 9D900EE5').toBI(),
        y: HEX('54C9288C 82733EFD F7808AE7 F27D0E73 2F7C73A7 D9AC98B7 D8740A91 D0DB3CF4').toBI(),
      },
    }
    const ZB_from_outside = sm2ec.di(ID_B, kb_from_outside)
    const sA_from_outside = sm2ec.dh(
      ka_from_outside,
      kx_from_outside,
      kb_from_outside,
      ky_from_outside,
      ZA_from_outside,
      ZB_from_outside,
    )
    const sB_from_outside = sm2ec.dh(
      kb_from_outside,
      ky_from_outside,
      ka_from_outside,
      kx_from_outside,
      ZA_from_outside,
      ZB_from_outside,
    )
    const kdf = x963kdf(sm3)
    expect(kdf(16, sA_from_outside)).toMatchObject(HEX('55B0AC62 A6B927BA 23703832 C853DED4'))
    expect(kdf(16, sB_from_outside)).toMatchObject(HEX('55B0AC62 A6B927BA 23703832 C853DED4'))
  })
  it('es', () => {
    const sm2ec = sm2(curve)
    const M = UTF8('encryption standard')

    const key = sm2ec.gen()
    const cipher = sm2ec.es()
    const C = cipher.encrypt(key, M)
    expect(cipher.decrypt(key, C)).toMatchObject(M)

    // Vector Source: SM2椭圆曲线公钥密码算法 第4部分：公钥加密算法
    const key_from_outside = {
      d: HEX('1649AB77 A00637BD 5E2EFE28 3FBF3535 34AA7F7C B89463F2 08DDBC29 20BB0DA0').toBI(),
      Q: {
        type: 'affine' as const,
        isInfinity: false,
        x: HEX('435B39CC A8F3B508 C1488AFC 67BE491A 0F7BA07E 581A0E48 49A5CF70 628A7E0A').toBI(),
        y: HEX('75DDBA78 F15FEECB 4C7895E2 C1CDF5FE 01DEBB2C DBADF453 99CCF77B BA076A42').toBI(),
      },
    }
    const C_from_outside = HEX('04245C26FB68B1DDDDB12C4B6BF9F2B6D5FE60A383B0D18D1C4144ABF17F6252E776CB9264C2A7E88E52B19903FDC47378F605E36811F5C07423A24B84400F01B8650053A89B41C418B0C3AAD00D886C002864679C3D7360C30156FAB7C80A0276712DA9D8094A634B766D3A285E07480653426D')
    const cipher_from_outside = sm2ec.es(undefined, undefined, 'c1c2c3')
    expect(cipher_from_outside.decrypt(key_from_outside, C_from_outside)).toMatchObject(M)
  })
})
