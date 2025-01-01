import { describe, expect, it } from 'vitest'
import { HEX, UTF8 } from '../src/core/codec'
import { U8 } from '../src/core/utils'
import { NO_PAD, ecb } from '../src/core/cipher'
import { hkdf, pbkdf2, x963kdf } from '../src/core/kdf'
import * as ecParams from '../src/core/ecParams'
import { rsa } from '../src/cipher/pkcs/rsa'
import { FpECC, es_xor } from '../src/cipher/pkcs/ecc'
import { hmac } from '../src/hash/hmac'
import { sha1 } from '../src/hash/sha1'
import { sha256 } from '../src/hash/sha256'
import * as pkcs1 from '../src/cipher/pkcs/pkcs1'
import { sm2 } from '../src/cipher/pkcs/sm2'
import { sm3 } from '../src/hash/sm3'
import { x25519, x448 } from '../src/cipher/pkcs/x25519_448'

const { pkcs1_es_1_5, pkcs1_es_oaep } = pkcs1
const { pkcs1_ssa_1_5, pkcs1_ssa_pss } = pkcs1

const { secp160r1 } = ecParams

describe('pkcs#1', () => {
  const m = UTF8('meow, 喵， 🐱')
  // Test RSA key generation and primitive operations
  it('rsa-1024-primitive', () => {
    const key = rsa(1024)
    const c_primitive = key.encrypt(m)
    const m_primitive = key.decrypt(U8.fromBI(c_primitive))
    expect(U8.fromBI(m_primitive)).toMatchObject(m)
    const s_primitive = key.sign(m)
    const v_primitive = key.verify(U8.fromBI(s_primitive))
    expect(U8.fromBI(v_primitive)).toMatchObject(m)
  })
  // RSA key pair generated by openssl
  const k = {
    n: 23034080759402304954888991887802936735581020885665804692622785350787833273336027165800162576643838272814069629997780257763268774904296946407410169722772195017541865386041868676644094723536583363632943297373887810704590403746600324371386072918199011912739739106757252537669855062664499713068797496332808041215435285453504152166404650385585541987491395587410485926961498584998114679811776955935327243542488505836673816774191840071042560769570332886799373666503006760407148607803169790337578683254767532523634222461003336205601885814533750902064700739776673052922508824355085867516473069592820928726324340661538666438001n,
    e: 65537n,
    d: 1714209104594852708492608452238907233172853703490514201555291072087484920335715783385829881365716960007264015844304341840316016843015815443381015621540150247326806842658986619720100755223842684887116504330098463755580798269577395395830771830323817703007545806878361044936099975542572355319139509420083382813045239893385986546211290733460894117483909304791683295825774787918505185794122982214472273311683090574562460992157247455036411515047693512937811065749535735794780136188890205494034509465966286027698508703822803534269342157011917819950339003482232734188492513631978734291383622720106600899383102949405070239483n,
    p: 175925677156926875499174098551522017056607943612981648655590557225779632088379734462875947824883450783116629825852744859318970414428483766827694041298372995292058766408130273618762492034688096181117464042609737633468262537717705882763738071155259693313372820164074053526477708404484124771992437417364360705891n,
    q: 130930749459931034031927233494845062690141198400963536802657812322173203795519525741233331674430612844732631140205593794808227047229543180741916474275364801388744161323832619980346208469165511138556131653085933424324409789007204438224267105253343587294282731704392104467429908538791706637605350029247996445211n,
    dP: 165357305230124899381252185342230438541389586440631544885856513497841300893299840439952368677431383313853005131033295441262928994747922548126797884309318041869338236579959791490543807457417744552799728169198465572449837074071298386838675331235241117355139321636738967258663454807455667576403163783963938225473n,
    dQ: 44769018487992958811380706705921586429396739474910232329993117114417494298698400176011989097644317000131430050519052616809703829918470987949488171140525959905402565132761114807506876811351296811021321607855145675048990630664547419872249287602761439304172936429249472344029125844115283794529781479247117694443n,
    qInv: 160937167178207524295610451814066095385572147263777716867708329696414608083973997132045861957529058792413591004332654412998518712757807599489050843117756319807618529703557350579355329922371276634128961839426287628239395280190483331041945498565822329466355581303125609486447364335254610856872471221022309989881n,
  }
  const key = rsa(k)
  // Test RSA encryption schemes: RSAES-PKCS1-v1_5 and RSAES-OAEP
  it('rsa-2048-pkcs-es', () => {
    const c_1_5 = pkcs1_es_1_5(key).encrypt(m)
    const c_1_5_from_outside = HEX('84c17540d4808633e4783319fb4f4424f9fdf89a4b0fd84d57042f8cd39fa72846941fc3c180cfcb9f6cba5a71a26315f508fc24d2da3413144d646bed49ecf026f378af78325f8dfdc06728a01f511654640e745a7d8bad952b1b252c4426da27ab6c6fa6804aa5a134703eb72f13efd2b8cef6b41c4e00bbf5521fdf2ac69743ae2b7d1548c73d9c8403beaf8363177c0890264a6b4366167a00547f6cb7c9346879eab55e764dfb69d09ff56ac4fca61e115317eff1dc05c36b0555aa7dac0173bb637d98b84333fdfd022d150f3086d290b02e5acea6c41642fbd57166df4b049d1c1f2bf8a0d01f22d264567417a36774434d85a4ed0ef27bbd162a28a9')
    expect(pkcs1_es_1_5(key).decrypt(c_1_5)).toMatchObject(m)
    expect(pkcs1_es_1_5(key).decrypt(c_1_5_from_outside)).toMatchObject(m)

    const c_oaep = pkcs1_es_oaep(key, sha256).encrypt(m)
    const c_oaep_from_outside = HEX('4a93b17defee62de1bf30e6ba8be7a4d9d88e46feabdb402054fecfa097eb6491b46b49426b4fd114c9b10f407f2b40ea4531d93bd151805f4b6e37b64a0bae1e5a959a9d1d691bfe6d215a5cefc57ab31093915f82ba5b3903dddbf7582c539cf379ce4c51e24d710308abbe07c9aa2cb9d48fc2a8de1c76bf5e4d3b1bdb949608bd66958087c5185e097d11816d262418b451412172e687f52508714a43c8e0f605ae8c5bfb2344617e46912261e3b579ce4e50f066b123c9e047d6f570dcff7c175e1b261798997bdec6ce1292c023f55ae13492f2d6c4c89225b86940b250aea40c1e141a9813cab18e55168a3697ec38865576e04e5035d351c9872cebc')
    expect(pkcs1_es_oaep(key, sha256).decrypt(c_oaep)).toMatchObject(m)
    expect(pkcs1_es_oaep(key, sha256).decrypt(c_oaep_from_outside)).toMatchObject(m)
  })
  // Test RSA signature schemes: RSASSA-PKCS1-v1_5 and RSASSA-PSS
  it('rsa-2048-pkcs-ssa', () => {
    const s_sha256_1_5 = pkcs1_ssa_1_5(key, sha256).sign(m)
    expect(s_sha256_1_5.to(HEX)).toMatchInlineSnapshot(`"5151d45e0b652f5c5e2f0a794b35c8b821cdad3f3c3530c22a897aae3e8c662bf7003027d328dccbd9a705828deab583799d3454b287c03db5f759a643d6d81693cfb1e3c96eaef26df883e571dc66f20c84543c3bffeba5a0b1d732929bd36b60b1bbe553f020c3cb9f7045d95b1ca3f51f601a02b78ce164e155af128cf0dfe96c078d8caec9aae1748d76195e0dd919de6546b7eb8ea9332170eef491e519d8af4690183465fbb343f9a3ef71e71bc3ffc790d23e5617aed1733969b8b1ed3e5c64b0808305ef7759d8b95b9139ce2e88cd493379c12e152c2087591d26f2a38a9acccb28201d3a4546dc50e64c4dfc4a788a8d15a0597524f39fe55388b9"`)
    expect(pkcs1_ssa_1_5(key, sha256).verify(m, s_sha256_1_5)).toBe(true)

    const s_sha256_pss = pkcs1_ssa_pss(key, sha256).sign(m)
    const s_sha256_pss_from_outside = HEX('2f5acb4d2082078ab320cf1a06b5d383ab864b77ee5530e0e1657371e6af8f50c0bf3935def1a1f53f1f4fae22e3ecfabc1cc39e95725a76f216f002577a8329815e89f27bd94531f2c2d06d4bc6d9166caa59b501165e1bf41109baaa36cf436dba853a19e98990f3b5eee256540f65aa92ded4b511b6a18748168a5914061ad4742868c3393620060979caeca05aedc75f93ae27f07188ef7b17e06dd2132459e57c5a161686af36c698064c5936f8e76de1c1e11aeaace86694e187c24e20a1049e986a90e0e0b44af8d2c75443d4b18bbac8b15bf043f70077043ff885cd331b02bc15c94eda152cbef8eed024f6667b8c1f07cd4df8c705116d9fca48ad')
    expect(pkcs1_ssa_pss(key, sha256).verify(m, s_sha256_pss)).toBe(true)
    expect(pkcs1_ssa_pss(key, sha256).verify(m, s_sha256_pss_from_outside)).toBe(true)
  })
})

describe('ecc', () => {
  // vector source: http://rfc.nop.hu/secg/gec2.pdf
  it('secp160r1-ecdh', () => {
    const ec = FpECC(secp160r1)
    const u_k = {
      d: 971761939728640320549601132085879836204587084162n,
      Q: {
        isInfinity: false,
        x: 466448783855397898016055842232266600516272889280n,
        y: 1110706324081757720403272427311003102474457754220n,
      },
    }
    const v_k = {
      d: 399525573676508631577122671218044116107572676710n,
      Q: {
        isInfinity: false,
        x: 420773078745784176406965940076771545932416607676n,
        y: 221937774842090227911893783570676792435918278531n,
      },
    }
    const s_u = ec.ecdh(u_k, v_k)
    const s_v = ec.ecdh(v_k, u_k)
    const s_outside = U8.fromBI(1155982782519895915997745984453282631351432623114n)
    expect(s_u.x).toMatchObject(s_v.x)
    expect(s_u.x).toMatchObject(s_outside)
    const kdf = x963kdf(sha1)
    const K = kdf(20 << 3, s_outside)
    const K_outside = HEX('744AB703F5BC082E59185F6D049D2D367DB245C2')
    expect(K_outside.every((v, i) => v === K[i])).toBe(true)
  })
  it('secp160r1-ecmqv', () => {
    const ec = FpECC(secp160r1)
    const u_k1 = {
      d: 971761939728640320549601132085879836204587084162n,
      Q: {
        isInfinity: false,
        x: 466448783855397898016055842232266600516272889280n,
        y: 1110706324081757720403272427311003102474457754220n,
      },
    }
    const u_k2 = {
      d: 117720748206090884214100397070943062470184499100n,
      Q: {
        isInfinity: false,
        x: 1242349848876241038961169594145217616154763512351n,
        y: 1228723083615049968259530566733073401525145323751n,
      },
    }
    const v_k1 = {
      d: 399525573676508631577122671218044116107572676710n,
      Q: {
        isInfinity: false,
        x: 420773078745784176406965940076771545932416607676n,
        y: 221937774842090227911893783570676792435918278531n,
      },
    }
    const v_k2 = {
      d: 141325380784931851783969312377642205317371311134n,
      Q: {
        isInfinity: false,
        x: 641868187219485959973483930084949222543277290421n,
        y: 560813476551307469487939594456722559518188737232n,
      },
    }
    const s_u = ec.ecmqv(u_k1, u_k2, v_k1, v_k2)
    const s_v = ec.ecmqv(v_k1, v_k2, u_k1, u_k2)
    const s_outside = U8.fromBI(516158222599696982690660648801682584432269985196n)
    expect(s_u.x).toMatchObject(s_v.x)
    expect(s_u.x).toMatchObject(s_outside)
    const kdf = x963kdf(sha1)
    const K = kdf(20 << 3, s_outside)
    const K_outside = HEX('C06763F8C3D2452C1CC5D29BD61918FB485063F6')
    expect(K_outside.every((v, i) => v === K[i])).toBe(true)
  })
  it('secp160r1-ecdsa', () => {
    const ec = FpECC(secp160r1)
    const dsa = ec.ecdsa(sha1)
    const key = {
      d: 971761939728640320549601132085879836204587084162n,
      Q: {
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
    const ec = FpECC(secp160r1)
    const cipher = ecb(es_xor, NO_PAD)
    const kdf = x963kdf(sha1)
    /** HMAC-SHA-1-160 with 20 bytes keys */
    const mac = hmac(sha1, 160, 160)
    const ecies = ec.ecies({ cipher, mac, kdf })

    const key = {
      d: 399525573676508631577122671218044116107572676710n,
      Q: {
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
    const ec = FpECC(secp160r1)
    const { PointToU8, U8ToPoint } = ec.utils
    const R = {
      isInfinity: false,
      x: 1176954224688105769566774212902092897866168635793n,
      y: 1130322298812061698910820170565981471918861336822n,
    }
    const P = PointToU8(R, true)
    const P_outside = HEX('02CE2873E5BE449563391FEB47DDCBA2DC16379191')
    const Q = U8ToPoint(P_outside)
    expect(P).toMatchObject(P_outside)
    expect(Q.y.toBI()).toBe(R.y)
  })
  // vector source: https://tools.ietf.org/html/rfc7748
  it('x25519', () => {
    const k_a_d = HEX('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a').toReversed()
    const k_a = x25519.gen('public_key', { d: k_a_d })
    const k_b_d = HEX('5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb').toReversed()
    const k_b = x25519.gen('public_key', { d: k_b_d })
    const s_a = x25519.ecdh(k_a, k_b)
    const s_b = x25519.ecdh(k_b, k_a)
    const s_outside = HEX('4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742').toReversed()
    expect(s_a).toMatchObject(s_b)
    expect(s_a).toMatchObject(s_outside)
  })
  it('x448', () => {
    const k_a_d = HEX('9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b').toReversed()
    const k_a = x448.gen('public_key', { d: k_a_d })
    const k_b_d = HEX('1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d').toReversed()
    const k_b = x448.gen('public_key', { d: k_b_d })
    const s_a = x448.ecdh(k_a, k_b)
    const s_b = x448.ecdh(k_b, k_a)
    const s_outside = HEX('07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282bb60c0b56fd2464c335543936521c24403085d59a449a5037514a879d').toReversed()
    expect(s_a).toMatchObject(s_b)
    expect(s_a).toMatchObject(s_outside)
  })
})

describe('kdf', () => {
  // vector source: http://rfc.nop.hu/secg/gec2.pdf
  it('x963kdf', () => {
    const kdf = x963kdf(sha1)
    const ikm = HEX('0499B502FC8B5BAFB0F4047E731D1F9FD8CD0D8881')
    expect(kdf(40 << 3, ikm)).toMatchObject(HEX('03C62280C894E103C680B13CD4B4AE740A5EF0C72547292F82DC6B1777F47D63BA9D1EA732DBF386'))
  })
  // vector source: https://www.rfc-editor.org/rfc/rfc5869
  it('hkdf', () => {
    const ikm = HEX('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f')
    const salt = HEX('606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf')
    const info = HEX('b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff')
    const L = 82 << 3
    const kdf_sha256 = hkdf(hmac(sha256), salt)
    expect(kdf_sha256(L, ikm, info)).toMatchObject(HEX('b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87'))
  })
  // vector source: https://www.dcode.fr/pbkdf2-hash
  it('pbkdf2', () => {
    const ikm = UTF8('password')
    const salt = UTF8('salt')
    const kdf = pbkdf2(hmac(sha1), salt, 5000)
    expect(kdf(20 << 3, ikm)).toMatchObject(HEX('edf738254821c55da61e6afa20efd0c657cb941c'))
  })
})

describe('sm2', () => {
  const curve: typeof secp160r1 = {
    type: 'Weierstrass',
    p: HEX('8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3').toBI(),
    a: HEX('787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498').toBI(),
    b: HEX('63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A').toBI(),
    G: {
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

    // Vector Source: SM2椭圆曲线公钥密码算法 第2部分：数字签名算法
    const key_from_outside = {
      d: HEX('128B2FA8BD433C6C068C8D803DFF79792A519A55171B1B650C23661D15897263').toBI(),
      Q: {
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

    // Vector Source: SM2椭圆曲线公钥密码算法 第3部分：数字证书
    const ka_from_outside = {
      d: HEX('6FCBA2EF 9AE0AB90 2BC3BDE3 FF915D44 BA4CC78F 88E2F8E7 F8996D3B 8CCEEDEE').toBI(),
      Q: {
        isInfinity: false,
        x: HEX('3099093B F3C137D8 FCBBCDF4 A2AE50F3 B0F216C3 122D7942 5FE03A45 DBFE1655').toBI(),
        y: HEX('3DF79E8D AC1CF0EC BAA2F2B4 9D51A4B3 87F2EFAF 48233908 6A27A8E0 5BAED98B').toBI(),
      },
    }
    const kx_from_outside = {
      d: HEX('83A2C9C8 B96E5AF7 0BD480B4 72409A9A 327257F1 EBB73F5B 073354B2 48668563').toBI(),
      Q: {
        isInfinity: false,
        x: HEX('6CB56338 16F4DD56 0B1DEC45 8310CBCC 6856C095 05324A6D 23150C40 8F162BF0').toBI(),
        y: HEX('0D6FCF62 F1036C0A 1B6DACCF 57399223 A65F7D7B F2D9637E 5BBBEB85 7961BF1A').toBI(),
      },
    }
    const ZA_from_outside = sm2ec.di(ID_A, ka_from_outside)
    const kb_from_outside = {
      d: HEX('5E35D7D3 F3C54DBA C72E6181 9E730B01 9A84208C A3A35E4C 2E353DFC CB2A3B53').toBI(),
      Q: {
        isInfinity: false,
        x: HEX('245493D4 46C38D8C C0F11837 4690E7DF 633A8A4B FB3329B5 ECE604B2 B4F37F43').toBI(),
        y: HEX('53C0869F 4B9E1777 3DE68FEC 45E14904 E0DEA45B F6CECF99 18C85EA0 47C60A4C').toBI(),
      },
    }
    const ky_from_outside = {
      d: HEX('33FE2194 0342161C 55619C4A 0C060293 D543C80A F19748CE 176D8347 7DE71C80').toBI(),
      Q: {
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
    expect(kdf(128, sA_from_outside)).toMatchObject(HEX('55B0AC62 A6B927BA 23703832 C853DED4'))
    expect(kdf(128, sB_from_outside)).toMatchObject(HEX('55B0AC62 A6B927BA 23703832 C853DED4'))
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
