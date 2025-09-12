import { describe, expect, it } from 'vitest'
import { FbEC, FpEC } from '../src/core/ec'
import { curve25519, secp160r1, sect163k1, sect163r1 } from '../src/core/ecParams'
import { CoordinateSystem, GF, GF2 } from '../src/core/field'

describe('field-p', () => {
  it('op', () => {
    const gf = GF(0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEDn)
    const x = 0x6C533682766ED5FB0CF26AF5DD566E29922A5337ED849AAB78F697D80E60D885n
    const y = 0x3DE8BB63832A430EB26B4D6BCCCC49E30B1429B75C14F989A32FD8305E074164n

    expect(gf.add(x, y)).toBe(0x2A3BF1E5F9991909BF5DB861AA22B80C9D3E7CEF499994351C2670086C6819FCn)
    expect(gf.sub(x, y)).toBe(0x2E6A7B1EF34492EC5A871D8A108A244687162980916FA121D5C6BFA7B0599721n)
    expect(gf.mul(x, y)).toBe(0x6800A96CAB0F23CDFE657EA1EA0E7D7FEFCFB0ED95559C1606802431397FD6F3n)
    expect(gf.div(x, y)).toBe(0x19C6491BE351DF42A7051EA6427ADDDD9BC680C09352BDBA34AB6022BC1BC836n)
    expect(gf.squ(x)).toBe(0x68A61FC28D771792C9D831DF25D69DCE3F3D1248BD3FCB75BA330EE13959C59n)
    expect(gf.inv(x)).toBe(0x2C8F6A2D142F9272C7895D50283498870DA0DD1AF5E2D3EEF17DF13AC8AF9492n)
    expect(gf.root(x)).toBe(2358163505433048610056987694548018235043609703918291809597028843250752468275n)
    expect(gf.pow(x, y)).toBe(0x60B2782342839E41A9D315327FA38B95992B2A36269CE5B7E5B61A91798B58BBn)
  })

  it('coordinate-system', () => {
    const F = GF(secp160r1.p)
    const cs = CoordinateSystem(F)
    const { toAffine, toJacobian } = cs

    const G = secp160r1.G
    const J = toJacobian(G, 0x3804B518F749CBC304D9D0D296BB9A1017992CB8n)
    const R = {
      type: 'jacobian',
      isInfinity: false,
      x: 0xC4897651B4B5653DF7AEA36A58FBC450D31E6A4En,
      y: 0x0BC560C62AE2E229F2D5A7FA8D198A2E2136342Bn,
      z: 0x3804B518F749CBC304D9D0D296BB9A1017992CB8n,
    }
    expect(J).toMatchObject(R)
    expect(toAffine(J)).toMatchObject(G)
  })

  it('weierstrass', () => {
    const ec = FpEC(secp160r1)
    const R = {
      isInfinity: false,
      x: 0x4A96B5688EF573284664698968C38BB913CBFC82n,
      y: 0x23A628553168947D59DCC912042351377AC5FB32n,
    }
    const R2 = {
      isInfinity: false,
      x: 0x2F997F33C5ED04C55D3EDF8675D3E92E8F46686n,
      y: 0xF083A323482993E9440E817E21CFB7737DF8797Bn,
    }
    const R3 = {
      isInfinity: false,
      x: 0x7B76FF541EF363F2DF13DE1650BD48DAA958BC59n,
      y: 0xC915CA790D8C8877B55BE0079D12854FFE9F6F5An,
    }
    const R4 = {
      isInfinity: false,
      x: 0xB4041D8683BE99F0AFE01C307B1AD4C100CF2A88n,
      y: 0x3F32CAED841F08C00660CC74CAF4A5BCF9BEED08n,
    }
    const n = 520883674333875308841598528610693034323391171945n
    const Rn = {
      isInfinity: false,
      x: 0x6FCC9F4A03A1432381C74DC478AB79A6845D101En,
      y: 0x58453ABB84F81EDC065373215E59281855628D33n,
    }

    const G = secp160r1.G
    const G2 = ec._addPoint!(G, G)
    const G3 = ec._addPoint!(G2, G)
    const G4 = ec._addPoint!(G3, G)
    // const Gn = ec._mulPoint!(G, n)
    expect(G).toMatchObject(R)
    expect(G2).toMatchObject(R2)
    expect(G3).toMatchObject(R3)
    expect(G4).toMatchObject(R4)
    // expect(Gn).toMatchObject(Rn)

    const J = ec.toJacobian(G)
    const J2 = ec.addPoint(J, J)
    const J3 = ec.addPoint(J2, J)
    const J4 = ec.addPoint(J3, J)
    const Jn = ec.mulPoint(J, n)
    expect(ec.toAffine(J)).toMatchObject(G)
    expect(ec.toAffine(J2)).toMatchObject(G2)
    expect(ec.toAffine(J3)).toMatchObject(G3)
    expect(ec.toAffine(J4)).toMatchObject(G4)
    expect(ec.toAffine(Jn)).toMatchObject(Rn)
  })

  it('montgomery', () => {
    const ec = FpEC(curve25519)
    const R = {
      isInfinity: false,
      x: 0x9n,
      y: 0x20AE19A1B8A086B4E01EDD2C7748D14C923D4D7E6D7C61B229E9C5A27ECED3D9n,
    }
    const R2 = {
      isInfinity: false,
      x: 0x20D342D51873F1B7D9750C687D1571148F3F5CED1E350B5C5CAE469CDD684EFBn,
      y: 0x13B57E011700E8AE050A00945D2BA2F377659EB28D8D391EBCD70465C72DF563n,
    }
    const R3 = {
      isInfinity: false,
      x: 0x1C12BC1A6D57ABE645534D91C21BBA64F8824E67621C0859C00A03AFFB713C12n,
      y: 0x2986855CBE387EAEACEEA446532C338C536AF570F71EF7CF75C665019C41222Bn,
    }
    const R4 = {
      isInfinity: false,
      x: 0x79CE98B7E0689D7DE7D1D074A15B315FFE1805DFCD5D2A230FEE85E4550013EFn,
      y: 0x75AF5BF4EBDC75C8FE26873427D275D73C0FB13DA361077A565539F46DE1C30n,
    }
    const n = 28858031113744144219319953636765136992609993254249076323988998198036398117213n
    const Rn = {
      isInfinity: false,
      x: 0x2AA87D5B3E78AAB1745F5CE9FD10B12B107CF0E30AE388E7E309030327A59714n,
      y: 0x550094A00CA4C5A805BB5E882F20E362E7A164CF920028BF893152F687C5E3B9n,
    }

    const G = curve25519.G
    const G2 = ec._addPoint!(G, G)
    const G3 = ec._addPoint!(G2, G)
    const G4 = ec._addPoint!(G3, G)
    const Gn = ec._mulPoint!(G, n)
    expect(G).toMatchObject(R)
    expect(G2).toMatchObject(R2)
    expect(G3).toMatchObject(R3)
    expect(G4).toMatchObject(R4)
    expect(Gn).toMatchObject(Rn)

    const J = ec.toJacobian(G)
    const J2 = ec.addPoint(J, J)
    const J3 = ec.addPoint(J2, J)
    const J4 = ec.addPoint(J3, J)
    const Jn = ec.mulPoint(J, n)
    expect(ec.toAffine(J)).toMatchObject(G)
    expect(ec.toAffine(J2)).toMatchObject(G2)
    expect(ec.toAffine(J3)).toMatchObject(G3)
    expect(ec.toAffine(J4)).toMatchObject(G4)
    expect(ec.toAffine(Jn)).toMatchObject(Rn)
  })
})

describe('field-2m', () => {
  it('op', () => {
    const m = 163n
    const ip = 0x800000000000000000000000000000000000000C9n
    const gf = GF2(m, ip)
    const x = 0x1DBFD60B8BC7B317EE5B82B49BC4331D3516C4226n
    const y = 0x3CB11CBD786BF745C8FFA5CFEB34A2E89E3D5514Bn

    expect(gf.add(x, y)).toBe(0x210ECAB6F3AC445226A4277B70F091F5AB2B9136Dn)
    expect(gf.sub(x, y)).toBe(0x210ECAB6F3AC445226A4277B70F091F5AB2B9136Dn)
    expect(gf.mul(x, y)).toBe(0xE1425E42292CD16D6B6EAF8A0CF9F9B59BE5B720n)
    expect(gf.div(x, y)).toBe(0x5465392D46497EF0F837A62B7AB9CE9ACAE211F12n)
    expect(gf.squ(x)).toBe(0x6E157102393D623EB377AB890CCB9DC492F0916A7n)
    expect(gf.inv(x)).toBe(0x511D27B568F484E177FCEC85712E7C3EA44D59BB0n)
    expect(gf.root(x)).toBe(0x7AA6A350395887F4D27F4DC468C5377B0EB2462E1n)
    expect(gf.pow(x, y)).toBe(0x4B70BD3D9949890AC03A284CD6996CD29C46088F4n)
  })

  it('coordinate-system', () => {
    const F = GF2(sect163r1.m, sect163r1.IP)
    const cs = CoordinateSystem(F)
    const { toAffine, toLD } = cs

    const G = sect163r1.G
    const L = toLD(G, 0x4581D79888B23905C7FFFB8B7FEB862BE5F73EB98n)
    const R = {
      type: 'ld',
      isInfinity: false,
      x: 0x7422FB7B60AC486E3AB0A3A73281480FA9DAD5EADn,
      y: 0x38BBF17705658F03D9B3FDCA9F1694B4059B19C65n,
      z: 0x4581D79888B23905C7FFFB8B7FEB862BE5F73EB98n,
    }
    expect(L).toMatchObject(R)
    expect(toAffine(L)).toMatchObject(G)
  })

  it('pseudo-random', () => {
    const ec = FbEC(sect163r1)
    const R = {
      isInfinity: false,
      x: 0x0369979697AB43897789566789567F787A7876A654n,
      y: 0x00435EDB42EFAFB2989D51FEFCE3C80988F41FF883n,
    }
    const R2 = {
      isInfinity: false,
      x: 0x04E1456FFEAD56A68862E3006A87BCF6D6FC3672B4n,
      y: 0x0223F5DD8AB164D4E51D903623764F48A787E528A8n,
    }
    const R3 = {
      isInfinity: false,
      x: 0x048A0A8A89D53DFB023EA98CEE93381C6715AA87D1n,
      y: 0x06BE5460DA1AD9AC2EFF25554DDB5FE237BAE5D412n,
    }
    const R4 = {
      isInfinity: false,
      x: 0x06580F74EE239912537F7C8BF2C2D9320D448F0057n,
      y: 0x07E641D37C09C6B64909DAC22A1627D63C428DCCC9n,
    }
    const n = 8731870941184819475799947245630709385883641160251n
    const Rn = {
      isInfinity: false,
      x: 0x2C78B4D66711CF62CA0FAC917690671E546DBB0E3n,
      y: 0x602D79F7E63EAD2AF3B687D1A89A68A56BFCD7EDAn,
    }

    const G = sect163r1.G
    // const G2 = ec._addPoint!(G, G)
    // const G3 = ec._addPoint!(G2, G)
    // const G4 = ec._addPoint!(G3, G)
    // const Gn = ec._mulPoint!(G, n)
    // expect(G).toMatchObject(R)
    // expect(G2).toMatchObject(R2)
    // expect(G3).toMatchObject(R3)
    // expect(G4).toMatchObject(R4)
    // expect(ec._addPoint!(G2, G2)).toMatchObject(R4)
    // expect(Gn).toMatchObject(Rn)

    const J = ec.toLD(G, 0x28B22AA5B3CD1EB33B17A2FB272492F9C612B7160n)
    const J2 = ec.addPoint(J, J)
    const J3 = ec.addPoint(J2, J)
    const J4 = ec.addPoint(J3, J)
    const Jn = ec.mulPoint(J, n)
    expect(ec.toAffine(J)).toMatchObject(R)
    expect(ec.toAffine(J2)).toMatchObject(R2)
    expect(ec.toAffine(J3)).toMatchObject(R3)
    expect(ec.toAffine(J4)).toMatchObject(R4)
    expect(ec.toAffine(Jn)).toMatchObject(Rn)
  })

  it('koblitz', () => {
    const ec = FbEC(sect163k1)
    const R = {
      isInfinity: false,
      x: 0x02FE13C0537BBC11ACAA07D793DE4E6D5E5C94EEE8n,
      y: 0x0289070FB05D38FF58321F2E800536D538CCDAA3D9n,
    }
    const R2 = {
      isInfinity: false,
      x: 0x0CB5CA2738FE300AACFB00B42A77B828D8A5C41EBn,
      y: 0x229C79E9AB85F90ACD3D5FA3A696664515EFEFA6Bn,
    }
    const R3 = {
      isInfinity: false,
      x: 0x2ACFCFCC9A2AF8E3F2828024F820033DB20F69520n,
      y: 0x5729C47F915BADC7B4C17DF14E5804109FFECDFE4n,
    }
    const R4 = {
      isInfinity: false,
      x: 0x0BA8C7E6E2523EF94CBC1E56FACFEDE24F3F91578n,
      y: 0x510F96CBC41CF3BDFA0157E9E8FEE2C605791DB0Dn,
    }
    const n = 860749895544662177846543624795725813985896149794n
    const Rn = {
      isInfinity: false,
      x: 0x0FD34391FC1240E14C36D6749328A5591B63983C0n,
      y: 0x3AEC697608E7252B72147591FA8AEBC4CCFC8A9DDn,
    }

    const G = sect163k1.G
    // const G2 = ec._addPoint!(G, G)
    // const G3 = ec._addPoint!(G2, G)
    // const G4 = ec._addPoint!(G3, G)
    // const Gn = ec._mulPoint!(G, n)
    // expect(G).toMatchObject(R)
    // expect(G2).toMatchObject(R2)
    // expect(G3).toMatchObject(R3)
    // expect(G4).toMatchObject(R4)
    // expect(Gn).toMatchObject(Rn)

    const J = ec.toLD(G)
    const J2 = ec.addPoint(J, J)
    const J3 = ec.addPoint(J2, J)
    const J4 = ec.addPoint(J3, J)
    const Jn = ec.mulPoint(J, n)
    expect(ec.toAffine(J)).toMatchObject(R)
    expect(ec.toAffine(J2)).toMatchObject(R2)
    expect(ec.toAffine(J3)).toMatchObject(R3)
    expect(ec.toAffine(J4)).toMatchObject(R4)
    expect(ec.toAffine(Jn)).toMatchObject(Rn)
  })
})

// vector source: https://sagecell.sagemath.org
