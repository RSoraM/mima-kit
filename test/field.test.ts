import { describe, expect, it } from 'vitest'
import { CoordinateSystem } from '../src/core/coordinate_system'
import { EC } from '../src/core/ec'
import { curve25519, secp160r1, sect163k1, sect163r1 } from '../src/core/ec_params'
import { GF, GF2 } from '../src/core/galois_field'

describe('field-p', () => {
  it('op', () => {
    const gf = GF(0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffedn)
    const x = 0x6c533682766ed5fb0cf26af5dd566e29922a5337ed849aab78f697d80e60d885n
    const y = 0x3de8bb63832a430eb26b4d6bcccc49e30b1429b75c14f989a32fd8305e074164n

    expect(gf.add(x, y)).toBe(0x2a3bf1e5f9991909bf5db861aa22b80c9d3e7cef499994351c2670086c6819fcn)
    expect(gf.sub(x, y)).toBe(0x2e6a7b1ef34492ec5a871d8a108a244687162980916fa121d5c6bfa7b0599721n)
    expect(gf.mul(x, y)).toBe(0x6800a96cab0f23cdfe657ea1ea0e7d7fefcfb0ed95559c1606802431397fd6f3n)
    expect(gf.div(x, y)).toBe(0x19c6491be351df42a7051ea6427adddd9bc680c09352bdba34ab6022bc1bc836n)
    expect(gf.squ(x)).toBe(0x68a61fc28d771792c9d831df25d69dce3f3d1248bd3fcb75ba330ee13959c59n)
    expect(gf.inv(x)).toBe(0x2c8f6a2d142f9272c7895d50283498870da0dd1af5e2d3eef17df13ac8af9492n)
    expect(gf.root(x)).toBe(2358163505433048610056987694548018235043609703918291809597028843250752468275n)
    expect(gf.pow(x, y)).toBe(0x60b2782342839e41a9d315327fa38b95992b2a36269ce5b7e5b61a91798b58bbn)
  })

  it('coordinate-system', () => {
    const F = GF(secp160r1.p)
    const cs = CoordinateSystem(F)
    const { toAffine, toJacobian } = cs

    const G = secp160r1.G
    const J = toJacobian(G, 0x3804b518f749cbc304d9d0d296bb9a1017992cb8n)
    const R = {
      type: 'jacobian',
      isInfinity: false,
      x: 0xc4897651b4b5653df7aea36a58fbc450d31e6a4en,
      y: 0x0bc560c62ae2e229f2d5a7fa8d198a2e2136342bn,
      z: 0x3804b518f749cbc304d9d0d296bb9a1017992cb8n,
    }
    expect(J).toMatchObject(R)
    expect(toAffine(J)).toMatchObject(G)
  })

  it('weierstrass', () => {
    const ec = EC(secp160r1)
    const R = {
      isInfinity: false,
      x: 0x4a96b5688ef573284664698968c38bb913cbfc82n,
      y: 0x23a628553168947d59dcc912042351377ac5fb32n,
    }
    const R2 = {
      isInfinity: false,
      x: 0x2f997f33c5ed04c55d3edf8675d3e92e8f46686n,
      y: 0xf083a323482993e9440e817e21cfb7737df8797bn,
    }
    const R3 = {
      isInfinity: false,
      x: 0x7b76ff541ef363f2df13de1650bd48daa958bc59n,
      y: 0xc915ca790d8c8877b55be0079d12854ffe9f6f5an,
    }
    const R4 = {
      isInfinity: false,
      x: 0xb4041d8683be99f0afe01c307b1ad4c100cf2a88n,
      y: 0x3f32caed841f08c00660cc74caf4a5bcf9beed08n,
    }
    const n = 520883674333875308841598528610693034323391171945n
    const Rn = {
      isInfinity: false,
      x: 0x6fcc9f4a03a1432381c74dc478ab79a6845d101en,
      y: 0x58453abb84f81edc065373215e59281855628d33n,
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

    const J = ec.cs.toJacobian(G)
    const J2 = ec.addPoint(J, J)
    const J3 = ec.addPoint(J2, J)
    const J4 = ec.addPoint(J3, J)
    const Jn = ec.mulPoint(J, n)
    expect(ec.cs.toAffine(J)).toMatchObject(G)
    expect(ec.cs.toAffine(J2)).toMatchObject(G2)
    expect(ec.cs.toAffine(J3)).toMatchObject(G3)
    expect(ec.cs.toAffine(J4)).toMatchObject(G4)
    expect(ec.cs.toAffine(Jn)).toMatchObject(Rn)
  })

  it('montgomery', () => {
    const ec = EC(curve25519)
    const R = {
      isInfinity: false,
      x: 0x9n,
      y: 0x20ae19a1b8a086b4e01edd2c7748d14c923d4d7e6d7c61b229e9c5a27eced3d9n,
    }
    const R2 = {
      isInfinity: false,
      x: 0x20d342d51873f1b7d9750c687d1571148f3f5ced1e350b5c5cae469cdd684efbn,
      y: 0x13b57e011700e8ae050a00945d2ba2f377659eb28d8d391ebcd70465c72df563n,
    }
    const R3 = {
      isInfinity: false,
      x: 0x1c12bc1a6d57abe645534d91c21bba64f8824e67621c0859c00a03affb713c12n,
      y: 0x2986855cbe387eaeaceea446532c338c536af570f71ef7cf75c665019c41222bn,
    }
    const R4 = {
      isInfinity: false,
      x: 0x79ce98b7e0689d7de7d1d074a15b315ffe1805dfcd5d2a230fee85e4550013efn,
      y: 0x75af5bf4ebdc75c8fe26873427d275d73c0fb13da361077a565539f46de1c30n,
    }
    const n = 28858031113744144219319953636765136992609993254249076323988998198036398117213n
    const Rn = {
      isInfinity: false,
      x: 0x2aa87d5b3e78aab1745f5ce9fd10b12b107cf0e30ae388e7e309030327a59714n,
      y: 0x550094a00ca4c5a805bb5e882f20e362e7a164cf920028bf893152f687c5e3b9n,
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

    const J = ec.cs.toJacobian(G)
    const J2 = ec.addPoint(J, J)
    const J3 = ec.addPoint(J2, J)
    const J4 = ec.addPoint(J3, J)
    const Jn = ec.mulPoint(J, n)
    expect(ec.cs.toAffine(J)).toMatchObject(G)
    expect(ec.cs.toAffine(J2)).toMatchObject(G2)
    expect(ec.cs.toAffine(J3)).toMatchObject(G3)
    expect(ec.cs.toAffine(J4)).toMatchObject(G4)
    expect(ec.cs.toAffine(Jn)).toMatchObject(Rn)
  })
})

describe('field-2m', () => {
  it('op', () => {
    const m = 163n
    const ip = 0x800000000000000000000000000000000000000c9n
    const gf = GF2(m, ip)
    const x = 0x1dbfd60b8bc7b317ee5b82b49bc4331d3516c4226n
    const y = 0x3cb11cbd786bf745c8ffa5cfeb34a2e89e3d5514bn

    expect(gf.add(x, y)).toBe(0x210ecab6f3ac445226a4277b70f091f5ab2b9136dn)
    expect(gf.sub(x, y)).toBe(0x210ecab6f3ac445226a4277b70f091f5ab2b9136dn)
    expect(gf.mul(x, y)).toBe(0xe1425e42292cd16d6b6eaf8a0cf9f9b59be5b720n)
    expect(gf.div(x, y)).toBe(0x5465392d46497ef0f837a62b7ab9ce9acae211f12n)
    expect(gf.squ(x)).toBe(0x6e157102393d623eb377ab890ccb9dc492f0916a7n)
    expect(gf.inv(x)).toBe(0x511d27b568f484e177fcec85712e7c3ea44d59bb0n)
    expect(gf.root(x)).toBe(0x7aa6a350395887f4d27f4dc468c5377b0eb2462e1n)
    expect(gf.pow(x, y)).toBe(0x4b70bd3d9949890ac03a284cd6996cd29c46088f4n)
  })

  it('coordinate-system', () => {
    const F = GF2(sect163r1.m, sect163r1.IP)
    const cs = CoordinateSystem(F)
    const { toAffine, toLD } = cs

    const G = sect163r1.G
    const L = toLD(G, 0x4581d79888b23905c7fffb8b7feb862be5f73eb98n)
    const R = {
      type: 'ld',
      isInfinity: false,
      x: 0x7422fb7b60ac486e3ab0a3a73281480fa9dad5eadn,
      y: 0x38bbf17705658f03d9b3fdca9f1694b4059b19c65n,
      z: 0x4581d79888b23905c7fffb8b7feb862be5f73eb98n,
    }
    expect(L).toMatchObject(R)
    expect(toAffine(L)).toMatchObject(G)
  })

  it('pseudo-random', () => {
    const ec = EC(sect163r1)
    const R = {
      isInfinity: false,
      x: 0x0369979697ab43897789566789567f787a7876a654n,
      y: 0x00435edb42efafb2989d51fefce3c80988f41ff883n,
    }
    const R2 = {
      isInfinity: false,
      x: 0x04e1456ffead56a68862e3006a87bcf6d6fc3672b4n,
      y: 0x0223f5dd8ab164d4e51d903623764f48a787e528a8n,
    }
    const R3 = {
      isInfinity: false,
      x: 0x048a0a8a89d53dfb023ea98cee93381c6715aa87d1n,
      y: 0x06be5460da1ad9ac2eff25554ddb5fe237bae5d412n,
    }
    const R4 = {
      isInfinity: false,
      x: 0x06580f74ee239912537f7c8bf2c2d9320d448f0057n,
      y: 0x07e641d37c09c6b64909dac22a1627d63c428dccc9n,
    }
    const n = 8731870941184819475799947245630709385883641160251n
    const Rn = {
      isInfinity: false,
      x: 0x2c78b4d66711cf62ca0fac917690671e546dbb0e3n,
      y: 0x602d79f7e63ead2af3b687d1a89a68a56bfcd7edan,
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

    const J = ec.cs.toLD(G, 0x28b22aa5b3cd1eb33b17a2fb272492f9c612b7160n)
    const J2 = ec.addPoint(J, J)
    const J3 = ec.addPoint(J2, J)
    const J4 = ec.addPoint(J3, J)
    const Jn = ec.mulPoint(J, n)
    expect(ec.cs.toAffine(J)).toMatchObject(R)
    expect(ec.cs.toAffine(J2)).toMatchObject(R2)
    expect(ec.cs.toAffine(J3)).toMatchObject(R3)
    expect(ec.cs.toAffine(J4)).toMatchObject(R4)
    expect(ec.cs.toAffine(Jn)).toMatchObject(Rn)
  })

  it('koblitz', () => {
    const ec = EC(sect163k1)
    const R = {
      isInfinity: false,
      x: 0x02fe13c0537bbc11acaa07d793de4e6d5e5c94eee8n,
      y: 0x0289070fb05d38ff58321f2e800536d538ccdaa3d9n,
    }
    const R2 = {
      isInfinity: false,
      x: 0x0cb5ca2738fe300aacfb00b42a77b828d8a5c41ebn,
      y: 0x229c79e9ab85f90acd3d5fa3a696664515efefa6bn,
    }
    const R3 = {
      isInfinity: false,
      x: 0x2acfcfcc9a2af8e3f2828024f820033db20f69520n,
      y: 0x5729c47f915badc7b4c17df14e5804109ffecdfe4n,
    }
    const R4 = {
      isInfinity: false,
      x: 0x0ba8c7e6e2523ef94cbc1e56facfede24f3f91578n,
      y: 0x510f96cbc41cf3bdfa0157e9e8fee2c605791db0dn,
    }
    const n = 860749895544662177846543624795725813985896149794n
    const Rn = {
      isInfinity: false,
      x: 0x0fd34391fc1240e14c36d6749328a5591b63983c0n,
      y: 0x3aec697608e7252b72147591fa8aebc4ccfc8a9ddn,
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

    const J = ec.cs.toLD(G)
    const J2 = ec.addPoint(J, J)
    const J3 = ec.addPoint(J2, J)
    const J4 = ec.addPoint(J3, J)
    const Jn = ec.mulPoint(J, n)
    expect(ec.cs.toAffine(J)).toMatchObject(R)
    expect(ec.cs.toAffine(J2)).toMatchObject(R2)
    expect(ec.cs.toAffine(J3)).toMatchObject(R3)
    expect(ec.cs.toAffine(J4)).toMatchObject(R4)
    expect(ec.cs.toAffine(Jn)).toMatchObject(Rn)
  })
})

// vector source: https://sagecell.sagemath.org
