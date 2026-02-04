import type { FbKECParams, FbPECParams, FpMECParams, FpTECParams, FpWECParams } from './ec';

// * SM2 Prime Curve

/**
 * 256 位素域上的 SM2 曲线
 *
 * SM2 curve over a 256 bit prime field
 */
export const sm2p256v1: FpWECParams = Object.freeze({
  type: 'Weierstrass',
  p: 0xfffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffffffn,
  a: 0xfffffffeffffffffffffffffffffffffffffffff00000000fffffffffffffffcn,
  b: 0x28e9fa9e9d9f5e344d5a9e4bcf6509a7f39789f515ab8f92ddbcbd414d940e93n,
  G: {
    type: 'affine' as const,
    isInfinity: false,
    x: 0x32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7n,
    y: 0xbc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0n,
  },
  n: 0xfffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54123n,
  h: 1n,
});

// * SEC-1 Prime Curves

/**
 * 112 位素域上的 SECG/WTLS 曲线
 *
 * SECG/WTLS curve over a 112 bit prime field
 *
 * @alias secp112r1
 * @alias wtls6
 */
export const secp112r1: FpWECParams = Object.freeze({
  type: 'Weierstrass',
  p: 0xdb7c2abf62e35e668076bead208bn,
  a: 0xdb7c2abf62e35e668076bead2088n,
  b: 0x659ef8ba043916eede8911702b22n,
  G: {
    type: 'affine' as const,
    isInfinity: false,
    x: 0x09487239995a5ee76b55f9c2f098n,
    y: 0xa89ce5af8724c0a23e0e0ff77500n,
  },
  n: 0xdb7c2abf62e35e7628dfac6561c5n,
  h: 1n,
});

/**
 * 112 位素域上的 SECG 曲线
 *
 * SECG curve over a 112 bit prime field
 */
export const secp112r2: FpWECParams = Object.freeze({
  type: 'Weierstrass',
  p: 0xdb7c2abf62e35e668076bead208bn,
  a: 0x6127c24c05f38a0aaaf65c0ef02cn,
  b: 0x51def1815db5ed74fcc34c85d709n,
  G: {
    type: 'affine' as const,
    isInfinity: false,
    x: 0x4ba30ab5e892b4e1649dd0928643n,
    y: 0xadcd46f5882e3747def36e956e97n,
  },
  n: 0x36df0aafd8b8d7597ca10520d04bn,
  h: 4n,
});

/**
 * 128 位素域上的 SECG 曲线
 *
 * SECG curve over a 128 bit prime field
 */
export const secp128r1: FpWECParams = Object.freeze({
  type: 'Weierstrass',
  p: 0xfffffffdffffffffffffffffffffffffn,
  a: 0xfffffffdfffffffffffffffffffffffcn,
  b: 0xe87579c11079f43dd824993c2cee5ed3n,
  G: {
    type: 'affine' as const,
    isInfinity: false,
    x: 0x161ff7528b899b2d0c28607ca52c5b86n,
    y: 0xcf5ac8395bafeb13c02da292dded7a83n,
  },
  n: 0xfffffffe0000000075a30d1b9038a115n,
  h: 1n,
});

/**
 * 128 位素域上的 SECG 曲线
 *
 * SECG curve over a 128 bit prime field
 */
export const secp128r2: FpWECParams = Object.freeze({
  type: 'Weierstrass',
  p: 0xfffffffdffffffffffffffffffffffffn,
  a: 0xd6031998d1b3bbfebf59cc9bbff9aee1n,
  b: 0x5eeefca380d02919dc2c6558bb6d8a5dn,
  G: {
    type: 'affine' as const,
    isInfinity: false,
    x: 0x7b6aa5d85e572983e6fb32a7cdebc140n,
    y: 0x27b6916a894d3aee7106fe805fc34b44n,
  },
  n: 0x3fffffff7fffffffbe0024720613b5a3n,
  h: 4n,
});

/**
 * 160 位素域上的 SECG 曲线
 *
 * SECG curve over a 160 bit prime field
 */
export const secp160k1: FpWECParams = Object.freeze({
  type: 'Weierstrass',
  p: 0xfffffffffffffffffffffffffffffffeffffac73n,
  a: 0n,
  b: 7n,
  G: {
    type: 'affine' as const,
    isInfinity: false,
    x: 0x3b4c382ce37aa192a4019e763036f4f5dd4d7ebbn,
    y: 0x938cf935318fdced6bc28286531733c3f03c4feen,
  },
  n: 0x0100000000000000000001b8fa16dfab9aca16b6b3n,
  h: 1n,
});

/**
 * 160 位素域上的 SECG/WTLS 曲线
 *
 * SECG/WTLS curve over a 160 bit prime field
 *
 * @alias secp160r1
 * @alias wtls7
 */
export const secp160r1: FpWECParams = Object.freeze({
  type: 'Weierstrass',
  p: 0xffffffffffffffffffffffffffffffff7fffffffn,
  a: 0xffffffffffffffffffffffffffffffff7ffffffcn,
  b: 0x1c97befc54bd7a8b65acf89f81d4d4adc565fa45n,
  G: {
    type: 'affine' as const,
    isInfinity: false,
    x: 0x4a96b5688ef573284664698968c38bb913cbfc82n,
    y: 0x23a628553168947d59dcc912042351377ac5fb32n,
  },
  n: 0x0100000000000000000001f4c8f927aed3ca752257n,
  h: 1n,
});

/**
 * 160 位素域上的 SECG 曲线
 *
 * SECG curve over a 160 bit prime field
 */
export const secp160r2: FpWECParams = Object.freeze({
  type: 'Weierstrass',
  p: 0xffffffffffffffffffffffffffffffff7fffffffn,
  a: 0xffffffffffffffffffffffffffffffff7ffffffcn,
  b: 0xb4e134d3fb59eb8bab57274904664d5af50388ban,
  G: {
    type: 'affine' as const,
    isInfinity: false,
    x: 0x52dcb034293a117e1f4ff11b30f7199d3144ce6dn,
    y: 0xfeaffef2e331f296e071fa0df9982cfea7d43f2en,
  },
  n: 0x0100000000000000000000351ee786a818f3a1a16bn,
  h: 1n,
});

/**
 * 192 位素域上的 SECG 曲线
 *
 * SECG curve over a 192 bit prime field
 */
export const secp192k1: FpWECParams = Object.freeze({
  type: 'Weierstrass',
  p: 0xfffffffffffffffffffffffffffffffffffffffeffffee37n,
  a: 0x000000000000000000000000000000000000000000000000n,
  b: 0x000000000000000000000000000000000000000000000003n,
  G: {
    type: 'affine' as const,
    isInfinity: false,
    x: 0xdb4ff10ec057e9ae26b07d0280b7f4341da5d1b1eae06c7dn,
    y: 0x9b2f2f6d9c5628a7844163d015be86344082aa88d95e2f9dn,
  },
  n: 0xfffffffffffffffffffffffe26f2fc170f69466a74defd8dn,
  h: 1n,
});

/**
 * 192 位素域上的 NIST/X9.62/SECG 曲线
 *
 * NIST/X9.62/SECG curve over a 192 bit prime field
 *
 * @alias p192
 * @alias prime192v1
 * @alias secp192r1
 */
export const secp192r1: FpWECParams = Object.freeze({
  type: 'Weierstrass',
  p: 0xfffffffffffffffffffffffffffffffeffffffffffffffffn,
  a: 0xfffffffffffffffffffffffffffffffefffffffffffffffcn,
  b: 0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1n,
  G: {
    type: 'affine' as const,
    isInfinity: false,
    x: 0x188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012n,
    y: 0x07192b95ffc8da78631011ed6b24cdd573f977a11e794811n,
  },
  n: 0xffffffffffffffffffffffff99def836146bc9b1b4d22831n,
  h: 1n,
});

/**
 * 224 位素域上的 SECG 曲线
 *
 * SECG curve over a 224 bit prime field
 */
export const secp224k1: FpWECParams = Object.freeze({
  type: 'Weierstrass',
  p: 0xfffffffffffffffffffffffffffffffffffffffffffffffeffffe56dn,
  a: 0x00000000000000000000000000000000000000000000000000000000n,
  b: 0x00000000000000000000000000000000000000000000000000000005n,
  G: {
    type: 'affine' as const,
    isInfinity: false,
    x: 0xa1455b334df099df30fc28a169a467e9e47075a90f7e650eb6b7a45cn,
    y: 0x7e089fed7fba344282cafbd6f7e319f7c0b0bd59e2ca4bdb556d61a5n,
  },
  n: 0x010000000000000000000000000001dce8d2ec6184caf0a971769fb1f7n,
  h: 1n,
});

/**
 * 224 位素域上的 NIST/SECG 曲线
 *
 * NIST/SECG curve over a 224 bit prime field
 *
 * @alias p224
 * @alias secp224r1
 */
export const secp224r1: FpWECParams = Object.freeze({
  type: 'Weierstrass',
  p: 0xffffffffffffffffffffffffffffffff000000000000000000000001n,
  a: 0xfffffffffffffffffffffffffffffffefffffffffffffffffffffffen,
  b: 0xb4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4n,
  G: {
    type: 'affine' as const,
    isInfinity: false,
    x: 0xb70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21n,
    y: 0xbd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34n,
  },
  n: 0xffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3dn,
  h: 1n,
});

/**
 * 256 位素域上的 SECG 曲线
 *
 * SECG curve over a 256 bit prime field
 */
export const secp256k1: FpWECParams = Object.freeze({
  type: 'Weierstrass',
  p: 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn,
  a: 0x0000000000000000000000000000000000000000000000000000000000000000n,
  b: 0x0000000000000000000000000000000000000000000000000000000000000007n,
  G: {
    type: 'affine' as const,
    isInfinity: false,
    x: 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n,
    y: 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n,
  },
  n: 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n,
  h: 1n,
});

/**
 * 256 位素域上的 NIST/X9.62/SECG 曲线
 *
 * NIST/X9.62/SECG curve over a 256 bit prime field
 *
 * @alias p256
 * @alias prime256v1
 * @alias secp256r1
 */
export const secp256r1: FpWECParams = Object.freeze({
  type: 'Weierstrass',
  p: 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn,
  a: 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffcn,
  b: 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn,
  G: {
    type: 'affine' as const,
    isInfinity: false,
    x: 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n,
    y: 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n,
  },
  n: 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n,
  h: 1n,
});

/**
 * 384 位素域上的 NIST/SECG 曲线
 *
 * NIST/SECG curve over a 384 bit prime field
 *
 * @alias p384
 * @alias secp384r1
 */
export const secp384r1: FpWECParams = Object.freeze({
  type: 'Weierstrass',
  p: 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffffn,
  a: 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffcn,
  b: 0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aefn,
  G: {
    type: 'affine' as const,
    isInfinity: false,
    x: 0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7n,
    y: 0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5fn,
  },
  n: 0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973n,
  h: 1n,
});

/**
 * 521 位素域上的 NIST/SECG 曲线
 *
 * NIST/SECG curve over a 521 bit prime field
 *
 * @alias p521
 * @alias secp521r1
 */
export const secp521r1: FpWECParams = Object.freeze({
  type: 'Weierstrass',
  p: 0x01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffn,
  a: 0x01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffcn,
  b: 0x0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00n,
  G: {
    type: 'affine' as const,
    isInfinity: false,
    x: 0x00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66n,
    y: 0x011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650n,
  },
  n: 0x01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409n,
  h: 1n,
});

// * SEC-1 Binary Curves

export const sect163k1: FbKECParams = Object.freeze({
  type: 'Koblitz',
  m: 163n,
  IP: (1n << 163n) + (1n << 7n) + (1n << 6n) + (1n << 3n) + 1n,
  a: 0x1n,
  b: 0x1n,
  G: {
    type: 'affine' as const,
    isInfinity: false,
    x: 0x02fe13c0537bbc11acaa07d793de4e6d5e5c94eee8n,
    y: 0x0289070fb05d38ff58321f2e800536d538ccdaa3d9n,
  },
  n: 0x04000000000000000000020108a2e0cc0d99f8a5efn,
  h: 2n,
});

export const sect163r1: FbPECParams = Object.freeze({
  type: 'Pseudo-Random',
  m: 163n,
  IP: (1n << 163n) + (1n << 7n) + (1n << 6n) + (1n << 3n) + 1n,
  a: 0x07b6882caaefa84f9554ff8428bd88e246d2782ae2n,
  b: 0x0713612dcddcb40aab946bda29ca91f73af958afd9n,
  G: {
    type: 'affine' as const,
    isInfinity: false,
    x: 0x0369979697ab43897789566789567f787a7876a654n,
    y: 0x00435edb42efafb2989d51fefce3c80988f41ff883n,
  },
  n: 0x03ffffffffffffffffffff48aab689c29ca710279bn,
  h: 2n,
});

export const sect163r2: FbPECParams = Object.freeze({
  type: 'Pseudo-Random',
  m: 163n,
  IP: (1n << 163n) + (1n << 7n) + (1n << 6n) + (1n << 3n) + 1n,
  a: 0x01n,
  b: 0x020a601907b8c953ca1481eb10512f78744a3205fdn,
  G: {
    type: 'affine' as const,
    isInfinity: false,
    x: 0x03f0eba16286a2d57ea0991168d4994637e8343e36n,
    y: 0x00d51fbc6c71a0094fa2cdd545b11c5c0c797324f1n,
  },
  n: 0x040000000000000000000292fe77e70c12a4234c33n,
  h: 2n,
});

export const sect233k1: FbKECParams = Object.freeze({
  type: 'Koblitz',
  m: 233n,
  IP: (1n << 233n) + (1n << 74n) + 1n,
  a: 0n,
  b: 1n,
  G: {
    type: 'affine' as const,
    isInfinity: false,
    x: 0x017232ba853a7e731af129f22ff4149563a419c26bf50a4c9d6eefad6126n,
    y: 0x01db537dece819b7f70f555a67c427a8cd9bf18aeb9b56e0c11056fae6a3n,
  },
  n: 0x8000000000000000000000000000069d5bb915bcd46efb1ad5f173abdfn,
  h: 4n,
});

export const sect233r1: FbPECParams = Object.freeze({
  type: 'Pseudo-Random',
  m: 233n,
  IP: (1n << 233n) + (1n << 74n) + 1n,
  a: 1n,
  b: 0x0066647ede6c332c7f8c0923bb58213b333b20e9ce4281fe115f7d8f90adn,
  G: {
    type: 'affine' as const,
    isInfinity: false,
    x: 0x00fac9dfcbac8313bb2139f1bb755fef65bc391f8b36f8f8eb7371fd558bn,
    y: 0x01006a08a41903350678e58528bebf8a0beff867a7ca36716f7e01f81052n,
  },
  n: 0x01000000000000000000000000000013e974e72f8a6922031d2603cfe0d7n,
  h: 2n,
});

export const sect239k1: FbKECParams = Object.freeze({
  type: 'Koblitz',
  m: 239n,
  IP: (1n << 239n) + (1n << 158n) + 1n,
  a: 0n,
  b: 1n,
  G: {
    type: 'affine' as const,
    isInfinity: false,
    x: 0x29a0b6a887a983e9730988a68727a8b2d126c44cc2cc7b2a6555193035dcn,
    y: 0x76310804f12e549bdb011c103089e73510acb275fc312a5dc6b76553f0can,
  },
  n: 0x2000000000000000000000000000005a79fec67cb6e91f1c1da800e478a5n,
  h: 4n,
});

export const sect283k1: FbKECParams = Object.freeze({
  type: 'Koblitz',
  m: 283n,
  IP: (1n << 283n) + (1n << 12n) + (1n << 7n) + (1n << 5n) + 1n,
  a: 0n,
  b: 1n,
  G: {
    type: 'affine' as const,
    isInfinity: false,
    x: 0x0503213f78ca44883f1a3b8162f188e553cd265f23c1567a16876913b0c2ac2458492836n,
    y: 0x01ccda380f1c9e318d90f95d07e5426fe87e45c0e8184698e45962364e34116177dd2259n,
  },
  n: 0x01ffffffffffffffffffffffffffffffffffe9ae2ed07577265dff7f94451e061e163c61n,
  h: 4n,
});

export const sect283r1: FbPECParams = Object.freeze({
  type: 'Pseudo-Random',
  m: 283n,
  IP: (1n << 283n) + (1n << 12n) + (1n << 7n) + (1n << 5n) + 1n,
  a: 1n,
  b: 0x027b680ac8b8596da5a4af8a19a0303fca97fd7645309fa2a581485af6263e313b79a2f5n,
  G: {
    type: 'affine' as const,
    isInfinity: false,
    x: 0x05f939258db7dd90e1934f8c70b0dfec2eed25b8557eac9c80e2e198f8cdbecd86b12053n,
    y: 0x03676854fe24141cb98fe6d4b20d02b4516ff702350eddb0826779c813f0df45be8112f4n,
  },
  n: 0x03ffffffffffffffffffffffffffffffffffef90399660fc938a90165b042a7cefadb307n,
  h: 2n,
});

export const sect409k1: FbKECParams = Object.freeze({
  type: 'Koblitz',
  m: 409n,
  IP: (1n << 409n) + (1n << 87n) + 1n,
  a: 0n,
  b: 1n,
  G: {
    type: 'affine' as const,
    isInfinity: false,
    x: 0x0060f05f658f49c1ad3ab1890f7184210efd0987e307c84c27accfb8f9f67cc2c460189eb5aaaa62ee222eb1b35540cfe9023746n,
    y: 0x01e369050b7c4e42acba1dacbf04299c3460782f918ea427e6325165e9ea10e3da5f6c42e9c55215aa9ca27a5863ec48d8e0286bn,
  },
  n: 0x7ffffffffffffffffffffffffffffffffffffffffffffffffffe5f83b2d4ea20400ec4557d5ed3e3e7ca5b4b5c83b8e01e5fcfn,
  h: 4n,
});

export const sect409r1: FbPECParams = Object.freeze({
  type: 'Pseudo-Random',
  m: 409n,
  IP: (1n << 409n) + (1n << 87n) + 1n,
  a: 1n,
  b: 0x0021a5c2c8ee9feb5c4b9a753b7b476b7fd6422ef1f3dd674761fa99d6ac27c8a9a197b272822f6cd57a55aa4f50ae317b13545fn,
  G: {
    type: 'affine' as const,
    isInfinity: false,
    x: 0x015d4860d088ddb3496b0c6064756260441cde4af1771d4db01ffe5b34e59703dc255a868a1180515603aeab60794e54bb7996a7n,
    y: 0x0061b1cfab6be5f32bbfa78324ed106a7636b9c5a7bd198d0158aa4f5488d08f38514f1fdf4b4f40d2181b3681c364ba0273c706n,
  },
  n: 0x010000000000000000000000000000000000000000000000000001e2aad6a612f33307be5fa47c3c9e052f838164cd37d9a21173n,
  h: 2n,
});

export const sect571k1: FbKECParams = Object.freeze({
  type: 'Koblitz',
  m: 571n,
  IP: (1n << 571n) + (1n << 10n) + (1n << 5n) + (1n << 2n) + 1n,
  a: 0n,
  b: 1n,
  G: {
    type: 'affine' as const,
    isInfinity: false,
    x: 0x026eb7a859923fbc82189631f8103fe4ac9ca2970012d5d46024804801841ca44370958493b205e647da304db4ceb08cbbd1ba39494776fb988b47174dca88c7e2945283a01c8972n,
    y: 0x0349dc807f4fbf374f4aeade3bca95314dd58cec9f307a54ffc61efc006d8a2c9d4979c0ac44aea74fbebbb9f772aedcb620b01a7ba7af1b320430c8591984f601cd4c143ef1c7a3n,
  },
  n: 0x020000000000000000000000000000000000000000000000000000000000000000000000131850e1f19a63e4b391a8db917f4138b630d84be5d639381e91deb45cfe778f637c1001n,
  h: 4n,
});

export const sect571r1: FbPECParams = Object.freeze({
  type: 'Pseudo-Random',
  m: 571n,
  IP: (1n << 571n) + (1n << 10n) + (1n << 5n) + (1n << 2n) + 1n,
  a: 1n,
  b: 0x02f40e7e2221f295de297117b7f3d62f5c6a97ffcb8ceff1cd6ba8ce4a9a18ad84ffabbd8efa59332be7ad6756a66e294afd185a78ff12aa520e4de739baca0c7ffeff7f2955727an,
  G: {
    type: 'affine' as const,
    isInfinity: false,
    x: 0x0303001d34b856296c16c0d40d3cd7750a93d1d2955fa80aa5f40fc8db7b2abdbde53950f4c0d293cdd711a35b67fb1499ae60038614f1394abfa3b4c850d927e1e7769c8eec2d19n,
    y: 0x037bf27342da639b6dccfffeb73d69d78c6c27a6009cbbca1980f8533921e8a684423e43bab08a576291af8f461bb2a8b3531d2f0485c19b16e2f1516e23dd3c1a4827af1b8ac15bn,
  },
  n: 0x03ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe661ce18ff55987308059b186823851ec7dd9ca1161de93d5174d66e8382e9bb2fe84e47n,
  h: 2n,
});

// * X9.63 Prime Curves

/**
 * 192 位素域上的 NIST/X9.62/SECG 曲线
 *
 * NIST/X9.62/SECG curve over a 192 bit prime field
 *
 * @alias p192
 * @alias prime192v1
 * @alias secp192r1
 */
export const prime192v1 = secp192r1;

/**
 * 256 位素域上的 NIST/X9.62/SECG 曲线
 *
 * NIST/X9.62/SECG curve over a 256 bit prime field
 *
 * @alias p256
 * @alias prime256v1
 * @alias secp256r1
 */
export const prime256v1 = secp256r1;

// * NIST Prime Curves

/**
 * 192 位素域上的 NIST/X9.62/SECG 曲线
 *
 * NIST/X9.62/SECG curve over a 192 bit prime field
 *
 * @alias p192
 * @alias prime192v1
 * @alias secp192r1
 */
export const p192 = secp192r1;

/**
 * 224 位素域上的 NIST/SECG 曲线
 *
 * NIST/SECG curve over a 224 bit prime field
 *
 * @alias p224
 * @alias secp224r1
 */
export const p224 = secp224r1;

/**
 * 256 位素域上的 SECG 曲线
 *
 * SECG curve over a 256 bit prime field
 *
 * @alias p256
 * @alias prime256v1
 * @alias secp256r1
 */
export const p256 = secp256r1;

/**
 * 384 位素域上的 NIST/SECG 曲线
 *
 * NIST/SECG curve over a 384 bit prime field
 *
 * @alias p384
 * @alias secp384r1
 */
export const p384 = secp384r1;

/**
 * 521 位素域上的 NIST/SECG 曲线
 *
 * NIST/SECG curve over a 521 bit prime field
 *
 * @alias p521
 * @alias secp521r1
 */
export const p521 = secp521r1;

/**
 * NIST W-25519 是与 Curve25519 同构的 Weierstrass 曲线
 *
 * NIST W-25519 is a Weierstrass curve isomorphic to Curve25519
 */
export const w25519: FpWECParams = Object.freeze({
  type: 'Weierstrass',
  p: 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffedn,
  a: 0x2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa984914a144n,
  b: 0x7b425ed097b425ed097b425ed097b425ed097b425ed097b4260b5e9c7710c864n,
  G: {
    type: 'affine' as const,
    isInfinity: false,
    x: 0x2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad245an,
    y: 0x5f51e65e475f794b1fe122d388b72eb36dc2b28192839e4dd6163a5d81312c14n,
  },
  n: 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3edn,
  h: 8n,
});

/**
 * NIST W-448 是与 Curve448 同构的 Weierstrass 曲线
 *
 * NISt W-448 is a Weierstrass curve isomorphic to Curve448
 */
export const w448: FpWECParams = Object.freeze({
  type: 'Weierstrass',
  p: 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffffffn,
  a: 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa9fffffffffffffffffffffffffffffffffffffffffffffffe1a76d41fn,
  b: 0x5ed097b425ed097b425ed097b425ed097b425ed097b425ed097b425e71c71c71c71c71c71c71c71c71c71c71c71c71c71c72c87b7cc69f70n,
  G: {
    type: 'affine' as const,
    isInfinity: false,
    x: 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0000000000000000000000000000000000000000000000000000cb91n,
    y: 0x7d235d1295f5b1f66c98ab6e58326fcecbae5d34f55545d060f75dc28df3f6edb8027e2346430d211312c4b150677af76fd7223d457b5b1an,
  },
  n: 0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffff7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f3n,
  h: 4n,
});

/**
 * 素域 p^255 - 19 上的 NIST Montgomery 曲线
 *
 * NIST Montgomery curve over a prime field p^255 - 19
 */
export const curve25519: FpMECParams = Object.freeze({
  type: 'Montgomery',
  p: 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffedn,
  a: 486662n,
  b: 1n,
  G: {
    type: 'affine' as const,
    isInfinity: false,
    x: 9n,
    y: 0x20ae19a1b8a086b4e01edd2c7748d14c923d4d7e6d7c61b229e9c5a27eced3d9n,
  },
  n: 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3edn,
  h: 8n,
});

/**
 * 素域 p^448 - 2^224 - 1 上的 NIST Montgomery 曲线
 *
 * NIST Montgomery curve over a prime field p^448 - 2^224 - 1
 */
export const curve448: FpMECParams = Object.freeze({
  type: 'Montgomery',
  p: 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffffffn,
  a: 156326n,
  b: 1n,
  G: {
    type: 'affine' as const,
    isInfinity: false,
    x: 5n,
    y: 0x7d235d1295f5b1f66c98ab6e58326fcecbae5d34f55545d060f75dc28df3f6edb8027e2346430d211312c4b150677af76fd7223d457b5b1an,
  },
  n: 0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffff7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f3n,
  h: 4n,
});

/**
 * ed25519 是与 Curve25519 同构的 Twisted Edwards 曲线
 *
 * ed25519 is a Twisted Edwards curve isomorphic to Curve25519
 */
export const ed25519: FpTECParams = Object.freeze({
  type: 'TwistedEdwards',
  p: 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffedn,
  a: -1n,
  b: 0x52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3n,
  G: {
    type: 'affine' as const,
    isInfinity: false,
    x: 0x216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51an,
    y: 0x6666666666666666666666666666666666666666666666666666666666666658n,
  },
  n: 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3edn,
  h: 8n,
});

/**
 * ed448 是与 Curve448 同构的 Twisted Edwards 曲线
 *
 * ed448 is a Twisted Edwards curve isomorphic to Curve448
 */
export const ed448: FpTECParams = Object.freeze({
  type: 'TwistedEdwards',
  p: 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffffffn,
  a: 1n,
  b: -39081n,
  G: {
    type: 'affine' as const,
    isInfinity: false,
    x: 0x4f1970c66bed0ded221d15a622bf36da9e146570470f1767ea6de324a3d3a46412ae1af72ab66511433b80e18b00938e2626a82bc70cc05en,
    y: 0x693f46716eb6bc248876203756c9c7624bea73736ca3984087789c1e05a0c2d73ad3ff1ce67c39c4fdbd132c4ed7c8ad9808795bf230fa14n,
  },
  n: 0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffff7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f3n,
  h: 4n,
});

// * Brainpool Prime Curves

/**
 * 160 位素域上的 RFC 5639 曲线
 *
 * RFC 5639 curve over a 160 bit prime field
 */
export const bp160r1: FpWECParams = Object.freeze({
  type: 'Weierstrass',
  p: 0xe95e4a5f737059dc60dfc7ad95b3d8139515620fn,
  a: 0x340e7be2a280eb74e2be61bada745d97e8f7c300n,
  b: 0x1e589a8595423412134faa2dbdec95c8d8675e58n,
  G: {
    type: 'affine' as const,
    isInfinity: false,
    x: 0xbed5af16ea3f6a4f62938c4631eb5af7bdbcdbc3n,
    y: 0x1667cb477a1a8ec338f94741669c976316da6321n,
  },
  n: 0xe95e4a5f737059dc60df5991d45029409e60fc09n,
  h: 1n,
});

/**
 * 192 位素域上的 RFC 5639 曲线
 *
 * RFC 5639 curve over a 192 bit prime field
 */
export const bp192r1: FpWECParams = Object.freeze({
  type: 'Weierstrass',
  p: 0xc302f41d932a36cda7a3463093d18db78fce476de1a86297n,
  a: 0x6a91174076b1e0e19c39c031fe8685c1cae040e5c69a28efn,
  b: 0x469a28ef7c28cca3dc721d044f4496bcca7ef4146fbf25c9n,
  G: {
    type: 'affine' as const,
    isInfinity: false,
    x: 0xc0a0647eaab6a48753b033c56cb0f0900a2f5c4853375fd6n,
    y: 0x14b690866abd5bb88b5f4828c1490002e6773fa2fa299b8fn,
  },
  n: 0xc302f41d932a36cda7a3462f9e9e916b5be8f1029ac4acc1n,
  h: 1n,
});

/**
 * 224 位素域上的 RFC 5639 曲线
 *
 * RFC 5639 curve over a 224 bit prime field
 */
export const bp224r1: FpWECParams = Object.freeze({
  type: 'Weierstrass',
  p: 0xd7c134aa264366862a18302575d1d787b09f075797da89f57ec8c0ffn,
  a: 0x68a5e62ca9ce6c1c299803a6c1530b514e182ad8b0042a59cad29f43n,
  b: 0x2580f63ccfe44138870713b1a92369e33e2135d266dbb372386c400bn,
  G: {
    type: 'affine' as const,
    isInfinity: false,
    x: 0x0d9029ad2c7e5cf4340823b2a87dc68c9e4ce3174c1e6efdee12c07dn,
    y: 0x58aa56f772c0726f24c6b89e4ecdac24354b9e99caa3f6d3761402cdn,
  },
  n: 0xd7c134aa264366862a18302575d0fb98d116bc4b6ddebca3a5a7939fn,
  h: 1n,
});

/**
 * 256 位素域上的 RFC 5639 曲线
 *
 * RFC 5639 curve over a 256 bit prime field
 */
export const bp256r1: FpWECParams = Object.freeze({
  type: 'Weierstrass',
  p: 0xa9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377n,
  a: 0x7d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6ce94a4b44f330b5d9n,
  b: 0x26dc5c6ce94a4b44f330b5d9bbd77cbf958416295cf7e1ce6bccdc18ff8c07b6n,
  G: {
    type: 'affine' as const,
    isInfinity: false,
    x: 0x8bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262n,
    y: 0x547ef835c3dac4fd97f8461a14611dc9c27745132ded8e545c1d54c72f046997n,
  },
  n: 0xa9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7n,
  h: 1n,
});

/**
 * 320 位素域上的 RFC 5639 曲线
 *
 * RFC 5639 curve over a 320 bit prime field
 */
export const bp320r1: FpWECParams = Object.freeze({
  type: 'Weierstrass',
  p: 0xd35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e27n,
  a: 0x3ee30b568fbab0f883ccebd46d3f3bb8a2a73513f5eb79da66190eb085ffa9f492f375a97d860eb4n,
  b: 0x520883949dfdbc42d3ad198640688a6fe13f41349554b49acc31dccd884539816f5eb4ac8fb1f1a6n,
  G: {
    type: 'affine' as const,
    isInfinity: false,
    x: 0x43bd7e9afb53d8b85289bcc48ee5bfe6f20137d10a087eb6e7871e2a10a599c710af8d0d39e20611n,
    y: 0x14fdd05545ec1cc8ab4093247f77275e0743ffed117182eaa9c77877aaac6ac7d35245d1692e8ee1n,
  },
  n: 0xd35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59311n,
  h: 1n,
});

/**
 * 384 位素域上的 RFC 5639 曲线
 *
 * RFC 5639 curve over a 384 bit prime field
 */
export const bp384r1: FpWECParams = Object.freeze({
  type: 'Weierstrass',
  p: 0x8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53n,
  a: 0x7bc382c63d8c150c3c72080ace05afa0c2bea28e4fb22787139165efba91f90f8aa5814a503ad4eb04a8c7dd22ce2826n,
  b: 0x04a8c7dd22ce28268b39b55416f0447c2fb77de107dcd2a62e880ea53eeb62d57cb4390295dbc9943ab78696fa504c11n,
  G: {
    type: 'affine' as const,
    isInfinity: false,
    x: 0x1d1c64f068cf45ffa2a63a81b7c13f6b8847a3e77ef14fe3db7fcafe0cbd10e8e826e03436d646aaef87b2e247d4af1en,
    y: 0x8abe1d7520f9c2a45cb1eb8e95cfd55262b70b29feec5864e19c054ff99129280e4646217791811142820341263c5315n,
  },
  n: 0x8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046565n,
  h: 1n,
});

/**
 * 512 位素域上的 RFC 5639 曲线
 *
 * RFC 5639 curve over a 512 bit prime field
 */
export const bp512r1: FpWECParams = Object.freeze({
  type: 'Weierstrass',
  p: 0xaadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f3n,
  a: 0x7830a3318b603b89e2327145ac234cc594cbdd8d3df91610a83441caea9863bc2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a72bf2c7b9e7c1ac4d77fc94can,
  b: 0x3df91610a83441caea9863bc2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a72bf2c7b9e7c1ac4d77fc94cadc083e67984050b75ebae5dd2809bd638016f723n,
  G: {
    type: 'affine' as const,
    isInfinity: false,
    x: 0x81aee4bdd82ed9645a21322e9c4c6a9385ed9f70b5d916c1b43b62eef4d0098eff3b1f78e2d0d48d50d1687b93b97d5f7c6d5047406a5e688b352209bcb9f822n,
    y: 0x7dde385d566332ecc0eabfa9cf7822fdf209f70024a57b1aa000c55b881f8111b2dcde494a5f485e5bca4bd88a2763aed1ca2b2fa8f0540678cd1e0f3ad80892n,
  },
  n: 0xaadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90069n,
  h: 1n,
});
