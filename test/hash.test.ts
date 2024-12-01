import { describe, expect, it } from 'vitest'
import { HEX, UTF8 } from '../src/core/codec'
import { md5 } from '../src/hash/md5'
import { sha1 } from '../src/hash/sha1'
import { sha224, sha256 } from '../src/hash/sha256'
import { sha384, sha512, sha512t } from '../src/hash/sha512'
import * as sha3 from '../src/hash/sha3'
import * as sha3Derived from '../src/hash/sha3Derived'
import { sm3 } from '../src/hash/sm3'
import { hmac } from '../src/hash/hmac'

const { sha3_224, sha3_256 } = sha3
const { sha3_384, sha3_512 } = sha3
const { shake128, shake256 } = sha3

const { cShake128, cShake256 } = sha3Derived
const { kmac128, kmac256 } = sha3Derived
const { kmac128XOF, kmac256XOF } = sha3Derived
const { tupleHash128, tupleHash256 } = sha3Derived
const { tupleHash128XOF, tupleHash256XOF } = sha3Derived
const { parallelHash128, parallelHash256 } = sha3Derived
const { parallelHash128XOF, parallelHash256XOF } = sha3Derived

// * MD5
it('md5', () => {
  const _ = UTF8('')
  const meow = UTF8('meow, 喵， 🐱')
  expect(md5(_).to(HEX)).toMatchInlineSnapshot('"d41d8cd98f00b204e9800998ecf8427e"')
  expect(md5(meow).to(HEX)).toMatchInlineSnapshot('"49ac572e5f34b3e212e727fbd05df30c"')
})
// * SHA-1
it('sha1', () => {
  const _ = UTF8('')
  const meow = UTF8('meow, 喵， 🐱')
  expect(sha1(_).to(HEX)).toMatchInlineSnapshot('"da39a3ee5e6b4b0d3255bfef95601890afd80709"')
  expect(sha1(meow).to(HEX)).toMatchInlineSnapshot('"d4af2eec98c3f9c25c53dd1304c5963ed80f48ff"')
})
// * SHA-2
describe('sha2', () => {
  it('sha224', () => {
    const _ = UTF8('')
    const meow = UTF8('meow, 喵， 🐱')
    expect(sha224(_).to(HEX)).toMatchInlineSnapshot('"d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"')
    expect(sha224(meow).to(HEX)).toMatchInlineSnapshot('"b2b263f005ba9a07783a97269fcf79863657bc4dbe6716373d6a4744"')
  })
  it('sha256', () => {
    const _ = UTF8('')
    const meow = UTF8('meow, 喵， 🐱')
    expect(sha256(_).to(HEX)).toMatchInlineSnapshot('"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"')
    expect(sha256(meow).to(HEX)).toMatchInlineSnapshot('"9325c5351e2c58f0c4f3b973bd48e6b8981c04c1a6474d35686d5fdce77aebca"')
  })
  it('sha384', () => {
    const _ = UTF8('')
    const meow = UTF8('meow, 喵， 🐱')
    expect(sha384(_).to(HEX)).toMatchInlineSnapshot('"38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"')
    expect(sha384(meow).to(HEX)).toMatchInlineSnapshot('"51dcb8ca5e46938c2aa35956bf5fa2c24d0e8595720943f5fe0ac5d66190675af7a84ae14f6546b8bf2d86c29c214b0e"')
  })
  it('sha512', () => {
    const _ = UTF8('')
    const meow = UTF8('meow, 喵， 🐱')
    expect(sha512(_).to(HEX)).toMatchInlineSnapshot('"cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"')
    expect(sha512(meow).to(HEX)).toMatchInlineSnapshot('"385e2b3fee115b4df04bf67f08861413637294b56586aa238b11806b315f9b626dba973338a9463631a11b9882a30a56fc9300ead6fe3dbcf0a5a5f12769d4df"')
  })
  it('sha512/t', () => {
    const _ = UTF8('')
    const meow = UTF8('meow, 喵， 🐱')
    const sha512_224 = sha512t(224)
    expect(sha512_224(_).to(HEX)).toMatchInlineSnapshot('"6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4"')
    expect(sha512_224(_).to(HEX)).toMatchInlineSnapshot('"6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4"')
    expect(sha512_224(meow).to(HEX)).toMatchInlineSnapshot('"988a78f176c3f4cb1b19b3a4e0ae4f6924df720a04068713a6ee519e"')
  })
})
// * SHA-3
describe('sha3', () => {
  it('sha3', () => {
    const _ = UTF8('')
    const meow = UTF8('meow, 喵， 🐱')
    expect(sha3_224(_).to(HEX)).toMatchInlineSnapshot('"6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"')
    expect(sha3_224(meow).to(HEX)).toMatchInlineSnapshot('"19b2d0e73d5e0ba70850be3714f651af047e50a66889a06cf3a23f37"')
    expect(sha3_256(_).to(HEX)).toMatchInlineSnapshot('"a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"')
    expect(sha3_256(meow).to(HEX)).toMatchInlineSnapshot('"11253eef825cfe6766c2e9afad051084bf60e5998823f3f6455b3a00e850dead"')
    expect(sha3_384(_).to(HEX)).toMatchInlineSnapshot('"0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"')
    expect(sha3_384(meow).to(HEX)).toMatchInlineSnapshot('"a240008e6a6899b793f2ab3fce4022eaa48b319ce1c4025e64b19c63f230ee8d57bb20f6c05b058e01781952f0b960c9"')
    expect(sha3_512(_).to(HEX)).toMatchInlineSnapshot('"a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"')
    expect(sha3_512(meow).to(HEX)).toMatchInlineSnapshot('"624e65a5587f89665d43f2c47de89df0bdb8b93d775ce950afd75aca9306630df3d1f27bf67c8a068f9f4724512d30520e19c0e9241138a4fe37a7267844f703"')
  })
  it('shake', () => {
    const _ = UTF8('')
    const meow = UTF8('meow, 喵， 🐱')
    expect(shake128(256)(_).to(HEX)).toMatchInlineSnapshot('"7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26"')
    expect(shake128(256)(meow).to(HEX)).toMatchInlineSnapshot('"5b6a7f04e608d48139e2b72aa4fc2d047fc1ae5c77aefec0fd822ad77dff56f1"')
    expect(shake256(512)(_).to(HEX)).toMatchInlineSnapshot('"46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be"')
    expect(shake256(512)(meow).to(HEX)).toMatchInlineSnapshot('"5db7c1ba86c680ac9d8442d18057f7bd28fb125e324271ca0327f2862173411b65ae4a9d454b31c52ab24a3b779bb67b2d9298e418d16ea737fc5d5d3fac760f"')
    expect(shake256(2048)(_).to(HEX)).toMatchInlineSnapshot('"46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be141e96616fb13957692cc7edd0b45ae3dc07223c8e92937bef84bc0eab862853349ec75546f58fb7c2775c38462c5010d846c185c15111e595522a6bcd16cf86f3d122109e3b1fdd943b6aec468a2d621a7c06c6a957c62b54dafc3be87567d677231395f6147293b68ceab7a9e0c58d864e8efde4e1b9a46cbe854713672f5caaae314ed9083dab4b099f8e300f01b8650f1f4b1d8fcf3f3cb53fb8e9eb2ea203bdc970f50ae55428a91f7f53ac266b28419c3778a15fd248d339ede785fb7f"')
  })
  // * SHA-3 Derived
  it('cShake', () => {
    const _ = UTF8('')
    const meow = UTF8('meow, 喵， 🐱')
    const fn = UTF8('fn')
    const fn2 = UTF8('meow')
    const custom = UTF8('password')
    expect(cShake128(256)(_).to(HEX)).toMatchInlineSnapshot('"7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26"')
    expect(cShake128(256, { N: fn, S: custom })(_).to(HEX)).toMatchInlineSnapshot('"8949abe9aa6f75cc32d7ae0668798a5491530d2dad1c85a3fea68689fc20cb0e"')
    expect(cShake128(256, { N: fn2, S: custom })(meow).to(HEX)).toMatchInlineSnapshot('"c6c729b124020e81cec50c281b2fa863ae613ee5c5f0432b4f43fedb29364c7a"')

    expect(cShake256(512)(_).to(HEX)).toMatchInlineSnapshot('"46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be"')
    expect(cShake256(512, { N: fn, S: custom })(_).to(HEX)).toMatchInlineSnapshot('"1ff1d7cc4b14a1d86eb1d763501705199ae4208ca3ebd83809f95189c9b08a1fdf6d9b182f14541888b3b0ba7023dc53a7f8025de2eed1b8dacc95edf9c13b91"')
    expect(cShake256(512, { N: fn2, S: custom })(meow).to(HEX)).toMatchInlineSnapshot('"6ba1b872ade77effc824d222654c841d8a99369b533e540007ac3383693d3ff68687892dbd2cc2ea3c8ae61578a6c3c0c7a89235db524db223ff7770293724a3"')
  })
  it('kmac', () => {
    const _ = UTF8('')
    const meow = UTF8('meow, 喵， 🐱')
    const custom = UTF8('custom')
    const key = UTF8('password')
    expect(kmac128(256, _)(_)(_).to(HEX)).toMatchInlineSnapshot('"5c135c615152fb4d9784dd1155f9b6034e013fd77165c327dfa4d36701983ef7"')
    expect(kmac128(256, custom)(key)(meow).to(HEX)).toMatchInlineSnapshot(`"ef74e577ff0eef49974b6c2a707067ac6d3fba7afeccc2ff3ea40935d0471635"`)
    expect(kmac128XOF(256, custom)(key)(meow).to(HEX)).toMatchInlineSnapshot(`"8e8b4b4eacf9feee5bec9559a6091f48ee3c26de38adb4191e9eadf8f428f0fd"`)

    expect(kmac256(512, _)(_)(_).to(HEX)).toMatchInlineSnapshot('"2b70c18a81bb6446868dbc411e0dc1331c4399101d6b8b14ea16e951eee001033207bfe3bede15b946bfc209c62fc5d95e3e7b530b507319f24947d6ad7c18fe"')
    expect(kmac256(512, custom)(key)(meow).to(HEX)).toMatchInlineSnapshot(`"7ac4bd71ef93bfa57560f069ed832b785b9ddd855200974a9025240c44f39d8739c31c201f92919c075bcac16313761765c32a20b8a1dbae1cef32e015e3e7f5"`)
    expect(kmac256XOF(512, custom)(key)(meow).to(HEX)).toMatchInlineSnapshot(`"16066139244a9b649547be5fa349a3f9ce568ab6dcb753b00573cca1d2f6b47e354e175520fff098c3124048f8524771518e4cae9de9f026c76b347dc79058f2"`)
  })
  it('tupleHash', () => {
    const m1 = UTF8('meow')
    const m2 = UTF8('喵')
    const m3 = UTF8('🐱')
    const custom = UTF8('custom')
    expect(tupleHash128(256, custom)([m1, m2, m3]).to(HEX)).toMatchInlineSnapshot(`"3c981a838a10737fc32609fde65f87ad928d1321450279e6318f629ed3ef89de"`)
    expect(tupleHash128XOF(256, custom)([m1, m2, m3]).to(HEX)).toMatchInlineSnapshot(`"506a35e6f751612bd496d6647c4f33f428f7670acd3dbe5417c2fc16dc9852c5"`)
    expect(tupleHash256(512, custom)([m1, m2, m3]).to(HEX)).toMatchInlineSnapshot(`"9c30d7333705d6d5614a735bc2990328229b9b0d301d1645a931d3f33ba9f38cb6c1681196ae4107835823abc90bf06b1b113c85e000d808f0eef3a125a15dc0"`)
    expect(tupleHash256XOF(512, custom)([m1, m2, m3]).to(HEX)).toMatchInlineSnapshot(`"7df7f72679ea7bc2b517c80a0d62d0635a343e1c40d96094da0cecd531e897a440faa28d4eff45cd46605cf050ea0a634e6d1cf5a63f56d3faf71e500e15dc98"`)
  })
  it('parallelHash', async () => {
    const meow = UTF8('meow, 喵， 🐱')
    const custom = UTF8('custom')
    expect(parallelHash128(1024, 256, custom)(meow).to(HEX)).toMatchInlineSnapshot(`"11deeb6a3ba603b959e1c0c04bdf7f5c4a7b026ff772f0f3ddb1beab216eff04"`)
    expect(parallelHash128XOF(1024, 256, custom)(meow).to(HEX)).toMatchInlineSnapshot(`"98d0496b5a4875856fdfd4585a007093fa507989f12fe9c14182183ae53d108a"`)
    expect(parallelHash256(1024, 512, custom)(meow).to(HEX)).toMatchInlineSnapshot(`"e5ccc4a5f8bb7948eef9af5f901bf95ecf1b5af82e8b78b0d14d20a5a65b9f1845f235bd82d67b88c7f260a8ff316f17ed5b46199b8c60e77625c2ac166fdc81"`)
    expect(parallelHash256XOF(1024, 512, custom)(meow).to(HEX)).toMatchInlineSnapshot(`"bbb761d72744302b54aecbb62ad310f416b5b55e0ec75fe9eac113889e625c75d78aafd46fd54efe11b75f2ab99d780f0f70c6c9e4cb352c08b39a1f7b2a2fc2"`)
  })
})
// * SM3
it('sm3', () => {
  const _ = UTF8('')
  const meow = UTF8('meow, 喵， 🐱')
  expect(sm3(_).to(HEX)).toMatchInlineSnapshot('"1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b"')
  expect(sm3(meow).to(HEX)).toMatchInlineSnapshot('"cc1b7af8950bbb8dd71e4ef2ca85d527ba83502920c714ba8a1d61214d23c1e1"')
})
// * HMAC
it('hmac', () => {
  const meow = UTF8('meow, 喵， 🐱')
  const lorem = UTF8('xqxokmcswidaxxhpihnxorkqijxcuimukvkfpajpmxpgvvsoalctwhduvnatkhswijvngzpfwyxyycaxxiggtxhfucubguovxpwenosdnanqhefmqypqcehjmqxhnonipdlkfqufitmznkaautleeeestcwhvtdwmnfqsvjbxvsocmvshdqufdaxmvrjafpqcxwiczgoyhzgmxttlvydtnltebuqrwwoftgwokpuvnyccmeewauzvnixzpdksdlrqvdxthtyarobmwbyymqdnqaekczrhdupfcbtvzvdathjgrcytefgplbjfenjnzwohktafimwixswiggnidoatbeejlweuznphnxyhbbbwnubzuvwgjcdhhxszhnjulsavzfkkcbmjfgwiedqqzlhtjfcjeulcbjsaagglvmplprxqwhpxnyqfgtcqxghvbcahhguenbbzaaodqhlexgwpohwzmvcovmsksmvgkmbtfkomztnaabjzngbwujqbpuopytsotzyooikasrwftsjzkavfzhikvicsghrrmxeskcjrnhvlwaikwdjpdytnbfebliygpjzhsgcidtoyihtwlbwgrpngigonpjzbvuyyseibdgwgfefobvnduwympccyfevseqtbhwmbknldvzlkskbrxuxjdocpazjizixmthntuclfigpraiekufbpfgsfpytegmwdqvtxgxygcytxwjvjildrrqhfpittjnlydthgoysgfkpbypnbtagmpdyzmodogrxoxqiicjhzlmfqavbhtopxnmhdzzcukcqywzcyajckxqljnqzpsqkfenboayiqbfbqbjtiyxbxwzbirpbeikuyyhwbbrirzfbrbvkjpsftokpiezyiroxycqdjkrgssakuwrvuqqppecvwnufvapbgmblxleesdncjlhlqjiszvcxevtcnhgjdeoimdrziqjbmdqjiaoryodxepmweypxwwjczzkdnzmwbpmmpicihclwgxaxvrwfvsyawelwhwjzqeilmgykdyxzbtbnwlzyhyzsyolbwjujxlbilcjtgqqzrirznypkzwavchlwjzbjfmijoxacbdowbjbmifwctonqmxqvgsgmqnqraoqxezdkcqnmnpojxuktqopsuocsiqfjvtolsnflouvicscngescvvtoskngblqjwbxcczqgxfhjhajqhifylpuksaafoialypdgnywpevcmmepvopdircucjaylvecunojfyngozadyysfetqfutropvlewfkmpnefyttwogjevmriqbaxpddnajhhoxjvbbcnidkqlrtpgngqzxwcxfwjpldxwyoeuocafvhiooyhsdvpdahrivovnmzwgkbgorgcmatpkepzczorvfhmcnqazvykpxxwxjuxydtilfsrkxubzjcweqfywabddkuiqupungujxvjxlyifvfudnbnwahjpnyfnnjsmcebnoqxpqvxysygyrynxjuktjeojgklxbmxlulqrlfmiyjzvhkxikzesoxalpgxjwyhlxflyhzufoiskghnzrzcunmhhcdpmudbfipxdjaivyhamnxrseyoskjnnhpzpjkrqltrbcbnaodiiigfyxugifgujnqxhgumegxeyaonanmzcnjkidmnacxjzncfgpcagfbwcukjvusgtclkeouoqwpngtixbpixrdtlkxjysslzmorfbnnbmnehokdtqiwxmppmimfowmigausofrjflkotlhdszumlrtjrxkxlndzanfoalhvibkitklnrshlhpjzofjztsxmdfexhunxlkdpuhttxrppnflqsvwepneyvskubezsvnzwgsshclwgizsckghlxeyffkczxyrqdjtdrqasxybrdntputkarkxrqsdvueefrdctnltnnlmdedkqimqdvflnfqrlydsxzmriaydhirlyccpbtwhfxcraofzyrydpedrrirgfnbadexjbwuiufsozncrlgqqtuiwtaxscljvbfbpbpefzvecuoqc')
  const password = UTF8('password')

  const hmac_sha256 = hmac(sha256)(password)
  expect(hmac_sha256(meow).to(HEX)).toMatchInlineSnapshot('"d1460c736797bff7d4ff11940451421e7f693a7d1d7b10e2a2c163f11a9ca53c"')
  expect(hmac_sha256(lorem).to(HEX)).toMatchInlineSnapshot('"6298a318f4926c6dab11ce985146d60fec36b6c10f863bbff67d0c301e0fb140"')

  const hmac_sm3 = hmac(sm3)(password)
  expect(hmac_sm3(meow).to(HEX)).toMatchInlineSnapshot('"c8e111cdad100b08d04315081893bd5ac0b75180c492abe2fadcfbe027924904"')
  expect(hmac_sm3(lorem).to(HEX)).toMatchInlineSnapshot('"396a39e89a34ed585d29c30ea316dac259cbcf6424512424e04f1cb96975f671"')

  const hmac_sha3 = hmac(sha3_256)(password)
  expect(hmac_sha3(meow).to(HEX)).toMatchInlineSnapshot('"969bdb3d05db27ee7df5ba69b6e2e2bf5d7abb3b13e8c181d6418d6f0403f3f0"')
})
