import { describe, expect, it } from 'vitest'
import { HEX, UTF8 } from '../src/core/codec'
import { joinBuffer } from '../src/core/utils'
import { hmac } from '../src/hash/hmac'
import { kt128, kt256 } from '../src/hash/kangaroo12'
import { md5 } from '../src/hash/md5'
import { sha1 } from '../src/hash/sha1'
import * as sha3 from '../src/hash/sha3'
import * as sha3Derived from '../src/hash/sha3Derived'
import { sha224, sha256 } from '../src/hash/sha256'
import { sha384, sha512, sha512t } from '../src/hash/sha512'
import { sm3 } from '../src/hash/sm3'
import { totp } from '../src/hash/totp'
import { turboshake128, turboshake256 } from '../src/hash/turboSHAKE'

const { sha3_224, sha3_256 } = sha3
const { sha3_384, sha3_512 } = sha3
const { shake128, shake256 } = sha3

const { cshake128, cshake256 } = sha3Derived
const { kmac128, kmac256 } = sha3Derived
const { kmac128XOF, kmac256XOF } = sha3Derived
const { tuplehash128, tuplehash256 } = sha3Derived
const { tuplehash128XOF, tuplehash256XOF } = sha3Derived
const { parallelhash128, parallelhash256 } = sha3Derived
const { parallelhash128XOF, parallelhash256XOF } = sha3Derived

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
  it('cshake', () => {
    const _ = UTF8('')
    const meow = UTF8('meow, 喵， 🐱')
    const fn = UTF8('fn')
    const fn2 = UTF8('meow')
    const custom = UTF8('password')
    expect(cshake128(256)(_).to(HEX)).toMatchInlineSnapshot('"7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26"')
    expect(cshake128(256, fn, custom)(_).to(HEX)).toMatchInlineSnapshot('"8949abe9aa6f75cc32d7ae0668798a5491530d2dad1c85a3fea68689fc20cb0e"')
    expect(cshake128(256, fn2, custom)(meow).to(HEX)).toMatchInlineSnapshot('"c6c729b124020e81cec50c281b2fa863ae613ee5c5f0432b4f43fedb29364c7a"')

    expect(cshake256(512)(_).to(HEX)).toMatchInlineSnapshot('"46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be"')
    expect(cshake256(512, fn, custom)(_).to(HEX)).toMatchInlineSnapshot('"1ff1d7cc4b14a1d86eb1d763501705199ae4208ca3ebd83809f95189c9b08a1fdf6d9b182f14541888b3b0ba7023dc53a7f8025de2eed1b8dacc95edf9c13b91"')
    expect(cshake256(512, fn2, custom)(meow).to(HEX)).toMatchInlineSnapshot('"6ba1b872ade77effc824d222654c841d8a99369b533e540007ac3383693d3ff68687892dbd2cc2ea3c8ae61578a6c3c0c7a89235db524db223ff7770293724a3"')
  })
  it('kmac', () => {
    const empty = UTF8('')
    const meow = UTF8('meow, 喵， 🐱')
    const custom = UTF8('custom')
    const key = UTF8('password')
    expect(kmac128(256, empty)(empty, empty).to(HEX)).toMatchInlineSnapshot('"5c135c615152fb4d9784dd1155f9b6034e013fd77165c327dfa4d36701983ef7"')
    expect(kmac128(256, custom)(key, meow).to(HEX)).toMatchInlineSnapshot(`"ef74e577ff0eef49974b6c2a707067ac6d3fba7afeccc2ff3ea40935d0471635"`)
    expect(kmac128XOF(256, custom)(key, meow).to(HEX)).toMatchInlineSnapshot(`"8e8b4b4eacf9feee5bec9559a6091f48ee3c26de38adb4191e9eadf8f428f0fd"`)

    expect(kmac256(512, empty)(empty, empty).to(HEX)).toMatchInlineSnapshot('"2b70c18a81bb6446868dbc411e0dc1331c4399101d6b8b14ea16e951eee001033207bfe3bede15b946bfc209c62fc5d95e3e7b530b507319f24947d6ad7c18fe"')
    expect(kmac256(512, custom)(key, meow).to(HEX)).toMatchInlineSnapshot(`"7ac4bd71ef93bfa57560f069ed832b785b9ddd855200974a9025240c44f39d8739c31c201f92919c075bcac16313761765c32a20b8a1dbae1cef32e015e3e7f5"`)
    expect(kmac256XOF(512, custom)(key, meow).to(HEX)).toMatchInlineSnapshot(`"16066139244a9b649547be5fa349a3f9ce568ab6dcb753b00573cca1d2f6b47e354e175520fff098c3124048f8524771518e4cae9de9f026c76b347dc79058f2"`)
  })
  it('tuplehash', () => {
    const m = ['meow', '喵', '🐱'].map(v => UTF8(v))
    const custom = UTF8('custom')
    expect(tuplehash128(256, custom)(m).to(HEX)).toMatchInlineSnapshot(`"3c981a838a10737fc32609fde65f87ad928d1321450279e6318f629ed3ef89de"`)
    expect(tuplehash128XOF(256, custom)(m).to(HEX)).toMatchInlineSnapshot(`"506a35e6f751612bd496d6647c4f33f428f7670acd3dbe5417c2fc16dc9852c5"`)
    expect(tuplehash256(512, custom)(m).to(HEX)).toMatchInlineSnapshot(`"9c30d7333705d6d5614a735bc2990328229b9b0d301d1645a931d3f33ba9f38cb6c1681196ae4107835823abc90bf06b1b113c85e000d808f0eef3a125a15dc0"`)
    expect(tuplehash256XOF(512, custom)(m).to(HEX)).toMatchInlineSnapshot(`"7df7f72679ea7bc2b517c80a0d62d0635a343e1c40d96094da0cecd531e897a440faa28d4eff45cd46605cf050ea0a634e6d1cf5a63f56d3faf71e500e15dc98"`)
  })
  it('parallelhash', async () => {
    const meow = UTF8('meow, 喵， 🐱')
    const custom = UTF8('custom')
    expect(parallelhash128(1024, 256, custom)(meow).to(HEX)).toMatchInlineSnapshot(`"11deeb6a3ba603b959e1c0c04bdf7f5c4a7b026ff772f0f3ddb1beab216eff04"`)
    expect(parallelhash128XOF(1024, 256, custom)(meow).to(HEX)).toMatchInlineSnapshot(`"98d0496b5a4875856fdfd4585a007093fa507989f12fe9c14182183ae53d108a"`)
    expect(parallelhash256(1024, 512, custom)(meow).to(HEX)).toMatchInlineSnapshot(`"e5ccc4a5f8bb7948eef9af5f901bf95ecf1b5af82e8b78b0d14d20a5a65b9f1845f235bd82d67b88c7f260a8ff316f17ed5b46199b8c60e77625c2ac166fdc81"`)
    expect(parallelhash256XOF(1024, 512, custom)(meow).to(HEX)).toMatchInlineSnapshot(`"bbb761d72744302b54aecbb62ad310f416b5b55e0ec75fe9eac113889e625c75d78aafd46fd54efe11b75f2ab99d780f0f70c6c9e4cb352c08b39a1f7b2a2fc2"`)
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

  const hmac_sha256 = hmac(sha256)
  expect(hmac_sha256(password, meow).to(HEX)).toMatchInlineSnapshot('"d1460c736797bff7d4ff11940451421e7f693a7d1d7b10e2a2c163f11a9ca53c"')
  expect(hmac_sha256(password, lorem).to(HEX)).toMatchInlineSnapshot('"6298a318f4926c6dab11ce985146d60fec36b6c10f863bbff67d0c301e0fb140"')

  const hmac_sm3 = hmac(sm3)
  expect(hmac_sm3(password, meow).to(HEX)).toMatchInlineSnapshot('"c8e111cdad100b08d04315081893bd5ac0b75180c492abe2fadcfbe027924904"')
  expect(hmac_sm3(password, lorem).to(HEX)).toMatchInlineSnapshot('"396a39e89a34ed585d29c30ea316dac259cbcf6424512424e04f1cb96975f671"')

  const hmac_sha3 = hmac(sha3_256)
  expect(hmac_sha3(password, meow).to(HEX)).toMatchInlineSnapshot('"969bdb3d05db27ee7df5ba69b6e2e2bf5d7abb3b13e8c181d6418d6f0403f3f0"')
})
// * TurboSHAKE
function ptn(n: number) {
  const sample = new Uint8Array([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF, 0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF, 0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF, 0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF, 0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA])
  const sample_size = sample.length
  const ptn: Uint8Array[] = []
  for (let ptn_size = 0; ptn_size < n; ptn_size += sample_size) {
    ptn.push(sample)
  }
  return joinBuffer(...ptn).slice(0, n)
}
it('turboShake', () => {
  // Vector Source: https://datatracker.ietf.org/doc/draft-irtf-cfrg-kangarootwelve/
  const empty = new Uint8Array(0)
  expect(turboshake128(32 << 3, 0x1F)(empty))
    .toMatchObject(HEX('1E415F1C5983AFF2169217277D17BB538CD945A397DDEC541F1CE41AF2C1B74C'))
  expect(turboshake128(64 << 3, 0x1F)(empty))
    .toMatchObject(HEX('1E415F1C5983AFF2169217277D17BB538CD945A397DDEC541F1CE41AF2C1B74C3E8CCAE2A4DAE56C84A04C2385C03C15E8193BDF58737363321691C05462C8DF'))
  expect(turboshake128(10032 << 3, 0x1F)(empty).slice(10000))
    .toMatchObject(HEX('A3B9B0385900CE761F22AED548E754DA10A5242D62E8C658E3F3A923A7555607'))
  expect(turboshake128(32 << 3, 0x1F)(ptn(17 ** 0)))
    .toMatchObject(HEX('55CEDD6F60AF7BB29A4042AE832EF3F58DB7299F893EBB9247247D856958DAA9'))
  expect(turboshake128(32 << 3, 0x1F)(ptn(17 ** 1)))
    .toMatchObject(HEX('9C97D036A3BAC819DB70EDE0CA554EC6E4C2A1A4FFBFD9EC269CA6A111161233'))
  expect(turboshake128(32 << 3, 0x1F)(ptn(17 ** 2)))
    .toMatchObject(HEX('96C77C279E0126F7FC07C9B07F5CDAE1E0BE60BDBE10620040E75D7223A624D2'))
  expect(turboshake128(32 << 3, 0x1F)(ptn(17 ** 3)))
    .toMatchObject(HEX('D4976EB56BCF118520582B709F73E1D6853E001FDAF80E1B13E0D0599D5FB372'))
  expect(turboshake128(32 << 3, 0x1F)(ptn(17 ** 4)))
    .toMatchObject(HEX('DA67C7039E98BF530CF7A37830C6664E14CBAB7F540F58403B1B82951318EE5C'))
  // expect(turboshake128(32 << 3, 0x1F)(ptn(17 ** 5)))
  //   .toMatchObject(HEX('B97A906FBF83EF7C812517ABF3B2D0AEA0C4F60318CE11CF103925127F59EECD'))
  // expect(turboshake128(32 << 3, 0x1F)(ptn(17 ** 6)))
  //   .toMatchObject(HEX('35CD494ADEDED2F25239AF09A7B8EF0C4D1CA4FE2D1AC370FA63216FE7B4C2B1'))
  expect(turboshake128(32 << 3, 0x01)(HEX('FFFFFF')))
    .toMatchObject(HEX('BF323F940494E88EE1C540FE660BE8A0C93F43D15EC006998462FA994EED5DAB'))
  expect(turboshake128(32 << 3, 0x06)(HEX('FF')))
    .toMatchObject(HEX('8EC9C66465ED0D4A6C35D13506718D687A25CB05C74CCA1E42501ABD83874A67'))
  expect(turboshake128(32 << 3, 0x07)(HEX('FFFFFF')))
    .toMatchObject(HEX('B658576001CAD9B1E5F399A9F77723BBA05458042D68206F7252682DBA3663ED'))
  expect(turboshake128(32 << 3, 0x0B)(HEX('FFFFFFFFFFFFFF')))
    .toMatchObject(HEX('8DEEAA1AEC47CCEE569F659C21DFA8E112DB3CEE37B18178B2ACD805B799CC37'))
  expect(turboshake128(32 << 3, 0x30)(HEX('FF')))
    .toMatchObject(HEX('553122E2135E363C3292BED2C6421FA232BAB03DAA07C7D6636603286506325B'))
  expect(turboshake128(32 << 3, 0x7F)(HEX('FFFFFF')))
    .toMatchObject(HEX('16274CC656D44CEFD422395D0F9053BDA6D28E122ABA15C765E5AD0E6EAF26F9'))

  expect(turboshake256(64 << 3, 0x1F)(empty))
    .toMatchObject(HEX('367A329DAFEA871C7802EC67F905AE13C57695DC2C6663C61035F59A18F8E7DB11EDC0E12E91EA60EB6B32DF06DD7F002FBAFABB6E13EC1CC20D995547600DB0'))
  expect(turboshake256(10032 << 3, 0x1F)(empty).slice(10000))
    .toMatchObject(HEX('ABEFA11630C661269249742685EC082F207265DCCF2F43534E9C61BA0C9D1D75'))
  expect(turboshake256(64 << 3, 0x1F)(ptn(17 ** 0)))
    .toMatchObject(HEX('3E1712F928F8EAF1054632B2AA0A246ED8B0C378728F60BC970410155C28820E90CC90D8A3006AA2372C5C5EA176B0682BF22BAE7467AC94F74D43D39B0482E2'))
  expect(turboshake256(64 << 3, 0x1F)(ptn(17 ** 1)))
    .toMatchObject(HEX('B3BAB0300E6A191FBE6137939835923578794EA54843F5011090FA2F3780A9E5CB22C59D78B40A0FBFF9E672C0FBE0970BD2C845091C6044D687054DA5D8E9C7'))
  expect(turboshake256(64 << 3, 0x1F)(ptn(17 ** 2)))
    .toMatchObject(HEX('66B810DB8E90780424C0847372FDC95710882FDE31C6DF75BEB9D4CD9305CFCAE35E7B83E8B7E6EB4B78605880116316FE2C078A09B94AD7B8213C0A738B65C0'))
  expect(turboshake256(64 << 3, 0x1F)(ptn(17 ** 3)))
    .toMatchObject(HEX('C74EBC919A5B3B0DD1228185BA02D29EF442D69D3D4276A93EFE0BF9A16A7DC0CD4EABADAB8CD7A5EDD96695F5D360ABE09E2C6511A3EC397DA3B76B9E1674FB'))
  expect(turboshake256(64 << 3, 0x1F)(ptn(17 ** 4)))
    .toMatchObject(HEX('02CC3A8897E6F4F6CCB6FD46631B1F5207B66C6DE9C7B55B2D1A23134A170AFDAC234EABA9A77CFF88C1F020B73724618C5687B362C430B248CD38647F848A1D'))
  // expect(turboshake256(64 << 3, 0x1F)(ptn(17 ** 5)))
  //   .toMatchObject(HEX('ADD53B06543E584B5823F626996AEE50FE45ED15F20243A7165485ACB4AA76B4FFDA75CEDF6D8CDC95C332BD56F4B986B58BB17D1778BFC1B1A97545CDF4EC9F'))
  // expect(turboshake256(64 << 3, 0x1F)(ptn(17 ** 6)))
  //   .toMatchObject(HEX('9E11BC59C24E73993C1484EC66358EF71DB74AEFD84E123F7800BA9C4853E02CFE701D9E6BB765A304F0DC34A4EE3BA82C410F0DA70E86BFBD90EA877C2D6104'))
  expect(turboshake256(64 << 3, 0x01)(HEX('FFFFFF')))
    .toMatchObject(HEX('D21C6FBBF587FA2282F29AEA620175FB0257413AF78A0B1B2A87419CE031D933AE7A4D383327A8A17641A34F8A1D1003AD7DA6B72DBA84BB62FEF28F62F12424'))
  expect(turboshake256(64 << 3, 0x06)(HEX('FF')))
    .toMatchObject(HEX('738D7B4E37D18B7F22AD1B5313E357E3DD7D07056A26A303C433FA3533455280F4F5A7D4F700EFB437FE6D281405E07BE32A0A972E22E63ADC1B090DAEFE004B'))
  expect(turboshake256(64 << 3, 0x07)(HEX('FFFFFF')))
    .toMatchObject(HEX('18B3B5B7061C2E67C1753A00E6AD7ED7BA1C906CF93EFB7092EAF27FBEEBB755AE6E292493C110E48D260028492B8E09B5500612B8F2578985DED5357D00EC67'))
  expect(turboshake256(64 << 3, 0x0B)(HEX('FFFFFFFFFFFFFF')))
    .toMatchObject(HEX('BB36764951EC97E9D85F7EE9A67A7718FC005CF42556BE79CE12C0BDE50E5736D6632B0D0DFB202D1BBB8FFE3DD74CB00834FA756CB03471BAB13A1E2C16B3C0'))
  expect(turboshake256(64 << 3, 0x30)(HEX('FF')))
    .toMatchObject(HEX('F3FE12873D34BCBB2E608779D6B70E7F86BEC7E90BF113CBD4FDD0C4E2F4625E148DD7EE1A52776CF77F240514D9CCFC3B5DDAB8EE255E39EE389072962C111A'))
  expect(turboshake256(64 << 3, 0x7F)(HEX('FFFFFF')))
    .toMatchObject(HEX('ABE569C1F77EC340F02705E7D37C9AB7E155516E4A6A150021D70B6FAC0BB40C069F9A9828A0D575CD99F9BAE435AB1ACF7ED9110BA97CE0388D074BAC768776'))
})
// * kangarooTwelve
it('kt12', async () => {
  // Vector Source: https://datatracker.ietf.org/doc/draft-irtf-cfrg-kangarootwelve/
  const empty = new Uint8Array(0)
  expect(kt128(32 << 3, empty)(empty))
    .toMatchObject(HEX('1AC2D450FC3B4205D19DA7BFCA1B37513C0803577AC7167F06FE2CE1F0EF39E5'))
  expect(kt128(64 << 3, empty)(empty))
    .toMatchObject(HEX('1AC2D450FC3B4205D19DA7BFCA1B37513C0803577AC7167F06FE2CE1F0EF39E54269C056B8C82E48276038B6D292966CC07A3D4645272E31FF38508139EB0A71'))
  expect(kt128(10032 << 3, empty)(empty).slice(10000))
    .toMatchObject(HEX('E8DC563642F7228C84684C898405D3A834799158C079B12880277A1D28E2FF6D'))
  expect(kt128(32 << 3, empty)(ptn(1)))
    .toMatchObject(HEX('2BDA92450E8B147F8A7CB629E784A058EFCA7CF7D8218E02D345DFAA65244A1F'))
  expect(kt128(32 << 3, empty)(ptn(17)))
    .toMatchObject(HEX('6BF75FA2239198DB4772E36478F8E19B0F371205F6A9A93A273F51DF37122888'))
  expect(kt128(32 << 3, empty)(ptn(17 ** 2)))
    .toMatchObject(HEX('0C315EBCDEDBF61426DE7DCF8FB725D1E74675D7F5327A5067F367B108ECB67C'))
  expect(kt128(32 << 3, empty)(ptn(17 ** 3)))
    .toMatchObject(HEX('CB552E2EC77D9910701D578B457DDF772C12E322E4EE7FE417F92C758F0D59D0'))
  expect(kt128(32 << 3, empty)(ptn(17 ** 4)))
    .toMatchObject(HEX('8701045E22205345FF4DDA05555CBB5C3AF1A771C2B89BAEF37DB43D9998B9FE'))
  // expect(kt128(32 << 3, empty)(ptn(17 ** 5)))
  //   .toMatchObject(HEX('844D610933B1B9963CBDEB5AE3B6B05CC7CBD67CEEDF883EB678A0A8E0371682'))
  // expect(kt128(32 << 3, empty)(ptn(17 ** 6)))
  //   .toMatchObject(HEX('3C390782A8A4E89FA6367F72FEAAF13255C8D95878481D3CD8CE85F58E880AF8'))
  expect(kt128(32 << 3, ptn(1))(empty))
    .toMatchObject(HEX('FAB658DB63E94A246188BF7AF69A133045F46EE984C56E3C3328CAAF1AA1A583'))
  expect(kt128(32 << 3, ptn(41))(HEX('FF')))
    .toMatchObject(HEX('D848C5068CED736F4462159B9867FD4C20B808ACC3D5BC48E0B06BA0A3762EC4'))
  expect(kt128(32 << 3, ptn(41 ** 2))(HEX('FFFFFF')))
    .toMatchObject(HEX('C389E5009AE57120854C2E8C64670AC01358CF4C1BAF89447A724234DC7CED74'))
  expect(kt128(32 << 3, ptn(41 ** 3))(HEX('FFFFFFFFFFFFFF')))
    .toMatchObject(HEX('75D2F86A2E644566726B4FBCFC5657B9DBCF070C7B0DCA06450AB291D7443BCF'))
  expect(kt128(32 << 3, empty)(ptn(8191)))
    .toMatchObject(HEX('1B577636F723643E990CC7D6A659837436FD6A103626600EB8301CD1DBE553D6'))
  expect(kt128(32 << 3, empty)(ptn(8192)))
    .toMatchObject(HEX('48F256F6772F9EDFB6A8B661EC92DC93B95EBD05A08A17B39AE3490870C926C3'))
  expect(kt128(32 << 3, ptn(8189))(ptn(8192)))
    .toMatchObject(HEX('3ED12F70FB05DDB58689510AB3E4D23C6C6033849AA01E1D8C220A297FEDCD0B'))
  expect(kt128(32 << 3, ptn(8190))(ptn(8192)))
    .toMatchObject(HEX('6A7C1B6A5CD0D8C9CA943A4A216CC64604559A2EA45F78570A15253D67BA00AE'))

  expect(kt256(64 << 3, empty)(empty))
    .toMatchObject(HEX('B23D2E9CEA9F4904E02BEC06817FC10CE38CE8E93EF4C89E6537076AF8646404E3E8B68107B8833A5D30490AA33482353FD4ADC7148ECB782855003AAEBDE4A9'))
  expect(kt256(128 << 3, empty)(empty))
    .toMatchObject(HEX('B23D2E9CEA9F4904E02BEC06817FC10CE38CE8E93EF4C89E6537076AF8646404E3E8B68107B8833A5D30490AA33482353FD4ADC7148ECB782855003AAEBDE4A9B0925319D8EA1E121A609821EC19EFEA89E6D08DAEE1662B69C840289F188BA860F55760B61F82114C030C97E5178449608CCD2CD2D919FC7829FF69931AC4D0'))
  expect(kt256(10064 << 3, empty)(empty).slice(10000))
    .toMatchObject(HEX('AD4A1D718CF950506709A4C33396139B4449041FC79A05D68DA35F1E453522E056C64FE94958E7085F2964888259B9932752F3CCD855288EFEE5FCBB8B563069'))
  expect(kt256(64 << 3, empty)(ptn(1)))
    .toMatchObject(HEX('0D005A194085360217128CF17F91E1F71314EFA5564539D444912E3437EFA17F82DB6F6FFE76E781EAA068BCE01F2BBF81EACB983D7230F2FB02834A21B1DDD0'))
  expect(kt256(64 << 3, empty)(ptn(17)))
    .toMatchObject(HEX('1BA3C02B1FC514474F06C8979978A9056C8483F4A1B63D0DCCEFE3A28A2F323E1CDCCA40EBF006AC76EF0397152346837B1277D3E7FAA9C9653B19075098527B'))
  expect(kt256(64 << 3, empty)(ptn(17 ** 2)))
    .toMatchObject(HEX('DE8CCBC63E0F133EBB4416814D4C66F691BBF8B6A61EC0A7700F836B086CB029D54F12AC7159472C72DB118C35B4E6AA213C6562CAAA9DCC518959E69B10F3BA'))
  expect(kt256(64 << 3, empty)(ptn(17 ** 3)))
    .toMatchObject(HEX('647EFB49FE9D717500171B41E7F11BD491544443209997CE1C2530D15EB1FFBB598935EF954528FFC152B1E4D731EE2683680674365CD191D562BAE753B84AA5'))
  expect(kt256(64 << 3, empty)(ptn(17 ** 4)))
    .toMatchObject(HEX('B06275D284CD1CF205BCBE57DCCD3EC1FF6686E3ED15776383E1F2FA3C6AC8F08BF8A162829DB1A44B2A43FF83DD89C3CF1CEB61EDE659766D5CCF817A62BA8D'))
  // expect(kt256(64 << 3, empty)(ptn(17 ** 5)))
  //   .toMatchObject(HEX('9473831D76A4C7BF77ACE45B59F1458B1673D64BCD877A7C66B2664AA6DD149E60EAB71B5C2BAB858C074DED81DDCE2B4022B5215935C0D4D19BF511AEEB0772'))
  // expect(kt256(64 << 3, empty)(ptn(17 ** 6)))
  //   .toMatchObject(HEX('0652B740D78C5E1F7C8DCC1777097382768B7FF38F9A7A20F29F413BB1B3045B31A5578F568F911E09CF44746DA84224A5266E96A4A535E871324E4F9C7004DA'))
  expect(kt256(64 << 3, ptn(1))(empty))
    .toMatchObject(HEX('9280F5CC39B54A5A594EC63DE0BB99371E4609D44BF845C2F5B8C316D72B159811F748F23E3FABBE5C3226EC96C62186DF2D33E9DF74C5069CEECBB4DD10EFF6'))
  expect(kt256(64 << 3, ptn(41))(HEX('FF')))
    .toMatchObject(HEX('47EF96DD616F200937AA7847E34EC2FEAE8087E3761DC0F8C1A154F51DC9CCF845D7ADBCE57FF64B639722C6A1672E3BF5372D87E00AFF89BE97240756998853'))
  expect(kt256(64 << 3, ptn(41 ** 2))(HEX('FFFFFF')))
    .toMatchObject(HEX('3B48667A5051C5966C53C5D42B95DE451E05584E7806E2FB765EDA959074172CB438A9E91DDE337C98E9C41BED94C4E0AEF431D0B64EF2324F7932CAA6F54969'))
  expect(kt256(64 << 3, ptn(41 ** 3))(HEX('FFFFFFFFFFFFFF')))
    .toMatchObject(HEX('E0911CC00025E1540831E266D94ADD9B98712142B80D2629E643AAC4EFAF5A3A30A88CBF4AC2A91A2432743054FBCC9897670E86BA8CEC2FC2ACE9C966369724'))
  expect(kt256(64 << 3, empty)(ptn(8191)))
    .toMatchObject(HEX('3081434D93A4108D8D8A3305B89682CEBEDC7CA4EA8A3CE869FBB73CBE4A58EEF6F24DE38FFC170514C70E7AB2D01F03812616E863D769AFB3753193BA045B20'))
  expect(kt256(64 << 3, empty)(ptn(8192)))
    .toMatchObject(HEX('C6EE8E2AD3200C018AC87AAA031CDAC22121B412D07DC6E0DCCBB53423747E9A1C18834D99DF596CF0CF4B8DFAFB7BF02D139D0C9035725ADC1A01B7230A41FA'))
  expect(kt256(64 << 3, ptn(8189))(ptn(8192)))
    .toMatchObject(HEX('74E47879F10A9C5D11BD2DA7E194FE57E86378BF3C3F7448EFF3C576A0F18C5CAAE0999979512090A7F348AF4260D4DE3C37F1ECAF8D2C2C96C1D16C64B12496'))
  expect(kt256(64 << 3, ptn(8190))(ptn(8192)))
    .toMatchObject(HEX('F4B5908B929FFE01E0F79EC2F21243D41A396B2E7303A6AF1D6399CD6C7A0A2DD7C4F607E8277F9C9B1CB4AB9DDC59D4B92D1FC7558441F1832C3279A4241B8B'))
})
// * TOTP
it('totp', async () => {
  const S0 = UTF8('12345678901234567890')
  const S1 = UTF8('12345678901234567890123456789012')
  const S2 = UTF8('1234567890123456789012345678901234567890123456789012345678901234')
  expect(totp({ current: 59000, digits: 8 })(S0))
    .toMatchInlineSnapshot('"94287082"')
  expect(totp({ current: 59000, digits: 8, mac: hmac(sha256) })(S1))
    .toMatchInlineSnapshot('"46119246"')
  expect(totp({ current: 59000, digits: 8, mac: hmac(sha512) })(S2))
    .toMatchInlineSnapshot('"90693936"')

  expect(totp({ current: 1111111109000, digits: 8 })(S0))
    .toMatchInlineSnapshot('"07081804"')
  expect(totp({ current: 1111111109000, digits: 8, mac: hmac(sha256) })(S1))
    .toMatchInlineSnapshot('"68084774"')
  expect(totp({ current: 1111111109000, digits: 8, mac: hmac(sha512) })(S2))
    .toMatchInlineSnapshot('"25091201"')

  expect(totp({ current: 20000000000000, digits: 8 })(S0))
    .toMatchInlineSnapshot('"65353130"')
  expect(totp({ current: 20000000000000, digits: 8, mac: hmac(sha256) })(S1))
    .toMatchInlineSnapshot('"77737706"')
  expect(totp({ current: 20000000000000, digits: 8, mac: hmac(sha512) })(S2))
    .toMatchInlineSnapshot('"47863826"')
})
