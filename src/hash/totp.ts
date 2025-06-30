import type { KeyHash } from '../core/hash'
import { U8 } from '../core/utils'
import { hmac } from './hmac'
import { sha1 } from './sha1'

/**
 * 生成 HOTP (基于计数的一次性密码)
 *
 * Generate HOTP (HMAC-based One-Time Password)
 *
 * @param {Uint8Array} secret - 密钥
 * @param {Uint8Array} counter - 计数器
 * @param {KeyHash} mac - 带密钥的加密散列算法
 * @returns {U8} - 返回的 HOTP 字节数组
 */
function hotp(
  secret: Uint8Array,
  counter: Uint8Array,
  mac: KeyHash = hmac(sha1),
): U8 {
  const HS = mac(secret, counter)
  const offset = HS[HS.length - 1] & 0x0F
  return HS.slice(offset, offset + 4)
}

interface TOTP {
  /**
   * 生成 TOTP (时间同步的一次性密码)
   *
   * Generate TOTP (Time-based One-Time Password)
   *
   * @param {Uint8Array} secret - 密钥
   * @returns {string} - 返回的 TOTP 字符串
   */
  (secret: Uint8Array): string
}

interface TOTPParams {
  /**
   * 带密钥的加密散列算法 / Keyed Hashing Algorithm (default: HMAC-SHA1)
   */
  mac?: KeyHash
  /**
   * 当前时间戳 / Current timestamp (default: Date.now() milliseconds)
   *
   * 指定此参数时，将不再从 `Date.now()` 获取当前时间戳.
   *
   * When this parameter is specified, the current timestamp will not be obtained from `Date.now()`.
   */
  current?: number
  /**
   * 纪元时间戳 / Epoch timestamp (default: 0 milliseconds)
   */
  epoch?: number
  /**
   * 时间步长 / Time step (default: 30000 milliseconds)
   */
  step?: number
  /**
   * 计数器 / Counter
   *
   * `counter = (cuttent_time - epoch_time) / step`
   *
   * 指定此参数时，将不再从当前时间戳计算计数器.
   *
   * When this parameter is specified, the counter will not be calculated from the current timestamp.
   */
  counter?: number | bigint | Uint8Array
  /**
   * 返回的数字位数 / Number of digits in the returned OTP (default: 6)
   */
  digits?: number
}

/**
 * 生成 TOTP (时间同步的一次性密码)
 *
 * Generate TOTP (Time-based One-Time Password)
 *
 * @param {Uint8Array} secret - 密钥
 * @returns {string} - 返回的 TOTP 字符串
 */
export function totp(secret: Uint8Array): string
/**
 * 创建 TOTP 函数 / Create a TOTP function
 *
 * @param {TOTPParams} params - TOTP 参数
 * @returns {TOTP} - 返回的 TOTP 函数
 */
export function totp(params: TOTPParams): TOTP
export function totp(
  args: Uint8Array | TOTPParams,
) {
  if (args instanceof Uint8Array) {
    const K = args
    const C = U8.fromBI(BigInt(Math.floor(Date.now() / 30000)), 8, false)
    const HS = hotp(K, C, hmac(sha1))
    const OTP = 0
      | (HS[0] & 0x7F) << 24
      | (HS[1] & 0xFF) << 16
      | (HS[2] & 0xFF) << 8
      | (HS[3] & 0xFF)
    return (OTP % 1_000_000)
      .toString()
      .padStart(6, '0')
  }

  return (secret: Uint8Array) => {
    let {
      mac = hmac(sha1),
      current = Date.now(),
      epoch = 0,
      step = 30000,
      counter = 0,
      digits = 6,
    } = args || {}

    if (!counter) {
      const T = BigInt(Math.floor((current - epoch) / step))
      counter = U8.fromBI(T, 8, false)
    }
    if (!(counter instanceof Uint8Array)) {
      counter = U8.fromBI(BigInt(counter), 8, false)
    }

    const BIN = hotp(secret, counter, mac)
    const OTP = 0
      | (BIN[0] & 0x7F) << 24
      | (BIN[1] & 0xFF) << 16
      | (BIN[2] & 0xFF) << 8
      | (BIN[3] & 0xFF)
    return (OTP % (10 ** digits))
      .toString()
      .padStart(digits, '0')
  }
}
