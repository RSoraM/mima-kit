import { U8, modPow } from './utils'

// * Constants

/** deterministic >= 1 - 0.5^t */
const T = 40
const LOW_PRIMES = [2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n, 41n, 43n, 47n, 53n, 59n, 61n, 67n, 71n, 73n, 79n, 83n, 89n, 97n, 101n, 103n, 107n, 109n, 113n, 127n, 131n, 137n, 139n, 149n, 151n, 157n, 163n, 167n, 173n, 179n, 181n, 191n, 193n, 197n, 199n, 211n, 223n, 227n, 229n, 233n, 239n, 241n, 251n, 257n, 263n, 269n, 271n, 277n, 281n, 283n, 293n, 307n, 311n, 313n, 317n, 331n, 337n, 347n, 349n, 353n, 359n, 367n, 373n, 379n, 383n, 389n, 397n, 401n, 409n, 419n, 421n, 431n, 433n, 439n, 443n, 449n, 457n, 461n, 463n, 467n, 479n, 487n, 491n, 499n, 503n, 509n, 521n, 523n, 541n, 547n, 557n, 563n, 569n, 571n, 577n, 587n, 593n, 599n, 601n, 607n, 613n, 617n, 619n, 631n, 641n, 643n, 647n, 653n, 659n, 661n, 673n, 677n, 683n, 691n, 701n, 709n, 719n, 727n, 733n, 739n, 743n, 751n, 757n, 761n, 769n, 773n, 787n, 797n, 809n, 811n, 821n, 823n, 827n, 829n, 839n, 853n, 857n, 859n, 863n, 877n, 881n, 883n, 887n, 907n, 911n, 919n, 929n, 937n, 941n, 947n, 953n, 967n, 971n, 977n, 983n, 991n, 997n]
const LOW_PRIMES_LIMIT = (1n << 26n) / LOW_PRIMES[LOW_PRIMES.length - 1]

// * Functions

/**
 * Miller-Rabin 素性测试
 *
 * Miller-Rabin primality test
 */
function MillerRabin(n: bigint, t: number): boolean {
  const n1 = n - 1n
  let r = n1
  let k = 1
  while ((r & 1n) === 0n) {
    r >>= 1n
    k++
  }

  t = (t + 1) >> 1
  if (t > LOW_PRIMES.length)
    t = LOW_PRIMES.length
  for (let i = 0; i < t; ++i) {
    // Pick bases at random, instead of starting at 2
    const a = LOW_PRIMES[Math.floor(Math.random() * LOW_PRIMES.length)]
    let y = modPow(a, r, n)
    if (y !== 1n && y !== n1) {
      for (let j = 1; j < k && y !== n1; j++) {
        y = modPow(y, 2n, n)
        if (y === 1n)
          return false
      }
      if (y !== n1)
        return false
    }
  }
  return true
}

/**
 * 素性测试: 确定性 >= 1-.5^t
 *
 * Primality test: deterministic >= 1-.5^t
 */
export function isProbablePrime(n: bigint, t: number = T): boolean {
  if (t <= 0)
    return false
  // 偶数
  if ((n & 1n) === 0n)
    return false

  // 小素数
  if (n <= LOW_PRIMES[LOW_PRIMES.length - 1])
    return LOW_PRIMES.includes(n)
  for (let i = 1; i < LOW_PRIMES.length;) {
    let m = LOW_PRIMES[i]
    let j = i + 1
    while (j < LOW_PRIMES.length && m < LOW_PRIMES_LIMIT) {
      m *= LOW_PRIMES[j++]
    }
    m = n % m
    while (i < j) {
      if (m % LOW_PRIMES[i++] === 0n)
        return false
    }
  }

  return MillerRabin(n, t)
}

/**
 * 生成一个 `b` 位的素数
 *
 * Generate a prime number with `b` bits
 */
export function genPrime(b: number): bigint {
  // using Node.js crypto module
  // eslint-disable-next-line node/prefer-global/process
  if (typeof process !== 'undefined' && process.versions != null && process.versions.node != null) {
    // eslint-disable-next-line ts/no-require-imports
    const crypto = require('node:crypto')
    return crypto.generatePrimeSync(b, { bigint: true })
  }

  // using Web Crypto API
  const buffer = new U8(b >> 3)
  crypto.getRandomValues(buffer)
  const prime = buffer.toBI() | 1n
  if (isProbablePrime(prime))
    return prime
  else
    return nextPrime(prime)
}

export function nextPrime(n: bigint): bigint {
  do {
    n += 2n
  } while (isProbablePrime(n) === false)
  return n
}
