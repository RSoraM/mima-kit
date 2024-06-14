export function ROTL(x: number, n: number) {
  return (x << n) | (x >>> (32 - n))
}
