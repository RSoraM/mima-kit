import type { GFUtils } from './galois_field'
import { KitError } from './utils'

// * Interfaces

export type ECPoint = AffinePoint | JacobianPoint | LDPoint

/**
 * 仿射坐标系的点
 *
 * Affine Coordinate Point
 */
export interface AffinePoint {
  type: 'affine'
  isInfinity: boolean
  x: bigint
  y: bigint
}

/**
 * 雅可比坐标系的点
 *
 * Jacobian Coordinate Point
 */
export interface JacobianPoint {
  type: 'jacobian'
  isInfinity: boolean
  x: bigint
  y: bigint
  z: bigint
}

/**
 * 洛佩兹-达哈布坐标系的点
 *
 * López-Dahab Coordinate Point
 */
export interface LDPoint {
  type: 'ld'
  isInfinity: boolean
  x: bigint
  y: bigint
  z: bigint
}

/**
 * 坐标系转换接口
 *
 * Coordinate System Conversion Interface
 */
export interface CSUtils {
  /**
   * 雅可比坐标系 -> 仿射坐标系
   *
   * Jacobian Coordinate System to Affine Coordinate System
   */
  toAffine: {
    (P: ECPoint): AffinePoint
    (P: undefined): AffinePoint
  }
  /**
   * 仿射坐标系 -> 雅可比坐标系 (bigint)
   *
   * Affine Coordinate System to Jacobian Coordinate System (bigint)
   */
  toJacobian: {
    (P: JacobianPoint): JacobianPoint
    (P: AffinePoint, Z?: bigint): JacobianPoint
    (P: undefined): JacobianPoint
  }
  /**
   * 洛佩兹-达哈布坐标系 -> 仿射坐标系
   *
   * López-Dahab Coordinate System to Affine Coordinate System
   */
  toLD: {
    (P: LDPoint): LDPoint
    (P: AffinePoint, Z?: bigint): LDPoint
    (P: undefined): LDPoint
  }
}

// * Coordinate Systems

export function CoordinateSystem(field: GFUtils): CSUtils {
  const { mul, inv, mod, squ } = field

  const toAffine: CSUtils['toAffine'] = (P?: ECPoint): AffinePoint => {
    if (!P || P.isInfinity)
      return { type: 'affine', isInfinity: true, x: 0n, y: 0n }

    if (P.type === 'affine')
      return P

    if (P.z === 0n)
      return { type: 'affine', isInfinity: true, x: 0n, y: 0n }
    if (P.z === 1n)
      return { type: 'affine', isInfinity: false, x: mod(P.x), y: mod(P.y) }

    if (P.type !== 'jacobian' && P.type !== 'ld')
      throw new KitError('Invalid point type')

    let x = 0n
    let y = 0n
    const z_inv = inv(P.z)
    const z_inv2 = squ(z_inv)
    if (P.type === 'jacobian') {
      const z_inv3 = mul(z_inv2, z_inv)
      x = mul(P.x, z_inv2)
      y = mul(P.y, z_inv3)
    }
    else if (P.type === 'ld') {
      x = mul(P.x, z_inv)
      y = mul(P.y, z_inv2) // y = Y / Z^2
    }

    return { type: 'affine', isInfinity: false, x, y }
  }

  function toJacobian(P?: JacobianPoint | AffinePoint, Z = 1n): JacobianPoint {
    if (!P || P.isInfinity || Z === 0n)
      return { type: 'jacobian', isInfinity: true, x: 1n, y: 1n, z: 0n }

    if (P.type === 'jacobian')
      return P

    let { x, y } = P
    if (Z === 1n)
      return { type: 'jacobian', isInfinity: false, x, y, z: Z }

    const ZZ = squ(Z)
    const ZZZ = mul(ZZ, Z)
    x = mul(x, ZZ)
    y = mul(y, ZZZ)

    return { type: 'jacobian', isInfinity: false, x, y, z: Z }
  }

  function toLD(P?: LDPoint | AffinePoint, Z = 1n): LDPoint {
    if (!P || P.isInfinity)
      return { type: 'ld', isInfinity: true, x: 1n, y: 1n, z: 0n }

    if (P.type === 'ld')
      return P

    let { x, y } = P
    if (Z === 1n)
      return { type: 'ld', isInfinity: false, x, y, z: Z }

    const ZZ = squ(Z)
    x = mul(x, Z)
    y = mul(y, ZZ)

    return { type: 'ld', isInfinity: false, x, y, z: Z }
  }

  return {
    toAffine,
    toJacobian,
    toLD,
  }
}
