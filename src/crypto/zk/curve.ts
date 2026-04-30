import { ristretto255, ristretto255_hasher } from '@noble/curves/ed25519.js';
import { bytesToNumberLE, numberToBytesLE } from '@noble/curves/utils.js';

export const Point = ristretto255.Point;
export type Point = InstanceType<typeof ristretto255.Point>;

export const G: Point = Point.BASE;
export const ORDER: bigint = Point.Fn.ORDER;
export const SCALAR_LEN = 32;
export const POINT_LEN = 32;

const DST_PREFIX = 'SSS3/';

export type Rng = (n: number) => Uint8Array;

const defaultRng: Rng = (n) => {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
};

export function randomScalar(rng: Rng = defaultRng): bigint {
  return ristretto255_hasher.hashToScalar(rng(64), { DST: DST_PREFIX + 'randomScalar' });
}

export function hashToScalar(domain: string, ...parts: Uint8Array[]): bigint {
  return ristretto255_hasher.hashToScalar(concatBytes(parts), { DST: DST_PREFIX + domain });
}

export function hashToPoint(domain: string, ...parts: Uint8Array[]): Point {
  return ristretto255_hasher.hashToCurve(concatBytes(parts), { DST: DST_PREFIX + domain }) as Point;
}

export function pointToBytes(p: Point): Uint8Array {
  return p.toBytes();
}

export function pointFromBytes(b: Uint8Array): Point {
  if (b.length !== POINT_LEN) throw new Error(`ristretto255 point must be ${POINT_LEN} bytes`);
  return Point.fromBytes(b);
}

export function scalarToBytes(s: bigint): Uint8Array {
  const reduced = ((s % ORDER) + ORDER) % ORDER;
  return numberToBytesLE(reduced, SCALAR_LEN);
}

export function scalarFromBytes(b: Uint8Array): bigint {
  if (b.length !== SCALAR_LEN) throw new Error(`scalar must be ${SCALAR_LEN} bytes`);
  return bytesToNumberLE(b) % ORDER;
}

export function scalarAdd(a: bigint, b: bigint): bigint {
  return ((a + b) % ORDER + ORDER) % ORDER;
}

export function scalarMul(a: bigint, b: bigint): bigint {
  return ((a * b) % ORDER + ORDER) % ORDER;
}

function concatBytes(parts: Uint8Array[]): Uint8Array {
  const len = parts.reduce((s, p) => s + p.length, 0);
  const out = new Uint8Array(len);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}
