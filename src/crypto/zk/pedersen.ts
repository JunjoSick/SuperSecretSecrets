import {
  G,
  Point,
  hashToPoint,
  hashToScalar,
  pointFromBytes,
  pointToBytes,
  POINT_LEN,
} from './curve.js';

let _H: Point | undefined;

export function H(): Point {
  if (!_H) _H = hashToPoint('pedersen-H', new Uint8Array(0));
  return _H;
}

export function pedersenCommit(value: bigint, blinding: bigint): Point {
  return G.multiply(value).add(H().multiply(blinding));
}

export function commitmentToBytes(c: Point): Uint8Array {
  return pointToBytes(c);
}

export function commitmentFromBytes(b: Uint8Array): Point {
  if (b.length !== POINT_LEN) throw new Error(`commitment must be ${POINT_LEN} bytes`);
  return pointFromBytes(b);
}

export function valueScalar(domain: string, payload: Uint8Array): bigint {
  return hashToScalar(domain, payload);
}
