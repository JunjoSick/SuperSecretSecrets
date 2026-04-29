import {
  G,
  type Point,
  type Rng,
  hashToScalar,
  pointFromBytes,
  pointToBytes,
  POINT_LEN,
  randomScalar,
  scalarAdd,
  scalarFromBytes,
  scalarMul,
  scalarToBytes,
  SCALAR_LEN,
} from './curve.js';
import { H } from './pedersen.js';

export const SCHNORR_PROOF_LEN = POINT_LEN + SCALAR_LEN * 2;

export type SchnorrProof = {
  A: Point;
  z1: bigint;
  z2: bigint;
};

function challenge(ctx: Uint8Array, C: Point, A: Point): bigint {
  return hashToScalar('schnorr-pok', ctx, pointToBytes(C), pointToBytes(A));
}

export function schnorrProveCommit(
  value: bigint,
  blinding: bigint,
  C: Point,
  ctx: Uint8Array,
  rng?: Rng,
): SchnorrProof {
  const a = randomScalar(rng);
  const b = randomScalar(rng);
  const A = G.multiply(a).add(H().multiply(b));
  const c = challenge(ctx, C, A);
  const z1 = scalarAdd(a, scalarMul(c, value));
  const z2 = scalarAdd(b, scalarMul(c, blinding));
  return { A, z1, z2 };
}

export function schnorrVerifyCommit(
  C: Point,
  proof: SchnorrProof,
  ctx: Uint8Array,
): boolean {
  const c = challenge(ctx, C, proof.A);
  const lhs = G.multiply(proof.z1).add(H().multiply(proof.z2));
  const rhs = proof.A.add(C.multiply(c));
  return lhs.equals(rhs);
}

export function encodeSchnorrProof(proof: SchnorrProof): Uint8Array {
  const out = new Uint8Array(SCHNORR_PROOF_LEN);
  out.set(pointToBytes(proof.A), 0);
  out.set(scalarToBytes(proof.z1), POINT_LEN);
  out.set(scalarToBytes(proof.z2), POINT_LEN + SCALAR_LEN);
  return out;
}

export function decodeSchnorrProof(raw: Uint8Array): SchnorrProof {
  if (raw.length !== SCHNORR_PROOF_LEN) throw new Error('schnorr proof length mismatch');
  const A = pointFromBytes(raw.subarray(0, POINT_LEN));
  const z1 = scalarFromBytes(raw.subarray(POINT_LEN, POINT_LEN + SCALAR_LEN));
  const z2 = scalarFromBytes(raw.subarray(POINT_LEN + SCALAR_LEN));
  return { A, z1, z2 };
}
