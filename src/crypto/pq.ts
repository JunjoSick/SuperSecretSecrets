import { ml_kem512, ml_kem768, ml_kem1024 } from '@noble/post-quantum/ml-kem.js';

export type KemAlg = 'ml-kem-512' | 'ml-kem-768' | 'ml-kem-1024';

export const KEM_ALG_ID: Record<KemAlg, number> = {
  'ml-kem-512': 0,
  'ml-kem-768': 1,
  'ml-kem-1024': 2,
};

export const KEM_ALG_NAME: Record<number, KemAlg> = {
  0: 'ml-kem-512',
  1: 'ml-kem-768',
  2: 'ml-kem-1024',
};

const IMPLS = {
  'ml-kem-512': ml_kem512,
  'ml-kem-768': ml_kem768,
  'ml-kem-1024': ml_kem1024,
} as const;

export const KEM_SEED_LEN = 64;

export function kem(alg: KemAlg) {
  return IMPLS[alg];
}

export function keygenFromSeed(alg: KemAlg, seed: Uint8Array) {
  if (seed.length !== KEM_SEED_LEN) {
    throw new Error(`KEM seed must be ${KEM_SEED_LEN} bytes, got ${seed.length}`);
  }
  return IMPLS[alg].keygen(seed);
}

export function encapsulate(alg: KemAlg, publicKey: Uint8Array) {
  return IMPLS[alg].encapsulate(publicKey);
}

export function decapsulate(alg: KemAlg, secretKey: Uint8Array, cipherText: Uint8Array) {
  return IMPLS[alg].decapsulate(cipherText, secretKey);
}

export function kemLengths(alg: KemAlg) {
  return IMPLS[alg].lengths;
}
