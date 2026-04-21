import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { sha3_256 } from '@noble/hashes/sha3.js';
import { argon2id } from '@noble/hashes/argon2.js';

export type KdfAlg = 'hkdf-sha256' | 'hkdf-sha3-256';

export const KDF_ALG_ID: Record<KdfAlg, number> = {
  'hkdf-sha256': 0,
  'hkdf-sha3-256': 1,
};

export const KDF_ALG_NAME: Record<number, KdfAlg> = {
  0: 'hkdf-sha256',
  1: 'hkdf-sha3-256',
};

export function deriveKey(
  alg: KdfAlg,
  ikm: Uint8Array,
  salt: Uint8Array,
  info: string,
  length = 32,
): Uint8Array {
  const infoBytes = new TextEncoder().encode(info);
  switch (alg) {
    case 'hkdf-sha256':
      return hkdf(sha256, ikm, salt, infoBytes, length);
    case 'hkdf-sha3-256':
      return hkdf(sha3_256, ikm, salt, infoBytes, length);
  }
}

export type Argon2Params = {
  t: number;
  m: number;
  p: number;
};

export const ARGON2_DEFAULTS: Argon2Params = {
  t: 3,
  m: 64 * 1024,
  p: 1,
};

export function stretchPassphrase(
  passphrase: string,
  salt: Uint8Array,
  params: Argon2Params = ARGON2_DEFAULTS,
  length = 32,
): Uint8Array {
  const pw = new TextEncoder().encode(passphrase.normalize('NFKC'));
  return argon2id(pw, salt, { t: params.t, m: params.m, p: params.p, dkLen: length });
}
