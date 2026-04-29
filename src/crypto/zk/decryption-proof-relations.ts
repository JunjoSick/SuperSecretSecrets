import { sha256 } from '@noble/hashes/sha2.js';
import type { AeadAlg } from '../aead';
import type { KdfAlg } from '../kdf';
import type { KemAlg } from '../pq';

export const DECRYPTION_PROOF_ENVELOPE_VERSION = 1;

export const DECRYPTION_PROOF_SCHEME_HALO2_KZG = 0x01;
export const DECRYPTION_PROOF_SCHEME_TEST_MOCK = 0x7f;

export const DECRYPTION_PROOF_DIGEST_BYTES = 32;

export const RELATION_V1_ID =
  'sss-v3-mlkem768-hkdfsha256-aes256gcm-poseidon2bn254-vaultroot-nopass-v1';

export const RELATION_V1_VAULTROOT_ONLY_ID =
  'sss-v3-poseidon2bn254-vaultroot-only-v1';

export const RELATION_V1_DIGEST_DOMAIN =
  'SSS/v3/decryption-proof/relation-digest/v1';

export const TRANSCRIPT_V1_DOMAIN =
  'SSS/v3/decryption-proof/public-inputs/v1';

export const ML_KEM_768_PUBLIC_KEY_BYTES = 1184;
export const ML_KEM_768_SECRET_KEY_BYTES = 2400;
export const ML_KEM_768_CIPHERTEXT_BYTES = 1088;
export const ML_KEM_768_SHARED_SECRET_BYTES = 32;
export const ML_KEM_SEED_BYTES = 64;

export const AES_256_GCM_KEY_BYTES = 32;
export const AES_256_GCM_NONCE_BYTES = 12;
export const AES_256_GCM_TAG_BYTES = 16;
export const VAULT_ROOT_KEY_BYTES = 32;

export const PROOF_KEM_ID_ML_KEM_768 = 0x01;
export const PROOF_KDF_ID_HKDF_SHA256 = 0x01;
export const PROOF_AEAD_ID_AES_256_GCM = 0x01;
export const PROOF_COMMITMENT_HASH_ID_POSEIDON2_BN254 = 0x01;

export const BN254_TRANSCRIPT_DIGEST_BYTES = 32;
export const BN254_TRANSCRIPT_DIGEST_LIMB_BYTES = 16;
export const BN254_TRANSCRIPT_DIGEST_PUBLIC_INPUTS = 2;

const textEncoder = new TextEncoder();

export type DecryptionProofSupportInput = {
  formatVersion: number;
  payloadKind: string;
  kemAlg: KemAlg;
  kdfAlg: KdfAlg;
  aeadAlg: AeadAlg;
  passphrase: boolean;
};

export type DecryptionProofSupport =
  | { supported: true; relationId: typeof RELATION_V1_ID }
  | { supported: false; reason: string };

export function digestDecryptionProofRelation(
  relationId: string = RELATION_V1_ID,
  domain: string = RELATION_V1_DIGEST_DOMAIN,
): Uint8Array {
  return sha256(concat(u16LengthPrefixed(textEncoder.encode(domain)), u16LengthPrefixed(textEncoder.encode(relationId))));
}

export const RELATION_V1_DIGEST = digestDecryptionProofRelation();
export const RELATION_V1_VAULTROOT_ONLY_DIGEST = digestDecryptionProofRelation(RELATION_V1_VAULTROOT_ONLY_ID);

export type SupportedHalo2RelationId =
  | typeof RELATION_V1_ID
  | typeof RELATION_V1_VAULTROOT_ONLY_ID;

export type SupportedHalo2Relation = {
  id: SupportedHalo2RelationId;
  digest: Uint8Array;
};

export const SUPPORTED_HALO2_RELATIONS: readonly SupportedHalo2Relation[] = [
  { id: RELATION_V1_ID, digest: RELATION_V1_DIGEST },
  { id: RELATION_V1_VAULTROOT_ONLY_ID, digest: RELATION_V1_VAULTROOT_ONLY_DIGEST },
] as const;

export function lookupSupportedHalo2Relation(
  digest: Uint8Array,
): SupportedHalo2Relation | null {
  if (!(digest instanceof Uint8Array)) return null;
  for (const relation of SUPPORTED_HALO2_RELATIONS) {
    if (constantTimeBytesEqual(digest, relation.digest)) return relation;
  }
  return null;
}

function constantTimeBytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

export function getSupportedDecryptionProofRelation(
  input: DecryptionProofSupportInput,
): DecryptionProofSupport {
  if (input.formatVersion !== 3) {
    return { supported: false, reason: 'decryption proofs are supported only for v3 bundles' };
  }
  if (input.payloadKind !== 'vault-root') {
    return { supported: false, reason: 'first proof relation supports only vault-root payloads' };
  }
  if (input.kemAlg !== 'ml-kem-768') {
    return { supported: false, reason: 'first proof relation supports only ML-KEM-768' };
  }
  if (input.kdfAlg !== 'hkdf-sha256') {
    return { supported: false, reason: 'first proof relation supports only HKDF-SHA256' };
  }
  if (input.aeadAlg !== 'aes-256-gcm') {
    return { supported: false, reason: 'first proof relation supports only AES-256-GCM' };
  }
  if (input.passphrase) {
    return { supported: false, reason: 'first proof relation does not support passphrase bundles' };
  }
  return { supported: true, relationId: RELATION_V1_ID };
}

function u16LengthPrefixed(bytes: Uint8Array): Uint8Array {
  if (bytes.length > 0xffff) throw new Error('decryption proof relation component too long');
  const out = new Uint8Array(2 + bytes.length);
  out[0] = (bytes.length >>> 8) & 0xff;
  out[1] = bytes.length & 0xff;
  out.set(bytes, 2);
  return out;
}

function concat(...chunks: Uint8Array[]): Uint8Array {
  const len = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const out = new Uint8Array(len);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}
