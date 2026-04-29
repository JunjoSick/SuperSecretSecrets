import { describe, expect, it } from 'vitest';
import { AEAD_ALG_ID } from '../src/crypto/aead';
import { KDF_ALG_ID } from '../src/crypto/kdf';
import { kemLengths } from '../src/crypto/pq';
import {
  ML_KEM_768_CIPHERTEXT_BYTES,
  PROOF_AEAD_ID_AES_256_GCM,
  PROOF_KDF_ID_HKDF_SHA256,
  RELATION_V1_DIGEST,
  RELATION_V1_ID,
  digestDecryptionProofRelation,
  getSupportedDecryptionProofRelation,
  type DecryptionProofSupportInput,
} from '../src/crypto/zk/decryption-proof-relations';

describe('decryption proof relation support', () => {
  const base: DecryptionProofSupportInput = {
    formatVersion: 3,
    payloadKind: 'vault-root',
    kemAlg: 'ml-kem-768',
    kdfAlg: 'hkdf-sha256',
    aeadAlg: 'aes-256-gcm',
    passphrase: false,
  };

  it('supports only the first v3 vault-root no-passphrase relation', () => {
    expect(getSupportedDecryptionProofRelation(base)).toEqual({
      supported: true,
      relationId: RELATION_V1_ID,
    });
  });

  it('rejects unsupported relation variants', () => {
    const unsupported: Array<[string, Partial<DecryptionProofSupportInput>]> = [
      ['secret payload', { payloadKind: 'secret' }],
      ['passphrase', { passphrase: true }],
      ['v1', { formatVersion: 1 }],
      ['v2', { formatVersion: 2 }],
      ['ML-KEM-512', { kemAlg: 'ml-kem-512' }],
      ['ML-KEM-1024', { kemAlg: 'ml-kem-1024' }],
      ['SHA3 KDF', { kdfAlg: 'hkdf-sha3-256' }],
      ['ChaCha AEAD', { aeadAlg: 'chacha20-poly1305' }],
    ];

    for (const [, override] of unsupported) {
      const result = getSupportedDecryptionProofRelation({ ...base, ...override });
      expect(result.supported).toBe(false);
    }
  });

  it('uses proof-local IDs rather than app codec IDs', () => {
    expect(PROOF_KDF_ID_HKDF_SHA256).toBe(0x01);
    expect(PROOF_AEAD_ID_AES_256_GCM).toBe(0x01);
    expect(PROOF_KDF_ID_HKDF_SHA256).not.toBe(KDF_ALG_ID['hkdf-sha256']);
    expect(PROOF_AEAD_ID_AES_256_GCM).not.toBe(AEAD_ALG_ID['aes-256-gcm']);
  });

  it('keeps the ML-KEM-768 ciphertext length hardcoded and dependency-confirmed', () => {
    expect(ML_KEM_768_CIPHERTEXT_BYTES).toBe(1088);
    expect(kemLengths('ml-kem-768').cipherText).toBe(ML_KEM_768_CIPHERTEXT_BYTES);
  });

  it('computes a stable 32-byte relation digest that changes with the relation', () => {
    expect(RELATION_V1_DIGEST.length).toBe(32);
    expect(digestDecryptionProofRelation()).toEqual(RELATION_V1_DIGEST);
    expect(digestDecryptionProofRelation(`${RELATION_V1_ID}-changed`)).not.toEqual(RELATION_V1_DIGEST);
  });
});
