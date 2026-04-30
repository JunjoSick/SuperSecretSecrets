import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';
import {
  DECRYPTION_PROOF_FLAG_TEST_ONLY,
  type DecryptionProofEnvelope,
} from '../../src/crypto/zk/decryption-proof-envelope';
import type { DecryptionProofProver } from '../../src/crypto/zk/decryption-proof-prover';
import {
  DECRYPTION_PROOF_SCHEME_TEST_MOCK,
  ML_KEM_SEED_BYTES,
  RELATION_V1_VAULTROOT_ONLY_DIGEST,
  RELATION_V1_VAULTROOT_ONLY_ID,
  VAULT_ROOT_KEY_BYTES,
} from '../../src/crypto/zk/decryption-proof-relations';
import {
  digestDecryptionProofPublicInputsV1,
  type DecryptionProofPublicInputsV1,
} from '../../src/crypto/zk/decryption-proof-transcript';
import type {
  DecryptionProofVerificationResult,
  DecryptionProofVerifier,
} from '../../src/crypto/zk/decryption-proof-verifier';

const textEncoder = new TextEncoder();
const TEST_KEY = textEncoder.encode('SSS/v3/decryption-proof/mock-test-key/v1');

export const MOCK_DECRYPTION_PROOF_VERIFIER_ARTIFACT_DIGEST = sha256(
  textEncoder.encode('SSS/v3/decryption-proof/mock-verifier-artifact/v1'),
);

export function mockProofBytes(transcriptDigest: Uint8Array): Uint8Array {
  return hmac(sha256, TEST_KEY, transcriptDigest);
}

export function createMockDecryptionProofEnvelope(
  publicInputs: DecryptionProofPublicInputsV1,
): DecryptionProofEnvelope {
  const transcriptDigest = digestDecryptionProofPublicInputsV1(publicInputs);
  return {
    envelopeVersion: 1,
    schemeId: DECRYPTION_PROOF_SCHEME_TEST_MOCK,
    flags: DECRYPTION_PROOF_FLAG_TEST_ONLY,
    relationId: RELATION_V1_VAULTROOT_ONLY_ID,
    relationDigest: RELATION_V1_VAULTROOT_ONLY_DIGEST,
    verifierArtifactDigest: MOCK_DECRYPTION_PROOF_VERIFIER_ARTIFACT_DIGEST,
    transcriptDigest,
    proofBytes: mockProofBytes(transcriptDigest),
  };
}

export const mockDecryptionProofVerifier: DecryptionProofVerifier = {
  schemeId: DECRYPTION_PROOF_SCHEME_TEST_MOCK,
  relationId: RELATION_V1_VAULTROOT_ONLY_ID,
  relationDigest: RELATION_V1_VAULTROOT_ONLY_DIGEST,
  verifierArtifactDigest: MOCK_DECRYPTION_PROOF_VERIFIER_ARTIFACT_DIGEST,
  async verifyEnvelopeV1({ envelope, publicInputs, signal }): Promise<DecryptionProofVerificationResult> {
    if (signal?.aborted) return { status: 'failed', reason: 'mock proof verification aborted' };
    if ((envelope.flags & DECRYPTION_PROOF_FLAG_TEST_ONLY) === 0) {
      return { status: 'failed', reason: 'mock proof is missing test-only flag' };
    }
    const transcriptDigest = digestDecryptionProofPublicInputsV1(publicInputs);
    const expected = mockProofBytes(transcriptDigest);
    return constantTimeEqual(envelope.proofBytes, expected)
      ? { status: 'verified' }
      : { status: 'failed', reason: 'mock proof rejected' };
  },
};

export const mockDecryptionProofProver: DecryptionProofProver = {
  schemeId: DECRYPTION_PROOF_SCHEME_TEST_MOCK,
  relationId: RELATION_V1_VAULTROOT_ONLY_ID,
  relationDigest: RELATION_V1_VAULTROOT_ONLY_DIGEST,
  verifierArtifactDigest: MOCK_DECRYPTION_PROOF_VERIFIER_ARTIFACT_DIGEST,
  async proveV1(input) {
    if (input.signal?.aborted) throw new Error('mock proof generation aborted');
    if (input.witness.kemSeed.length !== ML_KEM_SEED_BYTES) throw new Error('mock KEM seed has wrong length');
    if (input.witness.vaultRootKey.length !== VAULT_ROOT_KEY_BYTES) {
      throw new Error('mock vault root key has wrong length');
    }
    input.onProgress?.({ phase: 'initializing' });
    input.onProgress?.({ phase: 'proving' });
    const envelope = createMockDecryptionProofEnvelope(input.publicInputs);
    input.onProgress?.({ phase: 'done', progress: 1 });
    return envelope;
  },
};

function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}
