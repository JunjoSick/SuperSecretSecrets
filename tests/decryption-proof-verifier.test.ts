import { afterEach, describe, expect, it } from 'vitest';
import {
  decodeDecryptionProofEnvelope,
  encodeDecryptionProofEnvelope,
} from '../src/crypto/zk/decryption-proof-envelope';
import { ML_KEM_768_CIPHERTEXT_BYTES } from '../src/crypto/zk/decryption-proof-relations';
import type { DecryptionProofPublicInputsV1 } from '../src/crypto/zk/decryption-proof-transcript';
import {
  clearDecryptionProofVerifiers,
  findDecryptionProofVerifier,
  registerDecryptionProofVerifier,
  verifyDecryptionProofEnvelopeV1,
} from '../src/crypto/zk/decryption-proof-verifier';
import {
  createMockDecryptionProofEnvelope,
  mockDecryptionProofProver,
  mockDecryptionProofVerifier,
} from './helpers/decryption-proof-mock';

describe('decryption proof verifier registry and mock backend', () => {
  afterEach(() => clearDecryptionProofVerifiers());

  it('matches registry entries by scheme, relation digest, and verifier artifact digest', () => {
    const envelope = createMockDecryptionProofEnvelope(samplePublicInputs());
    expect(findDecryptionProofVerifier(envelope)).toBeNull();
    const unregister = registerDecryptionProofVerifier(mockDecryptionProofVerifier);
    expect(findDecryptionProofVerifier(envelope)).toEqual(mockDecryptionProofVerifier);
    unregister();
    expect(findDecryptionProofVerifier(envelope)).toBeNull();
  });

  it('reports unsupported when no verifier matches', async () => {
    const result = await verifyDecryptionProofEnvelopeV1({
      envelope: createMockDecryptionProofEnvelope(samplePublicInputs()),
      publicInputs: samplePublicInputs(),
      verifiers: [],
    });
    expect(result.status).toBe('unsupported');
  });

  it('fails before calling the verifier when the transcript digest does not match public inputs', async () => {
    const envelope = createMockDecryptionProofEnvelope(samplePublicInputs());
    const tamperedInputs = samplePublicInputs();
    tamperedInputs.policyCommitment[0]! ^= 1;
    let called = false;
    const result = await verifyDecryptionProofEnvelopeV1({
      envelope,
      publicInputs: tamperedInputs,
      verifiers: [
        {
          ...mockDecryptionProofVerifier,
          async verifyEnvelopeV1() {
            called = true;
            return { status: 'verified' };
          },
        },
      ],
    });
    expect(result).toEqual({ status: 'failed', reason: 'decryption proof transcript mismatch' });
    expect(called).toBe(false);
  });

  it('verifies a deterministic test-only mock proof', async () => {
    const progress: string[] = [];
    const publicInputs = samplePublicInputs();
    const envelope = await mockDecryptionProofProver.proveV1({
      publicInputs,
      witness: {
        kemSeed: bytes(64, 9),
        vaultRootKey: bytes(32, 10),
      },
      onProgress: (event) => progress.push(event.phase),
    });
    expect(envelope.flags & 0x01).toBe(0x01);
    expect(progress).toEqual(['initializing', 'proving', 'done']);

    const decoded = decodeDecryptionProofEnvelope(encodeDecryptionProofEnvelope(envelope));
    await expect(
      verifyDecryptionProofEnvelopeV1({
        envelope: decoded,
        publicInputs,
        verifiers: [mockDecryptionProofVerifier],
      }),
    ).resolves.toEqual({ status: 'verified' });
  });

  it('rejects tampered mock proof bytes', async () => {
    const publicInputs = samplePublicInputs();
    const envelope = createMockDecryptionProofEnvelope(publicInputs);
    envelope.proofBytes = envelope.proofBytes.slice();
    envelope.proofBytes[0]! ^= 1;
    await expect(
      verifyDecryptionProofEnvelopeV1({
        envelope,
        publicInputs,
        verifiers: [mockDecryptionProofVerifier],
      }),
    ).resolves.toEqual({ status: 'failed', reason: 'mock proof rejected' });
  });
});

function samplePublicInputs(): DecryptionProofPublicInputsV1 {
  return {
    bundleId: bytes(8, 1),
    payloadKind: 'vault-root',
    kemAlgId: 1,
    kdfAlgId: 1,
    aeadAlgId: 1,
    commitmentHashId: 1,
    passphraseFlag: false,
    argon2TCost: 0,
    argon2MemLog2KiB: 0,
    argon2Parallelism: 0,
    policyCommitment: bytes(32, 2),
    plaintextCommitment: bytes(32, 3),
    vaultTreeRoot: bytes(32, 4),
    kemCiphertext: bytes(ML_KEM_768_CIPHERTEXT_BYTES, 5),
    aeadNonce: bytes(12, 6),
    aeadCiphertextAndTag: bytes(48, 7),
  };
}

function bytes(length: number, seed: number): Uint8Array {
  return Uint8Array.from({ length }, (_, index) => (seed + index) & 0xff);
}
