import { describe, expect, it } from 'vitest';
import {
  decodeBundle,
  decodeBundleAsync,
  encodeSecretAsync,
} from '../src/crypto';
import {
  encodeHeaderChunkV3,
  fromBase45,
  KIND_HEADER,
  makeTlv,
  parse,
  TLV_DECRYPTION_PROOF,
  toBase45,
} from '../src/crypto/codec';
import {
  decodeDecryptionProofEnvelope,
  encodeDecryptionProofEnvelope,
} from '../src/crypto/zk/decryption-proof-envelope';
import {
  DECRYPTION_PROOF_SCHEME_HALO2_KZG,
  RELATION_V1_DIGEST,
  RELATION_V1_ID,
  RELATION_V1_VAULTROOT_ONLY_DIGEST,
  RELATION_V1_VAULTROOT_ONLY_ID,
} from '../src/crypto/zk/decryption-proof-relations';
import {
  digestDecryptionProofPublicInputsV1,
} from '../src/crypto/zk/decryption-proof-transcript';
import type {
  DecryptionProofVerifier,
} from '../src/crypto/zk/decryption-proof-verifier';
import {
  MOCK_DECRYPTION_PROOF_VERIFIER_ARTIFACT_DIGEST,
  mockDecryptionProofProver,
  mockDecryptionProofVerifier,
  mockProofBytes,
} from './helpers/decryption-proof-mock';

const PROOF_FAST = {
  threshold: 2,
  shares: 3,
  kemAlg: 'ml-kem-768' as const,
  aeadAlg: 'aes-256-gcm' as const,
  kdfAlg: 'hkdf-sha256' as const,
  maxHeaderBytes: 4096,
  vaultMode: true,
  zk: true,
};

describe('v3 decryption proof integration', () => {
  it('emits a canonical test-only proof TLV and verifies it asynchronously', async () => {
    const bundle = await encodeSecretAsync('vault proof', {
      ...PROOF_FAST,
      decryptionProof: {
        enabled: true,
        prover: mockDecryptionProofProver,
        verifiers: [mockDecryptionProofVerifier],
      },
    });
    expect(bundle.formatVersion).toBe(3);
    const firstHeader = firstHeaderFromBundle(bundle.headerQrs);
    const proof = firstHeader.extensions?.find((extension) => extension.tagId === TLV_DECRYPTION_PROOF);
    expect(proof).toBeDefined();
    const envelope = decodeDecryptionProofEnvelope(proof!.value);
    expect(envelope.flags & 0x01).toBe(0x01);

    const syncDecoded = decodeBundle([...bundle.headerQrs, ...bundle.shareQrs.slice(0, 2)], {
      vaultBlob: bundle.vaultBlob!,
    });
    expect(syncDecoded.status).toBe('ok');
    if (syncDecoded.status !== 'ok') throw new Error('expected sync decode');
    expect(syncDecoded.decryptionProof?.status).toBe('unsupported');

    const decoded = await decodeBundleAsync([...bundle.headerQrs, ...bundle.shareQrs.slice(0, 2)], {
      vaultBlob: bundle.vaultBlob!,
      decryptionProofV1Verifiers: [mockDecryptionProofVerifier],
    });
    expect(decoded.status).toBe('ok');
    if (decoded.status !== 'ok' || decoded.kind !== 'vault') throw new Error('expected vault');
    expect(decoded.decryptionProof).toEqual({
      status: 'verified',
      schemeId: 0x7f,
    });
  });

  it('fails closed when canonical proof bytes are tampered', async () => {
    const bundle = await encodeSecretAsync('tamper proof', {
      ...PROOF_FAST,
      decryptionProof: {
        enabled: true,
        prover: mockDecryptionProofProver,
        verifiers: [mockDecryptionProofVerifier],
      },
    });
    const firstHeader = firstHeaderFromBundle(bundle.headerQrs);
    const proof = firstHeader.extensions?.find((extension) => extension.tagId === TLV_DECRYPTION_PROOF);
    if (!proof) throw new Error('expected proof');
    const envelope = decodeDecryptionProofEnvelope(proof.value);
    envelope.proofBytes = envelope.proofBytes.slice();
    envelope.proofBytes[0]! ^= 1;
    const tamperedProof = encodeDecryptionProofEnvelope(envelope);
    const reframed = encodeHeaderChunkV3({
      bundleId: firstHeader.bundleId,
      kemAlg: firstHeader.kemAlg,
      aeadAlg: firstHeader.aeadAlg,
      kdfAlg: firstHeader.kdfAlg,
      flags: firstHeader.flags,
      argon2: firstHeader.argon2,
      t: firstHeader.t,
      n: firstHeader.n,
      chunkIdx: firstHeader.chunkIdx,
      chunkTotal: firstHeader.chunkTotal,
      extensions: (firstHeader.extensions ?? []).map((extension) =>
        extension.tagId === TLV_DECRYPTION_PROOF
          ? makeTlv(TLV_DECRYPTION_PROOF, tamperedProof, false)
          : makeTlv(extension.tagId, extension.value, extension.critical),
      ),
      payload: firstHeader.payload,
    });

    const decoded = await decodeBundleAsync(
      [toBase45(reframed), ...bundle.headerQrs.slice(1), ...bundle.shareQrs.slice(0, 2)],
      {
        vaultBlob: bundle.vaultBlob!,
        decryptionProofV1Verifiers: [mockDecryptionProofVerifier],
      },
    );
    expect(decoded.status).toBe('error');
    if (decoded.status === 'error') expect(decoded.error).toMatch(/decryption proof failed/);
  });

  it('does not require a prover for unsupported proof requests', async () => {
    const bundle = await encodeSecretAsync('plain unsupported proof request', {
      threshold: 2,
      shares: 3,
      kemAlg: 'ml-kem-512',
      aeadAlg: 'aes-256-gcm',
      kdfAlg: 'hkdf-sha256',
      decryptionProof: { enabled: true },
    });
    expect(bundle.formatVersion).toBe(1);
  });

  it('requires a prover for supported proof requests', async () => {
    await expect(
      encodeSecretAsync('missing prover', {
        ...PROOF_FAST,
        decryptionProof: { enabled: true },
      }),
    ).rejects.toThrow(/prover/);
  });

  it('rejects proof envelopes that cannot fit in one renderable header QR', async () => {
    const verifier: DecryptionProofVerifier = {
      ...mockDecryptionProofVerifier,
      async verifyEnvelopeV1() {
        return { status: 'verified' };
      },
    };

    await expect(
      encodeSecretAsync('oversized proof qr', {
        ...PROOF_FAST,
        decryptionProof: {
          enabled: true,
          prover: {
            ...mockDecryptionProofProver,
            async proveV1(input) {
              const transcriptDigest = digestDecryptionProofPublicInputsV1(input.publicInputs);
              return {
                envelopeVersion: 1,
                schemeId: mockDecryptionProofProver.schemeId,
                flags: 0x01,
                relationId: mockDecryptionProofProver.relationId,
                relationDigest: mockDecryptionProofProver.relationDigest,
                verifierArtifactDigest: mockDecryptionProofProver.verifierArtifactDigest,
                transcriptDigest,
                proofBytes: bytes(2500, 37),
              };
            },
          },
          verifiers: [verifier],
          allowLargeProof: true,
        },
      }),
    ).rejects.toThrow(/too large for a single QR header|exceeds renderable size/);
  });

  it('rejects provers that still claim the future full relation', async () => {
    await expect(
      encodeSecretAsync('wrong relation prover', {
        ...PROOF_FAST,
        decryptionProof: {
          enabled: true,
          prover: {
            ...mockDecryptionProofProver,
            relationId: RELATION_V1_ID,
            relationDigest: RELATION_V1_DIGEST,
          },
          verifiers: [mockDecryptionProofVerifier],
        },
      }),
    ).rejects.toThrow(/current supported relation/);
  });

  it('passes cancellation signals into proof generation and local verification', async () => {
    const controller = new AbortController();
    let proverSignal: AbortSignal | undefined;
    let verifierSignal: AbortSignal | undefined;
    const verifier: DecryptionProofVerifier = {
      ...mockDecryptionProofVerifier,
      async verifyEnvelopeV1({ signal }) {
        verifierSignal = signal;
        return { status: 'verified' };
      },
    };

    const bundle = await encodeSecretAsync(
      'signal proof path',
      {
        ...PROOF_FAST,
        decryptionProof: {
          enabled: true,
          prover: {
            ...mockDecryptionProofProver,
            async proveV1(input) {
              proverSignal = input.signal;
              return mockDecryptionProofProver.proveV1(input);
            },
          },
          verifiers: [verifier],
        },
      },
      { signal: controller.signal },
    );

    expect(bundle.formatVersion).toBe(3);
    expect(proverSignal).toBe(controller.signal);
    expect(verifierSignal).toBe(controller.signal);
  });

  it('emits non-test proof envelopes once supported bundles publish Poseidon2 commitments', async () => {
    let proverCalled = false;
    const verifier: DecryptionProofVerifier = {
      schemeId: DECRYPTION_PROOF_SCHEME_HALO2_KZG,
      relationId: RELATION_V1_VAULTROOT_ONLY_ID,
      relationDigest: RELATION_V1_VAULTROOT_ONLY_DIGEST,
      verifierArtifactDigest: MOCK_DECRYPTION_PROOF_VERIFIER_ARTIFACT_DIGEST,
      async verifyEnvelopeV1({ envelope, publicInputs }) {
        const expected = mockProofBytes(digestDecryptionProofPublicInputsV1(publicInputs));
        return hex(envelope.proofBytes) === hex(expected)
          ? { status: 'verified' }
          : { status: 'failed', reason: 'production-like test proof rejected' };
      },
    };
    const bundle = await encodeSecretAsync('production proof path', {
      ...PROOF_FAST,
      decryptionProof: {
        enabled: true,
        prover: {
          ...mockDecryptionProofProver,
          schemeId: DECRYPTION_PROOF_SCHEME_HALO2_KZG,
          verifierArtifactDigest: MOCK_DECRYPTION_PROOF_VERIFIER_ARTIFACT_DIGEST,
          async proveV1(input) {
            proverCalled = true;
            const transcriptDigest = digestDecryptionProofPublicInputsV1(input.publicInputs);
            return {
              envelopeVersion: 1,
              schemeId: DECRYPTION_PROOF_SCHEME_HALO2_KZG,
              flags: 0,
              relationId: RELATION_V1_VAULTROOT_ONLY_ID,
              relationDigest: RELATION_V1_VAULTROOT_ONLY_DIGEST,
              verifierArtifactDigest: MOCK_DECRYPTION_PROOF_VERIFIER_ARTIFACT_DIGEST,
              transcriptDigest,
              proofBytes: mockProofBytes(transcriptDigest),
            };
          },
        },
        verifiers: [verifier],
      },
    });
    expect(proverCalled).toBe(true);
    const firstHeader = firstHeaderFromBundle(bundle.headerQrs);
    const proof = firstHeader.extensions?.find((extension) => extension.tagId === TLV_DECRYPTION_PROOF);
    if (!proof) throw new Error('expected proof');
    const envelope = decodeDecryptionProofEnvelope(proof.value);
    expect(envelope.flags).toBe(0);
    expect(envelope.schemeId).toBe(DECRYPTION_PROOF_SCHEME_HALO2_KZG);

    const decoded = await decodeBundleAsync([...bundle.headerQrs, ...bundle.shareQrs.slice(0, 2)], {
      vaultBlob: bundle.vaultBlob!,
      decryptionProofV1Verifiers: [verifier],
    });
    expect(decoded.status).toBe('ok');
    if (decoded.status !== 'ok') throw new Error('expected decode');
    expect(decoded.decryptionProof).toEqual({
      status: 'verified',
      schemeId: DECRYPTION_PROOF_SCHEME_HALO2_KZG,
    });
  });
});

function firstHeaderFromBundle(headerQrs: string[]) {
  const parsed = headerQrs
    .map((qr) => parse(fromBase45(qr)))
    .filter((qr): qr is Extract<ReturnType<typeof parse>, { kind: typeof KIND_HEADER }> => qr.kind === KIND_HEADER)
    .sort((a, b) => a.chunkIdx - b.chunkIdx);
  return parsed[0]!;
}

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function bytes(length: number, seed: number): Uint8Array {
  return Uint8Array.from({ length }, (_, index) => (seed + index) & 0xff);
}
