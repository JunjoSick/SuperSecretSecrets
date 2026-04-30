import { describe, expect, it } from 'vitest';
import {
  DECRYPTION_PROOF_FLAG_TEST_ONLY,
  DECRYPTION_PROOF_HARD_MAX_BYTES,
  DECRYPTION_PROOF_IDEAL_MAX_BYTES,
  DECRYPTION_PROOF_WARN_MAX_BYTES,
  decodeDecryptionProofEnvelope,
  encodeDecryptionProofEnvelope,
  estimateDecryptionProofQrImpact,
  type DecryptionProofEnvelope,
} from '../src/crypto/zk/decryption-proof-envelope';
import {
  DECRYPTION_PROOF_SCHEME_TEST_MOCK,
  RELATION_V1_DIGEST,
  RELATION_V1_ID,
} from '../src/crypto/zk/decryption-proof-relations';

describe('decryption proof envelope codec', () => {
  it('round-trips spec envelope fields', () => {
    const envelope = sampleEnvelope();
    expect(decodeDecryptionProofEnvelope(encodeDecryptionProofEnvelope(envelope))).toEqual(envelope);
  });

  it('rejects reserved flags', () => {
    expect(() => encodeDecryptionProofEnvelope({ ...sampleEnvelope(), flags: 0x08 })).toThrow(/reserved flags/);
    const raw = encodeDecryptionProofEnvelope(sampleEnvelope());
    raw[2] = 0x08;
    expect(() => decodeDecryptionProofEnvelope(raw)).toThrow(/reserved flags/);
  });

  it('rejects zero-length relation ids and proof bytes', () => {
    expect(() => encodeDecryptionProofEnvelope({ ...sampleEnvelope(), relationId: '' })).toThrow(/relation id/);
    expect(() => encodeDecryptionProofEnvelope({ ...sampleEnvelope(), proofBytes: new Uint8Array(0) })).toThrow(
      /nonempty/,
    );
  });

  it('rejects non-32-byte digests', () => {
    expect(() =>
      encodeDecryptionProofEnvelope({ ...sampleEnvelope(), relationDigest: bytes(31, 1) }),
    ).toThrow(/relation digest/);

    const raw = encodeDecryptionProofEnvelope(sampleEnvelope());
    raw[4 + RELATION_V1_ID.length] = 31;
    expect(() => decodeDecryptionProofEnvelope(raw)).toThrow(/relation digest/);
  });

  it('rejects proofs over the hard size limit', () => {
    expect(() =>
      encodeDecryptionProofEnvelope({
        ...sampleEnvelope(),
        proofBytes: bytes(DECRYPTION_PROOF_HARD_MAX_BYTES + 1, 1),
      }),
    ).toThrow(/hard size/);
  });

  it('rejects trailing bytes', () => {
    const raw = encodeDecryptionProofEnvelope(sampleEnvelope());
    expect(() => decodeDecryptionProofEnvelope(concat(raw, new Uint8Array([0])))).toThrow(/trailing bytes|truncated/);
  });

  it('estimates QR impact from encoded envelope bytes and header sizing', () => {
    expect(DECRYPTION_PROOF_IDEAL_MAX_BYTES).toBe(2500);
    expect(DECRYPTION_PROOF_WARN_MAX_BYTES).toBe(5000);
    expect(DECRYPTION_PROOF_HARD_MAX_BYTES).toBe(10000);
    expect(
      estimateDecryptionProofQrImpact({ envelopeBytes: 900, currentHeaderBytes: 700, maxHeaderBytes: 800 }),
    ).toEqual({ addedBytes: 900, estimatedExtraHeaderQrs: 1, severity: 'ideal' });
    expect(
      estimateDecryptionProofQrImpact({ envelopeBytes: 6_000, currentHeaderBytes: 0, maxHeaderBytes: 800 }),
    ).toMatchObject({ severity: 'warn' });
    expect(
      estimateDecryptionProofQrImpact({ envelopeBytes: 10_001, currentHeaderBytes: 0, maxHeaderBytes: 800 }),
    ).toMatchObject({ severity: 'hard-error' });
  });
});

function sampleEnvelope(): DecryptionProofEnvelope {
  return {
    envelopeVersion: 1,
    schemeId: DECRYPTION_PROOF_SCHEME_TEST_MOCK,
    flags: DECRYPTION_PROOF_FLAG_TEST_ONLY,
    relationId: RELATION_V1_ID,
    relationDigest: RELATION_V1_DIGEST,
    verifierArtifactDigest: bytes(32, 2),
    transcriptDigest: bytes(32, 3),
    proofBytes: bytes(32, 4),
  };
}

function bytes(length: number, seed: number): Uint8Array {
  return Uint8Array.from({ length }, (_, index) => (seed + index) & 0xff);
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
