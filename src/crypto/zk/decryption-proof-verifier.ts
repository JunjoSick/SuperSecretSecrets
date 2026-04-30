import {
  DECRYPTION_PROOF_DIGEST_BYTES,
  DECRYPTION_PROOF_ENVELOPE_VERSION,
} from './decryption-proof-relations';
import type { DecryptionProofEnvelope } from './decryption-proof-envelope';
import {
  digestDecryptionProofPublicInputsV1,
  type DecryptionProofPublicInputsV1,
} from './decryption-proof-transcript';

export type DecryptionProofVerificationResult =
  | { status: 'verified' }
  | { status: 'unsupported'; reason: string }
  | { status: 'failed'; reason: string };

export type DecryptionProofVerifier = {
  schemeId: number;
  relationId: string;
  relationDigest: Uint8Array;
  verifierArtifactDigest: Uint8Array;
  verifyEnvelopeV1(args: {
    envelope: DecryptionProofEnvelope;
    publicInputs: DecryptionProofPublicInputsV1;
    signal?: AbortSignal;
  }): Promise<DecryptionProofVerificationResult>;
};

const verifiers = new Map<string, DecryptionProofVerifier>();

export function verifierKey(
  schemeId: number,
  relationDigest: Uint8Array,
  verifierArtifactDigest: Uint8Array,
): string {
  assertSchemeId(schemeId);
  assertDigest(relationDigest, 'decryption proof verifier relation digest');
  assertDigest(verifierArtifactDigest, 'decryption proof verifier artifact digest');
  return `${schemeId}:${hex(relationDigest)}:${hex(verifierArtifactDigest)}`;
}

export function registerDecryptionProofVerifier(
  verifier: DecryptionProofVerifier,
): () => void {
  assertVerifier(verifier);
  const registered: DecryptionProofVerifier = {
    ...verifier,
    relationDigest: verifier.relationDigest.slice(),
    verifierArtifactDigest: verifier.verifierArtifactDigest.slice(),
  };
  const key = verifierKey(registered.schemeId, registered.relationDigest, registered.verifierArtifactDigest);
  verifiers.set(key, registered);
  return () => {
    const current = verifiers.get(key);
    if (current === registered) verifiers.delete(key);
  };
}

export function clearDecryptionProofVerifiers(): void {
  verifiers.clear();
}

export function findDecryptionProofVerifier(
  envelope: DecryptionProofEnvelope,
): DecryptionProofVerifier | null {
  return verifiers.get(
    verifierKey(envelope.schemeId, envelope.relationDigest, envelope.verifierArtifactDigest),
  ) ?? null;
}

export async function verifyDecryptionProofEnvelopeV1(args: {
  envelope: DecryptionProofEnvelope;
  publicInputs: DecryptionProofPublicInputsV1;
  verifiers?: readonly DecryptionProofVerifier[];
  signal?: AbortSignal;
}): Promise<DecryptionProofVerificationResult> {
  const { envelope, publicInputs, signal } = args;
  if (signal?.aborted) return { status: 'failed', reason: 'decryption proof verification aborted' };
  if (envelope.envelopeVersion !== DECRYPTION_PROOF_ENVELOPE_VERSION) {
    return { status: 'failed', reason: 'unsupported decryption proof envelope version' };
  }

  let transcriptDigest: Uint8Array;
  try {
    transcriptDigest = digestDecryptionProofPublicInputsV1(publicInputs);
  } catch (e) {
    return { status: 'failed', reason: e instanceof Error ? e.message : String(e) };
  }
  if (!constantTimeEqual(envelope.transcriptDigest, transcriptDigest)) {
    return { status: 'failed', reason: 'decryption proof transcript mismatch' };
  }

  let verifier: DecryptionProofVerifier | null;
  try {
    verifier = findProvidedVerifier(envelope, args.verifiers) ?? findDecryptionProofVerifier(envelope);
  } catch (e) {
    return { status: 'failed', reason: e instanceof Error ? e.message : String(e) };
  }
  if (!verifier) return { status: 'unsupported', reason: 'no verifier registered for decryption proof envelope' };

  if (signal?.aborted) return { status: 'failed', reason: 'decryption proof verification aborted' };
  try {
    return await verifier.verifyEnvelopeV1({ envelope, publicInputs, signal });
  } catch (e) {
    return { status: 'failed', reason: e instanceof Error ? e.message : String(e) };
  }
}

function findProvidedVerifier(
  envelope: DecryptionProofEnvelope,
  provided: readonly DecryptionProofVerifier[] | undefined,
): DecryptionProofVerifier | null {
  for (const verifier of provided ?? []) {
    assertVerifier(verifier);
    if (verifierMatches(envelope, verifier)) return verifier;
  }
  return null;
}

function verifierMatches(envelope: DecryptionProofEnvelope, verifier: DecryptionProofVerifier): boolean {
  return (
    envelope.schemeId === verifier.schemeId &&
    constantTimeEqual(envelope.relationDigest, verifier.relationDigest) &&
    constantTimeEqual(envelope.verifierArtifactDigest, verifier.verifierArtifactDigest)
  );
}

function assertVerifier(verifier: DecryptionProofVerifier): void {
  assertSchemeId(verifier.schemeId);
  if (verifier.relationId.length === 0) throw new Error('decryption proof verifier relation id must be nonempty');
  assertDigest(verifier.relationDigest, 'decryption proof verifier relation digest');
  assertDigest(verifier.verifierArtifactDigest, 'decryption proof verifier artifact digest');
}

function assertSchemeId(schemeId: number): void {
  if (!Number.isInteger(schemeId) || schemeId < 0 || schemeId > 0xff) {
    throw new Error('decryption proof verifier scheme id must be one byte');
  }
}

function assertDigest(value: Uint8Array, label: string): void {
  if (!(value instanceof Uint8Array) || value.length !== DECRYPTION_PROOF_DIGEST_BYTES) {
    throw new Error(`${label} must be 32 bytes`);
  }
}

function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}
