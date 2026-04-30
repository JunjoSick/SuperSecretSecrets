import { DECRYPTION_PROOF_DIGEST_BYTES } from '../decryption-proof-relations';
import { PROOF_ARTIFACT_DIGEST } from './artifact';

const TRUSTED_PROOF_ARTIFACT_DIGESTS = new Set<string>(
  isPlaceholderDigest(PROOF_ARTIFACT_DIGEST) ? [] : [bytesToHex(PROOF_ARTIFACT_DIGEST)],
);

export function assertTrustedProofArtifactDigest(digest: Uint8Array): void {
  assertDigest(digest, 'Halo2 proof artifact digest');
  if (isPlaceholderDigest(digest) || !TRUSTED_PROOF_ARTIFACT_DIGESTS.has(bytesToHex(digest))) {
    throw new Error('Untrusted Halo2 proof artifact digest');
  }
}

export function isTrustedProofArtifactDigest(digest: Uint8Array): boolean {
  try {
    assertTrustedProofArtifactDigest(digest);
    return true;
  } catch {
    return false;
  }
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function assertDigest(value: Uint8Array, label: string): void {
  if (!(value instanceof Uint8Array) || value.length !== DECRYPTION_PROOF_DIGEST_BYTES) {
    throw new Error(`${label} must be 32 bytes`);
  }
}

function isPlaceholderDigest(digest: Uint8Array): boolean {
  let diff = 0;
  for (const byte of digest) diff |= byte;
  return diff === 0;
}
