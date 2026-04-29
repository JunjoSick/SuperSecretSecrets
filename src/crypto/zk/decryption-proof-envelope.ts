import {
  DECRYPTION_PROOF_DIGEST_BYTES,
  DECRYPTION_PROOF_ENVELOPE_VERSION,
} from './decryption-proof-relations';

export const DECRYPTION_PROOF_IDEAL_MAX_BYTES = 2_500;
export const DECRYPTION_PROOF_WARN_MAX_BYTES = 5_000;
export const DECRYPTION_PROOF_HARD_MAX_BYTES = 10_000;

export const DECRYPTION_PROOF_FLAG_TEST_ONLY = 0x01;
export const DECRYPTION_PROOF_FLAG_TRUSTED_SETUP = 0x02;
export const DECRYPTION_PROOF_FLAG_EXTERNAL_ARTIFACT = 0x04;
export const DECRYPTION_PROOF_KNOWN_FLAGS =
  DECRYPTION_PROOF_FLAG_TEST_ONLY |
  DECRYPTION_PROOF_FLAG_TRUSTED_SETUP |
  DECRYPTION_PROOF_FLAG_EXTERNAL_ARTIFACT;

export type DecryptionProofEnvelope = {
  envelopeVersion: typeof DECRYPTION_PROOF_ENVELOPE_VERSION;
  schemeId: number;
  flags: number;
  relationId: string;
  relationDigest: Uint8Array;
  verifierArtifactDigest: Uint8Array;
  transcriptDigest: Uint8Array;
  proofBytes: Uint8Array;
};

export type DecryptionProofQrImpact = {
  addedBytes: number;
  estimatedExtraHeaderQrs: number;
  severity: 'ideal' | 'warn' | 'hard-error';
};

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder('utf-8', { fatal: true });

export function encodeDecryptionProofEnvelope(
  envelope: DecryptionProofEnvelope,
): Uint8Array {
  validateEnvelope(envelope);
  const relationId = textEncoder.encode(envelope.relationId);
  const out = new Uint8Array(
    1 +
      1 +
      1 +
      1 +
      relationId.length +
      1 +
      DECRYPTION_PROOF_DIGEST_BYTES +
      1 +
      DECRYPTION_PROOF_DIGEST_BYTES +
      1 +
      DECRYPTION_PROOF_DIGEST_BYTES +
      4 +
      envelope.proofBytes.length,
  );
  let offset = 0;
  out[offset++] = envelope.envelopeVersion;
  out[offset++] = envelope.schemeId;
  out[offset++] = envelope.flags;
  out[offset++] = relationId.length;
  out.set(relationId, offset);
  offset += relationId.length;
  out[offset++] = DECRYPTION_PROOF_DIGEST_BYTES;
  out.set(envelope.relationDigest, offset);
  offset += DECRYPTION_PROOF_DIGEST_BYTES;
  out[offset++] = DECRYPTION_PROOF_DIGEST_BYTES;
  out.set(envelope.verifierArtifactDigest, offset);
  offset += DECRYPTION_PROOF_DIGEST_BYTES;
  out[offset++] = DECRYPTION_PROOF_DIGEST_BYTES;
  out.set(envelope.transcriptDigest, offset);
  offset += DECRYPTION_PROOF_DIGEST_BYTES;
  writeU32(out, offset, envelope.proofBytes.length);
  offset += 4;
  out.set(envelope.proofBytes, offset);
  return out;
}

export function decodeDecryptionProofEnvelope(raw: Uint8Array): DecryptionProofEnvelope {
  let offset = 0;
  const envelopeVersion = readU8(raw, offset, 'decryption proof envelope version');
  offset += 1;
  if (envelopeVersion !== DECRYPTION_PROOF_ENVELOPE_VERSION) {
    throw new Error('unsupported decryption proof envelope version');
  }
  const schemeId = readU8(raw, offset, 'decryption proof scheme id');
  offset += 1;
  const flags = readU8(raw, offset, 'decryption proof flags');
  offset += 1;
  validateFlags(flags);

  const relationIdLen = readU8(raw, offset, 'decryption proof relation id length');
  offset += 1;
  if (relationIdLen === 0) throw new Error('decryption proof relation id must be nonempty');
  const relationIdBytes = readBytes(raw, offset, relationIdLen, 'decryption proof relation id');
  offset += relationIdLen;
  const relationId = textDecoder.decode(relationIdBytes);

  const relationDigestLen = readU8(raw, offset, 'decryption proof relation digest length');
  offset += 1;
  if (relationDigestLen !== DECRYPTION_PROOF_DIGEST_BYTES) {
    throw new Error('decryption proof relation digest must be 32 bytes');
  }
  const relationDigest = readBytes(raw, offset, relationDigestLen, 'decryption proof relation digest');
  offset += relationDigestLen;

  const verifierDigestLen = readU8(raw, offset, 'decryption proof verifier artifact digest length');
  offset += 1;
  if (verifierDigestLen !== DECRYPTION_PROOF_DIGEST_BYTES) {
    throw new Error('decryption proof verifier artifact digest must be 32 bytes');
  }
  const verifierArtifactDigest = readBytes(raw, offset, verifierDigestLen, 'decryption proof verifier artifact digest');
  offset += verifierDigestLen;

  const transcriptDigestLen = readU8(raw, offset, 'decryption proof transcript digest length');
  offset += 1;
  if (transcriptDigestLen !== DECRYPTION_PROOF_DIGEST_BYTES) {
    throw new Error('decryption proof transcript digest must be 32 bytes');
  }
  const transcriptDigest = readBytes(raw, offset, transcriptDigestLen, 'decryption proof transcript digest');
  offset += transcriptDigestLen;

  const proofBytesLen = readU32(raw, offset, 'decryption proof length');
  offset += 4;
  if (proofBytesLen === 0) throw new Error('decryption proof bytes must be nonempty');
  if (proofBytesLen > DECRYPTION_PROOF_HARD_MAX_BYTES) {
    throw new Error('decryption proof exceeds hard size limit');
  }
  const proofBytes = readBytes(raw, offset, proofBytesLen, 'decryption proof bytes');
  offset += proofBytesLen;
  if (offset !== raw.length) throw new Error('trailing bytes after decryption proof envelope');

  return {
    envelopeVersion: DECRYPTION_PROOF_ENVELOPE_VERSION,
    schemeId,
    flags,
    relationId,
    relationDigest,
    verifierArtifactDigest,
    transcriptDigest,
    proofBytes,
  };
}

export function estimateDecryptionProofQrImpact(args: {
  envelopeBytes: number;
  currentHeaderBytes: number;
  maxHeaderBytes: number;
}): DecryptionProofQrImpact {
  const { envelopeBytes, currentHeaderBytes, maxHeaderBytes } = args;
  if (!Number.isFinite(envelopeBytes) || envelopeBytes < 0) throw new Error('envelopeBytes must be nonnegative');
  if (!Number.isFinite(currentHeaderBytes) || currentHeaderBytes < 0) {
    throw new Error('currentHeaderBytes must be nonnegative');
  }
  if (!Number.isFinite(maxHeaderBytes) || maxHeaderBytes <= 0) throw new Error('maxHeaderBytes must be positive');

  const before = Math.ceil(currentHeaderBytes / maxHeaderBytes);
  const after = Math.ceil((currentHeaderBytes + envelopeBytes) / maxHeaderBytes);
  return {
    addedBytes: envelopeBytes,
    estimatedExtraHeaderQrs: Math.max(0, after - before),
    severity:
      envelopeBytes <= DECRYPTION_PROOF_IDEAL_MAX_BYTES
        ? 'ideal'
        : envelopeBytes <= DECRYPTION_PROOF_HARD_MAX_BYTES
          ? 'warn'
          : 'hard-error',
  };
}

function validateEnvelope(envelope: DecryptionProofEnvelope): void {
  if (envelope.envelopeVersion !== DECRYPTION_PROOF_ENVELOPE_VERSION) {
    throw new Error('unsupported decryption proof envelope version');
  }
  if (!Number.isInteger(envelope.schemeId) || envelope.schemeId < 0 || envelope.schemeId > 0xff) {
    throw new Error('decryption proof scheme id must be one byte');
  }
  validateFlags(envelope.flags);
  const relationId = textEncoder.encode(envelope.relationId);
  if (relationId.length === 0) throw new Error('decryption proof relation id must be nonempty');
  if (relationId.length > 0xff) throw new Error('decryption proof relation id must fit in one byte');
  assertDigest(envelope.relationDigest, 'decryption proof relation digest');
  assertDigest(envelope.verifierArtifactDigest, 'decryption proof verifier artifact digest');
  assertDigest(envelope.transcriptDigest, 'decryption proof transcript digest');
  if (!(envelope.proofBytes instanceof Uint8Array)) {
    throw new Error('decryption proof bytes must be a Uint8Array');
  }
  if (envelope.proofBytes.length === 0) throw new Error('decryption proof bytes must be nonempty');
  if (envelope.proofBytes.length > DECRYPTION_PROOF_HARD_MAX_BYTES) {
    throw new Error('decryption proof exceeds hard size limit');
  }
}

function validateFlags(flags: number): void {
  if (!Number.isInteger(flags) || flags < 0 || flags > 0xff) {
    throw new Error('decryption proof flags must be one byte');
  }
  if ((flags & ~DECRYPTION_PROOF_KNOWN_FLAGS) !== 0) {
    throw new Error('decryption proof reserved flags must be zero');
  }
}

function assertDigest(value: Uint8Array, label: string): void {
  if (!(value instanceof Uint8Array) || value.length !== DECRYPTION_PROOF_DIGEST_BYTES) {
    throw new Error(`${label} must be 32 bytes`);
  }
}

function writeU32(out: Uint8Array, offset: number, value: number): void {
  if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) {
    throw new Error('decryption proof integer out of range');
  }
  out[offset] = (value >>> 24) & 0xff;
  out[offset + 1] = (value >>> 16) & 0xff;
  out[offset + 2] = (value >>> 8) & 0xff;
  out[offset + 3] = value & 0xff;
}

function readU8(buf: Uint8Array, offset: number, label: string): number {
  if (offset + 1 > buf.length) throw new Error(`truncated ${label}`);
  return buf[offset]!;
}

function readU32(buf: Uint8Array, offset: number, label: string): number {
  if (offset + 4 > buf.length) throw new Error(`truncated ${label}`);
  return (
    (buf[offset]! * 0x1000000) +
    ((buf[offset + 1]! << 16) | (buf[offset + 2]! << 8) | buf[offset + 3]!)
  ) >>> 0;
}

function readBytes(buf: Uint8Array, offset: number, length: number, label: string): Uint8Array {
  if (offset + length > buf.length) throw new Error(`truncated ${label}`);
  return buf.slice(offset, offset + length);
}
