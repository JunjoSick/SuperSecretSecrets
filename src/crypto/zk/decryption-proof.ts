import { sha256 } from '@noble/hashes/sha2.js';

const DOMAIN = 'SSS3/pt-commit';
const PROOF_TRANSCRIPT_DOMAIN = 'SSS3/decryption-proof-transcript/v2';
const PROOF_RELATION_DOMAIN = 'SSS3/decryption-proof-relation/aead-kem-sha256/v1';
export const DECRYPTION_PROOF_ENVELOPE_VERSION = 1;
export const DECRYPTION_PROOF_SCHEME_REGISTERED_BACKEND = 1;
export const DECRYPTION_PROOF_DIGEST_LEN = 32;

const enc = new TextEncoder();

export type DecryptionProofTranscriptInput = {
  bundleId: Uint8Array;
  payloadKind: string;
  kemAlg?: string;
  aeadAlg?: string;
  kdfAlg?: string;
  passphraseProtected?: boolean;
  argon2?: {
    tCost: number;
    memLog2KiB: number;
    parallelism: number;
  };
  kemCiphertext?: Uint8Array;
  nonce?: Uint8Array;
  ciphertext: Uint8Array;
  plaintextCommitment: Uint8Array;
};

export type DecryptionProofEnvelope = {
  version: typeof DECRYPTION_PROOF_ENVELOPE_VERSION;
  schemeId: number;
  relationDigest: Uint8Array;
  transcriptDigest: Uint8Array;
  verifierDigest: Uint8Array;
  proof: Uint8Array;
};

export type DecryptionProofVerifierInput = {
  envelope: DecryptionProofEnvelope;
  transcriptInput: DecryptionProofTranscriptInput;
  transcriptDigest: Uint8Array;
};

export type DecryptionProofVerifier = {
  schemeId: number;
  relationDigest: Uint8Array;
  verifierDigest: Uint8Array;
  label?: string;
  verify: (input: DecryptionProofVerifierInput) => boolean | Promise<boolean>;
};

export type DecryptionProofVerificationOptions = {
  verifiers?: readonly DecryptionProofVerifier[];
};

export type DecryptionProofVerification =
  | { status: 'verified'; schemeId: number; label?: string }
  | { status: 'unsupported'; schemeId: number }
  | { status: 'invalid'; schemeId: number; reason: string }
  | { status: 'tampered'; reason: string }
  | { status: 'malformed'; reason: string };

const registeredVerifiers = new Map<string, DecryptionProofVerifier>();

export const DECRYPTION_PROOF_RELATION_AEAD_KEM_SHA256_V1 = sha256(enc.encode(PROOF_RELATION_DOMAIN));

export function bindPlaintextCommitment(bundleId: Uint8Array, plaintext: Uint8Array): Uint8Array {
  const dst = enc.encode(DOMAIN);
  const buf = new Uint8Array(dst.length + 1 + bundleId.length + plaintext.length);
  let o = 0;
  buf.set(dst, o);
  o += dst.length;
  buf[o++] = bundleId.length;
  buf.set(bundleId, o);
  o += bundleId.length;
  buf.set(plaintext, o);
  return sha256(buf);
}

export function verifyPlaintextCommitment(
  commitment: Uint8Array,
  bundleId: Uint8Array,
  plaintext: Uint8Array,
): boolean {
  const expected = bindPlaintextCommitment(bundleId, plaintext);
  if (expected.length !== commitment.length) return false;
  let diff = 0;
  for (let i = 0; i < expected.length; i++) diff |= expected[i]! ^ commitment[i]!;
  return diff === 0;
}

export function decryptionProofTranscript(input: DecryptionProofTranscriptInput): Uint8Array {
  const argon2 = input.argon2
    ? u32Triplet(input.argon2.tCost, input.argon2.memLog2KiB, input.argon2.parallelism)
    : undefined;
  return sha256(
    concat(
      enc.encode(PROOF_TRANSCRIPT_DOMAIN),
      lengthPrefixed(input.bundleId),
      lengthPrefixed(enc.encode(input.payloadKind)),
      optionalLengthPrefixed(input.kemAlg ? enc.encode(input.kemAlg) : undefined),
      optionalLengthPrefixed(input.aeadAlg ? enc.encode(input.aeadAlg) : undefined),
      optionalLengthPrefixed(input.kdfAlg ? enc.encode(input.kdfAlg) : undefined),
      new Uint8Array([input.passphraseProtected ? 1 : 0]),
      optionalLengthPrefixed(argon2),
      optionalLengthPrefixed(input.kemCiphertext ? sha256(input.kemCiphertext) : undefined),
      optionalLengthPrefixed(input.nonce),
      lengthPrefixed(sha256(input.ciphertext)),
      lengthPrefixed(input.plaintextCommitment),
    ),
  );
}

export function createDecryptionProofEnvelope(input: {
  schemeId: number;
  relationDigest?: Uint8Array;
  verifierDigest: Uint8Array;
  transcriptInput: DecryptionProofTranscriptInput;
  proof: Uint8Array;
}): DecryptionProofEnvelope {
  return {
    version: DECRYPTION_PROOF_ENVELOPE_VERSION,
    schemeId: input.schemeId,
    relationDigest: (input.relationDigest ?? DECRYPTION_PROOF_RELATION_AEAD_KEM_SHA256_V1).slice(),
    transcriptDigest: decryptionProofTranscript(input.transcriptInput),
    verifierDigest: input.verifierDigest.slice(),
    proof: input.proof.slice(),
  };
}

export function encodeDecryptionProofEnvelope(envelope: DecryptionProofEnvelope): Uint8Array {
  if (envelope.version !== DECRYPTION_PROOF_ENVELOPE_VERSION) throw new Error('unsupported decryption proof version');
  if (!Number.isInteger(envelope.schemeId) || envelope.schemeId < 0 || envelope.schemeId > 0xff) {
    throw new Error('decryption proof scheme id must be one byte');
  }
  assertDigest(envelope.relationDigest, 'decryption proof relation digest');
  assertDigest(envelope.transcriptDigest, 'decryption proof transcript digest');
  assertDigest(envelope.verifierDigest, 'decryption proof verifier digest');
  if (envelope.proof.length > 0xffffffff) throw new Error('decryption proof too large');
  const out = new Uint8Array(1 + 1 + DECRYPTION_PROOF_DIGEST_LEN * 3 + 4 + envelope.proof.length);
  const view = new DataView(out.buffer);
  out[0] = envelope.version;
  out[1] = envelope.schemeId;
  let o = 2;
  out.set(envelope.relationDigest, o);
  o += DECRYPTION_PROOF_DIGEST_LEN;
  out.set(envelope.transcriptDigest, o);
  o += DECRYPTION_PROOF_DIGEST_LEN;
  out.set(envelope.verifierDigest, o);
  o += DECRYPTION_PROOF_DIGEST_LEN;
  view.setUint32(o, envelope.proof.length, false);
  o += 4;
  out.set(envelope.proof, o);
  return out;
}

export function decodeDecryptionProofEnvelope(raw: Uint8Array): DecryptionProofEnvelope {
  if (raw.length < 1 + 1 + DECRYPTION_PROOF_DIGEST_LEN * 3 + 4) {
    throw new Error('truncated decryption proof envelope');
  }
  const version = raw[0]!;
  if (version !== DECRYPTION_PROOF_ENVELOPE_VERSION) throw new Error('unsupported decryption proof version');
  const schemeId = raw[1]!;
  let o = 2;
  const relationDigest = raw.slice(o, o + DECRYPTION_PROOF_DIGEST_LEN);
  o += DECRYPTION_PROOF_DIGEST_LEN;
  const transcriptDigest = raw.slice(o, o + DECRYPTION_PROOF_DIGEST_LEN);
  o += DECRYPTION_PROOF_DIGEST_LEN;
  const verifierDigest = raw.slice(o, o + DECRYPTION_PROOF_DIGEST_LEN);
  o += DECRYPTION_PROOF_DIGEST_LEN;
  const view = new DataView(raw.buffer, raw.byteOffset, raw.byteLength);
  const proofLen = view.getUint32(o, false);
  const proofOffset = o + 4;
  if (raw.length !== proofOffset + proofLen) throw new Error('decryption proof envelope length mismatch');
  return {
    version: DECRYPTION_PROOF_ENVELOPE_VERSION,
    schemeId,
    relationDigest,
    transcriptDigest,
    verifierDigest,
    proof: raw.slice(proofOffset),
  };
}

export function registerDecryptionProofVerifier(verifier: DecryptionProofVerifier): () => void {
  assertVerifier(verifier);
  const registered: DecryptionProofVerifier = {
    ...verifier,
    relationDigest: verifier.relationDigest.slice(),
    verifierDigest: verifier.verifierDigest.slice(),
  };
  const key = verifierKey(registered);
  registeredVerifiers.set(key, registered);
  return () => {
    const current = registeredVerifiers.get(key);
    if (current === registered) registeredVerifiers.delete(key);
  };
}

export function clearDecryptionProofVerifiers(): void {
  registeredVerifiers.clear();
}

export function verifyDecryptionProofEnvelope(
  raw: Uint8Array,
  transcriptInput: DecryptionProofTranscriptInput,
  options: DecryptionProofVerificationOptions = {},
): DecryptionProofVerification {
  const prepared = prepareVerification(raw, transcriptInput, options);
  if (!('kind' in prepared)) return prepared;
  const input = verifierInput(prepared);
  try {
    const accepted = prepared.verifier.verify(input);
    if (isPromiseLike(accepted)) {
      return {
        status: 'invalid',
        schemeId: prepared.envelope.schemeId,
        reason: 'async verifier requires verifyDecryptionProofEnvelopeAsync',
      };
    }
    if (accepted) {
      return {
        status: 'verified',
        schemeId: prepared.envelope.schemeId,
        label: prepared.verifier.label,
      };
    }
    return { status: 'invalid', schemeId: prepared.envelope.schemeId, reason: 'verifier rejected proof' };
  } catch (e) {
    return {
      status: 'invalid',
      schemeId: prepared.envelope.schemeId,
      reason: e instanceof Error ? e.message : String(e),
    };
  }
}

export async function verifyDecryptionProofEnvelopeAsync(
  raw: Uint8Array,
  transcriptInput: DecryptionProofTranscriptInput,
  options: DecryptionProofVerificationOptions = {},
): Promise<DecryptionProofVerification> {
  const prepared = prepareVerification(raw, transcriptInput, options);
  if (!('kind' in prepared)) return prepared;
  try {
    if (await prepared.verifier.verify(verifierInput(prepared))) {
      return {
        status: 'verified',
        schemeId: prepared.envelope.schemeId,
        label: prepared.verifier.label,
      };
    }
    return { status: 'invalid', schemeId: prepared.envelope.schemeId, reason: 'verifier rejected proof' };
  } catch (e) {
    return {
      status: 'invalid',
      schemeId: prepared.envelope.schemeId,
      reason: e instanceof Error ? e.message : String(e),
    };
  }
}

type PreparedVerification = {
  kind: 'ready';
  envelope: DecryptionProofEnvelope;
  transcriptInput: DecryptionProofTranscriptInput;
  transcriptDigest: Uint8Array;
  verifier: DecryptionProofVerifier;
};

function prepareVerification(
  raw: Uint8Array,
  transcriptInput: DecryptionProofTranscriptInput,
  options: DecryptionProofVerificationOptions,
): PreparedVerification | DecryptionProofVerification {
  let envelope: DecryptionProofEnvelope;
  try {
    envelope = decodeDecryptionProofEnvelope(raw);
  } catch (e) {
    return { status: 'malformed', reason: e instanceof Error ? e.message : String(e) };
  }
  let transcriptDigest: Uint8Array;
  try {
    transcriptDigest = decryptionProofTranscript(transcriptInput);
  } catch (e) {
    return { status: 'malformed', reason: e instanceof Error ? e.message : String(e) };
  }
  if (!constantTimeEqual(envelope.transcriptDigest, transcriptDigest)) {
    return { status: 'tampered', reason: 'decryption proof transcript mismatch' };
  }
  let verifier: DecryptionProofVerifier | undefined;
  try {
    verifier = findVerifier(envelope, options.verifiers);
  } catch (e) {
    return { status: 'malformed', reason: e instanceof Error ? e.message : String(e) };
  }
  if (!verifier) return { status: 'unsupported', schemeId: envelope.schemeId };
  return { kind: 'ready', envelope, transcriptInput, transcriptDigest, verifier };
}

function verifierInput(prepared: PreparedVerification): DecryptionProofVerifierInput {
  return {
    envelope: prepared.envelope,
    transcriptInput: prepared.transcriptInput,
    transcriptDigest: prepared.transcriptDigest,
  };
}

function isPromiseLike(value: unknown): value is PromiseLike<unknown> {
  return (
    typeof value === 'object' &&
    value !== null &&
    typeof (value as { then?: unknown }).then === 'function'
  );
}

function lengthPrefixed(bytes: Uint8Array): Uint8Array {
  const out = new Uint8Array(4 + bytes.length);
  new DataView(out.buffer).setUint32(0, bytes.length, false);
  out.set(bytes, 4);
  return out;
}

function optionalLengthPrefixed(bytes: Uint8Array | undefined): Uint8Array {
  if (!bytes) return new Uint8Array([0]);
  return concat(new Uint8Array([1]), lengthPrefixed(bytes));
}

function u32Triplet(a: number, b: number, c: number): Uint8Array {
  const out = new Uint8Array(12);
  const view = new DataView(out.buffer);
  writeU32(view, 0, a);
  writeU32(view, 4, b);
  writeU32(view, 8, c);
  return out;
}

function writeU32(view: DataView, offset: number, value: number): void {
  if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) {
    throw new Error('decryption proof public input integer out of range');
  }
  view.setUint32(offset, value, false);
}

function assertDigest(bytes: Uint8Array, label: string): void {
  if (bytes.length !== DECRYPTION_PROOF_DIGEST_LEN) {
    throw new Error(`${label} must be ${DECRYPTION_PROOF_DIGEST_LEN} bytes`);
  }
}

function assertVerifier(verifier: DecryptionProofVerifier): void {
  if (!Number.isInteger(verifier.schemeId) || verifier.schemeId < 0 || verifier.schemeId > 0xff) {
    throw new Error('decryption proof verifier scheme id must be one byte');
  }
  assertDigest(verifier.relationDigest, 'decryption proof verifier relation digest');
  assertDigest(verifier.verifierDigest, 'decryption proof verifier digest');
}

function findVerifier(
  envelope: DecryptionProofEnvelope,
  provided: readonly DecryptionProofVerifier[] | undefined,
): DecryptionProofVerifier | undefined {
  for (const verifier of provided ?? []) {
    assertVerifier(verifier);
    if (verifierMatches(envelope, verifier)) return verifier;
  }
  return registeredVerifiers.get(envelopeKey(envelope));
}

function verifierMatches(envelope: DecryptionProofEnvelope, verifier: DecryptionProofVerifier): boolean {
  return (
    envelope.schemeId === verifier.schemeId &&
    constantTimeEqual(envelope.relationDigest, verifier.relationDigest) &&
    constantTimeEqual(envelope.verifierDigest, verifier.verifierDigest)
  );
}

function verifierKey(verifier: DecryptionProofVerifier): string {
  return `${verifier.schemeId}:${hex(verifier.relationDigest)}:${hex(verifier.verifierDigest)}`;
}

function envelopeKey(envelope: DecryptionProofEnvelope): string {
  return `${envelope.schemeId}:${hex(envelope.relationDigest)}:${hex(envelope.verifierDigest)}`;
}

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
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

function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}
