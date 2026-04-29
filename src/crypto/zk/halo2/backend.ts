import { sha256 } from '@noble/hashes/sha2.js';
import {
  DECRYPTION_PROOF_FLAG_EXTERNAL_ARTIFACT,
  DECRYPTION_PROOF_FLAG_TEST_ONLY,
  DECRYPTION_PROOF_FLAG_TRUSTED_SETUP,
  type DecryptionProofEnvelope,
} from '../decryption-proof-envelope';
import type { DecryptionProofProver } from '../decryption-proof-prover';
import {
  DECRYPTION_PROOF_ENVELOPE_VERSION,
  DECRYPTION_PROOF_SCHEME_HALO2_KZG,
  RELATION_V1_DIGEST,
  RELATION_V1_ID,
  lookupSupportedHalo2Relation,
  type SupportedHalo2Relation,
} from '../decryption-proof-relations';
import {
  digestDecryptionProofPublicInputsV1,
  encodeDecryptionProofPublicInputsV1,
} from '../decryption-proof-transcript';
import type {
  DecryptionProofVerificationResult,
  DecryptionProofVerifier,
} from '../decryption-proof-verifier';
import {
  CURVE_BN254,
  PCS_KZG,
  digestHalo2ArtifactMetadata,
  validateHalo2ArtifactMetadata,
  type Halo2ArtifactMetadata,
} from './artifact';
import {
  HALO2_WITNESS_V1_BYTES,
  copyWitnessToWasmMemory,
  validateDecryptionProofWitnessV1,
  zeroizeWasmMemoryRegion,
  type Halo2WasmProverSecureApi,
  type Halo2WasmVerifier,
} from './witness';

export const HALO2_BACKEND_NOT_BUNDLED = 'Halo2 decryption proof backend not bundled';

export type Halo2VerifierArtifact = {
  metadata: Halo2ArtifactMetadata;
  srsBytes: Uint8Array;
  srsHash?: Uint8Array;
  verifyingKeyBytes: Uint8Array;
  wasmBuildBytes?: Uint8Array;
  trustedSetupIdBytes?: Uint8Array;
};

export type Halo2ProverArtifact = Halo2VerifierArtifact & {
  provingKeyBytes: Uint8Array;
  provingKeyHash?: Uint8Array;
};

export type Halo2WasmScratchAllocator = {
  memory: WebAssembly.Memory;
  allocate_buffer(len: number): number;
  free_buffer(ptr: number, len: number): void;
};

export type Halo2WasmProver = Halo2WasmProverSecureApi & Halo2WasmScratchAllocator;

export type CreateHalo2VerifierArgs = {
  artifact: Halo2VerifierArtifact;
  wasm: Halo2WasmVerifier;
};

export type CreateHalo2ProverArgs = {
  artifact: Halo2ProverArtifact;
  wasm: Halo2WasmProver;
};

export function validateHalo2VerifierArtifact(artifact: Halo2VerifierArtifact): void {
  validateHalo2ArtifactForRelation(artifact.metadata);
  assertNonemptyBytes(artifact.srsBytes, 'Halo2 SRS');
  assertNonemptyBytes(artifact.verifyingKeyBytes, 'Halo2 verifying key');
  assertDigestMatches(artifact.verifyingKeyBytes, artifact.metadata.verifyingKeyHash, 'Halo2 verifying key hash');
  if (artifact.srsHash) {
    assertDigestMatches(artifact.srsBytes, artifact.srsHash, 'Halo2 SRS hash');
  }
  if (artifact.wasmBuildBytes) {
    assertDigestMatches(artifact.wasmBuildBytes, artifact.metadata.wasmBuildHash, 'Halo2 WASM build hash');
  }
  if (artifact.trustedSetupIdBytes) {
    assertDigestMatches(
      artifact.trustedSetupIdBytes,
      artifact.metadata.trustedSetupIdDigest,
      'Halo2 trusted setup id digest',
    );
  }
}

export function validateHalo2ProverArtifact(artifact: Halo2ProverArtifact): void {
  validateHalo2VerifierArtifact(artifact);
  assertNonemptyBytes(artifact.provingKeyBytes, 'Halo2 proving key');
  if (artifact.provingKeyHash) {
    assertDigestMatches(artifact.provingKeyBytes, artifact.provingKeyHash, 'Halo2 proving key hash');
  }
}

export function halo2VerifierArtifactDigest(artifact: Halo2VerifierArtifact): Uint8Array {
  validateHalo2VerifierArtifact(artifact);
  return digestHalo2ArtifactMetadata(artifact.metadata);
}

export function halo2EnvelopeFlagsForArtifact(metadata: Halo2ArtifactMetadata): number {
  validateHalo2ArtifactForRelation(metadata);
  return DECRYPTION_PROOF_FLAG_EXTERNAL_ARTIFACT | DECRYPTION_PROOF_FLAG_TRUSTED_SETUP;
}

export function createHalo2DecryptionProofVerifier(args: CreateHalo2VerifierArgs): DecryptionProofVerifier {
  const { artifact, wasm } = args;
  validateHalo2VerifierArtifact(artifact);
  assertVerifierWasm(wasm);
  const relation = resolveSupportedRelation(artifact.metadata.relationDigest);
  const verifierArtifactDigest = digestHalo2ArtifactMetadata(artifact.metadata);
  const expectedFlags = halo2EnvelopeFlagsForArtifact(artifact.metadata);

  return {
    schemeId: artifact.metadata.schemeId,
    relationId: relation.id,
    relationDigest: artifact.metadata.relationDigest.slice(),
    verifierArtifactDigest,
    async verifyEnvelopeV1({ envelope, publicInputs, signal }): Promise<DecryptionProofVerificationResult> {
      if (signal?.aborted) return { status: 'failed', reason: 'Halo2 proof verification aborted' };
      const preflight = verifyHalo2EnvelopePreflight(envelope, verifierArtifactDigest, expectedFlags, relation);
      if (preflight) return preflight;

      let encodedPublicInputs: Uint8Array;
      try {
        encodedPublicInputs = encodeDecryptionProofPublicInputsV1(publicInputs);
      } catch (e) {
        return { status: 'failed', reason: safeErrorMessage(e) };
      }
      const transcriptDigest = sha256(encodedPublicInputs);
      if (!constantTimeEqual(envelope.transcriptDigest, transcriptDigest)) {
        return { status: 'failed', reason: 'decryption proof transcript mismatch' };
      }

      try {
        if (signal?.aborted) return { status: 'failed', reason: 'Halo2 proof verification aborted' };
        const ok = wasm.verify_decryption_proof_v1(
          envelope.proofBytes,
          encodedPublicInputs,
          artifact.verifyingKeyBytes,
          artifact.srsBytes,
        );
        if (signal?.aborted) return { status: 'failed', reason: 'Halo2 proof verification aborted' };
        return ok ? { status: 'verified' } : { status: 'failed', reason: 'Halo2 proof rejected' };
      } catch (e) {
        return { status: 'failed', reason: `Halo2 verifier backend failed: ${safeErrorMessage(e)}` };
      }
    },
  };
}

export function createHalo2DecryptionProofProver(args: CreateHalo2ProverArgs): DecryptionProofProver {
  const { artifact, wasm } = args;
  validateHalo2ProverArtifact(artifact);
  assertProverWasm(wasm);
  const relation = resolveSupportedRelation(artifact.metadata.relationDigest);
  const verifierArtifactDigest = digestHalo2ArtifactMetadata(artifact.metadata);
  const flags = halo2EnvelopeFlagsForArtifact(artifact.metadata);

  return {
    schemeId: artifact.metadata.schemeId,
    relationId: relation.id,
    relationDigest: artifact.metadata.relationDigest.slice(),
    verifierArtifactDigest,
    async proveV1(input): Promise<DecryptionProofEnvelope> {
      if (input.signal?.aborted) throw new Error('Halo2 proof generation aborted');
      validateDecryptionProofWitnessV1(input.witness);
      const encodedPublicInputs = encodeDecryptionProofPublicInputsV1(input.publicInputs);
      const transcriptDigest = digestDecryptionProofPublicInputsV1(input.publicInputs);
      let envelope: DecryptionProofEnvelope | null = null;

      let publicPtr: number | null = null;
      let witnessPtr: number | null = null;
      let provingKeyPtr: number | null = null;
      let srsPtr: number | null = null;

      input.onProgress?.({ phase: 'initializing' });
      try {
        publicPtr = allocateScratch(wasm, encodedPublicInputs, 'Halo2 public inputs');
        copyBytesToWasmMemory(wasm.memory, publicPtr, encodedPublicInputs, 'Halo2 public inputs');
        provingKeyPtr = allocateScratch(wasm, artifact.provingKeyBytes, 'Halo2 proving key');
        copyBytesToWasmMemory(wasm.memory, provingKeyPtr, artifact.provingKeyBytes, 'Halo2 proving key');
        srsPtr = allocateScratch(wasm, artifact.srsBytes, 'Halo2 SRS');
        copyBytesToWasmMemory(wasm.memory, srsPtr, artifact.srsBytes, 'Halo2 SRS');
        witnessPtr = allocateWitnessBuffer(wasm);
        copyWitnessToWasmMemory({ memory: wasm.memory, ptr: witnessPtr, witness: input.witness });
        input.onProgress?.({ phase: 'witness' });
        if (input.signal?.aborted) throw new Error('Halo2 proof generation aborted');

        input.onProgress?.({ phase: 'proving' });
        const proofBytes = wasm.prove_decryption_proof_v1_from_witness_ptr(
          publicPtr,
          encodedPublicInputs.length,
          witnessPtr,
          HALO2_WITNESS_V1_BYTES,
          provingKeyPtr,
          artifact.provingKeyBytes.length,
          srsPtr,
          artifact.srsBytes.length,
        );
        if (!(proofBytes instanceof Uint8Array) || proofBytes.length === 0) {
          throw new Error('Halo2 prover returned empty proof bytes');
        }
        if (input.signal?.aborted) throw new Error('Halo2 proof generation aborted');

        envelope = {
          envelopeVersion: DECRYPTION_PROOF_ENVELOPE_VERSION,
          schemeId: artifact.metadata.schemeId,
          flags,
          relationId: relation.id,
          relationDigest: artifact.metadata.relationDigest.slice(),
          verifierArtifactDigest: verifierArtifactDigest.slice(),
          transcriptDigest,
          proofBytes,
        };
      } catch (e) {
        throw new Error(`Halo2 prover backend failed: ${safeErrorMessage(e)}`);
      } finally {
        input.onProgress?.({ phase: 'zeroizing' });
        if (witnessPtr !== null) {
          bestEffortZeroizeWasm(wasm.memory, witnessPtr, HALO2_WITNESS_V1_BYTES);
          bestEffortFreeWitness(wasm, witnessPtr, HALO2_WITNESS_V1_BYTES);
        }
        if (publicPtr !== null) {
          bestEffortZeroizeWasm(wasm.memory, publicPtr, encodedPublicInputs.length);
          bestEffortFreeScratch(wasm, publicPtr, encodedPublicInputs.length);
        }
        if (provingKeyPtr !== null) {
          bestEffortZeroizeWasm(wasm.memory, provingKeyPtr, artifact.provingKeyBytes.length);
          bestEffortFreeScratch(wasm, provingKeyPtr, artifact.provingKeyBytes.length);
        }
        if (srsPtr !== null) {
          bestEffortZeroizeWasm(wasm.memory, srsPtr, artifact.srsBytes.length);
          bestEffortFreeScratch(wasm, srsPtr, artifact.srsBytes.length);
        }
      }
      if (!envelope) throw new Error('Halo2 prover backend failed: no proof envelope was produced');
      input.onProgress?.({ phase: 'done', progress: 1 });
      return envelope;
    },
  };
}

export function createUnavailableHalo2DecryptionProofProver(): DecryptionProofProver {
  return {
    schemeId: DECRYPTION_PROOF_SCHEME_HALO2_KZG,
    relationId: RELATION_V1_ID,
    relationDigest: RELATION_V1_DIGEST,
    verifierArtifactDigest: new Uint8Array(32),
    async proveV1(): Promise<DecryptionProofEnvelope> {
      throw new Error(HALO2_BACKEND_NOT_BUNDLED);
    },
  };
}

function validateHalo2ArtifactForRelation(metadata: Halo2ArtifactMetadata): void {
  validateHalo2ArtifactMetadata(metadata);
  if (metadata.schemeId !== DECRYPTION_PROOF_SCHEME_HALO2_KZG) {
    throw new Error('Halo2 artifact scheme id is not supported');
  }
  if (metadata.pcsId !== PCS_KZG) throw new Error('Halo2 artifact PCS id is not supported');
  if (metadata.curveId !== CURVE_BN254) throw new Error('Halo2 artifact curve id is not supported');
  if (!lookupSupportedHalo2Relation(metadata.relationDigest)) {
    throw new Error('Halo2 artifact relation digest is not supported');
  }
}

function resolveSupportedRelation(digest: Uint8Array): SupportedHalo2Relation {
  const relation = lookupSupportedHalo2Relation(digest);
  if (!relation) throw new Error('Halo2 artifact relation digest is not supported');
  return relation;
}

function verifyHalo2EnvelopePreflight(
  envelope: DecryptionProofEnvelope,
  verifierArtifactDigest: Uint8Array,
  expectedFlags: number,
  relation: SupportedHalo2Relation,
): DecryptionProofVerificationResult | null {
  if (envelope.envelopeVersion !== DECRYPTION_PROOF_ENVELOPE_VERSION) {
    return { status: 'failed', reason: 'unsupported decryption proof envelope version' };
  }
  if (envelope.schemeId !== DECRYPTION_PROOF_SCHEME_HALO2_KZG) {
    return { status: 'failed', reason: 'Halo2 proof scheme mismatch' };
  }
  if (envelope.relationId !== relation.id || !constantTimeEqual(envelope.relationDigest, relation.digest)) {
    return { status: 'failed', reason: 'Halo2 proof relation mismatch' };
  }
  if (!constantTimeEqual(envelope.verifierArtifactDigest, verifierArtifactDigest)) {
    return { status: 'failed', reason: 'Halo2 verifier artifact mismatch' };
  }
  if ((envelope.flags & DECRYPTION_PROOF_FLAG_TEST_ONLY) !== 0) {
    return { status: 'failed', reason: 'Halo2 verifier rejects test-only proof envelopes' };
  }
  if (envelope.flags !== expectedFlags) {
    return { status: 'failed', reason: 'Halo2 proof envelope flags do not match verifier artifact' };
  }
  return null;
}

function allocateWitnessBuffer(wasm: Halo2WasmProver): number {
  const ptr = wasm.allocate_witness_buffer(HALO2_WITNESS_V1_BYTES);
  assertPtr(ptr, HALO2_WITNESS_V1_BYTES, wasm.memory, 'Halo2 witness buffer');
  return ptr;
}

function allocateScratch(
  wasm: Halo2WasmProver,
  bytes: Uint8Array,
  label: string,
): number {
  assertNonemptyBytes(bytes, label);
  const ptr = wasm.allocate_buffer(bytes.length);
  assertPtr(ptr, bytes.length, wasm.memory, label);
  return ptr;
}

function copyBytesToWasmMemory(
  memory: WebAssembly.Memory,
  ptr: number,
  bytes: Uint8Array,
  label: string,
): void {
  assertNonemptyBytes(bytes, label);
  wasmMemoryRegion(memory, ptr, bytes.length).set(bytes);
}

function assertVerifierWasm(wasm: Halo2WasmVerifier): void {
  if (typeof wasm?.verify_decryption_proof_v1 !== 'function') {
    throw new Error('Halo2 verifier WASM API is missing verify_decryption_proof_v1');
  }
}

function assertProverWasm(wasm: Halo2WasmProver): void {
  if (!(wasm?.memory instanceof WebAssembly.Memory)) throw new Error('Halo2 prover WASM memory is missing');
  if (typeof wasm.allocate_buffer !== 'function') throw new Error('Halo2 prover WASM API is missing allocate_buffer');
  if (typeof wasm.free_buffer !== 'function') throw new Error('Halo2 prover WASM API is missing free_buffer');
  if (typeof wasm.allocate_witness_buffer !== 'function') {
    throw new Error('Halo2 prover WASM API is missing allocate_witness_buffer');
  }
  if (typeof wasm.free_witness_buffer !== 'function') {
    throw new Error('Halo2 prover WASM API is missing free_witness_buffer');
  }
  if (typeof wasm.prove_decryption_proof_v1_from_witness_ptr !== 'function') {
    throw new Error('Halo2 prover WASM API is missing prove_decryption_proof_v1_from_witness_ptr');
  }
}

function assertPtr(ptr: number, len: number, memory: WebAssembly.Memory, label: string): void {
  if (!Number.isInteger(ptr) || ptr < 0) throw new Error(`${label} pointer is out of range`);
  if (ptr + len > memory.buffer.byteLength) throw new Error(`${label} memory region is out of bounds`);
}

function wasmMemoryRegion(memory: WebAssembly.Memory, ptr: number, len: number): Uint8Array {
  assertPtr(ptr, len, memory, 'Halo2 WASM buffer');
  return new Uint8Array(memory.buffer, ptr, len);
}

function bestEffortZeroizeWasm(memory: WebAssembly.Memory, ptr: number, len: number): void {
  try {
    zeroizeWasmMemoryRegion(memory, ptr, len);
  } catch {
    // The Rust/WASM boundary is responsible for zeroizing witness state before returning.
  }
}

function bestEffortFreeWitness(wasm: Halo2WasmProver, ptr: number, len: number): void {
  try {
    wasm.free_witness_buffer(ptr, len);
  } catch {
    // Cleanup must not hide the verifier/prover failure that triggered it.
  }
}

function bestEffortFreeScratch(wasm: Halo2WasmProver, ptr: number, len: number): void {
  try {
    wasm.free_buffer(ptr, len);
  } catch {
    // Cleanup must not hide the verifier/prover failure that triggered it.
  }
}

function assertNonemptyBytes(value: unknown, label: string): asserts value is Uint8Array {
  if (!(value instanceof Uint8Array) || value.length === 0) throw new Error(`${label} must be nonempty bytes`);
}

function assertDigestMatches(bytes: Uint8Array, expectedDigest: Uint8Array, label: string): void {
  if (!constantTimeEqual(sha256(bytes), expectedDigest)) throw new Error(`${label} mismatch`);
}

function safeErrorMessage(error: unknown): string {
  if (error instanceof Error && error.message.length > 0) return error.message;
  const message = String(error);
  return message.length > 0 ? message : 'unknown Halo2 backend error';
}

function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}
