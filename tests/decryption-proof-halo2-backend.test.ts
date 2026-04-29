import { sha256 } from '@noble/hashes/sha2.js';
import { describe, expect, it } from 'vitest';
import {
  DECRYPTION_PROOF_FLAG_EXTERNAL_ARTIFACT,
  DECRYPTION_PROOF_FLAG_TRUSTED_SETUP,
  type DecryptionProofEnvelope,
} from '../src/crypto/zk/decryption-proof-envelope';
import type { DecryptionProofWitnessV1 } from '../src/crypto/zk/decryption-proof-prover';
import {
  DECRYPTION_PROOF_ENVELOPE_VERSION,
  DECRYPTION_PROOF_SCHEME_HALO2_KZG,
  ML_KEM_768_CIPHERTEXT_BYTES,
  RELATION_V1_DIGEST,
  RELATION_V1_ID,
} from '../src/crypto/zk/decryption-proof-relations';
import {
  digestDecryptionProofPublicInputsV1,
  encodeDecryptionProofPublicInputsV1,
  type DecryptionProofPublicInputsV1,
} from '../src/crypto/zk/decryption-proof-transcript';
import {
  CURVE_BN254,
  PCS_KZG,
  digestHalo2ArtifactMetadata,
  type Halo2ArtifactMetadata,
} from '../src/crypto/zk/halo2/artifact';
import {
  HALO2_BACKEND_NOT_BUNDLED,
  HALO2_WITNESS_V1_BYTES,
  createHalo2DecryptionProofProver,
  createHalo2DecryptionProofVerifier,
  createUnavailableHalo2DecryptionProofProver,
  validateHalo2ProverArtifact,
  validateHalo2VerifierArtifact,
  type Halo2ProverArtifact,
  type Halo2VerifierArtifact,
  type Halo2WasmProver,
} from '../src/crypto/zk/halo2';

describe('Halo2 backend artifact and WASM wrappers', () => {
  it('validates artifact bytes against metadata digests and supported relation ids', () => {
    const artifact = sampleProverArtifact();
    expect(() => validateHalo2VerifierArtifact(artifact)).not.toThrow();
    expect(() => validateHalo2ProverArtifact(artifact)).not.toThrow();

    expect(() =>
      validateHalo2VerifierArtifact({ ...artifact, verifyingKeyBytes: bytes(24, 201) }),
    ).toThrow(/verifying key hash/);
    expect(() =>
      validateHalo2VerifierArtifact({ ...artifact, wasmBuildBytes: bytes(20, 202) }),
    ).toThrow(/WASM build hash/);
    expect(() =>
      validateHalo2VerifierArtifact({
        ...artifact,
        metadata: { ...artifact.metadata, relationDigest: bytes(32, 203) },
      }),
    ).toThrow(/relation digest/);
    expect(() =>
      validateHalo2ProverArtifact({ ...artifact, provingKeyBytes: new Uint8Array(0) }),
    ).toThrow(/proving key/);
    expect(() =>
      validateHalo2ProverArtifact({
        ...artifact,
        provingKeyHash: sha256(bytes(16, 204)),
      }),
    ).toThrow(/proving key hash/);
  });

  it('wraps verifier success, rejection, transcript mismatch, and backend exceptions', async () => {
    const artifact = sampleVerifierArtifact();
    const publicInputs = samplePublicInputs();
    const encodedPublicInputs = encodeDecryptionProofPublicInputsV1(publicInputs);
    const envelope = sampleEnvelope(artifact, publicInputs);
    const calls: Array<{
      proofBytes: Uint8Array;
      encodedPublicInputs: Uint8Array;
      verifyingKeyBytes: Uint8Array;
      srsBytes: Uint8Array;
    }> = [];

    const verifier = createHalo2DecryptionProofVerifier({
      artifact,
      wasm: {
        verify_decryption_proof_v1(proofBytes, encoded, verifyingKeyBytes, srsBytes) {
          calls.push({ proofBytes, encodedPublicInputs: encoded, verifyingKeyBytes, srsBytes });
          return true;
        },
      },
    });
    await expect(verifier.verifyEnvelopeV1({ envelope, publicInputs })).resolves.toEqual({ status: 'verified' });
    expect(calls).toHaveLength(1);
    expect(calls[0]?.proofBytes).toEqual(envelope.proofBytes);
    expect(calls[0]?.encodedPublicInputs).toEqual(encodedPublicInputs);
    expect(calls[0]?.verifyingKeyBytes).toEqual(artifact.verifyingKeyBytes);
    expect(calls[0]?.srsBytes).toEqual(artifact.srsBytes);

    const rejectingVerifier = createHalo2DecryptionProofVerifier({
      artifact,
      wasm: {
        verify_decryption_proof_v1() {
          return false;
        },
      },
    });
    await expect(rejectingVerifier.verifyEnvelopeV1({ envelope, publicInputs })).resolves.toEqual({
      status: 'failed',
      reason: 'Halo2 proof rejected',
    });

    const tamperedInputs = samplePublicInputs();
    tamperedInputs.policyCommitment[0]! ^= 1;
    await expect(verifier.verifyEnvelopeV1({ envelope, publicInputs: tamperedInputs })).resolves.toEqual({
      status: 'failed',
      reason: 'decryption proof transcript mismatch',
    });

    const throwingVerifier = createHalo2DecryptionProofVerifier({
      artifact,
      wasm: {
        verify_decryption_proof_v1() {
          throw new Error('panic boundary tripped');
        },
      },
    });
    await expect(throwingVerifier.verifyEnvelopeV1({ envelope, publicInputs })).resolves.toEqual({
      status: 'failed',
      reason: 'Halo2 verifier backend failed: panic boundary tripped',
    });
  });

  it('emits a real Halo2 envelope through pointer-based WASM memory and zeroizes buffers', async () => {
    const artifact = sampleProverArtifact();
    const wasm = new FakeHalo2WasmProver();
    const publicInputs = samplePublicInputs();
    const witness = sampleWitness();
    const progress: string[] = [];

    const prover = createHalo2DecryptionProofProver({ artifact, wasm });
    const envelope = await prover.proveV1({
      publicInputs,
      witness,
      onProgress: (event) => progress.push(event.phase),
    });

    expect(envelope).toMatchObject({
      envelopeVersion: DECRYPTION_PROOF_ENVELOPE_VERSION,
      schemeId: DECRYPTION_PROOF_SCHEME_HALO2_KZG,
      flags: DECRYPTION_PROOF_FLAG_EXTERNAL_ARTIFACT | DECRYPTION_PROOF_FLAG_TRUSTED_SETUP,
      relationId: RELATION_V1_ID,
    });
    expect(envelope.relationDigest).toEqual(RELATION_V1_DIGEST);
    expect(envelope.verifierArtifactDigest).toEqual(digestHalo2ArtifactMetadata(artifact.metadata));
    expect(envelope.transcriptDigest).toEqual(digestDecryptionProofPublicInputsV1(publicInputs));
    expect(envelope.proofBytes).toEqual(FakeHalo2WasmProver.PROOF_BYTES);

    expect(wasm.encodedPublicInputsSnapshot).toEqual(encodeDecryptionProofPublicInputsV1(publicInputs));
    expect(wasm.provingKeySnapshot).toEqual(artifact.provingKeyBytes);
    expect(wasm.srsSnapshot).toEqual(artifact.srsBytes);
    expect(wasm.witnessSnapshot?.slice(0, 64)).toEqual(witness.kemSeed);
    expect(wasm.witnessSnapshot?.slice(64)).toEqual(witness.vaultRootKey);
    expect(wasm.witnessPtr).not.toBeNull();
    expect(wasm.freeWitnessCalls).toEqual([{ ptr: wasm.witnessPtr, len: HALO2_WITNESS_V1_BYTES }]);
    expect(wasm.memoryRegion(wasm.witnessPtr!, HALO2_WITNESS_V1_BYTES)).toEqual(
      new Uint8Array(HALO2_WITNESS_V1_BYTES),
    );
    expect(progress).toEqual(['initializing', 'witness', 'proving', 'zeroizing', 'done']);
  });

  it('zeroizes and frees the witness buffer when prover backend fails', async () => {
    const artifact = sampleProverArtifact();
    const wasm = new FakeHalo2WasmProver();
    wasm.throwOnProve = true;
    const prover = createHalo2DecryptionProofProver({ artifact, wasm });

    await expect(
      prover.proveV1({
        publicInputs: samplePublicInputs(),
        witness: sampleWitness(),
      }),
    ).rejects.toThrow(/Halo2 prover backend failed: prover panic boundary tripped/);
    expect(wasm.witnessPtr).not.toBeNull();
    expect(wasm.freeWitnessCalls).toEqual([{ ptr: wasm.witnessPtr, len: HALO2_WITNESS_V1_BYTES }]);
    expect(wasm.memoryRegion(wasm.witnessPtr!, HALO2_WITNESS_V1_BYTES)).toEqual(
      new Uint8Array(HALO2_WITNESS_V1_BYTES),
    );
  });

  it('keeps an explicit unavailable backend placeholder for builds without artifacts', async () => {
    await expect(
      createUnavailableHalo2DecryptionProofProver().proveV1({
        publicInputs: samplePublicInputs(),
        witness: sampleWitness(),
      }),
    ).rejects.toThrow(HALO2_BACKEND_NOT_BUNDLED);
  });
});

class FakeHalo2WasmProver implements Halo2WasmProver {
  static readonly PROOF_BYTES = bytes(96, 150);

  readonly memory = new WebAssembly.Memory({ initial: 1 });
  throwOnProve = false;
  witnessPtr: number | null = null;
  witnessSnapshot: Uint8Array | null = null;
  encodedPublicInputsSnapshot: Uint8Array | null = null;
  provingKeySnapshot: Uint8Array | null = null;
  srsSnapshot: Uint8Array | null = null;
  readonly freeWitnessCalls: Array<{ ptr: number | null; len: number }> = [];

  private nextPtr = 128;

  allocate_buffer(len: number): number {
    return this.allocate(len);
  }

  free_buffer(): void {
    return;
  }

  allocate_witness_buffer(len: number): number {
    this.witnessPtr = this.allocate(len);
    return this.witnessPtr;
  }

  free_witness_buffer(ptr: number, len: number): void {
    this.freeWitnessCalls.push({ ptr, len });
  }

  prove_decryption_proof_v1_from_witness_ptr(
    encodedPublicInputsPtr: number,
    encodedPublicInputsLen: number,
    witnessPtr: number,
    witnessLen: number,
    provingKeyPtr: number,
    provingKeyLen: number,
    srsPtr: number,
    srsLen: number,
  ): Uint8Array {
    this.encodedPublicInputsSnapshot = this.memoryRegion(encodedPublicInputsPtr, encodedPublicInputsLen).slice();
    this.witnessSnapshot = this.memoryRegion(witnessPtr, witnessLen).slice();
    this.provingKeySnapshot = this.memoryRegion(provingKeyPtr, provingKeyLen).slice();
    this.srsSnapshot = this.memoryRegion(srsPtr, srsLen).slice();
    if (this.throwOnProve) throw new Error('prover panic boundary tripped');
    return FakeHalo2WasmProver.PROOF_BYTES.slice();
  }

  memoryRegion(ptr: number, len: number): Uint8Array {
    return new Uint8Array(this.memory.buffer, ptr, len);
  }

  private allocate(len: number): number {
    const ptr = this.nextPtr;
    this.nextPtr += len + 16;
    if (this.nextPtr > this.memory.buffer.byteLength) throw new Error('fake WASM memory exhausted');
    return ptr;
  }
}

function sampleVerifierArtifact(): Halo2VerifierArtifact {
  const wasmBuildBytes = bytes(20, 1);
  const trustedSetupIdBytes = bytes(16, 2);
  const verifyingKeyBytes = bytes(24, 3);
  const srsBytes = bytes(32, 8);
  return {
    metadata: sampleMetadata({ wasmBuildBytes, trustedSetupIdBytes, verifyingKeyBytes }),
    srsBytes,
    srsHash: sha256(srsBytes),
    wasmBuildBytes,
    trustedSetupIdBytes,
    verifyingKeyBytes,
  };
}

function sampleProverArtifact(): Halo2ProverArtifact {
  const verifierArtifact = sampleVerifierArtifact();
  const provingKeyBytes = bytes(40, 4);
  return {
    ...verifierArtifact,
    provingKeyBytes,
    provingKeyHash: sha256(provingKeyBytes),
  };
}

function sampleMetadata(args: {
  wasmBuildBytes: Uint8Array;
  trustedSetupIdBytes: Uint8Array;
  verifyingKeyBytes: Uint8Array;
}): Halo2ArtifactMetadata {
  return {
    schemeId: DECRYPTION_PROOF_SCHEME_HALO2_KZG,
    relationDigest: RELATION_V1_DIGEST,
    pcsId: PCS_KZG,
    curveId: CURVE_BN254,
    trustedSetupIdDigest: sha256(args.trustedSetupIdBytes),
    circuitVersionMajor: 1,
    circuitVersionMinor: 0,
    circuitVersionPatch: 0,
    wasmBuildHash: sha256(args.wasmBuildBytes),
    verifyingKeyHash: sha256(args.verifyingKeyBytes),
  };
}

function sampleEnvelope(
  artifact: Halo2VerifierArtifact,
  publicInputs: DecryptionProofPublicInputsV1,
): DecryptionProofEnvelope {
  return {
    envelopeVersion: DECRYPTION_PROOF_ENVELOPE_VERSION,
    schemeId: DECRYPTION_PROOF_SCHEME_HALO2_KZG,
    flags: DECRYPTION_PROOF_FLAG_EXTERNAL_ARTIFACT | DECRYPTION_PROOF_FLAG_TRUSTED_SETUP,
    relationId: RELATION_V1_ID,
    relationDigest: RELATION_V1_DIGEST,
    verifierArtifactDigest: digestHalo2ArtifactMetadata(artifact.metadata),
    transcriptDigest: digestDecryptionProofPublicInputsV1(publicInputs),
    proofBytes: bytes(96, 80),
  };
}

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

function sampleWitness(): DecryptionProofWitnessV1 {
  return {
    kemSeed: bytes(64, 9),
    vaultRootKey: bytes(32, 10),
  };
}

function bytes(length: number, seed: number): Uint8Array {
  return Uint8Array.from({ length }, (_, index) => (seed + index) & 0xff);
}
