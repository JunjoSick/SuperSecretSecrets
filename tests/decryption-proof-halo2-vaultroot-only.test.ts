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
  RELATION_V1_VAULTROOT_ONLY_DIGEST,
  RELATION_V1_VAULTROOT_ONLY_ID,
  digestDecryptionProofRelation,
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
  HALO2_WITNESS_V1_BYTES,
  createHalo2DecryptionProofProver,
  createHalo2DecryptionProofVerifier,
  type Halo2ProverArtifact,
  type Halo2VerifierArtifact,
  type Halo2WasmProver,
} from '../src/crypto/zk/halo2';

describe('Halo2 backend vaultroot-only relation', () => {
  it('derives the vaultroot-only relation id from artifact metadata', async () => {
    expect(RELATION_V1_VAULTROOT_ONLY_DIGEST).toEqual(
      digestDecryptionProofRelation(RELATION_V1_VAULTROOT_ONLY_ID),
    );

    const artifact = sampleProverArtifact();
    const wasm = new RecordingWasm();
    const prover = createHalo2DecryptionProofProver({ artifact, wasm });
    expect(prover.relationId).toBe(RELATION_V1_VAULTROOT_ONLY_ID);
    expect(prover.relationDigest).toEqual(RELATION_V1_VAULTROOT_ONLY_DIGEST);

    const publicInputs = samplePublicInputs();
    const witness = sampleWitness();
    const envelope = await prover.proveV1({ publicInputs, witness });
    expect(envelope).toMatchObject({
      envelopeVersion: DECRYPTION_PROOF_ENVELOPE_VERSION,
      schemeId: DECRYPTION_PROOF_SCHEME_HALO2_KZG,
      relationId: RELATION_V1_VAULTROOT_ONLY_ID,
      flags: DECRYPTION_PROOF_FLAG_EXTERNAL_ARTIFACT | DECRYPTION_PROOF_FLAG_TRUSTED_SETUP,
    });
    expect(envelope.relationDigest).toEqual(RELATION_V1_VAULTROOT_ONLY_DIGEST);
    expect(envelope.transcriptDigest).toEqual(digestDecryptionProofPublicInputsV1(publicInputs));

    const verifier = createHalo2DecryptionProofVerifier({
      artifact,
      wasm: { verify_decryption_proof_v1: () => true },
    });
    expect(verifier.relationId).toBe(RELATION_V1_VAULTROOT_ONLY_ID);
    await expect(verifier.verifyEnvelopeV1({ envelope, publicInputs })).resolves.toEqual({
      status: 'verified',
    });
  });

  it('rejects envelopes that quote the wrong relation id for the vaultroot-only artifact', async () => {
    const artifact = sampleProverArtifact();
    const verifier = createHalo2DecryptionProofVerifier({
      artifact,
      wasm: { verify_decryption_proof_v1: () => true },
    });
    const publicInputs = samplePublicInputs();
    const envelope: DecryptionProofEnvelope = {
      envelopeVersion: DECRYPTION_PROOF_ENVELOPE_VERSION,
      schemeId: DECRYPTION_PROOF_SCHEME_HALO2_KZG,
      flags: DECRYPTION_PROOF_FLAG_EXTERNAL_ARTIFACT | DECRYPTION_PROOF_FLAG_TRUSTED_SETUP,
      relationId: 'sss-v3-something-else-v1',
      relationDigest: RELATION_V1_VAULTROOT_ONLY_DIGEST,
      verifierArtifactDigest: digestHalo2ArtifactMetadata(artifact.metadata),
      transcriptDigest: digestDecryptionProofPublicInputsV1(publicInputs),
      proofBytes: bytes(48, 11),
    };
    await expect(verifier.verifyEnvelopeV1({ envelope, publicInputs })).resolves.toEqual({
      status: 'failed',
      reason: 'Halo2 proof relation mismatch',
    });
  });

  it('rejects unknown relation digests at artifact validation time', () => {
    expect(() =>
      createHalo2DecryptionProofVerifier({
        artifact: {
          ...sampleVerifierArtifact(),
          metadata: { ...sampleMetadata(), relationDigest: RELATION_V1_DIGEST },
        },
        wasm: { verify_decryption_proof_v1: () => true },
      }),
    ).toThrow(/relation digest/);

    expect(() =>
      createHalo2DecryptionProofVerifier({
        artifact: {
          ...sampleVerifierArtifact(),
          metadata: { ...sampleMetadata(), relationDigest: bytes(32, 99) },
        },
        wasm: { verify_decryption_proof_v1: () => true },
      }),
    ).toThrow(/relation digest/);
  });
});

class RecordingWasm implements Halo2WasmProver {
  readonly memory = new WebAssembly.Memory({ initial: 1 });
  private nextPtr = 256;

  allocate_buffer(len: number): number {
    return this.allocate(len);
  }

  free_buffer(): void {
    return;
  }

  allocate_witness_buffer(len: number): number {
    return this.allocate(len);
  }

  free_witness_buffer(): void {
    return;
  }

  prove_decryption_proof_v1_from_witness_ptr(
    _publicInputsPtr: number,
    _publicInputsLen: number,
    _witnessPtr: number,
    _witnessLen: number,
    _provingKeyPtr: number,
    _provingKeyLen: number,
    _srsPtr: number,
    _srsLen: number,
  ): Uint8Array {
    return Uint8Array.from({ length: 32 }, (_, index) => (index + 17) & 0xff);
  }

  private allocate(len: number): number {
    const ptr = this.nextPtr;
    this.nextPtr += len + 16;
    if (this.nextPtr > this.memory.buffer.byteLength) throw new Error('memory exhausted');
    return ptr;
  }
}

function sampleVerifierArtifact(): Halo2VerifierArtifact {
  const wasmBuildBytes = bytes(20, 30);
  const trustedSetupIdBytes = bytes(16, 31);
  const verifyingKeyBytes = bytes(40, 32);
  const srsBytes = bytes(48, 34);
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
  const verifier = sampleVerifierArtifact();
  const provingKeyBytes = bytes(64, 33);
  return {
    ...verifier,
    provingKeyBytes,
    provingKeyHash: sha256(provingKeyBytes),
  };
}

function sampleMetadata(args?: {
  wasmBuildBytes: Uint8Array;
  trustedSetupIdBytes: Uint8Array;
  verifyingKeyBytes: Uint8Array;
}): Halo2ArtifactMetadata {
  const wasmBuildBytes = args?.wasmBuildBytes ?? bytes(20, 30);
  const trustedSetupIdBytes = args?.trustedSetupIdBytes ?? bytes(16, 31);
  const verifyingKeyBytes = args?.verifyingKeyBytes ?? bytes(40, 32);
  return {
    schemeId: DECRYPTION_PROOF_SCHEME_HALO2_KZG,
    relationDigest: RELATION_V1_VAULTROOT_ONLY_DIGEST,
    pcsId: PCS_KZG,
    curveId: CURVE_BN254,
    trustedSetupIdDigest: sha256(trustedSetupIdBytes),
    circuitVersionMajor: 0,
    circuitVersionMinor: 1,
    circuitVersionPatch: 0,
    wasmBuildHash: sha256(wasmBuildBytes),
    verifyingKeyHash: sha256(verifyingKeyBytes),
  };
}

function samplePublicInputs(): DecryptionProofPublicInputsV1 {
  return {
    bundleId: bytes(8, 41),
    payloadKind: 'vault-root',
    kemAlgId: 1,
    kdfAlgId: 1,
    aeadAlgId: 1,
    commitmentHashId: 1,
    passphraseFlag: false,
    argon2TCost: 0,
    argon2MemLog2KiB: 0,
    argon2Parallelism: 0,
    policyCommitment: bytes(32, 42),
    plaintextCommitment: bytes(32, 43),
    vaultTreeRoot: bytes(32, 44),
    kemCiphertext: bytes(ML_KEM_768_CIPHERTEXT_BYTES, 45),
    aeadNonce: bytes(12, 46),
    aeadCiphertextAndTag: bytes(48, 47),
  };
}

function sampleWitness(): DecryptionProofWitnessV1 {
  return {
    kemSeed: bytes(64, 51),
    vaultRootKey: bytes(32, 52),
  };
}

function bytes(length: number, seed: number): Uint8Array {
  return Uint8Array.from({ length }, (_, index) => (seed + index) & 0xff);
}

// Reference imports kept for future end-to-end test asserting encoded inputs match wasm copy.
void encodeDecryptionProofPublicInputsV1;
void HALO2_WITNESS_V1_BYTES;
