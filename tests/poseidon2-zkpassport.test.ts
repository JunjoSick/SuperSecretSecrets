import { describe, expect, it } from 'vitest';
import manifestJson from './fixtures/poseidon2-bn254-vectors.json';
import {
  bytesToBn254Scalar,
  digestPoseidon2Bn254VectorManifest,
  poseidon2Bn254Hash,
  validatePoseidon2Bn254VectorManifest,
  type Poseidon2Bn254VectorManifest,
} from '../src/crypto/commitments/poseidon2-bn254';
import { POSEIDON2_BN254_VECTOR_MANIFEST } from '../src/crypto/commitments/poseidon2-bn254-vectors';
import {
  bindPoseidon2Bn254VaultRootPlaintextCommitment,
} from '../src/crypto/commitments/proof-facing';
import {
  ZK_PASSPORT_POSEIDON2_BN254_PARAMS,
  ZK_PASSPORT_POSEIDON2_BN254_VERSION,
  createZkPassportPoseidon2Bn254Implementation,
  poseidon2Bn254DomainTag,
} from '../src/crypto/commitments/poseidon2-zkpassport';

const manifest = manifestJson as Poseidon2Bn254VectorManifest;

describe('ZKPassport Poseidon2-BN254 backend', () => {
  it('accepts the checked-in vector manifest and verifies every vector through the package backend', () => {
    expect(POSEIDON2_BN254_VECTOR_MANIFEST).toEqual(manifest);
    expect(ZK_PASSPORT_POSEIDON2_BN254_VERSION).toBe('0.6.2');
    expect(() => validatePoseidon2Bn254VectorManifest(manifest)).not.toThrow();
    expect(manifest.width).toBe(ZK_PASSPORT_POSEIDON2_BN254_PARAMS.width);
    expect(manifest.rate).toBe(ZK_PASSPORT_POSEIDON2_BN254_PARAMS.rate);
    expect(manifest.capacity).toBe(ZK_PASSPORT_POSEIDON2_BN254_PARAMS.capacity);
    expect(manifest.roundsFull).toBe(ZK_PASSPORT_POSEIDON2_BN254_PARAMS.roundsFull);
    expect(manifest.roundsPartial).toBe(ZK_PASSPORT_POSEIDON2_BN254_PARAMS.roundsPartial);
    expect(manifest.mdsMatrixDigest).toBe(ZK_PASSPORT_POSEIDON2_BN254_PARAMS.mdsMatrixDigest);
    expect(manifest.roundConstantsDigest).toBe(ZK_PASSPORT_POSEIDON2_BN254_PARAMS.roundConstantsDigest);

    const implementation = createZkPassportPoseidon2Bn254Implementation(manifest);
    expect(implementation.vectorManifestDigest).toEqual(digestPoseidon2Bn254VectorManifest(manifest));

    for (const vector of manifest.vectors) {
      const inputs = vector.inputsHex.map((input) => bytesToBn254Scalar(hexToBytes(input)));
      expect(hex(poseidon2Bn254Hash(inputs, implementation, vector.domain)), vector.name).toBe(vector.outputHex);
    }
  });

  it('domain-separates package hashes with a fixed BN254-safe tag', () => {
    expect(poseidon2Bn254DomainTag('SSS/v3/poseidon2-bn254/plaintext-vault-root/v1')).toBe(
      0xd5e96c32da4bbfe395ccd6f3d49cf074n,
    );
    expect(poseidon2Bn254DomainTag('SSS/v3/poseidon2-bn254/policy-commitment/v1')).not.toBe(
      poseidon2Bn254DomainTag('SSS/v3/poseidon2-bn254/vault-tree-root/v1'),
    );
    expect(() => poseidon2Bn254DomainTag('')).toThrow(/nonempty/);
  });

  it('connects the real backend to the proof-facing plaintext commitment helper', () => {
    const implementation = createZkPassportPoseidon2Bn254Implementation(manifest);
    const bundleId = Uint8Array.from([1, 2, 3, 4, 5, 6, 7, 8]);
    const vaultRootKey = Uint8Array.from({ length: 32 }, (_, index) => 0x10 + index);

    expect(hex(bindPoseidon2Bn254VaultRootPlaintextCommitment({ bundleId, vaultRootKey, implementation }))).toBe(
      vectorByName('vault-root-plaintext').outputHex,
    );
  });

  it('rejects fixture drift before building a backend implementation', () => {
    expect(() =>
      createZkPassportPoseidon2Bn254Implementation({
        ...manifest,
        roundConstantsDigest: '00'.repeat(32),
      }),
    ).toThrow(/round-constants digest/);
    expect(() =>
      createZkPassportPoseidon2Bn254Implementation({
        ...manifest,
        vectors: [{ ...manifest.vectors[0]!, outputHex: '00'.repeat(32) }],
      }),
    ).toThrow(/vector mismatch/);
  });
});

function vectorByName(name: string) {
  const vector = manifest.vectors.find((candidate) => candidate.name === name);
  if (!vector) throw new Error(`missing vector ${name}`);
  return vector;
}

function hexToBytes(value: string): Uint8Array {
  const out = new Uint8Array(value.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(value.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}
