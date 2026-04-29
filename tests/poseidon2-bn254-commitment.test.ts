import { describe, expect, it } from 'vitest';
import {
  BN254_SCALAR_FIELD_ORDER,
  POSEIDON2_BN254_FIELD_ID,
  POSEIDON2_BN254_HASH_ID,
  POSEIDON2_BN254_PARAMS_ID,
  POSEIDON2_BN254_UNAVAILABLE_MESSAGE,
  assertBn254Scalar,
  bn254ScalarToBytes,
  bytesToBn254Scalar,
  commitPoseidon2Bn254FieldElements,
  createPoseidon2Bn254Implementation,
  digestPoseidon2Bn254VectorManifest,
  poseidon2Bn254Hash,
  validatePoseidon2Bn254VectorManifest,
  type Poseidon2Bn254Backend,
  type Poseidon2Bn254Implementation,
  type Poseidon2Bn254VectorManifest,
} from '../src/crypto/commitments/poseidon2-bn254';

describe('Poseidon2-BN254 commitment facade', () => {
  it('round-trips BN254 scalars as fixed-width big-endian bytes', () => {
    const encoded = bn254ScalarToBytes(0x010203n);
    expect(encoded.length).toBe(32);
    expect(Array.from(encoded.slice(29))).toEqual([0x01, 0x02, 0x03]);
    expect(bytesToBn254Scalar(encoded)).toBe(0x010203n);

    const max = BN254_SCALAR_FIELD_ORDER - 1n;
    expect(bytesToBn254Scalar(bn254ScalarToBytes(max))).toBe(max);
    expect(() => bn254ScalarToBytes(BN254_SCALAR_FIELD_ORDER)).toThrow(/BN254 scalar field/);
    expect(() => bytesToBn254Scalar(Uint8Array.from({ length: 32 }, () => 0xff))).toThrow(
      /BN254 scalar field/,
    );
    expect(() => assertBn254Scalar(-1n)).toThrow(/BN254 scalar field/);
  });

  it('validates and digests a vector manifest deterministically', () => {
    const manifest = sampleManifest();
    expect(() => validatePoseidon2Bn254VectorManifest(manifest)).not.toThrow();

    const digest = digestPoseidon2Bn254VectorManifest(manifest);
    expect(digest.length).toBe(32);
    expect(digestPoseidon2Bn254VectorManifest(sampleManifest())).toEqual(digest);

    const changedWidth = { ...manifest, width: '4' };
    const changedMdsDigest = { ...manifest, mdsMatrixDigest: repeatedHex('22') };
    const changedVectorDomain = {
      ...manifest,
      vectors: [{ ...manifest.vectors[0]!, domain: 'sss/v3/poseidon2/other' }],
    };
    const changedVectorInput = {
      ...manifest,
      vectors: [{ ...manifest.vectors[0]!, inputsHex: [fieldHex(3n)] }],
    };

    for (const mutation of [changedWidth, changedMdsDigest, changedVectorDomain, changedVectorInput]) {
      expect(digestPoseidon2Bn254VectorManifest(mutation)).not.toEqual(digest);
    }
  });

  it('rejects malformed vector manifests before they can define a commitment backend', () => {
    expect(() =>
      validatePoseidon2Bn254VectorManifest({ ...sampleManifest(), hash: 'poseidon' }),
    ).toThrow(/hash/);
    expect(() =>
      validatePoseidon2Bn254VectorManifest({ ...sampleManifest(), field: 'bn254-base' }),
    ).toThrow(/field/);
    expect(() =>
      validatePoseidon2Bn254VectorManifest({ ...sampleManifest(), paramsId: 'unreviewed' }),
    ).toThrow(/paramsId/);
    expect(() => validatePoseidon2Bn254VectorManifest({ ...sampleManifest(), width: '0' })).toThrow(
      /width/,
    );
    expect(() => validatePoseidon2Bn254VectorManifest({ ...sampleManifest(), vectors: [] })).toThrow(
      /vectors/,
    );
    expect(() =>
      validatePoseidon2Bn254VectorManifest({
        ...sampleManifest(),
        mdsMatrixDigest: '00',
      }),
    ).toThrow(/MDS matrix digest/);
    expect(() =>
      validatePoseidon2Bn254VectorManifest({
        ...sampleManifest(),
        vectors: [{ ...sampleManifest().vectors[0]!, domain: '' }],
      }),
    ).toThrow(/domain/);
    expect(() =>
      validatePoseidon2Bn254VectorManifest({
        ...sampleManifest(),
        vectors: [{ ...sampleManifest().vectors[0]!, outputHex: fieldHex(BN254_SCALAR_FIELD_ORDER) }],
      }),
    ).toThrow(/BN254 scalar field/);
  });

  it('fails closed when no audited implementation is supplied', () => {
    expect(() => poseidon2Bn254Hash([1n], undefined, 'domain')).toThrow(
      POSEIDON2_BN254_UNAVAILABLE_MESSAGE,
    );
  });

  it('builds an implementation only after the backend passes every manifest vector', () => {
    const manifest = sampleManifest();
    const implementation = createPoseidon2Bn254Implementation({
      manifest,
      backend: vectorBackend(10n),
    });

    expect(implementation.vectorManifestDigest).toEqual(digestPoseidon2Bn254VectorManifest(manifest));
    expect(poseidon2Bn254Hash([1n, 2n], implementation, 'sss/v3/poseidon2/test')).toEqual(
      bn254ScalarToBytes(10n),
    );

    expect(() =>
      createPoseidon2Bn254Implementation({
        manifest,
        backend: vectorBackend(11n),
      }),
    ).toThrow(/vector mismatch/);
    expect(() =>
      createPoseidon2Bn254Implementation({
        manifest,
        backend: { ...vectorBackend(10n), paramsId: 'other' as typeof POSEIDON2_BN254_PARAMS_ID },
      }),
    ).toThrow(/paramsId/);
  });

  it('delegates only to an implementation with the reviewed params and manifest digest', () => {
    const implementation = fakeImplementation();
    const commitment = commitPoseidon2Bn254FieldElements({
      domain: 'sss/v3/plaintext-commitment',
      inputs: [1n, 2n],
      implementation,
    });
    expect(bytesToBn254Scalar(commitment)).toBe(11n);

    expect(() =>
      poseidon2Bn254Hash([BN254_SCALAR_FIELD_ORDER], implementation, 'domain'),
    ).toThrow(/input 0/);
    expect(() =>
      poseidon2Bn254Hash([1n], { ...implementation, vectorManifestDigest: bytes(31, 1) }, 'domain'),
    ).toThrow(/manifest digest/);
    expect(() =>
      poseidon2Bn254Hash(
        [1n],
        { ...implementation, paramsId: 'other' as typeof POSEIDON2_BN254_PARAMS_ID },
        'domain',
      ),
    ).toThrow(/paramsId/);
    expect(() =>
      poseidon2Bn254Hash(
        [1n],
        { ...implementation, hash: () => Uint8Array.from({ length: 32 }, () => 0xff) },
        'domain',
      ),
    ).toThrow(/BN254 scalar field/);
  });
});

function sampleManifest(): Poseidon2Bn254VectorManifest {
  return {
    hash: POSEIDON2_BN254_HASH_ID,
    field: POSEIDON2_BN254_FIELD_ID,
    paramsId: POSEIDON2_BN254_PARAMS_ID,
    width: '3',
    rate: '2',
    capacity: '1',
    roundsFull: '8',
    roundsPartial: '56',
    mdsMatrixDigest: repeatedHex('11'),
    roundConstantsDigest: repeatedHex('aa'),
    vectors: [
      {
        name: 'manifest-validation-vector',
        domain: 'sss/v3/poseidon2/test',
        inputsHex: [fieldHex(1n), fieldHex(2n)],
        outputHex: fieldHex(10n),
      },
    ],
  };
}

function vectorBackend(output: bigint): Poseidon2Bn254Backend {
  return {
    paramsId: POSEIDON2_BN254_PARAMS_ID,
    hash(inputs, domain) {
      expect(inputs).toEqual([1n, 2n]);
      expect(domain).toBe('sss/v3/poseidon2/test');
      return output;
    },
  };
}

function fakeImplementation(): Poseidon2Bn254Implementation {
  return {
    paramsId: POSEIDON2_BN254_PARAMS_ID,
    vectorManifestDigest: digestPoseidon2Bn254VectorManifest(sampleManifest()),
    hash(inputs, domain) {
      expect(inputs).toEqual([1n, 2n]);
      expect(domain).toBe('sss/v3/plaintext-commitment');
      return 11n;
    },
  };
}

function fieldHex(value: bigint): string {
  return Array.from(bn254ScalarToBytes(value), (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function repeatedHex(byteHex: string): string {
  return byteHex.repeat(32);
}

function bytes(length: number, seed: number): Uint8Array {
  return Uint8Array.from({ length }, (_, index) => (seed + index) & 0xff);
}
