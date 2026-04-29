import { sha256 } from '@noble/hashes/sha2.js';
import { poseidon2Hash } from '@zkpassport/poseidon2';
import {
  POSEIDON2_BN254_PARAMS_ID,
  assertBn254Scalar,
  createPoseidon2Bn254Implementation,
  type Poseidon2Bn254Backend,
  type Poseidon2Bn254Implementation,
  type Poseidon2Bn254VectorManifest,
} from './poseidon2-bn254';
import { POSEIDON2_BN254_VECTOR_MANIFEST } from './poseidon2-bn254-vectors';

export const ZK_PASSPORT_POSEIDON2_BN254_PACKAGE = '@zkpassport/poseidon2';
export const ZK_PASSPORT_POSEIDON2_BN254_VERSION = '0.6.2';
export const ZK_PASSPORT_POSEIDON2_BN254_PARAMS = {
  width: '4',
  rate: '3',
  capacity: '1',
  roundsFull: '8',
  roundsPartial: '56',
  mdsMatrixDigest: '66009b3dde100734a94b470238f34f3300894bd666a8c5845d8e0b672ea5d373',
  roundConstantsDigest: 'a113481f5f579ad1e1d61f70257ad90c271993130aadb7318b53147336b1db36',
} as const;

const textEncoder = new TextEncoder();
let defaultImplementation: Poseidon2Bn254Implementation | null = null;

export const zkPassportPoseidon2Bn254Backend: Poseidon2Bn254Backend = {
  paramsId: POSEIDON2_BN254_PARAMS_ID,
  hash(inputs, domain) {
    const taggedInputs = [poseidon2Bn254DomainTag(domain), ...inputs];
    return poseidon2Hash(taggedInputs);
  },
};

export function createZkPassportPoseidon2Bn254Implementation(
  manifest: Poseidon2Bn254VectorManifest,
): Poseidon2Bn254Implementation {
  assertZkPassportPoseidon2Bn254Manifest(manifest);
  return createPoseidon2Bn254Implementation({
    manifest,
    backend: zkPassportPoseidon2Bn254Backend,
  });
}

export function getDefaultPoseidon2Bn254Implementation(): Poseidon2Bn254Implementation {
  defaultImplementation ??= createZkPassportPoseidon2Bn254Implementation(POSEIDON2_BN254_VECTOR_MANIFEST);
  return defaultImplementation;
}

export function poseidon2Bn254DomainTag(domain: string): bigint {
  if (typeof domain !== 'string' || domain.length === 0) {
    throw new Error('Poseidon2-BN254 domain must be a nonempty string');
  }
  const digest = sha256(textEncoder.encode(domain));
  let value = 0n;
  for (let i = 0; i < 16; i++) value = (value << 8n) | BigInt(digest[i]!);
  assertBn254Scalar(value, 'Poseidon2-BN254 domain tag');
  return value;
}

export function assertZkPassportPoseidon2Bn254Manifest(
  manifest: Poseidon2Bn254VectorManifest,
): void {
  if (manifest.width !== ZK_PASSPORT_POSEIDON2_BN254_PARAMS.width) {
    throw new Error('ZKPassport Poseidon2-BN254 manifest width mismatch');
  }
  if (manifest.rate !== ZK_PASSPORT_POSEIDON2_BN254_PARAMS.rate) {
    throw new Error('ZKPassport Poseidon2-BN254 manifest rate mismatch');
  }
  if (manifest.capacity !== ZK_PASSPORT_POSEIDON2_BN254_PARAMS.capacity) {
    throw new Error('ZKPassport Poseidon2-BN254 manifest capacity mismatch');
  }
  if (manifest.roundsFull !== ZK_PASSPORT_POSEIDON2_BN254_PARAMS.roundsFull) {
    throw new Error('ZKPassport Poseidon2-BN254 manifest full-round count mismatch');
  }
  if (manifest.roundsPartial !== ZK_PASSPORT_POSEIDON2_BN254_PARAMS.roundsPartial) {
    throw new Error('ZKPassport Poseidon2-BN254 manifest partial-round count mismatch');
  }
  if (manifest.mdsMatrixDigest !== ZK_PASSPORT_POSEIDON2_BN254_PARAMS.mdsMatrixDigest) {
    throw new Error('ZKPassport Poseidon2-BN254 manifest MDS digest mismatch');
  }
  if (manifest.roundConstantsDigest !== ZK_PASSPORT_POSEIDON2_BN254_PARAMS.roundConstantsDigest) {
    throw new Error('ZKPassport Poseidon2-BN254 manifest round-constants digest mismatch');
  }
}
