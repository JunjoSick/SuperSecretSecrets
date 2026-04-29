import {
  bytesToBn254Scalar,
  commitPoseidon2Bn254FieldElements,
  type Poseidon2Bn254Implementation,
} from './poseidon2-bn254';
import type { VaultEntry } from '../vault';

export const POSEIDON2_BN254_BUNDLE_ID_BYTES = 8;
export const POSEIDON2_BN254_VAULT_ROOT_KEY_BYTES = 32;
export const POSEIDON2_BN254_KEM_SEED_BYTES = 64;
export const POSEIDON2_BN254_LIMB128_BYTES = 16;

export const POSEIDON2_BN254_PLAINTEXT_VAULT_ROOT_COMMITMENT_DOMAIN =
  'SSS/v3/poseidon2-bn254/plaintext-vault-root/v1';
export const POSEIDON2_BN254_POLICY_COMMITMENT_DOMAIN =
  'SSS/v3/poseidon2-bn254/policy-kem-seed/v1';
export const POSEIDON2_BN254_VAULT_TREE_ROOT_DOMAIN =
  'SSS/v3/poseidon2-bn254/vault-tree-root/v1';
export const POSEIDON2_BN254_VAULT_TREE_LEAF_DOMAIN =
  'SSS/v3/poseidon2-bn254/vault-tree-leaf/v1';
export const POSEIDON2_BN254_VAULT_TREE_NODE_DOMAIN =
  'SSS/v3/poseidon2-bn254/vault-tree-node/v1';

export function bindPoseidon2Bn254VaultRootPlaintextCommitment(args: {
  bundleId: Uint8Array;
  vaultRootKey: Uint8Array;
  implementation?: Poseidon2Bn254Implementation;
}): Uint8Array {
  const bundleIdScalar = fixedWidthBytesToBn254Scalar(
    args.bundleId,
    POSEIDON2_BN254_BUNDLE_ID_BYTES,
    'Poseidon2-BN254 plaintext commitment bundleId',
  );
  const [vaultRootKeyHigh128, vaultRootKeyLow128] = splitBytes32ToBn254Limbs128(
    args.vaultRootKey,
    'Poseidon2-BN254 plaintext commitment vaultRootKey',
  );
  return commitPoseidon2Bn254FieldElements({
    domain: POSEIDON2_BN254_PLAINTEXT_VAULT_ROOT_COMMITMENT_DOMAIN,
    inputs: [bundleIdScalar, vaultRootKeyHigh128, vaultRootKeyLow128],
    implementation: args.implementation,
  });
}

export function commitPoseidon2Bn254PolicyFields(args: {
  fields: readonly bigint[];
  implementation?: Poseidon2Bn254Implementation;
}): Uint8Array {
  assertNonemptyFields(args.fields, 'Poseidon2-BN254 policy commitment');
  return commitPoseidon2Bn254FieldElements({
    domain: POSEIDON2_BN254_POLICY_COMMITMENT_DOMAIN,
    inputs: args.fields,
    implementation: args.implementation,
  });
}

export function bindPoseidon2Bn254PolicySeedCommitment(args: {
  kemSeed: Uint8Array;
  implementation?: Poseidon2Bn254Implementation;
}): Uint8Array {
  assertBytes(args.kemSeed, 'Poseidon2-BN254 policy KEM seed');
  if (args.kemSeed.length !== POSEIDON2_BN254_KEM_SEED_BYTES) {
    throw new Error(`Poseidon2-BN254 policy KEM seed must be ${POSEIDON2_BN254_KEM_SEED_BYTES} bytes`);
  }
  return commitPoseidon2Bn254PolicyFields({
    fields: bytesToBn254Limbs128(args.kemSeed, 'Poseidon2-BN254 policy KEM seed'),
    implementation: args.implementation,
  });
}

export function commitPoseidon2Bn254VaultTreeRootFields(args: {
  fields: readonly bigint[];
  implementation?: Poseidon2Bn254Implementation;
}): Uint8Array {
  assertNonemptyFields(args.fields, 'Poseidon2-BN254 vault tree root');
  return commitPoseidon2Bn254FieldElements({
    domain: POSEIDON2_BN254_VAULT_TREE_ROOT_DOMAIN,
    inputs: args.fields,
    implementation: args.implementation,
  });
}

export function commitPoseidon2Bn254VaultTreeRoot(args: {
  entries: readonly VaultEntry[];
  implementation?: Poseidon2Bn254Implementation;
}): Uint8Array {
  if (!Array.isArray(args.entries) || args.entries.length === 0) {
    throw new Error('Poseidon2-BN254 vault tree requires at least one entry');
  }
  const leaves = args.entries.map((entry) => poseidon2Bn254VaultEntryLeaf(entry, args.implementation));
  return poseidon2Bn254MerkleRoot(leaves, args.implementation);
}

export function poseidon2Bn254VaultEntryLeaf(
  entry: VaultEntry,
  implementation?: Poseidon2Bn254Implementation,
): Uint8Array {
  const fields = [
    ...stringToBn254Fields(entry.id, 'Poseidon2-BN254 vault entry id'),
    ...stringToBn254Fields(entry.name, 'Poseidon2-BN254 vault entry name'),
    ...stringToBn254Fields(entry.contentType ?? '', 'Poseidon2-BN254 vault entry contentType'),
    ...bytesToLengthPrefixedBn254Limbs128(entry.data, 'Poseidon2-BN254 vault entry data'),
  ];
  return commitPoseidon2Bn254FieldElements({
    domain: POSEIDON2_BN254_VAULT_TREE_LEAF_DOMAIN,
    inputs: fields,
    implementation,
  });
}

export function splitBytes32ToBn254Limbs128(bytes: Uint8Array, label = 'bytes32'): [bigint, bigint] {
  assertBytes(bytes, label);
  if (bytes.length !== POSEIDON2_BN254_VAULT_ROOT_KEY_BYTES) {
    throw new Error(`${label} must be 32 bytes`);
  }
  return [
    fixedWidthBytesToBn254Scalar(
      bytes.slice(0, POSEIDON2_BN254_LIMB128_BYTES),
      POSEIDON2_BN254_LIMB128_BYTES,
      label,
    ),
    fixedWidthBytesToBn254Scalar(
      bytes.slice(POSEIDON2_BN254_LIMB128_BYTES),
      POSEIDON2_BN254_LIMB128_BYTES,
      label,
    ),
  ];
}

export function bytesToBn254Limbs128(bytes: Uint8Array, label = 'bytes'): bigint[] {
  assertBytes(bytes, label);
  if (bytes.length === 0) return [];
  const fields: bigint[] = [];
  for (let offset = 0; offset < bytes.length; offset += POSEIDON2_BN254_LIMB128_BYTES) {
    fields.push(
      fixedWidthBytesToBn254Scalar(
        bytes.slice(offset, offset + POSEIDON2_BN254_LIMB128_BYTES),
        Math.min(POSEIDON2_BN254_LIMB128_BYTES, bytes.length - offset),
        label,
      ),
    );
  }
  return fields;
}

export function bytesToLengthPrefixedBn254Limbs128(bytes: Uint8Array, label = 'bytes'): bigint[] {
  assertBytes(bytes, label);
  return [BigInt(bytes.length), ...bytesToBn254Limbs128(bytes, label)];
}

export function stringToBn254Fields(value: string, label = 'string'): bigint[] {
  if (typeof value !== 'string') throw new Error(`${label} must be a string`);
  return bytesToLengthPrefixedBn254Limbs128(new TextEncoder().encode(value), label);
}

function fixedWidthBytesToBn254Scalar(bytes: Uint8Array, expectedLength: number, label: string): bigint {
  assertBytes(bytes, label);
  if (bytes.length !== expectedLength) throw new Error(`${label} must be ${expectedLength} bytes`);
  const padded = new Uint8Array(32);
  padded.set(bytes, 32 - bytes.length);
  return bytesToBn254Scalar(padded);
}

function assertNonemptyFields(fields: readonly bigint[], label: string): void {
  if (!Array.isArray(fields) || fields.length === 0) {
    throw new Error(`${label} requires at least one field element`);
  }
}

function assertBytes(value: unknown, label: string): asserts value is Uint8Array {
  if (!(value instanceof Uint8Array)) throw new Error(`${label} must be a Uint8Array`);
}

function poseidon2Bn254MerkleRoot(
  hashes: Uint8Array[],
  implementation?: Poseidon2Bn254Implementation,
): Uint8Array {
  if (hashes.length === 1) return hashes[0]!.slice();
  const k = splitPoint(hashes.length);
  const left = poseidon2Bn254MerkleRoot(hashes.slice(0, k), implementation);
  const right = poseidon2Bn254MerkleRoot(hashes.slice(k), implementation);
  return commitPoseidon2Bn254FieldElements({
    domain: POSEIDON2_BN254_VAULT_TREE_NODE_DOMAIN,
    inputs: [bytesToBn254Scalar(left), bytesToBn254Scalar(right)],
    implementation,
  });
}

function splitPoint(n: number): number {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}
