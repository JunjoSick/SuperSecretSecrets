import { describe, expect, it } from 'vitest';
import {
  bn254ScalarToBytes,
  POSEIDON2_BN254_PARAMS_ID,
  POSEIDON2_BN254_UNAVAILABLE_MESSAGE,
  type Poseidon2Bn254Implementation,
} from '../src/crypto/commitments/poseidon2-bn254';
import {
  POSEIDON2_BN254_PLAINTEXT_VAULT_ROOT_COMMITMENT_DOMAIN,
  POSEIDON2_BN254_POLICY_COMMITMENT_DOMAIN,
  POSEIDON2_BN254_VAULT_TREE_LEAF_DOMAIN,
  POSEIDON2_BN254_VAULT_TREE_NODE_DOMAIN,
  POSEIDON2_BN254_VAULT_TREE_ROOT_DOMAIN,
  bindPoseidon2Bn254VaultRootPlaintextCommitment,
  bindPoseidon2Bn254PolicySeedCommitment,
  commitPoseidon2Bn254VaultTreeRoot,
  commitPoseidon2Bn254PolicyFields,
  commitPoseidon2Bn254VaultTreeRootFields,
  splitBytes32ToBn254Limbs128,
} from '../src/crypto/commitments/proof-facing';

describe('proof-facing Poseidon2-BN254 commitments', () => {
  it('binds a vault-root plaintext commitment to bundleId and vaultRootKey limbs', () => {
    const calls: HashCall[] = [];
    const bundleId = Uint8Array.from([1, 2, 3, 4, 5, 6, 7, 8]);
    const vaultRootKey = bytes(32, 0x10);
    const commitment = bindPoseidon2Bn254VaultRootPlaintextCommitment({
      bundleId,
      vaultRootKey,
      implementation: recordingImplementation(42n, calls),
    });

    expect(commitment).toEqual(bn254ScalarToBytes(42n));
    expect(calls).toEqual([
      {
        domain: POSEIDON2_BN254_PLAINTEXT_VAULT_ROOT_COMMITMENT_DOMAIN,
        inputs: [
          0x0102030405060708n,
          bigEndian(vaultRootKey.slice(0, 16)),
          bigEndian(vaultRootKey.slice(16)),
        ],
      },
    ]);
  });

  it('fails closed without a Poseidon2 backend and rejects malformed fixed inputs', () => {
    expect(() =>
      bindPoseidon2Bn254VaultRootPlaintextCommitment({
        bundleId: bytes(8, 1),
        vaultRootKey: bytes(32, 2),
      }),
    ).toThrow(POSEIDON2_BN254_UNAVAILABLE_MESSAGE);
    expect(() =>
      bindPoseidon2Bn254VaultRootPlaintextCommitment({
        bundleId: bytes(7, 1),
        vaultRootKey: bytes(32, 2),
        implementation: recordingImplementation(1n, []),
      }),
    ).toThrow(/bundleId/);
    expect(() =>
      bindPoseidon2Bn254VaultRootPlaintextCommitment({
        bundleId: bytes(8, 1),
        vaultRootKey: bytes(31, 2),
        implementation: recordingImplementation(1n, []),
      }),
    ).toThrow(/vaultRootKey/);
  });

  it('splits bytes32 values into big-endian 128-bit BN254-safe limbs', () => {
    const value = bytes(32, 0);
    const [high128, low128] = splitBytes32ToBn254Limbs128(value);
    expect(high128).toBe(0x000102030405060708090a0b0c0d0e0fn);
    expect(low128).toBe(0x101112131415161718191a1b1c1d1e1fn);
    expect(() => splitBytes32ToBn254Limbs128(bytes(31, 0))).toThrow(/32 bytes/);
  });

  it('keeps policy and vault tree commitments on distinct Poseidon2 domains', () => {
    const calls: HashCall[] = [];
    const implementation = recordingImplementation(7n, calls);
    expect(commitPoseidon2Bn254PolicyFields({ fields: [1n, 2n], implementation })).toEqual(
      bn254ScalarToBytes(7n),
    );
    expect(commitPoseidon2Bn254VaultTreeRootFields({ fields: [3n, 4n], implementation })).toEqual(
      bn254ScalarToBytes(7n),
    );
    expect(calls).toEqual([
      { domain: POSEIDON2_BN254_POLICY_COMMITMENT_DOMAIN, inputs: [1n, 2n] },
      { domain: POSEIDON2_BN254_VAULT_TREE_ROOT_DOMAIN, inputs: [3n, 4n] },
    ]);
    expect(() => commitPoseidon2Bn254PolicyFields({ fields: [], implementation })).toThrow(/at least one/);
    expect(() => commitPoseidon2Bn254VaultTreeRootFields({ fields: [], implementation })).toThrow(
      /at least one/,
    );
  });

  it('binds the proof-facing policy commitment to the 64-byte KEM seed', () => {
    const calls: HashCall[] = [];
    const kemSeed = bytes(64, 0x20);
    const commitment = bindPoseidon2Bn254PolicySeedCommitment({
      kemSeed,
      implementation: recordingImplementation(9n, calls),
    });
    expect(commitment).toEqual(bn254ScalarToBytes(9n));
    expect(calls).toEqual([
      {
        domain: POSEIDON2_BN254_POLICY_COMMITMENT_DOMAIN,
        inputs: [
          bigEndian(kemSeed.slice(0, 16)),
          bigEndian(kemSeed.slice(16, 32)),
          bigEndian(kemSeed.slice(32, 48)),
          bigEndian(kemSeed.slice(48, 64)),
        ],
      },
    ]);
    expect(() =>
      bindPoseidon2Bn254PolicySeedCommitment({
        kemSeed: bytes(63, 0),
        implementation: recordingImplementation(1n, []),
      }),
    ).toThrow(/64 bytes/);
  });

  it('builds a Poseidon2 vault tree without SHA leaf hashing', () => {
    const calls: HashCall[] = [];
    const root = commitPoseidon2Bn254VaultTreeRoot({
      entries: [
        { id: 'one', name: 'one.txt', contentType: 'text/plain', data: Uint8Array.from([1, 2, 3]) },
        { id: 'two', name: 'two.txt', data: Uint8Array.from([4, 5]) },
      ],
      implementation: recordingImplementation(5n, calls),
    });
    expect(root).toEqual(bn254ScalarToBytes(5n));
    expect(calls.map((call) => call.domain)).toEqual([
      POSEIDON2_BN254_VAULT_TREE_LEAF_DOMAIN,
      POSEIDON2_BN254_VAULT_TREE_LEAF_DOMAIN,
      POSEIDON2_BN254_VAULT_TREE_NODE_DOMAIN,
    ]);
    expect(calls[0]!.inputs.slice(0, 2)).toEqual([3n, bigEndian(new TextEncoder().encode('one'))]);
    expect(calls[0]!.inputs.at(-2)).toBe(3n);
    expect(calls[0]!.inputs.at(-1)).toBe(0x010203n);
    expect(calls[2]!.inputs).toEqual([5n, 5n]);
    expect(() => commitPoseidon2Bn254VaultTreeRoot({ entries: [], implementation: recordingImplementation(1n, []) })).toThrow(
      /at least one/,
    );
  });
});

type HashCall = {
  domain: string;
  inputs: bigint[];
};

function recordingImplementation(output: bigint, calls: HashCall[]): Poseidon2Bn254Implementation {
  return {
    paramsId: POSEIDON2_BN254_PARAMS_ID,
    vectorManifestDigest: bytes(32, 0xa0),
    hash(inputs, domain) {
      calls.push({ domain, inputs: [...inputs] });
      return output;
    },
  };
}

function bytes(length: number, seed: number): Uint8Array {
  return Uint8Array.from({ length }, (_, index) => (seed + index) & 0xff);
}

function bigEndian(value: Uint8Array): bigint {
  let out = 0n;
  for (const byte of value) out = (out << 8n) | BigInt(byte);
  return out;
}
