import { describe, expect, it } from 'vitest';
import {
  encodeHeaderChunkV3,
  encodeShareV3,
  KIND_HEADER,
  KIND_SHARE,
  makeTlv,
  parse,
  TLV_PLAINTEXT_COMMITMENT,
  TLV_POLICY_COMMITMENT,
  TLV_SHARE_COMMIT_PROOF,
  TLV_VAULT_TREE_ROOT,
  TLV_VDF_LOCK,
  TLV_VDF_PARAMS,
  TLV_VDF_PROOF,
  TLV_DECRYPTION_PROOF,
  VERSION_V3,
} from '../src/crypto/codec';
import { commitPolicyManifest, verifyPolicyManifestCommitment } from '../src/crypto/zk/manifest';
import {
  bindPlaintextCommitment,
  clearDecryptionProofVerifiers,
  createDecryptionProofEnvelope,
  decodeDecryptionProofEnvelope,
  DECRYPTION_PROOF_RELATION_AEAD_KEM_SHA256_V1,
  DECRYPTION_PROOF_SCHEME_REGISTERED_BACKEND,
  decryptionProofTranscript,
  encodeDecryptionProofEnvelope,
  registerDecryptionProofVerifier,
  verifyDecryptionProofEnvelope,
  verifyDecryptionProofEnvelopeAsync,
  verifyPlaintextCommitment,
} from '../src/crypto/zk/decryption-proof';
import { proveVaultEntry, vaultTreeRoot, verifyVaultEntry } from '../src/crypto/zk/vault-tree';
import {
  decodeVdfTimeLockInfo,
  encodeVdfTimeLockInfo,
  VDF_TIMELOCK_SECURITY_NOTICE,
} from '../src/crypto/timelock';
import type { PolicyManifest } from '../src/crypto/policy';
import type { VaultEntry } from '../src/crypto/vault';

const utf8 = (s: string) => new TextEncoder().encode(s);

describe('v3 codec wire format', () => {
  const baseHeader = {
    bundleId: new Uint8Array(8).fill(7),
    kemAlg: 'ml-kem-768' as const,
    aeadAlg: 'aes-256-gcm' as const,
    kdfAlg: 'hkdf-sha256' as const,
    flags: { passphrase: false },
    argon2: { tCost: 3, memLog2KiB: 16, parallelism: 1 },
    t: 3,
    n: 5,
    chunkIdx: 0,
    chunkTotal: 1,
    payload: utf8('payload'),
  };

  it('encodeHeaderChunkV3 stamps version byte = 3', () => {
    const raw = encodeHeaderChunkV3(baseHeader);
    expect(raw[4]).toBe(VERSION_V3);
    const parsed = parse(raw);
    expect(parsed.version).toBe(VERSION_V3);
    expect(parsed.kind).toBe(KIND_HEADER);
  });

  it('encodeShareV3 stamps version byte = 3', () => {
    const raw = encodeShareV3({
      bundleId: baseHeader.bundleId,
      kemAlg: 'ml-kem-768',
      t: 3,
      n: 5,
      shareIdx: 1,
      share: utf8('share'),
    });
    expect(raw[4]).toBe(VERSION_V3);
    const parsed = parse(raw);
    expect(parsed.version).toBe(VERSION_V3);
    expect(parsed.kind).toBe(KIND_SHARE);
  });

  it('parses all eight new critical TLV tags as known', () => {
    const tlvs = [
      makeTlv(TLV_POLICY_COMMITMENT, new Uint8Array(32), true),
      makeTlv(TLV_PLAINTEXT_COMMITMENT, new Uint8Array(32), true),
      makeTlv(TLV_VAULT_TREE_ROOT, new Uint8Array(32), true),
      makeTlv(TLV_VDF_PARAMS, utf8('vdf-params'), true),
      makeTlv(TLV_VDF_PROOF, utf8('vdf-proof'), true),
      makeTlv(TLV_DECRYPTION_PROOF, utf8('dec-proof'), false),
    ];
    const raw = encodeHeaderChunkV3({ ...baseHeader, extensions: tlvs });
    const parsed = parse(raw);
    if (parsed.kind !== KIND_HEADER) throw new Error('expected header');
    expect(parsed.extensions).toHaveLength(6);
    expect(parsed.warnings ?? []).toHaveLength(0);
  });

  it('parses share-level VDF lock and share-commit-proof TLVs', () => {
    const raw = encodeShareV3({
      bundleId: baseHeader.bundleId,
      kemAlg: 'ml-kem-768',
      t: 3,
      n: 5,
      shareIdx: 0,
      share: utf8('locked'),
      extensions: [
        makeTlv(TLV_SHARE_COMMIT_PROOF, new Uint8Array(128), true),
        makeTlv(TLV_VDF_LOCK, utf8('vdf-lock'), true),
      ],
    });
    const parsed = parse(raw);
    if (parsed.kind !== KIND_SHARE) throw new Error('expected share');
    expect(parsed.extensions).toHaveLength(2);
  });

  it('still decodes existing v2 shares (back-compat)', () => {
    const v2 = new Uint8Array([
      0x53, 0x53, 0x53, 0x32, 0x02, 0x02, // SSS2 v2 share
      ...Array(8).fill(7), // bundleId
      1, 2, 5, 0, // kem, t, n, shareIdx
      0, 0, // ext len = 0
      0, 5, // share len = 5
      ...Array(5).fill(0xab),
    ]);
    const parsed = parse(v2);
    if (parsed.kind !== KIND_SHARE) throw new Error('expected share');
    expect(parsed.version).toBe(2);
  });
});

describe('zk/manifest: policy-manifest Merkle commitment', () => {
  const manifest: PolicyManifest = {
    version: 2,
    kind: 'flat',
    rootNodeId: 'root',
    threshold: 2,
    totalPoints: 3,
    custodians: [
      { id: 'a', shareIdx: 1, weight: 1 },
      { id: 'b', shareIdx: 2, weight: 1 },
      { id: 'c', shareIdx: 3, weight: 1 },
    ],
    nodes: {
      root: { id: 'root', type: 'THRESHOLD', threshold: 2, children: ['a', 'b', 'c'] },
      a: { id: 'a', type: 'LEAF', custodianId: 'a' },
      b: { id: 'b', type: 'LEAF', custodianId: 'b' },
      c: { id: 'c', type: 'LEAF', custodianId: 'c' },
    },
  };

  it('produces a 32-byte deterministic root', () => {
    const r1 = commitPolicyManifest(manifest);
    const r2 = commitPolicyManifest(manifest);
    expect(r1.length).toBe(32);
    expect(r1).toEqual(r2);
  });

  it('verifyPolicyManifestCommitment accepts the matching root', () => {
    const root = commitPolicyManifest(manifest);
    expect(verifyPolicyManifestCommitment(manifest, root)).toBe(true);
  });

  it('rejects a tampered manifest (changed threshold)', () => {
    const root = commitPolicyManifest(manifest);
    const tampered: PolicyManifest = {
      ...manifest,
      threshold: 3,
      nodes: {
        ...manifest.nodes,
        root: { id: 'root', type: 'THRESHOLD', threshold: 3, children: ['a', 'b', 'c'] },
      },
    };
    expect(verifyPolicyManifestCommitment(tampered, root)).toBe(false);
  });

  it('rejects a tampered manifest (added custodian)', () => {
    const root = commitPolicyManifest(manifest);
    const tampered: PolicyManifest = {
      ...manifest,
      custodians: [...manifest.custodians, { id: 'd', shareIdx: 4, weight: 1 }],
    };
    expect(verifyPolicyManifestCommitment(tampered, root)).toBe(false);
  });

  it('rejects a tampered root', () => {
    const root = commitPolicyManifest(manifest);
    const tampered = root.slice();
    tampered[0]! ^= 0xff;
    expect(verifyPolicyManifestCommitment(manifest, tampered)).toBe(false);
  });
});

describe('zk/decryption-proof: plaintext commitment', () => {
  const bundleId = utf8('bundleId');
  const plaintext = utf8('hello world');
  const verifierDigest = new Uint8Array(32).fill(0x42);

  it('binds and verifies plaintext', () => {
    const c = bindPlaintextCommitment(bundleId, plaintext);
    expect(c.length).toBe(32);
    expect(verifyPlaintextCommitment(c, bundleId, plaintext)).toBe(true);
  });

  it('rejects modified plaintext', () => {
    const c = bindPlaintextCommitment(bundleId, plaintext);
    expect(verifyPlaintextCommitment(c, bundleId, utf8('hello WORLD'))).toBe(false);
  });

  it('rejects modified bundleId', () => {
    const c = bindPlaintextCommitment(bundleId, plaintext);
    expect(verifyPlaintextCommitment(c, utf8('different'), plaintext)).toBe(false);
  });

  it('is deterministic', () => {
    const a = bindPlaintextCommitment(bundleId, plaintext);
    const b = bindPlaintextCommitment(bundleId, plaintext);
    expect(a).toEqual(b);
  });

  it('encodes a fail-closed decryption-proof envelope', () => {
    const ciphertext = utf8('ciphertext bytes');
    const plaintextCommitment = bindPlaintextCommitment(bundleId, plaintext);
    const transcriptDigest = decryptionProofTranscript({
      bundleId,
      payloadKind: 'secret',
      ciphertext,
      plaintextCommitment,
    });
    const raw = encodeDecryptionProofEnvelope(
      createDecryptionProofEnvelope({
        schemeId: DECRYPTION_PROOF_SCHEME_REGISTERED_BACKEND,
        verifierDigest,
        transcriptInput: {
          bundleId,
          payloadKind: 'secret',
          ciphertext,
          plaintextCommitment,
        },
        proof: utf8('future proof bytes'),
      }),
    );
    const decoded = decodeDecryptionProofEnvelope(raw);
    expect(decoded.schemeId).toBe(DECRYPTION_PROOF_SCHEME_REGISTERED_BACKEND);
    expect(decoded.relationDigest).toEqual(DECRYPTION_PROOF_RELATION_AEAD_KEM_SHA256_V1);
    expect(decoded.transcriptDigest).toEqual(transcriptDigest);
    expect(decoded.verifierDigest).toEqual(verifierDigest);
    expect(decoded.proof).toEqual(utf8('future proof bytes'));
    expect(
      verifyDecryptionProofEnvelope(raw, {
        bundleId,
        payloadKind: 'secret',
        ciphertext,
        plaintextCommitment,
      }),
    ).toEqual({ status: 'unsupported', schemeId: DECRYPTION_PROOF_SCHEME_REGISTERED_BACKEND });
  });

  it('rejects decryption-proof envelopes with mismatched transcripts', () => {
    const ciphertext = utf8('ciphertext bytes');
    const plaintextCommitment = bindPlaintextCommitment(bundleId, plaintext);
    const raw = encodeDecryptionProofEnvelope(
      createDecryptionProofEnvelope({
        schemeId: DECRYPTION_PROOF_SCHEME_REGISTERED_BACKEND,
        verifierDigest,
        transcriptInput: {
          bundleId,
          payloadKind: 'secret',
          ciphertext,
          plaintextCommitment,
        },
        proof: utf8('future proof bytes'),
      }),
    );
    const result = verifyDecryptionProofEnvelope(raw, {
      bundleId,
      payloadKind: 'vault-root',
      ciphertext,
      plaintextCommitment,
    });
    expect(result.status).toBe('tampered');
  });

  it('verifies decryption-proof envelopes through a registered verifier', () => {
    clearDecryptionProofVerifiers();
    const ciphertext = utf8('ciphertext bytes');
    const plaintextCommitment = bindPlaintextCommitment(bundleId, plaintext);
    const transcriptInput = {
      bundleId,
      payloadKind: 'secret',
      aeadAlg: 'aes-256-gcm',
      nonce: new Uint8Array(12).fill(0x11),
      ciphertext,
      plaintextCommitment,
    };
    const proof = utf8('backend proof bytes');
    const raw = encodeDecryptionProofEnvelope(
      createDecryptionProofEnvelope({
        schemeId: DECRYPTION_PROOF_SCHEME_REGISTERED_BACKEND,
        verifierDigest,
        transcriptInput,
        proof,
      }),
    );
    let called = false;
    const unregister = registerDecryptionProofVerifier({
      schemeId: DECRYPTION_PROOF_SCHEME_REGISTERED_BACKEND,
      relationDigest: DECRYPTION_PROOF_RELATION_AEAD_KEM_SHA256_V1,
      verifierDigest,
      label: 'test verifier',
      verify: ({ envelope, transcriptDigest }) => {
        called = true;
        expect(envelope.proof).toEqual(proof);
        expect(transcriptDigest).toEqual(decryptionProofTranscript(transcriptInput));
        return true;
      },
    });
    try {
      expect(verifyDecryptionProofEnvelope(raw, transcriptInput)).toEqual({
        status: 'verified',
        schemeId: DECRYPTION_PROOF_SCHEME_REGISTERED_BACKEND,
        label: 'test verifier',
      });
      expect(called).toBe(true);
    } finally {
      unregister();
      clearDecryptionProofVerifiers();
    }
  });

  it('reports verifier rejection without treating the envelope as malformed', () => {
    const ciphertext = utf8('ciphertext bytes');
    const plaintextCommitment = bindPlaintextCommitment(bundleId, plaintext);
    const transcriptInput = {
      bundleId,
      payloadKind: 'secret',
      ciphertext,
      plaintextCommitment,
    };
    const raw = encodeDecryptionProofEnvelope(
      createDecryptionProofEnvelope({
        schemeId: DECRYPTION_PROOF_SCHEME_REGISTERED_BACKEND,
        verifierDigest,
        transcriptInput,
        proof: utf8('bad proof bytes'),
      }),
    );
    const result = verifyDecryptionProofEnvelope(raw, transcriptInput, {
      verifiers: [
        {
          schemeId: DECRYPTION_PROOF_SCHEME_REGISTERED_BACKEND,
          relationDigest: DECRYPTION_PROOF_RELATION_AEAD_KEM_SHA256_V1,
          verifierDigest,
          verify: () => false,
        },
      ],
    });
    expect(result).toEqual({
      status: 'invalid',
      schemeId: DECRYPTION_PROOF_SCHEME_REGISTERED_BACKEND,
      reason: 'verifier rejected proof',
    });
  });

  it('supports async verifier backends without making sync verification unsafe', async () => {
    const ciphertext = utf8('ciphertext bytes');
    const plaintextCommitment = bindPlaintextCommitment(bundleId, plaintext);
    const transcriptInput = {
      bundleId,
      payloadKind: 'secret',
      ciphertext,
      plaintextCommitment,
    };
    const raw = encodeDecryptionProofEnvelope(
      createDecryptionProofEnvelope({
        schemeId: DECRYPTION_PROOF_SCHEME_REGISTERED_BACKEND,
        verifierDigest,
        transcriptInput,
        proof: utf8('async proof bytes'),
      }),
    );
    const verifier = {
      schemeId: DECRYPTION_PROOF_SCHEME_REGISTERED_BACKEND,
      relationDigest: DECRYPTION_PROOF_RELATION_AEAD_KEM_SHA256_V1,
      verifierDigest,
      label: 'async test verifier',
      verify: async () => true,
    };
    expect(verifyDecryptionProofEnvelope(raw, transcriptInput, { verifiers: [verifier] })).toEqual({
      status: 'invalid',
      schemeId: DECRYPTION_PROOF_SCHEME_REGISTERED_BACKEND,
      reason: 'async verifier requires verifyDecryptionProofEnvelopeAsync',
    });
    await expect(verifyDecryptionProofEnvelopeAsync(raw, transcriptInput, { verifiers: [verifier] })).resolves.toEqual({
      status: 'verified',
      schemeId: DECRYPTION_PROOF_SCHEME_REGISTERED_BACKEND,
      label: 'async test verifier',
    });
  });

  it('does not call a verifier when public inputs are tampered', () => {
    const ciphertext = utf8('ciphertext bytes');
    const plaintextCommitment = bindPlaintextCommitment(bundleId, plaintext);
    const raw = encodeDecryptionProofEnvelope(
      createDecryptionProofEnvelope({
        schemeId: DECRYPTION_PROOF_SCHEME_REGISTERED_BACKEND,
        verifierDigest,
        transcriptInput: {
          bundleId,
          payloadKind: 'secret',
          ciphertext,
          plaintextCommitment,
        },
        proof: utf8('future proof bytes'),
      }),
    );
    let called = false;
    const result = verifyDecryptionProofEnvelope(
      raw,
      {
        bundleId,
        payloadKind: 'vault-root',
        ciphertext,
        plaintextCommitment,
      },
      {
        verifiers: [
          {
            schemeId: DECRYPTION_PROOF_SCHEME_REGISTERED_BACKEND,
            relationDigest: DECRYPTION_PROOF_RELATION_AEAD_KEM_SHA256_V1,
            verifierDigest,
            verify: () => {
              called = true;
              return true;
            },
          },
        ],
      },
    );
    expect(result.status).toBe('tampered');
    expect(called).toBe(false);
  });
});

describe('zk/vault-tree: selective vault disclosure', () => {
  const entries: VaultEntry[] = [
    { id: 'e1', name: 'note.txt', data: utf8('note one'), contentType: 'text/plain' },
    { id: 'e2', name: 'pin.txt', data: utf8('123456') },
    { id: 'e3', name: 'photo.jpg', data: utf8('jpeg-bytes') },
    { id: 'e4', name: 'mnemonic.txt', data: utf8('twelve words here') },
  ];

  it('produces a deterministic 32-byte root', () => {
    const r1 = vaultTreeRoot(entries);
    const r2 = vaultTreeRoot(entries);
    expect(r1.length).toBe(32);
    expect(r1).toEqual(r2);
  });

  it('verifies an inclusion proof for each entry', () => {
    const root = vaultTreeRoot(entries);
    for (let i = 0; i < entries.length; i++) {
      const { proof } = proveVaultEntry(entries, i);
      expect(verifyVaultEntry(entries[i]!, proof, root)).toBe(true);
    }
  });

  it('rejects an inclusion proof when the entry data is tampered', () => {
    const root = vaultTreeRoot(entries);
    const { proof } = proveVaultEntry(entries, 1);
    const tampered: VaultEntry = { ...entries[1]!, data: utf8('999999') };
    expect(verifyVaultEntry(tampered, proof, root)).toBe(false);
  });

  it('rejects an inclusion proof when the name is tampered', () => {
    const root = vaultTreeRoot(entries);
    const { proof } = proveVaultEntry(entries, 0);
    const tampered: VaultEntry = { ...entries[0]!, name: 'evil.txt' };
    expect(verifyVaultEntry(tampered, proof, root)).toBe(false);
  });

  it('rejects an inclusion proof against a different root', () => {
    const { proof } = proveVaultEntry(entries, 0);
    const otherRoot = vaultTreeRoot([entries[0]!, entries[1]!]);
    expect(verifyVaultEntry(entries[0]!, proof, otherRoot)).toBe(false);
  });
});

describe('VDF time-lock info encoding', () => {
  const info = {
    scheme: 'wesolowski-classgroup' as const,
    discriminantBits: 256,
    T: 1n << 25n,
    paramsTlvDigest: new Uint8Array(32).fill(0xab),
    security: VDF_TIMELOCK_SECURITY_NOTICE,
  };

  it('round-trips through JSON', () => {
    const enc = encodeVdfTimeLockInfo(info);
    const dec = decodeVdfTimeLockInfo(enc);
    expect(dec.scheme).toBe('wesolowski-classgroup');
    expect(dec.discriminantBits).toBe(256);
    expect(dec.T).toBe(1n << 25n);
    expect(dec.paramsTlvDigest).toEqual(info.paramsTlvDigest);
  });

  it('rejects mismatched scheme', () => {
    const bad = new TextEncoder().encode(JSON.stringify({ scheme: 'fake', T: '0' }));
    expect(() => decodeVdfTimeLockInfo(bad)).toThrow();
  });

  it('rejects negative T', () => {
    expect(() =>
      encodeVdfTimeLockInfo({
        ...info,
        T: -1n,
      }),
    ).toThrow();
  });

  it('rejects wrong-length digest', () => {
    expect(() =>
      encodeVdfTimeLockInfo({
        ...info,
        paramsTlvDigest: new Uint8Array(31),
      }),
    ).toThrow();
  });
});
