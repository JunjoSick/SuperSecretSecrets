import { sha256 } from '@noble/hashes/sha2.js';
import { describe, expect, it } from 'vitest';
import {
  CURVE_BLS12_381,
  CURVE_BN254,
  HALO2_ARTIFACT_SCHEMA,
  HALO2_ARTIFACT_SERDE_FORMAT_PROCESSED,
  HALO2_ARTIFACT_SRS_SOURCE_DETERMINISTIC_DEV,
  HALO2_ARTIFACT_SRS_SOURCE_EXTERNAL,
  HALO2_VAULT_ROOT_PUBLIC_INSTANCES,
  HALO2_VERIFIER_ARTIFACT_DIGEST_DOMAIN,
  PCS_IPA,
  PCS_KZG,
  PROOF_ARTIFACT_DIGEST,
  digestHalo2ArtifactMetadata,
  encodeHalo2ArtifactMetadata,
  loadHalo2ProverArtifactBundle,
  parseHalo2ArtifactManifest,
  type Halo2ArtifactMetadata,
  type Halo2ArtifactManifest,
} from '../src/crypto/zk/halo2/artifact';
import {
  assertTrustedProofArtifactDigest,
  isTrustedProofArtifactDigest,
} from '../src/crypto/zk/halo2/verifierRegistry';
import {
  DECRYPTION_PROOF_SCHEME_HALO2_KZG,
  RELATION_V1_VAULTROOT_ONLY_DIGEST,
} from '../src/crypto/zk/decryption-proof-relations';

const DOMAIN_LEN = new TextEncoder().encode(HALO2_VERIFIER_ARTIFACT_DIGEST_DOMAIN).length;

describe('Halo2 verifier artifact metadata', () => {
  it('encodes the canonical verifier artifact digest input', () => {
    const encoded = encodeHalo2ArtifactMetadata(sampleMetadata());
    expect(encoded[0]).toBe(0);
    expect(encoded[1]).toBe(DOMAIN_LEN);
    expect(new TextDecoder().decode(encoded.slice(2, 2 + DOMAIN_LEN))).toBe(HALO2_VERIFIER_ARTIFACT_DIGEST_DOMAIN);
    expect(Array.from(encoded.slice(2 + DOMAIN_LEN, 2 + DOMAIN_LEN + 6))).toEqual([
      DECRYPTION_PROOF_SCHEME_HALO2_KZG,
      PCS_KZG,
      CURVE_BN254,
      1,
      2,
      3,
    ]);
    expect(encoded.slice(2 + DOMAIN_LEN + 6, 2 + DOMAIN_LEN + 6 + 32)).toEqual(RELATION_V1_VAULTROOT_ONLY_DIGEST);
    expect(encoded.length).toBe(2 + DOMAIN_LEN + 6 + 32 * 4);
  });

  it('digests deterministically and binds every security-relevant field', () => {
    const base = sampleMetadata();
    const baseDigest = digestHalo2ArtifactMetadata(base);
    expect(baseDigest.length).toBe(32);
    expect(digestHalo2ArtifactMetadata(sampleMetadata())).toEqual(baseDigest);

    const mutations: Array<[string, Halo2ArtifactMetadata]> = [
      ['scheme', { ...base, schemeId: 0x02 }],
      ['pcs', { ...base, pcsId: PCS_IPA }],
      ['curve', { ...base, curveId: CURVE_BLS12_381 }],
      ['major', { ...base, circuitVersionMajor: 2 }],
      ['minor', { ...base, circuitVersionMinor: 3 }],
      ['patch', { ...base, circuitVersionPatch: 4 }],
      ['relation', { ...base, relationDigest: bytes(32, 99) }],
      ['setup', { ...base, trustedSetupIdDigest: bytes(32, 100) }],
      ['wasm', { ...base, wasmBuildHash: bytes(32, 101) }],
      ['vk', { ...base, verifyingKeyHash: bytes(32, 102) }],
    ];
    for (const [name, metadata] of mutations) {
      expect(digestHalo2ArtifactMetadata(metadata), name).not.toEqual(baseDigest);
    }
  });

  it('rejects non-byte numeric ids and non-32-byte digests', () => {
    expect(() => encodeHalo2ArtifactMetadata({ ...sampleMetadata(), schemeId: 256 })).toThrow(/scheme id/);
    expect(() => encodeHalo2ArtifactMetadata({ ...sampleMetadata(), pcsId: -1 })).toThrow(/PCS id/);
    expect(() => encodeHalo2ArtifactMetadata({ ...sampleMetadata(), curveId: 1.5 })).toThrow(/curve id/);
    expect(() => encodeHalo2ArtifactMetadata({ ...sampleMetadata(), circuitVersionPatch: 256 })).toThrow(
      /patch version/,
    );
    expect(() => encodeHalo2ArtifactMetadata({ ...sampleMetadata(), relationDigest: bytes(31, 1) })).toThrow(
      /relation digest/,
    );
    expect(() =>
      encodeHalo2ArtifactMetadata({ ...sampleMetadata(), trustedSetupIdDigest: bytes(31, 1) }),
    ).toThrow(/trusted setup/);
    expect(() => encodeHalo2ArtifactMetadata({ ...sampleMetadata(), wasmBuildHash: bytes(31, 1) })).toThrow(
      /WASM build/,
    );
    expect(() => encodeHalo2ArtifactMetadata({ ...sampleMetadata(), verifyingKeyHash: bytes(31, 1) })).toThrow(
      /verifying key/,
    );
  });

  it('loads generated artifact manifests and gates deterministic development SRS bundles', () => {
    const bundle = sampleManifestBundle(HALO2_ARTIFACT_SRS_SOURCE_DETERMINISTIC_DEV);

    expect(() =>
      loadHalo2ProverArtifactBundle({
        manifest: JSON.stringify(bundle.manifest),
        files: bundle.files,
      }),
    ).toThrow(/deterministic development SRS/);

    const loaded = loadHalo2ProverArtifactBundle({
      manifest: bundle.manifest,
      files: bundle.files,
      allowDevelopmentSrs: true,
    });
    expect(loaded.metadata).toEqual(bundle.metadata);
    expect(loaded.srsBytes).toEqual(bundle.files['srs.bin']);
    expect(loaded.provingKeyBytes).toEqual(bundle.files['pk.bin']);
    expect(loaded.verifyingKeyBytes).toEqual(bundle.files['vk.bin']);
    expect(loaded.provingKeyHash).toEqual(sha256(bundle.files['pk.bin']!));

    expect(() =>
      loadHalo2ProverArtifactBundle({
        manifest: bundle.manifest,
        files: { ...bundle.files, 'vk.bin': bytes(32, 250) },
        allowDevelopmentSrs: true,
      }),
    ).toThrow(/verifying key hash/);

    expect(() =>
      parseHalo2ArtifactManifest({
        ...bundle.manifest,
        circuit: { ...bundle.manifest.circuit, publicInstances: ['bundleId', 'plaintextCommitment'] },
      }),
    ).toThrow(/public instance layout/);

    const external = sampleManifestBundle(HALO2_ARTIFACT_SRS_SOURCE_EXTERNAL);
    expect(() =>
      loadHalo2ProverArtifactBundle({
        manifest: parseHalo2ArtifactManifest(external.manifest),
        files: external.files,
      }),
    ).not.toThrow();
  });

  it('does not trust placeholder or unknown production proof artifact digests', () => {
    expect(PROOF_ARTIFACT_DIGEST).toEqual(new Uint8Array(32));
    expect(isTrustedProofArtifactDigest(PROOF_ARTIFACT_DIGEST)).toBe(false);
    expect(() => assertTrustedProofArtifactDigest(PROOF_ARTIFACT_DIGEST)).toThrow(/Untrusted/);
    expect(() => assertTrustedProofArtifactDigest(bytes(32, 121))).toThrow(/Untrusted/);
  });
});

function sampleMetadata(): Halo2ArtifactMetadata {
  return {
    schemeId: DECRYPTION_PROOF_SCHEME_HALO2_KZG,
    relationDigest: RELATION_V1_VAULTROOT_ONLY_DIGEST,
    pcsId: PCS_KZG,
    curveId: CURVE_BN254,
    trustedSetupIdDigest: bytes(32, 10),
    circuitVersionMajor: 1,
    circuitVersionMinor: 2,
    circuitVersionPatch: 3,
    wasmBuildHash: bytes(32, 20),
    verifyingKeyHash: bytes(32, 30),
  };
}

function bytes(length: number, seed: number): Uint8Array {
  return Uint8Array.from({ length }, (_, index) => (seed + index) & 0xff);
}

function sampleManifestBundle(srsSource: typeof HALO2_ARTIFACT_SRS_SOURCE_DETERMINISTIC_DEV | typeof HALO2_ARTIFACT_SRS_SOURCE_EXTERNAL): {
  manifest: Halo2ArtifactManifest;
  metadata: Halo2ArtifactMetadata;
  files: Record<string, Uint8Array>;
} {
  const srsBytes = bytes(48, 40);
  const provingKeyBytes = bytes(64, 50);
  const verifyingKeyBytes = bytes(40, 60);
  const wasmBuildBytes = bytes(20, 70);
  const trustedSetupIdBytes = new TextEncoder().encode(
    `sss-v3-halo2-kzg-bn254-srs-v1\nsource=${srsSource}\nk=11\nsrsSha256=${hex(sha256(srsBytes))}\nserde=processed\n`,
  );
  const metadata: Halo2ArtifactMetadata = {
    ...sampleMetadata(),
    trustedSetupIdDigest: sha256(trustedSetupIdBytes),
    wasmBuildHash: sha256(wasmBuildBytes),
    verifyingKeyHash: sha256(verifyingKeyBytes),
  };
  const verifierArtifactDigest = digestHalo2ArtifactMetadata(metadata);
  const manifest: Halo2ArtifactManifest = {
    schema: HALO2_ARTIFACT_SCHEMA,
    relationId: 'sss-v3-vault-root-mlkem768-hkdfsha256-aes256gcm-nopassphrase-v1',
    relationDigest: hex(metadata.relationDigest),
    verifierArtifactDigest: hex(verifierArtifactDigest),
    provingKeyHash: hex(sha256(provingKeyBytes)),
    srsHash: hex(sha256(srsBytes)),
    srsSource,
    serdeFormat: HALO2_ARTIFACT_SERDE_FORMAT_PROCESSED,
    metadata: {
      schemeId: metadata.schemeId,
      relationDigest: hex(metadata.relationDigest),
      pcsId: metadata.pcsId,
      curveId: metadata.curveId,
      trustedSetupIdDigest: hex(metadata.trustedSetupIdDigest),
      circuitVersionMajor: metadata.circuitVersionMajor,
      circuitVersionMinor: metadata.circuitVersionMinor,
      circuitVersionPatch: metadata.circuitVersionPatch,
      wasmBuildHash: hex(metadata.wasmBuildHash),
      verifyingKeyHash: hex(metadata.verifyingKeyHash),
    },
    circuit: {
      name: 'VaultRootCommitmentCircuit',
      k: 11,
      publicInstances: [...HALO2_VAULT_ROOT_PUBLIC_INSTANCES],
      version: '1.2.3',
    },
    files: {
      srs: 'srs.bin',
      provingKey: 'pk.bin',
      verifyingKey: 'vk.bin',
      trustedSetupId: 'trusted-setup-id.txt',
      wasmBuild: 'wasm-build.wasm',
    },
    warnings:
      srsSource === HALO2_ARTIFACT_SRS_SOURCE_DETERMINISTIC_DEV
        ? ['deterministic development SRS; replace before production']
        : [],
  };

  return {
    manifest,
    metadata,
    files: {
      'srs.bin': srsBytes,
      'pk.bin': provingKeyBytes,
      'vk.bin': verifyingKeyBytes,
      'trusted-setup-id.txt': trustedSetupIdBytes,
      'wasm-build.wasm': wasmBuildBytes,
    },
  };
}

function hex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, '0')).join('');
}
