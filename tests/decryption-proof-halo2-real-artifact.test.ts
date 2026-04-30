import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  loadHalo2ProverArtifactBundle,
  parseHalo2ArtifactManifest,
} from '../src/crypto/zk/halo2/artifact';
import {
  halo2VerifierArtifactDigest,
  validateHalo2ProverArtifact,
} from '../src/crypto/zk/halo2/backend';
import {
  RELATION_V1_VAULTROOT_ONLY_DIGEST,
  RELATION_V1_VAULTROOT_ONLY_ID,
} from '../src/crypto/zk/decryption-proof-relations';

const repoRoot = path.resolve(import.meta.dirname, '..');
const rustWorkspace = path.join(repoRoot, 'crates', 'halo2-decryption-proof');

describe('Halo2 real keygen artifact packaging', () => {
  it('loads the generated manifest + pk/vk/srs bundle and gates the dev SRS', () => {
    const outDir = mkdtempSync(path.join(tmpdir(), 'sss-halo2-artifact-'));
    execFileSync(
      'cargo',
      [
        'run',
        '-q',
        '-p',
        'halo2-decryption-proof-keygen',
        '--no-default-features',
        '--features',
        'dev-unsafe-srs',
        '--',
        '--allow-dev-srs',
        '--out',
        outDir,
      ],
      {
        cwd: rustWorkspace,
        stdio: 'pipe',
        timeout: 120_000,
      },
    );

    const manifestText = readFileSync(path.join(outDir, 'artifact-manifest.json'), 'utf8');
    const manifest = parseHalo2ArtifactManifest(manifestText);
    const files = {
      [manifest.files.srs]: readBytes(path.join(outDir, manifest.files.srs)),
      [manifest.files.provingKey]: readBytes(path.join(outDir, manifest.files.provingKey)),
      [manifest.files.verifyingKey]: readBytes(path.join(outDir, manifest.files.verifyingKey)),
      [manifest.files.trustedSetupId]: readBytes(path.join(outDir, manifest.files.trustedSetupId)),
    };

    expect(() =>
      loadHalo2ProverArtifactBundle({
        manifest,
        files,
      }),
    ).toThrow(/deterministic development SRS/);

    const artifact = loadHalo2ProverArtifactBundle({
      manifest,
      files,
      allowDevelopmentSrs: true,
    });
    validateHalo2ProverArtifact(artifact);
    expect(artifact.manifest.relationId).toBe(RELATION_V1_VAULTROOT_ONLY_ID);
    expect(artifact.metadata.relationDigest).toEqual(RELATION_V1_VAULTROOT_ONLY_DIGEST);
    expect(halo2VerifierArtifactDigest(artifact)).toEqual(hexToBytes(manifest.verifierArtifactDigest));
    expect(artifact.provingKeyBytes.length).toBeGreaterThan(artifact.verifyingKeyBytes.length);
    expect(artifact.srsBytes.length).toBeGreaterThan(0);
  });
});

function readBytes(filePath: string): Uint8Array {
  return readFileSync(filePath);
}

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}
