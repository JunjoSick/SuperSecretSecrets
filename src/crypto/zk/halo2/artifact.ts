import { sha256 } from '@noble/hashes/sha2.js';
import { DECRYPTION_PROOF_DIGEST_BYTES } from '../decryption-proof-relations';

export const HALO2_VERIFIER_ARTIFACT_DIGEST_DOMAIN =
  'SSS/v3/decryption-proof/verifier-artifact/v1';
export const HALO2_ARTIFACT_SCHEMA = 'sss-v3-halo2-artifact-v1';
export const HALO2_ARTIFACT_SERDE_FORMAT_PROCESSED = 'processed';
export const HALO2_ARTIFACT_SRS_SOURCE_DETERMINISTIC_DEV = 'deterministic-dev';
export const HALO2_ARTIFACT_SRS_SOURCE_EXTERNAL = 'external';

export const PCS_KZG = 0x01;
export const PCS_IPA = 0x02;

export const CURVE_BN254 = 0x01;
export const CURVE_BLS12_381 = 0x02;
export const CURVE_PALLAS_VESTA = 0x03;

export type Halo2ArtifactMetadata = {
  schemeId: number;
  relationDigest: Uint8Array;

  pcsId: number;
  curveId: number;
  trustedSetupIdDigest: Uint8Array;
  circuitVersionMajor: number;
  circuitVersionMinor: number;
  circuitVersionPatch: number;
  wasmBuildHash: Uint8Array;
  verifyingKeyHash: Uint8Array;
};

export type Halo2ArtifactManifest = {
  schema: typeof HALO2_ARTIFACT_SCHEMA;
  relationId: string;
  relationDigest: string;
  verifierArtifactDigest: string;
  provingKeyHash: string;
  srsHash: string;
  srsSource?: typeof HALO2_ARTIFACT_SRS_SOURCE_DETERMINISTIC_DEV | typeof HALO2_ARTIFACT_SRS_SOURCE_EXTERNAL;
  serdeFormat: typeof HALO2_ARTIFACT_SERDE_FORMAT_PROCESSED;
  metadata: {
    schemeId: number;
    relationDigest: string;
    pcsId: number;
    curveId: number;
    trustedSetupIdDigest: string;
    circuitVersionMajor: number;
    circuitVersionMinor: number;
    circuitVersionPatch: number;
    wasmBuildHash: string;
    verifyingKeyHash: string;
  };
  circuit: {
    name: string;
    k: number;
    publicInstances: string[];
    version: string;
  };
  files: {
    srs: string;
    provingKey: string;
    verifyingKey: string;
    trustedSetupId: string;
    wasmBuild?: string | null;
  };
  warnings: string[];
};

export type Halo2ArtifactFileMap = Record<string, Uint8Array>;

export type LoadedHalo2VerifierArtifactBundle = {
  manifest: Halo2ArtifactManifest;
  metadata: Halo2ArtifactMetadata;
  srsBytes: Uint8Array;
  srsHash: Uint8Array;
  verifyingKeyBytes: Uint8Array;
  trustedSetupIdBytes: Uint8Array;
  wasmBuildBytes?: Uint8Array;
};

export type LoadedHalo2ProverArtifactBundle = LoadedHalo2VerifierArtifactBundle & {
  provingKeyBytes: Uint8Array;
  provingKeyHash: Uint8Array;
};

export type LoadHalo2ArtifactBundleArgs = {
  manifest: unknown;
  files: Halo2ArtifactFileMap;
  allowDevelopmentSrs?: boolean;
};

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();
const DOMAIN_BYTES = textEncoder.encode(HALO2_VERIFIER_ARTIFACT_DIGEST_DOMAIN);

export function encodeHalo2ArtifactMetadata(metadata: Halo2ArtifactMetadata): Uint8Array {
  validateHalo2ArtifactMetadata(metadata);
  return concat(
    u16LengthPrefixed(DOMAIN_BYTES),
    new Uint8Array([
      metadata.schemeId,
      metadata.pcsId,
      metadata.curveId,
      metadata.circuitVersionMajor,
      metadata.circuitVersionMinor,
      metadata.circuitVersionPatch,
    ]),
    metadata.relationDigest,
    metadata.trustedSetupIdDigest,
    metadata.wasmBuildHash,
    metadata.verifyingKeyHash,
  );
}

export function digestHalo2ArtifactMetadata(metadata: Halo2ArtifactMetadata): Uint8Array {
  return sha256(encodeHalo2ArtifactMetadata(metadata));
}

export function parseHalo2ArtifactManifest(input: unknown): Halo2ArtifactManifest {
  const value = typeof input === 'string' ? JSON.parse(input) as unknown : input;
  const obj = asRecord(value, 'Halo2 artifact manifest');
  const metadata = asRecord(obj.metadata, 'Halo2 artifact manifest metadata');
  const circuit = asRecord(obj.circuit, 'Halo2 artifact manifest circuit');
  const files = asRecord(obj.files, 'Halo2 artifact manifest files');
  const publicInstances = readStringArray(circuit, 'publicInstances');
  const warnings = obj.warnings === undefined ? [] : readStringArray(obj, 'warnings');
  const srsSource = readOptionalString(obj, 'srsSource');
  if (
    srsSource !== undefined &&
    srsSource !== HALO2_ARTIFACT_SRS_SOURCE_DETERMINISTIC_DEV &&
    srsSource !== HALO2_ARTIFACT_SRS_SOURCE_EXTERNAL
  ) {
    throw new Error('Halo2 artifact manifest srsSource is not supported');
  }

  const manifest: Halo2ArtifactManifest = {
    schema: readString(obj, 'schema') as typeof HALO2_ARTIFACT_SCHEMA,
    relationId: readString(obj, 'relationId'),
    relationDigest: readDigestHex(obj, 'relationDigest'),
    verifierArtifactDigest: readDigestHex(obj, 'verifierArtifactDigest'),
    provingKeyHash: readDigestHex(obj, 'provingKeyHash'),
    srsHash: readDigestHex(obj, 'srsHash'),
    ...(srsSource === undefined ? {} : { srsSource }),
    serdeFormat: readString(obj, 'serdeFormat') as typeof HALO2_ARTIFACT_SERDE_FORMAT_PROCESSED,
    metadata: {
      schemeId: readU8Property(metadata, 'schemeId'),
      relationDigest: readDigestHex(metadata, 'relationDigest'),
      pcsId: readU8Property(metadata, 'pcsId'),
      curveId: readU8Property(metadata, 'curveId'),
      trustedSetupIdDigest: readDigestHex(metadata, 'trustedSetupIdDigest'),
      circuitVersionMajor: readU8Property(metadata, 'circuitVersionMajor'),
      circuitVersionMinor: readU8Property(metadata, 'circuitVersionMinor'),
      circuitVersionPatch: readU8Property(metadata, 'circuitVersionPatch'),
      wasmBuildHash: readDigestHex(metadata, 'wasmBuildHash'),
      verifyingKeyHash: readDigestHex(metadata, 'verifyingKeyHash'),
    },
    circuit: {
      name: readString(circuit, 'name'),
      k: readNonnegativeInteger(circuit, 'k'),
      publicInstances,
      version: readString(circuit, 'version'),
    },
    files: {
      srs: readString(files, 'srs'),
      provingKey: readString(files, 'provingKey'),
      verifyingKey: readString(files, 'verifyingKey'),
      trustedSetupId: readString(files, 'trustedSetupId'),
      wasmBuild: readNullableString(files, 'wasmBuild'),
    },
    warnings,
  };

  if (manifest.schema !== HALO2_ARTIFACT_SCHEMA) {
    throw new Error('Halo2 artifact manifest schema is not supported');
  }
  if (manifest.serdeFormat !== HALO2_ARTIFACT_SERDE_FORMAT_PROCESSED) {
    throw new Error('Halo2 artifact manifest serde format is not supported');
  }
  if (manifest.metadata.relationDigest !== manifest.relationDigest) {
    throw new Error('Halo2 artifact manifest relation digest mismatch');
  }
  if (manifest.circuit.publicInstances.length !== 2) {
    throw new Error('Halo2 artifact manifest must declare two public instances');
  }
  return manifest;
}

export function loadHalo2VerifierArtifactBundle(
  args: LoadHalo2ArtifactBundleArgs,
): LoadedHalo2VerifierArtifactBundle {
  const manifest = parseHalo2ArtifactManifest(args.manifest);
  const metadata = metadataFromManifest(manifest);
  validateHalo2ArtifactMetadata(metadata);

  const srsBytes = readFileBytes(args.files, manifest.files.srs);
  const verifyingKeyBytes = readFileBytes(args.files, manifest.files.verifyingKey);
  const trustedSetupIdBytes = readFileBytes(args.files, manifest.files.trustedSetupId);
  const wasmBuildBytes = manifest.files.wasmBuild ? readFileBytes(args.files, manifest.files.wasmBuild) : undefined;

  const srsHash = hexToBytes(manifest.srsHash);
  const verifierArtifactDigest = hexToBytes(manifest.verifierArtifactDigest);
  assertBytesDigest(srsBytes, srsHash, 'Halo2 SRS hash');
  assertBytesDigest(verifyingKeyBytes, metadata.verifyingKeyHash, 'Halo2 verifying key hash');
  assertBytesDigest(trustedSetupIdBytes, metadata.trustedSetupIdDigest, 'Halo2 trusted setup id digest');
  assertBytesDigest(wasmBuildBytes ?? new Uint8Array(0), metadata.wasmBuildHash, 'Halo2 WASM build hash');
  if (!constantTimeEqual(digestHalo2ArtifactMetadata(metadata), verifierArtifactDigest)) {
    throw new Error('Halo2 verifier artifact digest mismatch');
  }
  enforceDevelopmentSrsGate(manifest, trustedSetupIdBytes, args.allowDevelopmentSrs === true);

  return {
    manifest,
    metadata,
    srsBytes,
    srsHash,
    verifyingKeyBytes,
    trustedSetupIdBytes,
    ...(wasmBuildBytes ? { wasmBuildBytes } : {}),
  };
}

export function loadHalo2ProverArtifactBundle(
  args: LoadHalo2ArtifactBundleArgs,
): LoadedHalo2ProverArtifactBundle {
  const verifierBundle = loadHalo2VerifierArtifactBundle(args);
  const provingKeyBytes = readFileBytes(args.files, verifierBundle.manifest.files.provingKey);
  const provingKeyHash = hexToBytes(verifierBundle.manifest.provingKeyHash);
  assertBytesDigest(provingKeyBytes, provingKeyHash, 'Halo2 proving key hash');
  return {
    ...verifierBundle,
    provingKeyBytes,
    provingKeyHash,
  };
}

export function validateHalo2ArtifactMetadata(metadata: Halo2ArtifactMetadata): void {
  assertU8(metadata.schemeId, 'Halo2 scheme id');
  assertU8(metadata.pcsId, 'Halo2 PCS id');
  assertU8(metadata.curveId, 'Halo2 curve id');
  assertU8(metadata.circuitVersionMajor, 'Halo2 circuit major version');
  assertU8(metadata.circuitVersionMinor, 'Halo2 circuit minor version');
  assertU8(metadata.circuitVersionPatch, 'Halo2 circuit patch version');
  assertDigest(metadata.relationDigest, 'Halo2 relation digest');
  assertDigest(metadata.trustedSetupIdDigest, 'Halo2 trusted setup id digest');
  assertDigest(metadata.wasmBuildHash, 'Halo2 WASM build hash');
  assertDigest(metadata.verifyingKeyHash, 'Halo2 verifying key hash');
}

function assertU8(value: number, label: string): void {
  if (!Number.isInteger(value) || value < 0 || value > 0xff) {
    throw new Error(`${label} must be one byte`);
  }
}

function assertDigest(value: Uint8Array, label: string): void {
  if (!(value instanceof Uint8Array) || value.length !== DECRYPTION_PROOF_DIGEST_BYTES) {
    throw new Error(`${label} must be 32 bytes`);
  }
}

function metadataFromManifest(manifest: Halo2ArtifactManifest): Halo2ArtifactMetadata {
  return {
    schemeId: manifest.metadata.schemeId,
    relationDigest: hexToBytes(manifest.metadata.relationDigest),
    pcsId: manifest.metadata.pcsId,
    curveId: manifest.metadata.curveId,
    trustedSetupIdDigest: hexToBytes(manifest.metadata.trustedSetupIdDigest),
    circuitVersionMajor: manifest.metadata.circuitVersionMajor,
    circuitVersionMinor: manifest.metadata.circuitVersionMinor,
    circuitVersionPatch: manifest.metadata.circuitVersionPatch,
    wasmBuildHash: hexToBytes(manifest.metadata.wasmBuildHash),
    verifyingKeyHash: hexToBytes(manifest.metadata.verifyingKeyHash),
  };
}

function enforceDevelopmentSrsGate(
  manifest: Halo2ArtifactManifest,
  trustedSetupIdBytes: Uint8Array,
  allowDevelopmentSrs: boolean,
): void {
  const trustedSetupId = textDecoder.decode(trustedSetupIdBytes);
  const trustedSetupSource = trustedSetupId.match(/(?:^|\n)source=([^\n]+)/)?.[1];
  if (manifest.srsSource && trustedSetupSource && trustedSetupSource !== manifest.srsSource) {
    throw new Error('Halo2 artifact manifest SRS source does not match trusted setup id');
  }

  const isDevelopmentSrs =
    manifest.srsSource === HALO2_ARTIFACT_SRS_SOURCE_DETERMINISTIC_DEV ||
    trustedSetupSource === HALO2_ARTIFACT_SRS_SOURCE_DETERMINISTIC_DEV ||
    manifest.warnings.some((warning) => /deterministic development SRS/i.test(warning));
  if (isDevelopmentSrs && !allowDevelopmentSrs) {
    throw new Error('Halo2 artifact uses a deterministic development SRS; pass allowDevelopmentSrs only for tests');
  }
}

function assertBytesDigest(bytes: Uint8Array, expectedDigest: Uint8Array, label: string): void {
  if (!constantTimeEqual(sha256(bytes), expectedDigest)) throw new Error(`${label} mismatch`);
}

function readFileBytes(files: Halo2ArtifactFileMap, path: string): Uint8Array {
  const bytes = files[path];
  if (!(bytes instanceof Uint8Array) || bytes.length === 0) {
    throw new Error(`Halo2 artifact file ${path} is missing or empty`);
  }
  return bytes.slice();
}

function readDigestHex(record: Record<string, unknown>, key: string): string {
  const value = readString(record, key).toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(value)) throw new Error(`Halo2 artifact manifest ${key} must be 32-byte hex`);
  return value;
}

function hexToBytes(hex: string): Uint8Array {
  if (!/^[0-9a-f]{64}$/i.test(hex)) throw new Error('Halo2 artifact digest hex must be 32 bytes');
  const out = new Uint8Array(32);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function asRecord(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function readString(record: Record<string, unknown>, key: string): string {
  const value = record[key];
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error(`Halo2 artifact manifest ${key} must be a nonempty string`);
  }
  return value;
}

function readOptionalString(record: Record<string, unknown>, key: string): string | undefined {
  const value = record[key];
  if (value === undefined) return undefined;
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error(`Halo2 artifact manifest ${key} must be a nonempty string`);
  }
  return value;
}

function readNullableString(record: Record<string, unknown>, key: string): string | null | undefined {
  const value = record[key];
  if (value === undefined || value === null) return value;
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error(`Halo2 artifact manifest ${key} must be a nonempty string or null`);
  }
  return value;
}

function readStringArray(record: Record<string, unknown>, key: string): string[] {
  const value = record[key];
  if (!Array.isArray(value) || value.some((item) => typeof item !== 'string')) {
    throw new Error(`Halo2 artifact manifest ${key} must be a string array`);
  }
  return value.slice() as string[];
}

function readU8Property(record: Record<string, unknown>, key: string): number {
  const value = readNonnegativeInteger(record, key);
  if (value > 0xff) throw new Error(`Halo2 artifact manifest ${key} must be one byte`);
  return value;
}

function readNonnegativeInteger(record: Record<string, unknown>, key: string): number {
  const value = record[key];
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 0) {
    throw new Error(`Halo2 artifact manifest ${key} must be a nonnegative integer`);
  }
  return value;
}

function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

function u16LengthPrefixed(bytes: Uint8Array): Uint8Array {
  if (bytes.length > 0xffff) throw new Error('Halo2 artifact digest domain too long');
  const out = new Uint8Array(2 + bytes.length);
  out[0] = (bytes.length >>> 8) & 0xff;
  out[1] = bytes.length & 0xff;
  out.set(bytes, 2);
  return out;
}

function concat(...chunks: Uint8Array[]): Uint8Array {
  const len = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const out = new Uint8Array(len);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}
