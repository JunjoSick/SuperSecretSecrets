import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { deriveKey } from './kdf';

const METADATA_INFO = 'SSS/v2/share-metadata';

export type ShareMetadata = {
  bundleLabel?: string;
  custodianName?: string;
  hint?: string;
  issuedDate?: string;
  authorFingerprint?: string;
};

export type MetadataBinding = {
  bundleId: Uint8Array;
  shareIdx: number;
  componentIds?: string[];
};

export type MetadataVerification =
  | { status: 'none' }
  | { status: 'unverified'; metadata: ShareMetadata }
  | { status: 'verified'; metadata: ShareMetadata }
  | { status: 'tampered'; metadata: ShareMetadata };

const enc = new TextEncoder();
const dec = new TextDecoder();

export function encodeShareMetadata(metadata: ShareMetadata): Uint8Array {
  return enc.encode(canonicalJson(cleanMetadata(metadata)));
}

export function decodeShareMetadata(raw: Uint8Array): ShareMetadata {
  const decoded = JSON.parse(dec.decode(raw)) as unknown;
  if (!isRecord(decoded)) throw new Error('metadata must be a JSON object');
  return cleanMetadata(decoded);
}

export function deriveMetadataKey(kemSeed: Uint8Array, bundleId: Uint8Array): Uint8Array {
  return deriveKey('hkdf-sha256', kemSeed, bundleId, METADATA_INFO, 32);
}

export function metadataMac(
  key: Uint8Array,
  metadata: ShareMetadata,
  binding: MetadataBinding,
): Uint8Array {
  return hmac(sha256, key, metadataMacPayload(metadata, binding));
}

export function verifyMetadataMac(
  key: Uint8Array,
  metadata: ShareMetadata,
  binding: MetadataBinding,
  mac: Uint8Array,
): boolean {
  const expected = metadataMac(key, metadata, binding);
  if (expected.length !== mac.length) return false;
  let diff = 0;
  for (let i = 0; i < expected.length; i++) diff |= expected[i]! ^ mac[i]!;
  return diff === 0;
}

export function canonicalJson(value: unknown): string {
  return JSON.stringify(sortJson(value));
}

function metadataMacPayload(metadata: ShareMetadata, binding: MetadataBinding): Uint8Array {
  const payload = {
    binding: {
      bundleId: hex(binding.bundleId),
      shareIdx: binding.shareIdx,
      componentIds: [...(binding.componentIds ?? [])].sort(),
    },
    metadata: cleanMetadata(metadata),
  };
  return enc.encode(canonicalJson(payload));
}

function cleanMetadata(input: unknown): ShareMetadata {
  if (!isRecord(input)) return {};
  const out: ShareMetadata = {};
  copyString(input, out, 'bundleLabel');
  copyString(input, out, 'custodianName');
  copyString(input, out, 'hint');
  copyString(input, out, 'issuedDate');
  copyString(input, out, 'authorFingerprint');
  return out;
}

function copyString(input: Record<string, unknown>, out: ShareMetadata, key: keyof ShareMetadata): void {
  const value = input[key];
  if (value === undefined) return;
  if (typeof value !== 'string') throw new Error(`metadata.${key} must be a string`);
  if (value.length > 512) throw new Error(`metadata.${key} is too long`);
  if (value.length > 0) out[key] = value;
}

function sortJson(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortJson);
  if (!isRecord(value)) return value;
  const sorted: Record<string, unknown> = {};
  for (const key of Object.keys(value).sort()) {
    const child = value[key];
    if (child !== undefined) sorted[key] = sortJson(child);
  }
  return sorted;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function hex(b: Uint8Array): string {
  let s = '';
  for (const x of b) s += x.toString(16).padStart(2, '0');
  return s;
}
