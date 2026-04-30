import { KEM_ALG_ID, KEM_ALG_NAME, type KemAlg } from './pq';
import { AEAD_ALG_ID, AEAD_ALG_NAME, type AeadAlg } from './aead';
import { KDF_ALG_ID, KDF_ALG_NAME, type KdfAlg } from './kdf';

export const MAGIC = new Uint8Array([0x53, 0x53, 0x53, 0x31]); // "SSS1"
export const MAGIC_V2 = new Uint8Array([0x53, 0x53, 0x53, 0x32]); // "SSS2"
export const VERSION = 1;
export const VERSION_V2 = 2;
export const VERSION_V3 = 3;

export const KIND_HEADER = 0x01;
export const KIND_SHARE = 0x02;

export const TLV_CRITICAL = 0x80;
export const TLV_BUNDLE_METADATA = 0x01;
export const TLV_SHARE_METADATA = 0x02;
export const TLV_SHARE_METADATA_MAC = 0x03;
export const TLV_POLICY_MANIFEST = 0x04;
export const TLV_VAULT_INFO = 0x05;
export const TLV_TIMELOCK = 0x06;
export const TLV_PAYLOAD_FORMAT = 0x07;
export const TLV_POLICY_COMMITMENT = 0x08;
export const TLV_PLAINTEXT_COMMITMENT = 0x09;
export const TLV_VAULT_TREE_ROOT = 0x0a;
export const TLV_SHARE_COMMIT_PROOF = 0x0b;
export const TLV_VDF_PARAMS = 0x0c;
export const TLV_VDF_LOCK = 0x0d;
export const TLV_VDF_PROOF = 0x0e;
export const TLV_DECRYPTION_PROOF = 0x0f;

export type HeaderFlags = {
  passphrase: boolean;
};

export type Argon2Header = {
  tCost: number;
  memLog2KiB: number; // memory = 1 << memLog2KiB KiB
  parallelism: number;
};

export type HeaderChunkQr = {
  kind: typeof KIND_HEADER;
  version: number;
  bundleId: Uint8Array; // 8 bytes
  kemAlg: KemAlg;
  aeadAlg: AeadAlg;
  kdfAlg: KdfAlg;
  flags: HeaderFlags;
  argon2: Argon2Header;
  t: number;
  n: number;
  chunkIdx: number;
  chunkTotal: number;
  payload: Uint8Array;
  extensions?: ParsedTlv[];
  warnings?: string[];
};

export type ShareQr = {
  kind: typeof KIND_SHARE;
  version: number;
  bundleId: Uint8Array;
  kemAlg: KemAlg;
  t: number;
  n: number;
  shareIdx: number;
  share: Uint8Array;
  extensions?: ParsedTlv[];
  warnings?: string[];
};

export type ParsedQr = HeaderChunkQr | ShareQr;

export type Tlv = {
  tag: number;
  value: Uint8Array;
};

export type ParsedTlv = Tlv & {
  tagId: number;
  critical: boolean;
};

const KNOWN_TLV_TAGS = new Set([
  TLV_BUNDLE_METADATA,
  TLV_SHARE_METADATA,
  TLV_SHARE_METADATA_MAC,
  TLV_POLICY_MANIFEST,
  TLV_VAULT_INFO,
  TLV_TIMELOCK,
  TLV_PAYLOAD_FORMAT,
  TLV_POLICY_COMMITMENT,
  TLV_PLAINTEXT_COMMITMENT,
  TLV_VAULT_TREE_ROOT,
  TLV_SHARE_COMMIT_PROOF,
  TLV_VDF_PARAMS,
  TLV_VDF_LOCK,
  TLV_VDF_PROOF,
  TLV_DECRYPTION_PROOF,
]);

function assertBytes(a: Uint8Array, prefix: Uint8Array): boolean {
  if (a.length < prefix.length) return false;
  for (let i = 0; i < prefix.length; i++) if (a[i] !== prefix[i]) return false;
  return true;
}

function writeU16BE(out: Uint8Array, offset: number, v: number): void {
  if (!Number.isInteger(v) || v < 0 || v > 0xffff) throw new Error('u16 out of range');
  out[offset] = (v >>> 8) & 0xff;
  out[offset + 1] = v & 0xff;
}

function readU16BE(buf: Uint8Array, offset: number): number {
  if (offset + 2 > buf.length) throw new Error('truncated u16');
  return ((buf[offset]! << 8) | buf[offset + 1]!) >>> 0;
}

function ensureLen(buf: Uint8Array, need: number, label: string): void {
  if (buf.length < need) throw new Error(`truncated ${label}`);
}

function encodeTlvs(extensions: Tlv[] = []): Uint8Array {
  const len = extensions.reduce((sum, ext) => {
    if (ext.value.length > 0xffff) throw new Error('TLV value too long');
    return sum + 1 + 2 + ext.value.length;
  }, 0);
  if (len > 0xffff) throw new Error('TLV extension block too long');
  const out = new Uint8Array(len);
  let o = 0;
  for (const ext of extensions) {
    out[o++] = ext.tag & 0xff;
    writeU16BE(out, o, ext.value.length);
    o += 2;
    out.set(ext.value, o);
    o += ext.value.length;
  }
  return out;
}

function parseTlvs(raw: Uint8Array): { extensions: ParsedTlv[]; warnings: string[] } {
  const extensions: ParsedTlv[] = [];
  const warnings: string[] = [];
  let o = 0;
  while (o < raw.length) {
    ensureLen(raw, o + 3, 'TLV header');
    const tag = raw[o++]!;
    const len = readU16BE(raw, o);
    o += 2;
    ensureLen(raw, o + len, 'TLV value');
    const value = raw.slice(o, o + len);
    o += len;

    const critical = (tag & TLV_CRITICAL) !== 0;
    const tagId = tag & 0x7f;
    if (!KNOWN_TLV_TAGS.has(tagId)) {
      const msg = `unknown ${critical ? 'critical' : 'non-critical'} TLV 0x${tag.toString(16).padStart(2, '0')}`;
      if (critical) throw new Error(msg);
      warnings.push(msg);
      continue;
    }
    extensions.push({ tag, tagId, critical, value });
  }
  return { extensions, warnings };
}

export function makeTlv(tagId: number, value: Uint8Array, critical = false): Tlv {
  if (!Number.isInteger(tagId) || tagId < 0 || tagId > 0x7f) {
    throw new Error('TLV tag id must be in 0..127');
  }
  return { tag: tagId | (critical ? TLV_CRITICAL : 0), value };
}

export function encodeHeaderChunk(h: Omit<HeaderChunkQr, 'kind' | 'version'>): Uint8Array {
  const {
    bundleId,
    kemAlg,
    aeadAlg,
    kdfAlg,
    flags,
    argon2,
    t,
    n,
    chunkIdx,
    chunkTotal,
    payload,
  } = h;
  if (bundleId.length !== 8) throw new Error('bundleId must be 8 bytes');
  // Fixed-size header prefix: 4 + 1 + 1 + 8 + (kem,aead,kdf,flags,argon_t,argon_m,argon_p) + t + n + chunkIdx + chunkTotal + u16 len
  const out = new Uint8Array(4 + 1 + 1 + 8 + 3 + 1 + 3 + 1 + 1 + 1 + 1 + 2 + payload.length);
  let o = 0;
  out.set(MAGIC, o);
  o += 4;
  out[o++] = VERSION;
  out[o++] = KIND_HEADER;
  out.set(bundleId, o);
  o += 8;
  out[o++] = KEM_ALG_ID[kemAlg];
  out[o++] = AEAD_ALG_ID[aeadAlg];
  out[o++] = KDF_ALG_ID[kdfAlg];
  out[o++] = flags.passphrase ? 0x01 : 0x00;
  out[o++] = argon2.tCost & 0xff;
  out[o++] = argon2.memLog2KiB & 0xff;
  out[o++] = argon2.parallelism & 0xff;
  out[o++] = t;
  out[o++] = n;
  out[o++] = chunkIdx;
  out[o++] = chunkTotal;
  writeU16BE(out, o, payload.length);
  o += 2;
  out.set(payload, o);
  return out;
}

export function encodeShare(s: Omit<ShareQr, 'kind' | 'version'>): Uint8Array {
  const { bundleId, kemAlg, t, n, shareIdx, share } = s;
  if (bundleId.length !== 8) throw new Error('bundleId must be 8 bytes');
  const out = new Uint8Array(4 + 1 + 1 + 8 + 1 + 1 + 1 + 1 + 2 + share.length);
  let o = 0;
  out.set(MAGIC, o);
  o += 4;
  out[o++] = VERSION;
  out[o++] = KIND_SHARE;
  out.set(bundleId, o);
  o += 8;
  out[o++] = KEM_ALG_ID[kemAlg];
  out[o++] = t;
  out[o++] = n;
  out[o++] = shareIdx;
  writeU16BE(out, o, share.length);
  o += 2;
  out.set(share, o);
  return out;
}

export function encodeHeaderChunkV2(
  h: Omit<HeaderChunkQr, 'kind' | 'version' | 'extensions' | 'warnings'> & {
    extensions?: Tlv[];
  },
): Uint8Array {
  const {
    bundleId,
    kemAlg,
    aeadAlg,
    kdfAlg,
    flags,
    argon2,
    t,
    n,
    chunkIdx,
    chunkTotal,
    payload,
    extensions,
  } = h;
  if (bundleId.length !== 8) throw new Error('bundleId must be 8 bytes');
  const extBytes = encodeTlvs(extensions);
  const out = new Uint8Array(
    4 + 1 + 1 + 8 + 3 + 1 + 3 + 1 + 1 + 1 + 1 + 2 + extBytes.length + 2 + payload.length,
  );
  let o = 0;
  out.set(MAGIC_V2, o);
  o += 4;
  out[o++] = VERSION_V2;
  out[o++] = KIND_HEADER;
  out.set(bundleId, o);
  o += 8;
  out[o++] = KEM_ALG_ID[kemAlg];
  out[o++] = AEAD_ALG_ID[aeadAlg];
  out[o++] = KDF_ALG_ID[kdfAlg];
  out[o++] = flags.passphrase ? 0x01 : 0x00;
  out[o++] = argon2.tCost & 0xff;
  out[o++] = argon2.memLog2KiB & 0xff;
  out[o++] = argon2.parallelism & 0xff;
  out[o++] = t;
  out[o++] = n;
  out[o++] = chunkIdx;
  out[o++] = chunkTotal;
  writeU16BE(out, o, extBytes.length);
  o += 2;
  out.set(extBytes, o);
  o += extBytes.length;
  writeU16BE(out, o, payload.length);
  o += 2;
  out.set(payload, o);
  return out;
}

export function encodeHeaderChunkV3(
  h: Omit<HeaderChunkQr, 'kind' | 'version' | 'extensions' | 'warnings'> & {
    extensions?: Tlv[];
  },
): Uint8Array {
  const out = encodeHeaderChunkV2(h);
  out[4] = VERSION_V3;
  return out;
}

export function encodeShareV3(
  s: Omit<ShareQr, 'kind' | 'version' | 'extensions' | 'warnings'> & {
    extensions?: Tlv[];
  },
): Uint8Array {
  const out = encodeShareV2(s);
  out[4] = VERSION_V3;
  return out;
}

export function encodeShareV2(
  s: Omit<ShareQr, 'kind' | 'version' | 'extensions' | 'warnings'> & {
    extensions?: Tlv[];
  },
): Uint8Array {
  const { bundleId, kemAlg, t, n, shareIdx, share, extensions } = s;
  if (bundleId.length !== 8) throw new Error('bundleId must be 8 bytes');
  const extBytes = encodeTlvs(extensions);
  const out = new Uint8Array(4 + 1 + 1 + 8 + 1 + 1 + 1 + 1 + 2 + extBytes.length + 2 + share.length);
  let o = 0;
  out.set(MAGIC_V2, o);
  o += 4;
  out[o++] = VERSION_V2;
  out[o++] = KIND_SHARE;
  out.set(bundleId, o);
  o += 8;
  out[o++] = KEM_ALG_ID[kemAlg];
  out[o++] = t;
  out[o++] = n;
  out[o++] = shareIdx;
  writeU16BE(out, o, extBytes.length);
  o += 2;
  out.set(extBytes, o);
  o += extBytes.length;
  writeU16BE(out, o, share.length);
  o += 2;
  out.set(share, o);
  return out;
}

export function parse(raw: Uint8Array): ParsedQr {
  if (assertBytes(raw, MAGIC_V2)) {
    if (raw.length < 5) throw new Error('truncated SSS2 frame');
    const version = raw[4];
    if (version === VERSION_V2 || version === VERSION_V3) return parseV2OrV3(raw);
    throw new Error(`unsupported SSS2 version ${version}`);
  }
  if (!assertBytes(raw, MAGIC)) throw new Error('not a SuperSecretSecrets QR (bad magic)');
  return parseV1(raw);
}

function parseV1(raw: Uint8Array): ParsedQr {
  ensureLen(raw, 6, 'SSS1 frame header');
  const version = raw[4]!;
  if (version !== VERSION) throw new Error(`unsupported version ${version}`);
  const kind = raw[5]!;
  ensureLen(raw, 14, 'SSS1 bundle id');
  const bundleId = raw.slice(6, 14);
  if (kind === KIND_HEADER) {
    ensureLen(raw, 27, 'SSS1 header');
    const kemAlg = KEM_ALG_NAME[raw[14]!];
    const aeadAlg = AEAD_ALG_NAME[raw[15]!];
    const kdfAlg = KDF_ALG_NAME[raw[16]!];
    if (!kemAlg || !aeadAlg || !kdfAlg) throw new Error('unknown algorithm id in header');
    const flagsByte = raw[17]!;
    const flags: HeaderFlags = { passphrase: (flagsByte & 0x01) !== 0 };
    const argon2: Argon2Header = {
      tCost: raw[18]!,
      memLog2KiB: raw[19]!,
      parallelism: raw[20]!,
    };
    const t = raw[21]!;
    const n = raw[22]!;
    const chunkIdx = raw[23]!;
    const chunkTotal = raw[24]!;
    const payloadLen = readU16BE(raw, 25);
    const payload = raw.slice(27, 27 + payloadLen);
    if (payload.length !== payloadLen) throw new Error('truncated header payload');
    return {
      kind,
      version,
      bundleId,
      kemAlg,
      aeadAlg,
      kdfAlg,
      flags,
      argon2,
      t,
      n,
      chunkIdx,
      chunkTotal,
      payload,
    };
  }
  if (kind === KIND_SHARE) {
    const kemAlg = KEM_ALG_NAME[raw[14]!];
    if (!kemAlg) throw new Error('unknown KEM id in share');
    const t = raw[15]!;
    const n = raw[16]!;
    const shareIdx = raw[17]!;
    const shareLen = readU16BE(raw, 18);
    const share = raw.slice(20, 20 + shareLen);
    if (share.length !== shareLen) throw new Error('truncated share payload');
    return { kind, version, bundleId, kemAlg, t, n, shareIdx, share };
  }
  throw new Error(`unknown QR kind 0x${kind.toString(16)}`);
}

function parseV2OrV3(raw: Uint8Array): ParsedQr {
  ensureLen(raw, 6, 'SSS2 frame header');
  const version = raw[4]!;
  if (version !== VERSION_V2 && version !== VERSION_V3) {
    throw new Error(`unsupported version ${version}`);
  }
  const kind = raw[5]!;
  ensureLen(raw, 14, 'SSS2 bundle id');
  const bundleId = raw.slice(6, 14);
  if (kind === KIND_HEADER) {
    ensureLen(raw, 27, 'SSS2 header');
    const kemAlg = KEM_ALG_NAME[raw[14]!];
    const aeadAlg = AEAD_ALG_NAME[raw[15]!];
    const kdfAlg = KDF_ALG_NAME[raw[16]!];
    if (!kemAlg || !aeadAlg || !kdfAlg) throw new Error('unknown algorithm id in header');
    const flagsByte = raw[17]!;
    const flags: HeaderFlags = { passphrase: (flagsByte & 0x01) !== 0 };
    const argon2: Argon2Header = {
      tCost: raw[18]!,
      memLog2KiB: raw[19]!,
      parallelism: raw[20]!,
    };
    const t = raw[21]!;
    const n = raw[22]!;
    const chunkIdx = raw[23]!;
    const chunkTotal = raw[24]!;
    const extLen = readU16BE(raw, 25);
    ensureLen(raw, 27 + extLen + 2, 'SSS2 header extensions');
    const { extensions, warnings } = parseTlvs(raw.slice(27, 27 + extLen));
    const payloadLenOffset = 27 + extLen;
    const payloadLen = readU16BE(raw, payloadLenOffset);
    const payloadOffset = payloadLenOffset + 2;
    const payload = raw.slice(payloadOffset, payloadOffset + payloadLen);
    if (payload.length !== payloadLen) throw new Error('truncated header payload');
    return {
      kind,
      version,
      bundleId,
      kemAlg,
      aeadAlg,
      kdfAlg,
      flags,
      argon2,
      t,
      n,
      chunkIdx,
      chunkTotal,
      payload,
      extensions,
      warnings,
    };
  }
  if (kind === KIND_SHARE) {
    ensureLen(raw, 22, 'SSS2 share');
    const kemAlg = KEM_ALG_NAME[raw[14]!];
    if (!kemAlg) throw new Error('unknown KEM id in share');
    const t = raw[15]!;
    const n = raw[16]!;
    const shareIdx = raw[17]!;
    const extLen = readU16BE(raw, 18);
    ensureLen(raw, 20 + extLen + 2, 'SSS2 share extensions');
    const { extensions, warnings } = parseTlvs(raw.slice(20, 20 + extLen));
    const payloadLenOffset = 20 + extLen;
    const shareLen = readU16BE(raw, payloadLenOffset);
    const payloadOffset = payloadLenOffset + 2;
    const share = raw.slice(payloadOffset, payloadOffset + shareLen);
    if (share.length !== shareLen) throw new Error('truncated share payload');
    return { kind, version, bundleId, kemAlg, t, n, shareIdx, share, extensions, warnings };
  }
  throw new Error(`unknown QR kind 0x${kind.toString(16)}`);
}

// Inline base45 (RFC 9285). Self-contained so we don't depend on the `base45`
// npm package, which calls Node's `Buffer.from` inside decode() and crashes in
// browsers with "Buffer is not defined".
const B45_ALPHABET = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:';
const B45_INDEX: Record<string, number> = (() => {
  const m: Record<string, number> = {};
  for (let i = 0; i < B45_ALPHABET.length; i++) m[B45_ALPHABET[i]!] = i;
  return m;
})();

export function toBase45(raw: Uint8Array): string {
  let out = '';
  let i = 0;
  while (i + 2 <= raw.length) {
    const x = (raw[i]! << 8) + raw[i + 1]!;
    const e = Math.floor(x / (45 * 45));
    const rest = x - e * 45 * 45;
    const d = Math.floor(rest / 45);
    const c = rest - d * 45;
    out += B45_ALPHABET[c]! + B45_ALPHABET[d]! + B45_ALPHABET[e]!;
    i += 2;
  }
  if (i < raw.length) {
    const b = raw[i]!;
    const d = Math.floor(b / 45);
    const c = b - d * 45;
    out += B45_ALPHABET[c]! + B45_ALPHABET[d]!;
  }
  return out;
}

export function fromBase45(s: string): Uint8Array {
  const input = s.toUpperCase();
  const digits: number[] = new Array(input.length);
  for (let i = 0; i < input.length; i++) {
    const v = B45_INDEX[input[i]!];
    if (v === undefined) throw new Error(`invalid base45 character at position ${i}`);
    digits[i] = v;
  }
  const out: number[] = [];
  let i = 0;
  while (i + 3 <= digits.length) {
    const x = digits[i]! + digits[i + 1]! * 45 + digits[i + 2]! * 45 * 45;
    if (x > 0xffff) throw new Error('base45 triple out of range');
    out.push((x >> 8) & 0xff, x & 0xff);
    i += 3;
  }
  if (digits.length - i === 2) {
    const x = digits[i]! + digits[i + 1]! * 45;
    if (x > 0xff) throw new Error('base45 pair out of range');
    out.push(x);
  } else if (digits.length - i === 1) {
    throw new Error('base45 input has dangling character');
  }
  return new Uint8Array(out);
}
