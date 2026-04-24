import {
  keygenFromSeed,
  encapsulate,
  decapsulate,
  KEM_SEED_LEN,
  type KemAlg,
} from './pq';
import {
  aeadEncrypt,
  aeadDecrypt,
  AEAD_KEY_LEN,
  AEAD_NONCE_LEN,
  type AeadAlg,
} from './aead';
import {
  deriveKey,
  stretchPassphrase,
  ARGON2_DEFAULTS,
  type KdfAlg,
  type Argon2Params,
} from './kdf';
import { split, combine } from './shamir';
import {
  encodeHeaderChunk,
  encodeHeaderChunkV2,
  encodeShare,
  encodeShareV2,
  parse,
  toBase45,
  fromBase45,
  KIND_HEADER,
  KIND_SHARE,
  TLV_BUNDLE_METADATA,
  TLV_POLICY_MANIFEST,
  TLV_PAYLOAD_FORMAT,
  TLV_SHARE_METADATA,
  TLV_SHARE_METADATA_MAC,
  TLV_TIMELOCK,
  TLV_VAULT_INFO,
  makeTlv,
  VERSION,
  type HeaderChunkQr,
  type ParsedQr,
  type ShareQr,
} from './codec';
import {
  decodeShareMetadata,
  deriveMetadataKey,
  encodeShareMetadata,
  metadataMac,
  verifyMetadataMac,
  type MetadataVerification,
  type ShareMetadata,
} from './metadata';
import {
  compileFlatPolicy,
  compileTreePolicy,
  decodePolicyManifest,
  decodeShareComponents,
  encodePolicyManifest,
  encodeShareComponents,
  recoverPolicySecret,
  type Custodian,
  type PolicyManifest,
  type PolicyNode,
  type PolicyProgress,
  type ShareComponent,
} from './policy';
import {
  createVaultBlob,
  decodeVaultInfo,
  decryptVault,
  encodeVaultInfo,
  generateVaultRootKey,
  inspectVaultBlob,
  VAULT_FORMAT_VERSION,
  type VaultEntry,
  type VaultPlaintext,
} from './vault';
import {
  decodeTimeLockInfo,
  encodeTimeLockInfo,
  lockSharePayload,
  unlockSharePayload,
  type TimeLockAdapter,
  type TimeLockInfo,
  type TimeLockOptions,
} from './timelock';

export type EncodeOptions = {
  threshold: number; // T
  shares: number; // N
  kemAlg: KemAlg;
  aeadAlg: AeadAlg;
  kdfAlg: KdfAlg;
  passphrase?: string;
  argon2?: Argon2Params;
  /** Max bytes per header QR payload (after header-frame overhead). Default 800. */
  maxHeaderBytes?: number;
  custodians?: Custodian[];
  policy?: PolicyNode;
  metadata?: ShareMetadata;
  vaultMode?: boolean;
  vaultEntries?: VaultEntry[];
  timeLocks?: TimeLockOptions;
};

export const DEFAULT_OPTIONS: EncodeOptions = {
  threshold: 3,
  shares: 5,
  kemAlg: 'ml-kem-768',
  aeadAlg: 'aes-256-gcm',
  kdfAlg: 'hkdf-sha256',
  maxHeaderBytes: 800,
};

export type EncodedBundle = {
  bundleId: Uint8Array;
  options: EncodeOptions;
  formatVersion?: 1 | 2;
  /** Base45-encoded QR payloads for the header, split across `chunkTotal` codes. */
  headerQrs: string[];
  /** Base45-encoded QR payloads, one per Shamir share. */
  shareQrs: string[];
  vaultBlob?: Uint8Array;
  vaultId?: Uint8Array;
};

const INFO_AEAD = 'SSS/AEAD/v1';
const INFO_PASSPHRASE = 'SSS/passphrase/v1';
const BUNDLE_ID_LEN = 8;

function randBytes(n: number): Uint8Array {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
}

function concat(...chunks: Uint8Array[]): Uint8Array {
  const len = chunks.reduce((s, c) => s + c.length, 0);
  const out = new Uint8Array(len);
  let o = 0;
  for (const c of chunks) {
    out.set(c, o);
    o += c.length;
  }
  return out;
}

function buildAeadKey(
  sharedSecret: Uint8Array,
  opts: EncodeOptions,
  salt: Uint8Array,
): Uint8Array {
  let key = deriveKey(opts.kdfAlg, sharedSecret, salt, INFO_AEAD, AEAD_KEY_LEN);
  if (opts.passphrase && opts.passphrase.length > 0) {
    const stretched = stretchPassphrase(opts.passphrase, salt, opts.argon2);
    const mixed = new Uint8Array(AEAD_KEY_LEN);
    for (let i = 0; i < AEAD_KEY_LEN; i++) mixed[i] = key[i]! ^ stretched[i]!;
    key = deriveKey(opts.kdfAlg, mixed, salt, INFO_PASSPHRASE, AEAD_KEY_LEN);
  }
  return key;
}

export function encodeSecret(plaintext: string, optsIn: Partial<EncodeOptions> = {}): EncodedBundle {
  const opts: EncodeOptions = { ...DEFAULT_OPTIONS, ...optsIn };
  if (shouldUseV2(opts)) return encodeSecretV2(plaintext, opts);
  return encodeSecretV1(plaintext, opts);
}

function encodeSecretV1(plaintext: string, opts: EncodeOptions): EncodedBundle {
  if (opts.shares < opts.threshold) throw new Error('shares must be >= threshold');

  const pt = new TextEncoder().encode(plaintext);
  const bundleId = randBytes(BUNDLE_ID_LEN);
  const kemSeed = randBytes(KEM_SEED_LEN);

  const { secretKey, publicKey } = keygenFromSeed(opts.kemAlg, kemSeed);
  const { cipherText: kemCt, sharedSecret } = encapsulate(opts.kemAlg, publicKey);
  // Drop the secret key from memory — the seed (Shamir-split) is the long-term secret.
  secretKey.fill(0);

  const aeadNonce = randBytes(AEAD_NONCE_LEN);
  const salt = bundleId; // public, fixed-length per bundle; fine as a KDF salt
  const aeadKey = buildAeadKey(sharedSecret, opts, salt);
  const aeadCt = aeadEncrypt(opts.aeadAlg, aeadKey, aeadNonce, pt);
  aeadKey.fill(0);
  sharedSecret.fill(0);

  // Header payload = kem_ct || nonce || aead_ct_and_tag
  const headerPayload = concat(kemCt, aeadNonce, aeadCt);

  const argon2 = opts.argon2 ?? ARGON2_DEFAULTS;
  // Encode memory as log2(KiB), rounded down but ensuring round-trip fidelity for defaults.
  const memLog2KiB = Math.round(Math.log2(argon2.m));
  const headerArgon2 = { tCost: argon2.t, memLog2KiB, parallelism: argon2.p };
  const flags = { passphrase: !!(opts.passphrase && opts.passphrase.length > 0) };

  const headerChunks = chunkBytes(headerPayload, opts.maxHeaderBytes ?? 800);
  const headerQrs = headerChunks.map((chunk, idx) => {
    const framed = encodeHeaderChunk({
      bundleId,
      kemAlg: opts.kemAlg,
      aeadAlg: opts.aeadAlg,
      kdfAlg: opts.kdfAlg,
      flags,
      argon2: headerArgon2,
      t: opts.threshold,
      n: opts.shares,
      chunkIdx: idx,
      chunkTotal: headerChunks.length,
      payload: chunk,
    });
    return toBase45(framed);
  });

  const shamirShares = split(kemSeed, opts.threshold, opts.shares);
  const shareQrs = shamirShares.map((s) =>
    toBase45(
      encodeShare({
        bundleId,
        kemAlg: opts.kemAlg,
        t: opts.threshold,
        n: opts.shares,
        shareIdx: s[0]!,
        share: s,
      }),
    ),
  );

  kemSeed.fill(0);

  return { bundleId, options: opts, formatVersion: 1, headerQrs, shareQrs };
}

function encodeSecretV2(plaintext: string, opts: EncodeOptions): EncodedBundle {
  const custodians = effectiveCustodians(opts);
  const totalPoints = custodians.reduce((sum, c) => sum + (c.weight ?? 1), 0);
  if (totalPoints > 255) throw new Error('weighted point count must be <= 255');

  const pt = new TextEncoder().encode(plaintext);
  const bundleId = randBytes(BUNDLE_ID_LEN);
  const kemSeed = randBytes(KEM_SEED_LEN);

  const { secretKey, publicKey } = keygenFromSeed(opts.kemAlg, kemSeed);
  const { cipherText: kemCt, sharedSecret } = encapsulate(opts.kemAlg, publicKey);
  secretKey.fill(0);

  let vaultBlob: Uint8Array | undefined;
  let vaultId: Uint8Array | undefined;
  let protectedPayload: Uint8Array = pt;
  if (opts.vaultMode) {
    const rootKey = new Uint8Array(generateVaultRootKey());
    const entries = opts.vaultEntries ?? [
      { id: 'secret', name: 'secret.txt', data: pt, contentType: 'text/plain; charset=utf-8' },
    ];
    const vault = createVaultBlob(rootKey, entries);
    vaultBlob = vault.blob;
    vaultId = vault.vaultId;
    protectedPayload = rootKey;
  }

  const aeadNonce = randBytes(AEAD_NONCE_LEN);
  const salt = bundleId;
  const aeadKey = buildAeadKey(sharedSecret, opts, salt);
  const aeadCt = aeadEncrypt(opts.aeadAlg, aeadKey, aeadNonce, protectedPayload);
  aeadKey.fill(0);
  sharedSecret.fill(0);
  if (opts.vaultMode) protectedPayload.fill(0);

  const headerPayload = concat(kemCt, aeadNonce, aeadCt);
  const argon2 = opts.argon2 ?? ARGON2_DEFAULTS;
  const memLog2KiB = Math.round(Math.log2(argon2.m));
  const headerArgon2 = { tCost: argon2.t, memLog2KiB, parallelism: argon2.p };
  const flags = { passphrase: !!(opts.passphrase && opts.passphrase.length > 0) };

  const compiled = opts.policy
    ? compileTreePolicy(kemSeed, opts.policy, custodians)
    : compileFlatPolicy(kemSeed, opts.threshold, custodians);
  const policyManifest = compiled.manifest;
  const metadataKey = deriveMetadataKey(kemSeed, bundleId);
  const headerChunks = chunkBytes(headerPayload, opts.maxHeaderBytes ?? 800);
  const payloadKind = opts.vaultMode ? 'vault-root' : 'secret';

  const headerQrs = headerChunks.map((chunk, idx) => {
    const extensions =
      idx === 0
        ? [
            makeTlv(TLV_POLICY_MANIFEST, encodePolicyManifest(policyManifest), true),
            makeTlv(TLV_PAYLOAD_FORMAT, textBytes(payloadKind), true),
            ...(opts.metadata ? [makeTlv(TLV_BUNDLE_METADATA, encodeShareMetadata(opts.metadata), false)] : []),
            ...(vaultId ? [makeTlv(TLV_VAULT_INFO, encodeVaultInfo({ vaultId, formatVersion: VAULT_FORMAT_VERSION }), true)] : []),
          ]
        : [];
    const framed = encodeHeaderChunkV2({
      bundleId,
      kemAlg: opts.kemAlg,
      aeadAlg: opts.aeadAlg,
      kdfAlg: opts.kdfAlg,
      flags,
      argon2: headerArgon2,
      t: policyManifest.threshold,
      n: policyManifest.totalPoints,
      chunkIdx: idx,
      chunkTotal: headerChunks.length,
      extensions,
      payload: chunk,
    });
    return toBase45(framed);
  });

  const shareQrs = compiled.shares.map((share) => {
    const metadata = shareMetadataFor(opts.metadata, share.custodian);
    const componentIds = share.components.map((component) => component.id);
    const metadataBytes = encodeShareMetadata(metadata);
    const mac = metadataMac(metadataKey, metadata, {
      bundleId,
      shareIdx: share.shareIdx,
      componentIds,
    });
    let payload = encodeShareComponents(share.components);
    const extensions = [
      makeTlv(TLV_PAYLOAD_FORMAT, textBytes('policy-components'), true),
      makeTlv(TLV_SHARE_METADATA, metadataBytes, false),
      makeTlv(TLV_SHARE_METADATA_MAC, mac, false),
    ];
    if (opts.timeLocks) {
      const locked = lockSharePayload(payload, opts.timeLocks);
      payload = locked.ciphertext;
      extensions.push(makeTlv(TLV_TIMELOCK, encodeTimeLockInfo(locked.info), true));
    }
    return toBase45(
      encodeShareV2({
        bundleId,
        kemAlg: opts.kemAlg,
        t: policyManifest.threshold,
        n: policyManifest.totalPoints,
        shareIdx: share.shareIdx,
        extensions,
        share: payload,
      }),
    );
  });

  metadataKey.fill(0);
  kemSeed.fill(0);

  return {
    bundleId,
    options: { ...opts, shares: compiled.shares.length, threshold: policyManifest.threshold },
    formatVersion: 2,
    headerQrs,
    shareQrs,
    vaultBlob,
    vaultId,
  };
}

function shouldUseV2(opts: EncodeOptions): boolean {
  return Boolean(
    opts.policy ||
      opts.custodians ||
      opts.metadata ||
      opts.vaultMode ||
      opts.vaultEntries ||
      opts.timeLocks,
  );
}

function effectiveCustodians(opts: EncodeOptions): Custodian[] {
  if (opts.custodians && opts.custodians.length > 0) return opts.custodians;
  return Array.from({ length: opts.shares }, (_, i) => ({
    id: `share-${i + 1}`,
    name: `Share ${i + 1}`,
    weight: 1,
  }));
}

function shareMetadataFor(bundleMetadata: ShareMetadata | undefined, custodian: Custodian): ShareMetadata {
  return {
    ...bundleMetadata,
    ...custodian.metadata,
    custodianName: custodian.metadata?.custodianName ?? custodian.name ?? bundleMetadata?.custodianName,
  };
}

function chunkBytes(data: Uint8Array, maxSize: number): Uint8Array[] {
  if (maxSize < 1) throw new Error('maxSize must be >= 1');
  if (data.length <= maxSize) return [data];
  const out: Uint8Array[] = [];
  for (let o = 0; o < data.length; o += maxSize) {
    out.push(data.slice(o, Math.min(o + maxSize, data.length)));
  }
  return out;
}

export type DecodeNeedMore = {
  status: 'need-more';
  bundleId: Uint8Array | null;
  headerChunksSeen: number;
  headerChunksTotal: number | null;
  sharesSeen: number;
  threshold: number | null;
};

export type DecodeSuccess = {
  status: 'ok';
  bundleId: Uint8Array;
  plaintext: string;
};

export type DecodeError = {
  status: 'error';
  error: string;
};

export type DecodeResult = DecodeSuccess | DecodeNeedMore | DecodeError;

export type DecodedShareMetadata = {
  shareIdx: number;
  verification: MetadataVerification;
};

export type LockedShare = {
  shareIdx: number;
  timeLock: TimeLockInfo;
};

export type DecodeBundleNeedMore = DecodeNeedMore & {
  warnings: string[];
  policyProgress?: PolicyProgress;
  lockedShares: LockedShare[];
  metadata: DecodedShareMetadata[];
};

export type DecodeBundleSuccess =
  | {
      status: 'ok';
      kind: 'secret';
      bundleId: Uint8Array;
      plaintext: string;
      warnings: string[];
      policyProgress?: PolicyProgress;
      metadata: DecodedShareMetadata[];
    }
  | {
      status: 'ok';
      kind: 'vault';
      bundleId: Uint8Array;
      vaultRootKey: Uint8Array;
      vaultId: Uint8Array;
      vault?: VaultPlaintext;
      warnings: string[];
      policyProgress?: PolicyProgress;
      metadata: DecodedShareMetadata[];
    };

export type DecodeBundleError = DecodeError & {
  warnings?: string[];
};

export type DecodeBundleResult = DecodeBundleSuccess | DecodeBundleNeedMore | DecodeBundleError;

export type DecodeBundleOptions = {
  passphrase?: string;
  vaultBlob?: Uint8Array;
  timeLockAdapter?: TimeLockAdapter;
};

export function inspectQr(payload: string) {
  return parse(fromBase45(payload));
}

export function decodeSecret(qrPayloads: string[], passphrase?: string): DecodeResult {
  const result = decodeBundle(qrPayloads, { passphrase });
  if (result.status === 'need-more') {
    return {
      status: 'need-more',
      bundleId: result.bundleId,
      headerChunksSeen: result.headerChunksSeen,
      headerChunksTotal: result.headerChunksTotal,
      sharesSeen: result.sharesSeen,
      threshold: result.threshold,
    };
  }
  if (result.status === 'error') return { status: 'error', error: result.error };
  if (result.kind !== 'secret') {
    return { status: 'error', error: 'this bundle unlocks a .ssssvault blob; use decodeBundle with the vault blob' };
  }
  return { status: 'ok', bundleId: result.bundleId, plaintext: result.plaintext };
}

export function decodeBundle(qrPayloads: string[], opts: DecodeBundleOptions = {}): DecodeBundleResult {
  try {
    const parsed = qrPayloads.map((p) => parse(fromBase45(p)));
    if (parsed.length === 0) {
      return {
        status: 'need-more',
        bundleId: null,
        headerChunksSeen: 0,
        headerChunksTotal: null,
        sharesSeen: 0,
        threshold: null,
        warnings: [],
        lockedShares: [],
        metadata: [],
      };
    }

    const versions = new Set(parsed.map((p) => p.version));
    if (versions.size > 1) return { status: 'error', error: 'mixed SSS1/SSS2 QR payloads are not supported' };
    if (parsed[0]!.version === VERSION) return decodeV1Parsed(parsed, opts.passphrase);
    return decodeV2Parsed(parsed, opts);
  } catch (e) {
    return {
      status: 'error',
      error: e instanceof Error ? e.message : String(e),
    };
  }
}

function decodeV1Parsed(parsed: ParsedQr[], passphrase?: string): DecodeBundleResult {
  try {
    if (parsed.some((p) => p.version !== VERSION)) {
      return { status: 'error', error: 'decodeV1Parsed received non-v1 QR payloads' };
    }

    // Group by bundleId; use the most-frequent one
    const groups = new Map<string, typeof parsed>();
    for (const p of parsed) {
      const k = hex(p.bundleId);
      const list = groups.get(k) ?? [];
      list.push(p);
      groups.set(k, list);
    }
    let best: typeof parsed = [];
    for (const [, list] of groups) {
      if (list.length > best.length) best = list;
    }
    const bundleId = best[0]!.bundleId;

    const headers = best.filter((p): p is HeaderChunkQr => p.kind === KIND_HEADER);
    const shares = best.filter((p): p is ShareQr => p.kind === KIND_SHARE);

    // Dedupe headers by chunkIdx, shares by shareIdx
    const headersByIdx = new Map<number, HeaderChunkQr>();
    for (const h of headers) headersByIdx.set(h.chunkIdx, h);
    const sharesByIdx = new Map<number, ShareQr>();
    for (const s of shares) sharesByIdx.set(s.shareIdx, s);

    const chunkTotal = headers[0]?.chunkTotal ?? null;
    const threshold = best.find((p) => p.kind === KIND_HEADER || p.kind === KIND_SHARE)?.t ?? null;

    const needMore = (): DecodeBundleNeedMore => ({
      status: 'need-more',
      bundleId,
      headerChunksSeen: headersByIdx.size,
      headerChunksTotal: chunkTotal,
      sharesSeen: sharesByIdx.size,
      threshold,
      warnings: [],
      lockedShares: [],
      metadata: [],
    });

    if (chunkTotal === null || headersByIdx.size < chunkTotal) return needMore();
    if (threshold === null || sharesByIdx.size < threshold) return needMore();

    // Reassemble header payload
    const ordered: HeaderChunkQr[] = [];
    for (let i = 0; i < chunkTotal; i++) {
      const h = headersByIdx.get(i);
      if (!h) return needMore();
      ordered.push(h);
    }
    const fullPayload = concat(...ordered.map((h) => h.payload));

    // Pick any T shares deterministically (lowest indices)
    const chosen = Array.from(sharesByIdx.values())
      .sort((a, b) => a.shareIdx - b.shareIdx)
      .slice(0, threshold);

    // Reconstruct KEM seed
    const kemSeed = combine(chosen.map((s) => s.share));
    if (kemSeed.length !== KEM_SEED_LEN) {
      kemSeed.fill(0);
      return { status: 'error', error: 'reconstructed seed has wrong length' };
    }

    const head = ordered[0]!;
    const { secretKey } = keygenFromSeed(head.kemAlg, kemSeed);
    kemSeed.fill(0);

    // Slice fullPayload: kem_ct || aead_nonce || aead_ct_and_tag
    const kemCtLen = kemCtLenFor(head.kemAlg);
    if (fullPayload.length < kemCtLen + AEAD_NONCE_LEN) {
      secretKey.fill(0);
      return { status: 'error', error: 'header payload too short' };
    }
    const kemCt = fullPayload.slice(0, kemCtLen);
    const nonce = fullPayload.slice(kemCtLen, kemCtLen + AEAD_NONCE_LEN);
    const aeadCt = fullPayload.slice(kemCtLen + AEAD_NONCE_LEN);

    const sharedSecret = decapsulate(head.kemAlg, secretKey, kemCt);
    secretKey.fill(0);

    const salt = bundleId;
    const argon2Params: Argon2Params = {
      t: head.argon2.tCost,
      m: 1 << head.argon2.memLog2KiB,
      p: head.argon2.parallelism,
    };
    if (head.flags.passphrase && !passphrase) {
      return {
        status: 'error',
        error: 'this bundle is passphrase-protected — provide a passphrase to decrypt',
      };
    }
    const aeadKey = buildAeadKey(
      sharedSecret,
      {
        ...DEFAULT_OPTIONS,
        kemAlg: head.kemAlg,
        aeadAlg: head.aeadAlg,
        kdfAlg: head.kdfAlg,
        threshold: head.t,
        shares: head.n,
        passphrase: head.flags.passphrase ? passphrase : undefined,
        argon2: argon2Params,
      },
      salt,
    );
    sharedSecret.fill(0);

    let pt: Uint8Array;
    try {
      pt = aeadDecrypt(head.aeadAlg, aeadKey, nonce, aeadCt);
    } catch (e) {
      aeadKey.fill(0);
      return {
        status: 'error',
        error:
          passphrase !== undefined
            ? 'decryption failed — wrong passphrase or tampered QR'
            : 'decryption failed — this bundle may require a passphrase, or the QR data is damaged',
      };
    }
    aeadKey.fill(0);

    return {
      status: 'ok',
      kind: 'secret',
      bundleId,
      plaintext: new TextDecoder().decode(pt),
      warnings: [],
      metadata: [],
    };
  } catch (e) {
    return {
      status: 'error',
      error: e instanceof Error ? e.message : String(e),
    };
  }
}

function decodeV2Parsed(parsed: ParsedQr[], opts: DecodeBundleOptions): DecodeBundleResult {
  if (parsed.some((p) => p.version !== 2)) {
    return { status: 'error', error: 'decodeV2Parsed received non-v2 QR payloads' };
  }

  const warnings = parsed.flatMap((p) => p.warnings ?? []);
  const groups = new Map<string, typeof parsed>();
  for (const p of parsed) {
    const k = hex(p.bundleId);
    const list = groups.get(k) ?? [];
    list.push(p);
    groups.set(k, list);
  }
  let best: typeof parsed = [];
  for (const [, list] of groups) {
    if (list.length > best.length) best = list;
  }
  const bundleId = best[0]!.bundleId;

  const headers = best.filter((p): p is HeaderChunkQr => p.kind === KIND_HEADER);
  const shares = best.filter((p): p is ShareQr => p.kind === KIND_SHARE);
  const headersByIdx = new Map<number, HeaderChunkQr>();
  for (const h of headers) headersByIdx.set(h.chunkIdx, h);
  const sharesByIdx = new Map<number, ShareQr>();
  for (const s of shares) sharesByIdx.set(s.shareIdx, s);

  const chunkTotal = headers[0]?.chunkTotal ?? null;
  const threshold = best.find((p) => p.kind === KIND_HEADER || p.kind === KIND_SHARE)?.t ?? null;
  const unverifiedMetadata = inspectShareMetadata(sharesByIdx);

  const needMore = (
    policyProgress?: PolicyProgress,
    lockedShares: LockedShare[] = [],
  ): DecodeBundleNeedMore => ({
    status: 'need-more',
    bundleId,
    headerChunksSeen: headersByIdx.size,
    headerChunksTotal: chunkTotal,
    sharesSeen: sharesByIdx.size,
    threshold,
    warnings,
    policyProgress,
    lockedShares,
    metadata: unverifiedMetadata,
  });

  if (chunkTotal === null || headersByIdx.size < chunkTotal) return needMore();

  const ordered: HeaderChunkQr[] = [];
  for (let i = 0; i < chunkTotal; i++) {
    const h = headersByIdx.get(i);
    if (!h) return needMore();
    ordered.push(h);
  }
  const firstHeader = ordered[0]!;
  const policyManifest = headerPolicyManifest(firstHeader);
  const payloadKind = textFromTlv(firstHeader, TLV_PAYLOAD_FORMAT) ?? 'secret';
  const fullPayload = concat(...ordered.map((h) => h.payload));

  const prepared = prepareV2Shares(sharesByIdx, opts.timeLockAdapter);
  if (prepared.error) return { status: 'error', error: prepared.error, warnings };

  const recovered = recoverPolicySecret(policyManifest, prepared.shares);
  if (!recovered.secret) return needMore(recovered.progress, prepared.lockedShares);
  const kemSeed = recovered.secret;
  if (kemSeed.length !== KEM_SEED_LEN) {
    kemSeed.fill(0);
    return { status: 'error', error: 'reconstructed seed has wrong length', warnings };
  }

  const metadata = verifyShareMetadata(sharesByIdx, prepared.shares, kemSeed, bundleId);
  const decrypted = decryptHeaderPayload(firstHeader, fullPayload, bundleId, kemSeed, opts.passphrase);
  kemSeed.fill(0);
  if (decrypted.status === 'error') return { ...decrypted, warnings };

  if (payloadKind === 'vault-root') {
    if (decrypted.plaintextBytes.length !== AEAD_KEY_LEN) {
      return { status: 'error', error: 'vault root key has wrong length', warnings };
    }
    const vaultInfo = headerVaultInfo(firstHeader);
    if (!vaultInfo) return { status: 'error', error: 'vault bundle missing vault info', warnings };
    const vaultRootKey = decrypted.plaintextBytes;
    let vault: VaultPlaintext | undefined;
    if (opts.vaultBlob) {
      const blobInfo = inspectVaultBlob(opts.vaultBlob);
      if (hex(blobInfo.vaultId) !== hex(vaultInfo.vaultId)) {
        return { status: 'error', error: 'vault blob does not match QR vault id', warnings };
      }
      vault = decryptVault(vaultRootKey, opts.vaultBlob);
    }
    return {
      status: 'ok',
      kind: 'vault',
      bundleId,
      vaultRootKey,
      vaultId: vaultInfo.vaultId,
      vault,
      warnings,
      policyProgress: recovered.progress,
      metadata,
    };
  }

  if (payloadKind !== 'secret') return { status: 'error', error: `unsupported v2 payload kind ${payloadKind}`, warnings };
  return {
    status: 'ok',
    kind: 'secret',
    bundleId,
    plaintext: new TextDecoder().decode(decrypted.plaintextBytes),
    warnings,
    policyProgress: recovered.progress,
    metadata,
  };
}

type PreparedV2Share = {
  shareIdx: number;
  components: ShareComponent[];
};

function headerPolicyManifest(header: HeaderChunkQr): PolicyManifest {
  const raw = tlvValue(header, TLV_POLICY_MANIFEST);
  if (!raw) throw new Error('v2 header missing policy manifest');
  return decodePolicyManifest(raw);
}

function headerVaultInfo(header: HeaderChunkQr) {
  const raw = tlvValue(header, TLV_VAULT_INFO);
  return raw ? decodeVaultInfo(raw) : null;
}

function inspectShareMetadata(sharesByIdx: Map<number, ShareQr>): DecodedShareMetadata[] {
  const out: DecodedShareMetadata[] = [];
  for (const share of sharesByIdx.values()) {
    const raw = tlvValue(share, TLV_SHARE_METADATA);
    if (!raw) continue;
    try {
      out.push({
        shareIdx: share.shareIdx,
        verification: { status: 'unverified', metadata: decodeShareMetadata(raw) },
      });
    } catch {
      out.push({ shareIdx: share.shareIdx, verification: { status: 'tampered', metadata: {} } });
    }
  }
  return out.sort((a, b) => a.shareIdx - b.shareIdx);
}

function verifyShareMetadata(
  sharesByIdx: Map<number, ShareQr>,
  preparedShares: PreparedV2Share[],
  kemSeed: Uint8Array,
  bundleId: Uint8Array,
): DecodedShareMetadata[] {
  const key = deriveMetadataKey(kemSeed, bundleId);
  const componentsByShareIdx = new Map(preparedShares.map((share) => [share.shareIdx, share.components]));
  const out: DecodedShareMetadata[] = [];
  for (const share of sharesByIdx.values()) {
    const raw = tlvValue(share, TLV_SHARE_METADATA);
    if (!raw) continue;
    let metadata: ShareMetadata;
    try {
      metadata = decodeShareMetadata(raw);
    } catch {
      out.push({ shareIdx: share.shareIdx, verification: { status: 'tampered', metadata: {} } });
      continue;
    }
    const mac = tlvValue(share, TLV_SHARE_METADATA_MAC);
    const components = componentsByShareIdx.get(share.shareIdx);
    if (!components) {
      out.push({ shareIdx: share.shareIdx, verification: { status: 'unverified', metadata } });
      continue;
    }
    const verified =
      !!mac &&
      verifyMetadataMac(
        key,
        metadata,
        {
          bundleId,
          shareIdx: share.shareIdx,
          componentIds: components.map((component) => component.id),
        },
        mac,
      );
    out.push({
      shareIdx: share.shareIdx,
      verification: verified ? { status: 'verified', metadata } : { status: 'tampered', metadata },
    });
  }
  key.fill(0);
  return out.sort((a, b) => a.shareIdx - b.shareIdx);
}

function prepareV2Shares(
  sharesByIdx: Map<number, ShareQr>,
  timeLockAdapter?: TimeLockAdapter,
): { shares: PreparedV2Share[]; lockedShares: LockedShare[]; error?: string } {
  const shares: PreparedV2Share[] = [];
  const lockedShares: LockedShare[] = [];
  for (const share of sharesByIdx.values()) {
    let payload = share.share;
    const timeLockRaw = tlvValue(share, TLV_TIMELOCK);
    if (timeLockRaw) {
      let timeLock: TimeLockInfo;
      try {
        timeLock = decodeTimeLockInfo(timeLockRaw);
      } catch (e) {
        return { shares, lockedShares, error: e instanceof Error ? e.message : String(e) };
      }
      if (!timeLockAdapter) {
        lockedShares.push({ shareIdx: share.shareIdx, timeLock });
        continue;
      }
      try {
        payload = unlockSharePayload(payload, timeLock, timeLockAdapter);
      } catch (e) {
        return {
          shares,
          lockedShares,
          error: e instanceof Error ? e.message : 'failed to unlock time-locked share',
        };
      }
    }
    try {
      shares.push({ shareIdx: share.shareIdx, components: decodeShareComponents(payload) });
    } catch (e) {
      return { shares, lockedShares, error: e instanceof Error ? e.message : String(e) };
    }
  }
  return { shares, lockedShares };
}

function decryptHeaderPayload(
  head: HeaderChunkQr,
  fullPayload: Uint8Array,
  bundleId: Uint8Array,
  kemSeed: Uint8Array,
  passphrase?: string,
): { status: 'ok'; plaintextBytes: Uint8Array } | DecodeError {
  const { secretKey } = keygenFromSeed(head.kemAlg, kemSeed);
  const kemCtLen = kemCtLenFor(head.kemAlg);
  if (fullPayload.length < kemCtLen + AEAD_NONCE_LEN) {
    secretKey.fill(0);
    return { status: 'error', error: 'header payload too short' };
  }
  const kemCt = fullPayload.slice(0, kemCtLen);
  const nonce = fullPayload.slice(kemCtLen, kemCtLen + AEAD_NONCE_LEN);
  const aeadCt = fullPayload.slice(kemCtLen + AEAD_NONCE_LEN);

  const sharedSecret = decapsulate(head.kemAlg, secretKey, kemCt);
  secretKey.fill(0);

  const argon2Params: Argon2Params = {
    t: head.argon2.tCost,
    m: 1 << head.argon2.memLog2KiB,
    p: head.argon2.parallelism,
  };
  if (head.flags.passphrase && !passphrase) {
    sharedSecret.fill(0);
    return {
      status: 'error',
      error: 'this bundle is passphrase-protected — provide a passphrase to decrypt',
    };
  }
  const aeadKey = buildAeadKey(
    sharedSecret,
    {
      ...DEFAULT_OPTIONS,
      kemAlg: head.kemAlg,
      aeadAlg: head.aeadAlg,
      kdfAlg: head.kdfAlg,
      threshold: head.t,
      shares: head.n,
      passphrase: head.flags.passphrase ? passphrase : undefined,
      argon2: argon2Params,
    },
    bundleId,
  );
  sharedSecret.fill(0);

  try {
    const plaintextBytes = aeadDecrypt(head.aeadAlg, aeadKey, nonce, aeadCt);
    aeadKey.fill(0);
    return { status: 'ok', plaintextBytes };
  } catch {
    aeadKey.fill(0);
    return {
      status: 'error',
      error:
        passphrase !== undefined
          ? 'decryption failed — wrong passphrase or tampered QR'
          : 'decryption failed — this bundle may require a passphrase, or the QR data is damaged',
    };
  }
}

function tlvValue(qr: HeaderChunkQr | ShareQr, tagId: number): Uint8Array | undefined {
  return qr.extensions?.find((extension) => extension.tagId === tagId)?.value;
}

function textFromTlv(qr: HeaderChunkQr | ShareQr, tagId: number): string | undefined {
  const raw = tlvValue(qr, tagId);
  return raw ? new TextDecoder().decode(raw) : undefined;
}

function textBytes(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

function kemCtLenFor(alg: KemAlg): number {
  switch (alg) {
    case 'ml-kem-512':
      return 768;
    case 'ml-kem-768':
      return 1088;
    case 'ml-kem-1024':
      return 1568;
  }
}

function hex(b: Uint8Array): string {
  let s = '';
  for (const x of b) s += x.toString(16).padStart(2, '0');
  return s;
}

export function inspectQrKind(payload: string): 'header' | 'share' | 'unknown' {
  try {
    const p = parse(fromBase45(payload));
    return p.kind === KIND_HEADER ? 'header' : p.kind === KIND_SHARE ? 'share' : 'unknown';
  } catch {
    return 'unknown';
  }
}

export type { MetadataVerification, ShareMetadata } from './metadata';
export type { Custodian, PolicyManifest, PolicyNode, PolicyProgress, ShareComponent } from './policy';
export {
  decryptVault,
  encryptVault,
  inspectVaultBlob,
  updateVaultEntries,
  VAULT_FORMAT_VERSION,
  type VaultEntry,
  type VaultInfo,
  type VaultPlaintext,
} from './vault';
export {
  DRAND_QUICKNET_CHAIN_HASH,
  TIMELOCK_SECURITY_NOTICE,
  type TimeLockAdapter,
  type TimeLockInfo,
  type TimeLockOptions,
} from './timelock';
export { fromBase45, toBase45, parse };
