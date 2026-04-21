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
  encodeShare,
  parse,
  toBase45,
  fromBase45,
  KIND_HEADER,
  KIND_SHARE,
  type HeaderChunkQr,
  type ShareQr,
} from './codec';

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
  /** Base45-encoded QR payloads for the header, split across `chunkTotal` codes. */
  headerQrs: string[];
  /** Base45-encoded QR payloads, one per Shamir share. */
  shareQrs: string[];
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

  return { bundleId, options: opts, headerQrs, shareQrs };
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

export function inspectQr(payload: string) {
  return parse(fromBase45(payload));
}

export function decodeSecret(qrPayloads: string[], passphrase?: string): DecodeResult {
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
      };
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

    const needMore = (): DecodeNeedMore => ({
      status: 'need-more',
      bundleId,
      headerChunksSeen: headersByIdx.size,
      headerChunksTotal: chunkTotal,
      sharesSeen: sharesByIdx.size,
      threshold,
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

    return { status: 'ok', bundleId, plaintext: new TextDecoder().decode(pt) };
  } catch (e) {
    return {
      status: 'error',
      error: e instanceof Error ? e.message : String(e),
    };
  }
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

export { fromBase45, toBase45, parse };
