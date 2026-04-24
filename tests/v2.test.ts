import { describe, expect, it } from 'vitest';
import {
  decodeBundle,
  decodeSecret,
  encodeSecret,
  type EncodeOptions,
} from '../src/crypto';
import {
  encodeHeaderChunkV2,
  encodeShareV2,
  fromBase45,
  KIND_HEADER,
  KIND_SHARE,
  MAGIC,
  MAGIC_V2,
  makeTlv,
  parse,
  TLV_SHARE_METADATA,
  toBase45,
} from '../src/crypto/codec';
import { updateVaultEntries } from '../src/crypto/vault';
import type { TimeLockAdapter } from '../src/crypto/timelock';

const FAST: Pick<EncodeOptions, 'kemAlg' | 'aeadAlg' | 'kdfAlg'> = {
  kemAlg: 'ml-kem-512',
  aeadAlg: 'aes-256-gcm',
  kdfAlg: 'hkdf-sha256',
};

describe('SSS2 codec', () => {
  it('roundtrips header and share frames with explicit TLV extension length', () => {
    const bundleId = new Uint8Array([1, 1, 2, 3, 5, 8, 13, 21]);
    const header = encodeHeaderChunkV2({
      bundleId,
      kemAlg: 'ml-kem-512',
      aeadAlg: 'aes-256-gcm',
      kdfAlg: 'hkdf-sha256',
      flags: { passphrase: false },
      argon2: { tCost: 3, memLog2KiB: 16, parallelism: 1 },
      t: 2,
      n: 3,
      chunkIdx: 0,
      chunkTotal: 1,
      extensions: [makeTlv(0x01, new Uint8Array([7, 8, 9]), false)],
      payload: new Uint8Array([10, 11]),
    });
    const parsedHeader = parse(header);
    expect(parsedHeader.kind).toBe(KIND_HEADER);
    if (parsedHeader.kind !== KIND_HEADER) throw new Error('expected header');
    expect(parsedHeader.version).toBe(2);
    expect(parsedHeader.extensions).toHaveLength(1);
    expect(Array.from(parsedHeader.payload)).toEqual([10, 11]);

    const share = encodeShareV2({
      bundleId,
      kemAlg: 'ml-kem-512',
      t: 2,
      n: 3,
      shareIdx: 1,
      extensions: [makeTlv(0x02, new Uint8Array([1]), false)],
      share: new Uint8Array([1, 2, 3]),
    });
    const parsedShare = parse(share);
    expect(parsedShare.kind).toBe(KIND_SHARE);
    expect(parsedShare.version).toBe(2);
    if (parsedShare.kind !== KIND_SHARE) throw new Error('expected share');
    expect(Array.from(parsedShare.share)).toEqual([1, 2, 3]);
  });

  it('warns for unknown non-critical TLVs and rejects unknown critical TLVs', () => {
    const base = {
      bundleId: new Uint8Array(8),
      kemAlg: 'ml-kem-512' as const,
      aeadAlg: 'aes-256-gcm' as const,
      kdfAlg: 'hkdf-sha256' as const,
      flags: { passphrase: false },
      argon2: { tCost: 3, memLog2KiB: 16, parallelism: 1 },
      t: 2,
      n: 3,
      chunkIdx: 0,
      chunkTotal: 1,
      payload: new Uint8Array([1]),
    };
    const nonCritical = parse(
      encodeHeaderChunkV2({
        ...base,
        extensions: [makeTlv(0x7e, new Uint8Array([1]), false)],
      }),
    );
    expect(nonCritical.warnings?.[0]).toMatch(/unknown non-critical TLV/);
    expect(nonCritical.extensions).toHaveLength(0);

    expect(() =>
      parse(
        encodeHeaderChunkV2({
          ...base,
          extensions: [makeTlv(0x7e, new Uint8Array([1]), true)],
        }),
      ),
    ).toThrow(/unknown critical TLV/);
  });

  it('rejects truncated SSS2 payloads', () => {
    const raw = encodeShareV2({
      bundleId: new Uint8Array(8),
      kemAlg: 'ml-kem-512',
      t: 2,
      n: 3,
      shareIdx: 1,
      share: new Uint8Array([1, 2, 3]),
    });
    expect(() => parse(raw.slice(0, -1))).toThrow(/truncated share payload/);
  });
});

describe('high-level v2 behavior', () => {
  it('keeps plain flat no-metadata bundles on SSS1', () => {
    const bundle = encodeSecret('plain v1', { ...FAST, threshold: 2, shares: 3 });
    expect(bundle.formatVersion).toBe(1);
    expect(Array.from(fromBase45(bundle.headerQrs[0]!).slice(0, 4))).toEqual(Array.from(MAGIC));
    const decoded = decodeSecret([...bundle.headerQrs, ...bundle.shareQrs.slice(0, 2)]);
    expect(decoded.status).toBe('ok');
    if (decoded.status === 'ok') expect(decoded.plaintext).toBe('plain v1');
  });

  it('uses SSS2 for metadata and verifies share metadata after quorum', () => {
    const bundle = encodeSecret('metadata v2', {
      ...FAST,
      threshold: 2,
      shares: 3,
      metadata: { bundleLabel: 'estate', issuedDate: '2026-04-24' },
      custodians: [
        { id: 'alice', name: 'Alice' },
        { id: 'bob', name: 'Bob' },
        { id: 'chandra', name: 'Chandra' },
      ],
    });
    expect(bundle.formatVersion).toBe(2);
    expect(Array.from(fromBase45(bundle.headerQrs[0]!).slice(0, 4))).toEqual(Array.from(MAGIC_V2));

    const decoded = decodeBundle([...bundle.headerQrs, ...bundle.shareQrs.slice(0, 2)]);
    expect(decoded.status).toBe('ok');
    if (decoded.status !== 'ok' || decoded.kind !== 'secret') throw new Error('expected secret');
    expect(decoded.plaintext).toBe('metadata v2');
    expect(decoded.metadata[0]?.verification.status).toBe('verified');
    if (decoded.metadata[0]?.verification.status === 'verified') {
      expect(decoded.metadata[0].verification.metadata.custodianName).toBe('Alice');
    }
  });

  it('detects tampered metadata without breaking share reconstruction', () => {
    const bundle = encodeSecret('metadata tamper', {
      ...FAST,
      threshold: 2,
      shares: 3,
      metadata: { bundleLabel: 'tamper-check' },
      custodians: [
        { id: 'alice', name: 'Alice' },
        { id: 'bob', name: 'Bob' },
        { id: 'chandra', name: 'Chandra' },
      ],
    });
    const tamperedShare = toBase45(flipShareMetadataByte(fromBase45(bundle.shareQrs[0]!)));
    const decoded = decodeBundle([...bundle.headerQrs, tamperedShare, bundle.shareQrs[1]!]);
    expect(decoded.status).toBe('ok');
    if (decoded.status !== 'ok') throw new Error('expected ok');
    expect(decoded.metadata.find((m) => m.shareIdx === 1)?.verification.status).toBe('tampered');
  });

  it('recovers weighted flat policies by point count', () => {
    const bundle = encodeSecret('weighted v2', {
      ...FAST,
      threshold: 3,
      shares: 3,
      custodians: [
        { id: 'alice', name: 'Alice', weight: 2 },
        { id: 'bob', name: 'Bob', weight: 1 },
        { id: 'chandra', name: 'Chandra', weight: 1 },
      ],
    });
    const aliceBob = decodeSecret([...bundle.headerQrs, bundle.shareQrs[0]!, bundle.shareQrs[1]!]);
    expect(aliceBob.status).toBe('ok');
    if (aliceBob.status === 'ok') expect(aliceBob.plaintext).toBe('weighted v2');

    const bobChandra = decodeBundle([...bundle.headerQrs, bundle.shareQrs[1]!, bundle.shareQrs[2]!]);
    expect(bobChandra.status).toBe('need-more');
    if (bobChandra.status === 'need-more') {
      expect(bobChandra.policyProgress?.available).toBe(2);
      expect(bobChandra.policyProgress?.required).toBe(3);
    }
  });

  it('evaluates tree policies instead of raw share count', () => {
    const policy = {
      type: 'AND',
      children: [
        { type: 'LEAF', custodianId: 'alice' },
        {
          type: 'OR',
          children: [
            { type: 'LEAF', custodianId: 'bob' },
            { type: 'LEAF', custodianId: 'chandra' },
          ],
        },
      ],
    } satisfies EncodeOptions['policy'];
    const bundle = encodeSecret('tree v2', {
      ...FAST,
      threshold: 2,
      shares: 3,
      custodians: [{ id: 'alice' }, { id: 'bob' }, { id: 'chandra' }],
      policy,
    });

    const aliceBob = decodeSecret([...bundle.headerQrs, bundle.shareQrs[0]!, bundle.shareQrs[1]!]);
    expect(aliceBob.status).toBe('ok');
    const aliceChandra = decodeSecret([...bundle.headerQrs, bundle.shareQrs[0]!, bundle.shareQrs[2]!]);
    expect(aliceChandra.status).toBe('ok');
    const bobChandra = decodeBundle([...bundle.headerQrs, bundle.shareQrs[1]!, bundle.shareQrs[2]!]);
    expect(bobChandra.status).toBe('need-more');
  });

  it('decrypts vault blobs and allows edits without changing QR shares', () => {
    const bundle = encodeSecret('vault v2', {
      ...FAST,
      threshold: 2,
      shares: 3,
      vaultMode: true,
    });
    expect(bundle.vaultBlob).toBeInstanceOf(Uint8Array);
    const qrs = [...bundle.headerQrs, ...bundle.shareQrs.slice(0, 2)];
    const decoded = decodeBundle(qrs, { vaultBlob: bundle.vaultBlob });
    expect(decoded.status).toBe('ok');
    if (decoded.status !== 'ok' || decoded.kind !== 'vault' || !decoded.vault) {
      throw new Error('expected vault');
    }
    expect(new TextDecoder().decode(decoded.vault.entries[0]?.data)).toBe('vault v2');

    const edited = updateVaultEntries(decoded.vaultRootKey, bundle.vaultBlob!, [
      { id: 'secret', name: 'secret.txt', data: new TextEncoder().encode('edited vault') },
    ]);
    const afterEdit = decodeBundle(qrs, { vaultBlob: edited });
    expect(afterEdit.status).toBe('ok');
    if (afterEdit.status !== 'ok' || afterEdit.kind !== 'vault' || !afterEdit.vault) {
      throw new Error('expected edited vault');
    }
    expect(new TextDecoder().decode(afterEdit.vault.entries[0]?.data)).toBe('edited vault');

    const other = encodeSecret('other vault', { ...FAST, threshold: 2, shares: 3, vaultMode: true });
    const wrong = decodeBundle(qrs, { vaultBlob: other.vaultBlob });
    expect(wrong.status).toBe('error');
    if (wrong.status === 'error') expect(wrong.error).toMatch(/vault blob does not match/);
  });

  it('keeps time-locked payloads locked until an adapter unwraps them', () => {
    const adapter: TimeLockAdapter = {
      lock: (plaintext, info) => xor(plaintext, info.round & 0xff),
      unlock: (ciphertext, info) => xor(ciphertext, info.round & 0xff),
    };
    const bundle = encodeSecret('timelock v2', {
      ...FAST,
      threshold: 2,
      shares: 3,
      metadata: { bundleLabel: 'timelocked' },
      timeLocks: { round: 12345, adapter },
    });
    const qrs = [...bundle.headerQrs, ...bundle.shareQrs.slice(0, 2)];
    const locked = decodeBundle(qrs);
    expect(locked.status).toBe('need-more');
    if (locked.status === 'need-more') {
      expect(locked.lockedShares).toHaveLength(2);
      expect(locked.metadata[0]?.verification.status).toBe('unverified');
    }
    const unlocked = decodeBundle(qrs, { timeLockAdapter: adapter });
    expect(unlocked.status).toBe('ok');
    if (unlocked.status !== 'ok' || unlocked.kind !== 'secret') throw new Error('expected secret');
    expect(unlocked.plaintext).toBe('timelock v2');
  });

  it('rejects mixed SSS1 and SSS2 payload sets', () => {
    const v1 = encodeSecret('v1', { ...FAST, threshold: 2, shares: 3 });
    const v2 = encodeSecret('v2', {
      ...FAST,
      threshold: 2,
      shares: 3,
      metadata: { bundleLabel: 'v2' },
    });
    const decoded = decodeBundle([...v1.headerQrs, v2.shareQrs[0]!]);
    expect(decoded.status).toBe('error');
    if (decoded.status === 'error') expect(decoded.error).toMatch(/mixed SSS1\/SSS2/);
  });
});

function flipShareMetadataByte(raw: Uint8Array): Uint8Array {
  const out = new Uint8Array(raw);
  const extLen = (out[18]! << 8) | out[19]!;
  let offset = 20;
  const end = offset + extLen;
  while (offset < end) {
    const tag = out[offset]!;
    const len = (out[offset + 1]! << 8) | out[offset + 2]!;
    const valueStart = offset + 3;
    if ((tag & 0x7f) === TLV_SHARE_METADATA && len > 0) {
      out[valueStart] ^= 0x01;
      return out;
    }
    offset = valueStart + len;
  }
  throw new Error('metadata TLV not found');
}

function xor(input: Uint8Array, byte: number): Uint8Array {
  const out = new Uint8Array(input.length);
  for (let i = 0; i < input.length; i++) out[i] = input[i]! ^ byte;
  return out;
}
