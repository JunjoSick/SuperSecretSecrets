import { describe, expect, it } from 'vitest';
import {
  decodeAndDiscloseVaultEntry,
  decodeBundle,
  decodeVaultDisclosure,
  encodeSecret,
  encodeVaultDisclosure,
  verifyVaultDisclosure,
} from '../src/crypto';
import {
  encodeHeaderChunkV3,
  encodeShareV3,
  fromBase45,
  KIND_HEADER,
  KIND_SHARE,
  makeTlv,
  parse,
  TLV_DECRYPTION_PROOF,
  TLV_PLAINTEXT_COMMITMENT,
  TLV_POLICY_COMMITMENT,
  TLV_SHARE_COMMIT_PROOF,
  toBase45,
} from '../src/crypto/codec';
import {
  encodeDecryptionProofEnvelope,
} from '../src/crypto/zk/decryption-proof-envelope';
import { updateVaultEntries } from '../src/crypto/vault';

const FAST = {
  threshold: 2,
  shares: 3,
  kemAlg: 'ml-kem-512' as const,
  aeadAlg: 'aes-256-gcm' as const,
  kdfAlg: 'hkdf-sha256' as const,
  maxHeaderBytes: 4096,
};

const TINY_PNG = new Uint8Array([
  0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d,
  0x49, 0x48, 0x44, 0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
  0x08, 0x06, 0x00, 0x00, 0x00, 0x1f, 0x15, 0xc4, 0x89, 0x00, 0x00, 0x00,
  0x0a, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9c, 0x63, 0x00, 0x01, 0x00, 0x00,
  0x05, 0x00, 0x01, 0x0d, 0x0a, 0x2d, 0xb4, 0x00, 0x00, 0x00, 0x00, 0x49,
  0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82,
]);

function expectBytesEqual(actual: Uint8Array, expected: Uint8Array): void {
  expect(Array.from(actual)).toEqual(Array.from(expected));
}

describe('v3 pipeline: opts.zk', () => {
  it('encodeSecret with zk:true emits version=3 bundles', () => {
    const bundle = encodeSecret('hello v3', { ...FAST, zk: true });
    expect(bundle.formatVersion).toBe(3);
    for (const qr of [...bundle.headerQrs, ...bundle.shareQrs]) {
      const raw = fromBase45(qr);
      expect(raw[4]).toBe(3);
    }
  });

  it('default (no zk) still emits v1 or v2 untouched', () => {
    const v1 = encodeSecret('classic flow', FAST);
    expect(v1.formatVersion).toBe(1);
    const v2 = encodeSecret('with metadata', { ...FAST, metadata: { bundleLabel: 'foo' } });
    expect(v2.formatVersion).toBe(2);
  });

  it('round-trips a zk-enabled bundle through encode/decode', () => {
    const bundle = encodeSecret('round-trip plaintext', { ...FAST, zk: true });
    const qrs = [...bundle.headerQrs, ...bundle.shareQrs.slice(0, 2)];
    const decoded = decodeBundle(qrs);
    expect(decoded.status).toBe('ok');
    if (decoded.status !== 'ok' || decoded.kind !== 'secret') {
      throw new Error('expected secret');
    }
    expect(decoded.plaintext).toBe('round-trip plaintext');
  });

  it('carries valid per-share Schnorr commitment proofs', () => {
    const bundle = encodeSecret('share proofs', { ...FAST, zk: true });
    for (const qr of bundle.shareQrs) {
      const parsed = parse(fromBase45(qr));
      if (parsed.kind !== KIND_SHARE) throw new Error('expected share');
      const proof = parsed.extensions?.find((extension) => extension.tagId === TLV_SHARE_COMMIT_PROOF);
      expect(proof?.value.length).toBe(128);
    }

    const decoded = decodeBundle([...bundle.headerQrs, ...bundle.shareQrs.slice(0, 2)]);
    expect(decoded.status).toBe('ok');
    if (decoded.status !== 'ok' || decoded.kind !== 'secret') throw new Error('expected secret');
    expect(decoded.metadata.find((entry) => entry.shareIdx === 1)?.zkVerification).toBe('verified');
    expect(decoded.metadata.find((entry) => entry.shareIdx === 2)?.zkVerification).toBe('verified');
  });

  it('warns when a share commitment proof is tampered without dropping the share', () => {
    const bundle = encodeSecret('tamper share proof', { ...FAST, zk: true });
    const parsed = parse(fromBase45(bundle.shareQrs[0]!));
    if (parsed.kind !== KIND_SHARE) throw new Error('expected share');
    const proof = parsed.extensions?.find((extension) => extension.tagId === TLV_SHARE_COMMIT_PROOF);
    if (!proof) throw new Error('expected share proof');
    const tampered = proof.value.slice();
    tampered[0] ^= 0x01;
    const extensions = (parsed.extensions ?? []).map((extension) =>
      extension.tagId === TLV_SHARE_COMMIT_PROOF
        ? makeTlv(TLV_SHARE_COMMIT_PROOF, tampered, true)
        : makeTlv(extension.tagId, extension.value, extension.critical),
    );
    const reframed = encodeShareV3({
      bundleId: parsed.bundleId,
      kemAlg: parsed.kemAlg,
      t: parsed.t,
      n: parsed.n,
      shareIdx: parsed.shareIdx,
      extensions,
      share: parsed.share,
    });

    const decoded = decodeBundle([...bundle.headerQrs, toBase45(reframed), bundle.shareQrs[1]!]);
    expect(decoded.status).toBe('ok');
    if (decoded.status !== 'ok' || decoded.kind !== 'secret') throw new Error('expected secret');
    expect(decoded.plaintext).toBe('tamper share proof');
    expect(decoded.warnings.some((warning) => /commitment proof/.test(warning))).toBe(true);
    expect(decoded.metadata.find((entry) => entry.shareIdx === 1)?.zkVerification).toBe('tampered');
  });

  it('streams ZK commitment verification progress during decode', () => {
    const bundle = encodeSecret('zk progress', { ...FAST, zk: true });
    const progress: Array<{ check: string; status: string; done: number; total: number }> = [];
    const decoded = decodeBundle([...bundle.headerQrs, ...bundle.shareQrs.slice(0, 2)], {
      onZkProgress: (event) => progress.push(event),
    });
    expect(decoded.status).toBe('ok');
    expect(progress.some((event) => event.check === 'policy' && event.status === 'verified')).toBe(true);
    expect(progress.some((event) => event.check === 'plaintext' && event.status === 'verified')).toBe(true);
    expect(progress.at(-1)?.done).toBe(progress.at(-1)?.total);
  });

  it('rejects a bundle whose policy-commitment TLV does not match the manifest', () => {
    const bundle = encodeSecret('tamper test', { ...FAST, zk: true });
    const headerRaw = fromBase45(bundle.headerQrs[0]!);
    const parsed = parse(headerRaw);
    if (parsed.kind !== KIND_HEADER) throw new Error('expected header');
    const tamperedExtensions: { tag: number; value: Uint8Array }[] = [
      ...(parsed.extensions ?? []).filter((e) => e.tagId !== TLV_POLICY_COMMITMENT),
      makeTlv(TLV_POLICY_COMMITMENT, new Uint8Array(32).fill(0xff), true),
    ];
    const reframed = encodeHeaderChunkV3({
      bundleId: parsed.bundleId,
      kemAlg: parsed.kemAlg,
      aeadAlg: parsed.aeadAlg,
      kdfAlg: parsed.kdfAlg,
      flags: parsed.flags,
      argon2: parsed.argon2,
      t: parsed.t,
      n: parsed.n,
      chunkIdx: parsed.chunkIdx,
      chunkTotal: parsed.chunkTotal,
      extensions: tamperedExtensions,
      payload: parsed.payload,
    });
    const tamperedQrs = [toBase45(reframed), ...bundle.shareQrs.slice(0, 2)];
    const decoded = decodeBundle(tamperedQrs);
    expect(decoded.status).toBe('error');
    if (decoded.status === 'error') {
      expect(decoded.error).toMatch(/policy manifest/);
    }
  });

  it('rejects a bundle whose plaintext-commitment TLV does not match the recovered plaintext', () => {
    const bundle = encodeSecret('tamper plaintext commit', { ...FAST, zk: true });
    const headerRaw = fromBase45(bundle.headerQrs[0]!);
    const parsed = parse(headerRaw);
    if (parsed.kind !== KIND_HEADER) throw new Error('expected header');
    const tamperedExtensions: { tag: number; value: Uint8Array }[] = [
      ...(parsed.extensions ?? []).filter((e) => e.tagId !== TLV_PLAINTEXT_COMMITMENT),
      makeTlv(TLV_PLAINTEXT_COMMITMENT, new Uint8Array(32).fill(0xaa), true),
    ];
    const reframed = encodeHeaderChunkV3({
      bundleId: parsed.bundleId,
      kemAlg: parsed.kemAlg,
      aeadAlg: parsed.aeadAlg,
      kdfAlg: parsed.kdfAlg,
      flags: parsed.flags,
      argon2: parsed.argon2,
      t: parsed.t,
      n: parsed.n,
      chunkIdx: parsed.chunkIdx,
      chunkTotal: parsed.chunkTotal,
      extensions: tamperedExtensions,
      payload: parsed.payload,
    });
    const tamperedQrs = [toBase45(reframed), ...bundle.shareQrs.slice(0, 2)];
    const decoded = decodeBundle(tamperedQrs);
    expect(decoded.status).toBe('error');
    if (decoded.status === 'error') {
      expect(decoded.error).toMatch(/plaintext does not match/);
    }
  });

  it('surfaces unsupported decryption-proof TLVs without blocking recovery', () => {
    const bundle = encodeSecret('audited secret', { ...FAST, zk: true });
    const headers = bundle.headerQrs
      .map((qr) => parse(fromBase45(qr)))
      .filter((qr): qr is Extract<ReturnType<typeof parse>, { kind: typeof KIND_HEADER }> => qr.kind === KIND_HEADER)
      .sort((a, b) => a.chunkIdx - b.chunkIdx);
    const first = headers[0]!;
    const decryptionProof = encodeDecryptionProofEnvelope(
      {
        envelopeVersion: 1,
        schemeId: 0x44,
        flags: 0,
        relationId: 'unsupported-test-relation',
        relationDigest: new Uint8Array(32).fill(0x44),
        verifierArtifactDigest: new Uint8Array(32).fill(0x77),
        transcriptDigest: new Uint8Array(32).fill(0x88),
        proofBytes: new Uint8Array([1, 2, 3]),
      },
    );
    const reframed = encodeHeaderChunkV3({
      bundleId: first.bundleId,
      kemAlg: first.kemAlg,
      aeadAlg: first.aeadAlg,
      kdfAlg: first.kdfAlg,
      flags: first.flags,
      argon2: first.argon2,
      t: first.t,
      n: first.n,
      chunkIdx: first.chunkIdx,
      chunkTotal: first.chunkTotal,
      extensions: [...(first.extensions ?? []), makeTlv(TLV_DECRYPTION_PROOF, decryptionProof, false)],
      payload: first.payload,
    });

    const decoded = decodeBundle([toBase45(reframed), ...bundle.headerQrs.slice(1), ...bundle.shareQrs.slice(0, 2)]);
    expect(decoded.status).toBe('ok');
    if (decoded.status !== 'ok' || decoded.kind !== 'secret') throw new Error('expected secret');
    expect(decoded.plaintext).toBe('audited secret');
    expect(decoded.decryptionProof).toEqual({
      status: 'unsupported',
      schemeId: 0x44,
    });
    expect(decoded.warnings.some((warning) => /decryption proof scheme/.test(warning))).toBe(true);
  });

  it('zk + vault round-trips and emits a vault-tree-root TLV', () => {
    const bundle = encodeSecret('vault zk', {
      ...FAST,
      zk: true,
      vaultMode: true,
      vaultEntries: [
        { id: 'one', name: 'one.txt', data: new TextEncoder().encode('first entry') },
        { id: 'two', name: 'two.txt', data: new TextEncoder().encode('second entry') },
      ],
    });
    expect(bundle.formatVersion).toBe(3);
    expect(bundle.vaultBlob).toBeDefined();
    const decoded = decodeBundle([...bundle.headerQrs, ...bundle.shareQrs.slice(0, 2)], {
      vaultBlob: bundle.vaultBlob!,
    });
    expect(decoded.status).toBe('ok');
    if (decoded.status !== 'ok' || decoded.kind !== 'vault') throw new Error('expected vault');
    expect(decoded.vault?.entries.length).toBe(2);
  });

  it('rejects a v3 vault blob that no longer matches the published vault-tree-root TLV', () => {
    const bundle = encodeSecret('vault zk', {
      ...FAST,
      zk: true,
      vaultMode: true,
      vaultEntries: [
        { id: 'one', name: 'one.txt', data: new TextEncoder().encode('first entry') },
        { id: 'two', name: 'two.txt', data: new TextEncoder().encode('second entry') },
      ],
    });
    const qrs = [...bundle.headerQrs, ...bundle.shareQrs.slice(0, 2)];
    const decoded = decodeBundle(qrs, { vaultBlob: bundle.vaultBlob! });
    if (decoded.status !== 'ok' || decoded.kind !== 'vault') throw new Error('expected vault');

    const edited = updateVaultEntries(decoded.vaultRootKey, bundle.vaultBlob!, [
      { id: 'one', name: 'one.txt', data: new TextEncoder().encode('first entry') },
      { id: 'two', name: 'two.txt', data: new TextEncoder().encode('changed entry') },
    ]);
    const afterEdit = decodeBundle(qrs, { vaultBlob: edited });
    expect(afterEdit.status).toBe('error');
    if (afterEdit.status === 'error') expect(afterEdit.error).toMatch(/vault-tree root/);
  });

  it('exports and verifies a single-entry vault disclosure', () => {
    const bundle = encodeSecret('vault disclosure', {
      ...FAST,
      zk: true,
      vaultMode: true,
      vaultEntries: [
        { id: 'one', name: 'one.txt', data: new TextEncoder().encode('first entry') },
        { id: 'two', name: 'two.txt', data: new TextEncoder().encode('second entry') },
        { id: 'three', name: 'three.txt', data: new TextEncoder().encode('third entry') },
      ],
    });
    const disclosure = decodeAndDiscloseVaultEntry(
      [...bundle.headerQrs, ...bundle.shareQrs.slice(0, 2)],
      bundle.vaultBlob!,
      'two',
    );
    if ('status' in disclosure) throw new Error(disclosure.error);

    expect(disclosure.entry.id).toBe('two');
    expect(new TextDecoder().decode(disclosure.entry.data)).toBe('second entry');
    expect(verifyVaultDisclosure(disclosure)).toBe(true);

    const decodedDisclosure = decodeVaultDisclosure(encodeVaultDisclosure(disclosure));
    expect(decodedDisclosure.entry.name).toBe('two.txt');
    expect(verifyVaultDisclosure(decodedDisclosure)).toBe(true);

    decodedDisclosure.entry.data[0] ^= 0x01;
    expect(verifyVaultDisclosure(decodedDisclosure)).toBe(false);
  });

  it('preserves image vault entry bytes and proves the image in the vault tree', () => {
    const bundle = encodeSecret('tiny.png', {
      ...FAST,
      zk: true,
      vaultMode: true,
      vaultEntries: [
        {
          id: 'image',
          name: 'tiny.png',
          contentType: 'image/png',
          data: TINY_PNG,
        },
      ],
    });
    const decoded = decodeBundle([...bundle.headerQrs, ...bundle.shareQrs.slice(0, 2)], {
      vaultBlob: bundle.vaultBlob!,
    });
    expect(decoded.status).toBe('ok');
    if (decoded.status !== 'ok' || decoded.kind !== 'vault' || !decoded.vault) {
      throw new Error('expected image vault');
    }
    const entry = decoded.vault.entries[0]!;
    expect(entry.name).toBe('tiny.png');
    expect(entry.contentType).toBe('image/png');
    expectBytesEqual(entry.data, TINY_PNG);

    const disclosure = decodeAndDiscloseVaultEntry(
      [...bundle.headerQrs, ...bundle.shareQrs.slice(0, 2)],
      bundle.vaultBlob!,
      'image',
    );
    if ('status' in disclosure) throw new Error(disclosure.error);
    expect(disclosure.entry.contentType).toBe('image/png');
    expectBytesEqual(disclosure.entry.data, TINY_PNG);
    expect(verifyVaultDisclosure(disclosure)).toBe(true);
  });

  it('requires a published v3 vault-tree root before disclosing one vault entry', () => {
    const bundle = encodeSecret('vault v2', {
      ...FAST,
      vaultMode: true,
      vaultEntries: [
        { id: 'one', name: 'one.txt', data: new TextEncoder().encode('first entry') },
      ],
    });
    const disclosure = decodeAndDiscloseVaultEntry(
      [...bundle.headerQrs, ...bundle.shareQrs.slice(0, 2)],
      bundle.vaultBlob!,
      'one',
    );
    expect('status' in disclosure).toBe(true);
    if (!('status' in disclosure)) throw new Error('expected disclosure error');
    expect(disclosure.error).toMatch(/vault-tree root/);
  });
});
