import { afterEach, describe, expect, it, vi } from 'vitest';
import fixture from './fixtures/v3-bundle.json';
import {
  clearVdfDiscriminantCache,
  decodeBundle,
  encodeSecret,
  inspectQr,
} from '../src/crypto';
import {
  KIND_HEADER,
  KIND_SHARE,
  TLV_SHARE_COMMIT_PROOF,
  TLV_VAULT_TREE_ROOT,
  TLV_VDF_LOCK,
  TLV_VDF_PARAMS,
  TLV_VDF_PROOF,
} from '../src/crypto/codec';

const IMAGE_BYTES = new Uint8Array([
  0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a,
  0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52,
]);

function installDeterministicCrypto(seed: number) {
  let state = seed >>> 0;
  return vi.spyOn(globalThis.crypto, 'getRandomValues').mockImplementation((array) => {
    const bytes = new Uint8Array(array.buffer, array.byteOffset, array.byteLength);
    for (let i = 0; i < bytes.length; i++) {
      state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
      bytes[i] = (state >>> 24) & 0xff;
    }
    return array;
  });
}

function fixtureVaultBlob(): Uint8Array {
  return fromHex(fixture.vaultBlobHex);
}

function fromHex(value: string): Uint8Array {
  if (value.length % 2 !== 0) throw new Error('invalid hex length');
  const out = new Uint8Array(value.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(value.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function expectBytesEqual(actual: Uint8Array, expected: Uint8Array): void {
  expect(Array.from(actual)).toEqual(Array.from(expected));
}

describe('checked-in SSS3 fixture', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    clearVdfDiscriminantCache();
  });

  it('regenerates byte-identical QR and vault payloads under fixed RNG', () => {
    installDeterministicCrypto(0x53535333);
    clearVdfDiscriminantCache();
    const bundle = encodeSecret(fixture.plaintext, {
      threshold: 2,
      shares: 3,
      kemAlg: 'ml-kem-512',
      aeadAlg: 'aes-256-gcm',
      kdfAlg: 'hkdf-sha256',
      maxHeaderBytes: 4096,
      zk: true,
      vdf: { T: 4n, discriminantBits: 64 },
      vaultMode: true,
      vaultEntries: [
        {
          id: 'image',
          name: fixture.plaintext,
          contentType: 'image/png',
          data: IMAGE_BYTES,
        },
      ],
    });

    expect(bundle.formatVersion).toBe(3);
    expect(bundle.headerQrs).toEqual(fixture.headerQrs);
    expect(bundle.shareQrs).toEqual(fixture.shareQrs);
    expect(hex(bundle.vaultBlob ?? new Uint8Array())).toBe(fixture.vaultBlobHex);
  });

  it('decodes the checked-in v3 fixture and exposes the expected v3 TLVs', () => {
    const header = inspectQr(fixture.headerQrs[0]!);
    expect(header.kind).toBe(KIND_HEADER);
    if (header.kind !== KIND_HEADER) throw new Error('expected header');
    expect(header.version).toBe(3);
    expect(header.extensions?.some((extension) => extension.tagId === TLV_VAULT_TREE_ROOT)).toBe(true);
    expect(header.extensions?.some((extension) => extension.tagId === TLV_VDF_PARAMS)).toBe(true);

    const share = inspectQr(fixture.shareQrs[0]!);
    expect(share.kind).toBe(KIND_SHARE);
    if (share.kind !== KIND_SHARE) throw new Error('expected share');
    expect(share.version).toBe(3);
    expect(share.extensions?.some((extension) => extension.tagId === TLV_SHARE_COMMIT_PROOF)).toBe(true);
    expect(share.extensions?.some((extension) => extension.tagId === TLV_VDF_LOCK)).toBe(true);
    expect(share.extensions?.some((extension) => extension.tagId === TLV_VDF_PROOF)).toBe(true);

    const decoded = decodeBundle([...fixture.headerQrs, ...fixture.shareQrs.slice(0, 2)], {
      vaultBlob: fixtureVaultBlob(),
    });
    expect(decoded.status).toBe('ok');
    if (decoded.status !== 'ok' || decoded.kind !== 'vault' || !decoded.vault) {
      throw new Error('expected vault fixture');
    }
    expect(decoded.metadata.find((entry) => entry.shareIdx === 1)?.zkVerification).toBe('verified');
    expect(decoded.vault.entries[0]?.name).toBe(fixture.plaintext);
    expect(decoded.vault.entries[0]?.contentType).toBe('image/png');
    expectBytesEqual(decoded.vault.entries[0]!.data, IMAGE_BYTES);
  });
});
