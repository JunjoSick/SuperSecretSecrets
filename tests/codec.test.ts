import { describe, expect, it } from 'vitest';
import {
  encodeHeaderChunk,
  encodeShare,
  parse,
  toBase45,
  fromBase45,
  KIND_HEADER,
  KIND_SHARE,
  MAGIC,
} from '../src/crypto/codec';

describe('codec', () => {
  it('roundtrips a header chunk', () => {
    const bundleId = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
    const payload = new Uint8Array(123).fill(0xab);
    const raw = encodeHeaderChunk({
      bundleId,
      kemAlg: 'ml-kem-768',
      aeadAlg: 'aes-256-gcm',
      kdfAlg: 'hkdf-sha256',
      flags: { passphrase: true },
      argon2: { tCost: 3, memLog2KiB: 16, parallelism: 1 },
      t: 3,
      n: 5,
      chunkIdx: 0,
      chunkTotal: 1,
      payload,
    });
    const parsed = parse(raw);
    expect(parsed.kind).toBe(KIND_HEADER);
    if (parsed.kind !== KIND_HEADER) throw new Error();
    expect(parsed.version).toBe(1);
    expect(Array.from(parsed.bundleId)).toEqual(Array.from(bundleId));
    expect(parsed.kemAlg).toBe('ml-kem-768');
    expect(parsed.aeadAlg).toBe('aes-256-gcm');
    expect(parsed.kdfAlg).toBe('hkdf-sha256');
    expect(parsed.flags.passphrase).toBe(true);
    expect(parsed.argon2).toEqual({ tCost: 3, memLog2KiB: 16, parallelism: 1 });
    expect(parsed.t).toBe(3);
    expect(parsed.n).toBe(5);
    expect(parsed.chunkIdx).toBe(0);
    expect(parsed.chunkTotal).toBe(1);
    expect(Array.from(parsed.payload)).toEqual(Array.from(payload));
  });

  it('roundtrips a share', () => {
    const bundleId = new Uint8Array([9, 8, 7, 6, 5, 4, 3, 2]);
    const share = new Uint8Array(65).fill(0xcd);
    share[0] = 3;
    const raw = encodeShare({
      bundleId,
      kemAlg: 'ml-kem-768',
      t: 3,
      n: 5,
      shareIdx: 3,
      share,
    });
    const parsed = parse(raw);
    expect(parsed.kind).toBe(KIND_SHARE);
    if (parsed.kind !== KIND_SHARE) throw new Error();
    expect(parsed.shareIdx).toBe(3);
    expect(Array.from(parsed.share)).toEqual(Array.from(share));
  });

  it('rejects wrong magic', () => {
    const bogus = new Uint8Array([0, 0, 0, 0, 1, 1]);
    expect(() => parse(bogus)).toThrow();
  });

  it('rejects unknown version', () => {
    const raw = encodeShare({
      bundleId: new Uint8Array(8),
      kemAlg: 'ml-kem-768',
      t: 3,
      n: 5,
      shareIdx: 1,
      share: new Uint8Array([1, 2, 3]),
    });
    raw[4] = 99;
    expect(() => parse(raw)).toThrow(/unsupported version/);
  });

  it('base45 roundtrip preserves bytes', () => {
    const raw = new Uint8Array(200);
    crypto.getRandomValues(raw);
    const b45 = toBase45(raw);
    expect(b45.length).toBeGreaterThan(0);
    expect(Array.from(fromBase45(b45))).toEqual(Array.from(raw));
  });

  it('base45 roundtrip works without Node Buffer (browser-equivalent env)', () => {
    // Simulate the mobile-browser condition where `Buffer` is not defined.
    // Our inline base45 must not rely on it — the old `base45` npm dep did,
    // which is what caused "Buffer is not defined" on Brave mobile.
    const saved = (globalThis as unknown as { Buffer?: unknown }).Buffer;
    try {
      delete (globalThis as unknown as { Buffer?: unknown }).Buffer;
      for (const n of [1, 2, 3, 16, 100, 513]) {
        const raw = new Uint8Array(n);
        crypto.getRandomValues(raw);
        const decoded = fromBase45(toBase45(raw));
        expect(Array.from(decoded)).toEqual(Array.from(raw));
      }
    } finally {
      (globalThis as unknown as { Buffer?: unknown }).Buffer = saved;
    }
  });

  it('base45 matches RFC 9285 test vectors', () => {
    // From RFC 9285, Section 4.4
    const vectors: Array<[string, string]> = [
      ['AB', 'BB8'],
      ['Hello!!', '%69 VD92EX0'],
      ['base-45', 'UJCLQE7W581'],
      ['ietf!', 'QED8WEX0'],
    ];
    for (const [plain, encoded] of vectors) {
      const raw = new TextEncoder().encode(plain);
      expect(toBase45(raw)).toBe(encoded);
      expect(new TextDecoder().decode(fromBase45(encoded))).toBe(plain);
    }
  });

  it('fromBase45 rejects invalid characters and bad lengths', () => {
    expect(() => fromBase45('!!!')).toThrow(/invalid base45/);
    // Dangling single char (length % 3 == 1) is invalid per RFC 9285.
    expect(() => fromBase45('A')).toThrow(/dangling/);
  });

  it('magic bytes are SSS1', () => {
    expect(new TextDecoder().decode(MAGIC)).toBe('SSS1');
  });
});
