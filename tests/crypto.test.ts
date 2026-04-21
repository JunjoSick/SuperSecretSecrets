import { describe, expect, it } from 'vitest';
import { encodeSecret, decodeSecret, DEFAULT_OPTIONS } from '../src/crypto';

const PLAINTEXT_SAMPLES = [
  'hello post-quantum world',
  'short',
  'a'.repeat(4096),
  '🔐 unicode: café, привет, 日本語, emoji 🎉',
  JSON.stringify({ bank: '1234', note: 'rainy day' }),
];

describe('high-level encode / decode', () => {
  it('roundtrips with defaults (T=3 of N=5, ML-KEM-768, AES-GCM)', () => {
    for (const pt of PLAINTEXT_SAMPLES) {
      const bundle = encodeSecret(pt);
      expect(bundle.shareQrs).toHaveLength(5);
      expect(bundle.headerQrs.length).toBeGreaterThan(0);
      const result = decodeSecret([
        ...bundle.headerQrs,
        ...bundle.shareQrs.slice(0, 3),
      ]);
      expect(result.status).toBe('ok');
      if (result.status === 'ok') expect(result.plaintext).toBe(pt);
    }
  });

  it('any T of N shares decrypt', () => {
    const bundle = encodeSecret('any-T-works', { threshold: 3, shares: 5 });
    for (const picks of [[0, 1, 2], [0, 2, 4], [1, 3, 4], [2, 3, 4]]) {
      const qrs = [...bundle.headerQrs, ...picks.map((i) => bundle.shareQrs[i]!)];
      const r = decodeSecret(qrs);
      expect(r.status).toBe('ok');
      if (r.status === 'ok') expect(r.plaintext).toBe('any-T-works');
    }
  });

  it('T-1 shares returns need-more', () => {
    const bundle = encodeSecret('needs more', { threshold: 3, shares: 5 });
    const r = decodeSecret([...bundle.headerQrs, ...bundle.shareQrs.slice(0, 2)]);
    expect(r.status).toBe('need-more');
    if (r.status === 'need-more') {
      expect(r.sharesSeen).toBe(2);
      expect(r.threshold).toBe(3);
    }
  });

  it('missing header chunk returns need-more', () => {
    const bundle = encodeSecret('chunked '.repeat(200), {
      threshold: 2,
      shares: 3,
      maxHeaderBytes: 300,
    });
    expect(bundle.headerQrs.length).toBeGreaterThan(1);
    // Give all shares but only some header chunks
    const r = decodeSecret([bundle.headerQrs[0]!, ...bundle.shareQrs.slice(0, 2)]);
    expect(r.status).toBe('need-more');
  });

  it('tampered AEAD ciphertext is detected', () => {
    const bundle = encodeSecret('secret sauce');
    const last = bundle.headerQrs.length - 1;
    const raw = Array.from(bundle.headerQrs[last]!);
    // Mutate the last character (likely part of the AEAD ciphertext/tag)
    const flipped =
      raw.slice(0, -2).join('') +
      (raw.at(-2) === 'A' ? 'B' : 'A') +
      raw.at(-1);
    const tampered = [...bundle.headerQrs.slice(0, last), flipped, ...bundle.shareQrs.slice(0, 3)];
    const r = decodeSecret(tampered);
    // Either we fail at parse or at AEAD — both are acceptable
    expect(r.status === 'error' || r.status === 'need-more').toBe(true);
  });

  it('passphrase-protected roundtrip', () => {
    const bundle = encodeSecret('with passphrase', {
      passphrase: 'correct horse battery staple',
      argon2: { t: 2, m: 8 * 1024, p: 1 }, // fast for testing
    });
    const qrs = [...bundle.headerQrs, ...bundle.shareQrs.slice(0, 3)];
    const good = decodeSecret(qrs, 'correct horse battery staple');
    expect(good.status).toBe('ok');
    const bad = decodeSecret(qrs, 'wrong');
    expect(bad.status).toBe('error');
    const none = decodeSecret(qrs);
    expect(none.status).toBe('error');
  });

  it('works with ML-KEM-512 and ChaCha20-Poly1305', () => {
    const bundle = encodeSecret('alt algos', {
      kemAlg: 'ml-kem-512',
      aeadAlg: 'chacha20-poly1305',
      kdfAlg: 'hkdf-sha3-256',
      threshold: 2,
      shares: 4,
    });
    const r = decodeSecret([...bundle.headerQrs, ...bundle.shareQrs.slice(0, 2)]);
    expect(r.status).toBe('ok');
    if (r.status === 'ok') expect(r.plaintext).toBe('alt algos');
  });

  it('works with ML-KEM-1024', () => {
    const bundle = encodeSecret('big kem', { kemAlg: 'ml-kem-1024' });
    const r = decodeSecret([...bundle.headerQrs, ...bundle.shareQrs.slice(0, 3)]);
    expect(r.status).toBe('ok');
    if (r.status === 'ok') expect(r.plaintext).toBe('big kem');
  });

  it('rejects mixed-bundle QRs gracefully (uses majority bundle)', () => {
    const a = encodeSecret('bundle A');
    const b = encodeSecret('bundle B');
    // Three QRs from A + one stray from B
    const mixed = [...a.headerQrs, ...a.shareQrs.slice(0, 3), b.shareQrs[0]!];
    const r = decodeSecret(mixed);
    expect(r.status).toBe('ok');
    if (r.status === 'ok') expect(r.plaintext).toBe('bundle A');
  });

  it('defaults are safe-by-default', () => {
    expect(DEFAULT_OPTIONS.threshold).toBe(3);
    expect(DEFAULT_OPTIONS.shares).toBe(5);
    expect(DEFAULT_OPTIONS.kemAlg).toBe('ml-kem-768');
    expect(DEFAULT_OPTIONS.aeadAlg).toBe('aes-256-gcm');
    expect(DEFAULT_OPTIONS.kdfAlg).toBe('hkdf-sha256');
  });
});
