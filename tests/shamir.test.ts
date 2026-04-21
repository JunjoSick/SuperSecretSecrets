import { describe, expect, it } from 'vitest';
import { split, combine } from '../src/crypto/shamir';

describe('Shamir', () => {
  it('roundtrips a 64-byte secret with T=3 of N=5', () => {
    const secret = new Uint8Array(64);
    crypto.getRandomValues(secret);
    const shares = split(secret, 3, 5);
    expect(shares).toHaveLength(5);
    for (const s of shares) expect(s.length).toBe(65);
    // Any 3 combinations should reconstruct
    for (const pick of [[0, 1, 2], [0, 2, 4], [1, 3, 4], [2, 3, 4]]) {
      const recovered = combine(pick.map((i) => shares[i]!));
      expect(Array.from(recovered)).toEqual(Array.from(secret));
    }
  });

  it('T-1 shares do not reveal the secret (probabilistic check)', () => {
    const secret = new Uint8Array([1, 2, 3, 4, 5]);
    const shares = split(secret, 3, 5);
    // With only 2 shares, combine does NOT produce the original secret.
    const wrong = combine([shares[0]!, shares[1]!]);
    expect(Array.from(wrong)).not.toEqual(Array.from(secret));
  });

  it('works across the full byte range 0..255', () => {
    const secret = new Uint8Array(256);
    for (let i = 0; i < 256; i++) secret[i] = i;
    const shares = split(secret, 2, 3);
    const recovered = combine([shares[0]!, shares[2]!]);
    expect(Array.from(recovered)).toEqual(Array.from(secret));
  });

  it('rejects invalid parameters', () => {
    const secret = new Uint8Array([1]);
    expect(() => split(secret, 1, 5)).toThrow();
    expect(() => split(secret, 3, 2)).toThrow();
    expect(() => split(secret, 3, 300)).toThrow();
    expect(() => split(new Uint8Array(0), 2, 3)).toThrow();
  });

  it('rejects duplicate x-coordinates on combine', () => {
    const shares = split(new Uint8Array([42]), 2, 3);
    expect(() => combine([shares[0]!, shares[0]!])).toThrow();
  });

  it('supports N up to 255', () => {
    const secret = new Uint8Array([99, 100, 101]);
    const shares = split(secret, 5, 255);
    expect(shares).toHaveLength(255);
    const chosen = [10, 42, 100, 150, 200].map((i) => shares[i]!);
    expect(Array.from(combine(chosen))).toEqual(Array.from(secret));
  });
});
