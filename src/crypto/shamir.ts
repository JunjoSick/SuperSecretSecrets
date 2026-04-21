/**
 * Shamir's Secret Sharing over GF(2^8) with the AES irreducible polynomial (0x11b).
 *
 * Share layout (bytes):
 *   [0]     x-coordinate (1..255, unique per share)
 *   [1..L]  polynomial evaluation of each secret byte at x
 *
 * Shares have length `secret.length + 1`. Any T of N shares reconstruct the
 * original secret; strictly fewer than T reveal nothing (information-theoretic).
 */

const EXP = new Uint8Array(256);
const LOG = new Uint8Array(256);

(function initTables() {
  // Generator for GF(2^8) with AES reduction polynomial 0x11b.
  // 0x02 is NOT primitive; 0x03 (x + 1) is the standard primitive element.
  let x = 1;
  for (let i = 0; i < 255; i++) {
    EXP[i] = x;
    LOG[x] = i;
    // Multiply by 3: x = (x << 1) ^ x, reduced mod 0x11b
    let next = x ^ ((x << 1) & 0xff);
    if (x & 0x80) next ^= 0x1b;
    x = next;
  }
  EXP[255] = EXP[0]!;
})();

function gfMul(a: number, b: number): number {
  if (a === 0 || b === 0) return 0;
  return EXP[(LOG[a]! + LOG[b]!) % 255]!;
}

function gfDiv(a: number, b: number): number {
  if (b === 0) throw new Error('division by zero in GF(256)');
  if (a === 0) return 0;
  return EXP[(LOG[a]! + 255 - LOG[b]!) % 255]!;
}

function evalPoly(coeffs: Uint8Array, x: number): number {
  let result = 0;
  for (let i = coeffs.length - 1; i >= 0; i--) {
    result = gfMul(result, x) ^ coeffs[i]!;
  }
  return result;
}

function lagrangeInterpolateAtZero(xs: number[], ys: number[]): number {
  let result = 0;
  for (let i = 0; i < xs.length; i++) {
    let num = 1;
    let den = 1;
    for (let j = 0; j < xs.length; j++) {
      if (i === j) continue;
      num = gfMul(num, xs[j]!);
      den = gfMul(den, xs[i]! ^ xs[j]!);
    }
    result ^= gfMul(ys[i]!, gfDiv(num, den));
  }
  return result;
}

export type Share = Uint8Array;

export function split(
  secret: Uint8Array,
  threshold: number,
  shares: number,
  rng: (n: number) => Uint8Array = defaultRng,
): Share[] {
  if (!Number.isInteger(threshold) || !Number.isInteger(shares)) {
    throw new Error('threshold and shares must be integers');
  }
  if (threshold < 2) throw new Error('threshold must be >= 2');
  if (shares < threshold) throw new Error('shares must be >= threshold');
  if (shares > 255) throw new Error('shares must be <= 255');
  if (secret.length === 0) throw new Error('secret must not be empty');

  const L = secret.length;
  const out: Share[] = [];
  for (let i = 0; i < shares; i++) {
    const s = new Uint8Array(1 + L);
    s[0] = i + 1;
    out.push(s);
  }

  for (let byteIdx = 0; byteIdx < L; byteIdx++) {
    const coeffs = new Uint8Array(threshold);
    coeffs[0] = secret[byteIdx]!;
    const rand = rng(threshold - 1);
    for (let k = 1; k < threshold; k++) coeffs[k] = rand[k - 1]!;
    for (let i = 0; i < shares; i++) {
      out[i]![1 + byteIdx] = evalPoly(coeffs, i + 1);
    }
  }

  return out;
}

export function combine(shares: Share[]): Uint8Array {
  if (shares.length < 2) throw new Error('need at least 2 shares to combine');
  const L = shares[0]!.length - 1;
  if (L <= 0) throw new Error('invalid share length');
  const xs: number[] = [];
  for (const s of shares) {
    if (s.length !== L + 1) throw new Error('inconsistent share lengths');
    if (s[0] === 0) throw new Error('share x-coordinate must not be 0');
    if (xs.includes(s[0]!)) throw new Error('duplicate share x-coordinate');
    xs.push(s[0]!);
  }
  const secret = new Uint8Array(L);
  const ys: number[] = new Array(shares.length);
  for (let byteIdx = 0; byteIdx < L; byteIdx++) {
    for (let i = 0; i < shares.length; i++) ys[i] = shares[i]![1 + byteIdx]!;
    secret[byteIdx] = lagrangeInterpolateAtZero(xs, ys);
  }
  return secret;
}

function defaultRng(n: number): Uint8Array {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
}
