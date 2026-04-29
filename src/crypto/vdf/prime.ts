import { sha256 } from '@noble/hashes/sha2.js';

export type Rng = (n: number) => Uint8Array;

const defaultRng: Rng = (n) => {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
};

const SMALL_PRIMES: bigint[] = [
  2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n, 41n, 43n, 47n,
  53n, 59n, 61n, 67n, 71n, 73n, 79n, 83n, 89n, 97n, 101n, 103n, 107n, 109n, 113n,
];

const DET_WITNESSES: bigint[] = [2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n];
const DET_BOUND = 3317044064679887385961981n;

function modPow(base: bigint, exp: bigint, m: bigint): bigint {
  if (m === 1n) return 0n;
  let result = 1n;
  let b = ((base % m) + m) % m;
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % m;
    e >>= 1n;
    b = (b * b) % m;
  }
  return result;
}

function millerRabinWitness(n: bigint, a: bigint): boolean {
  if (n <= 1n) return false;
  if (a % n === 0n) return true;
  let d = n - 1n;
  let s = 0;
  while ((d & 1n) === 0n) {
    d >>= 1n;
    s++;
  }
  let x = modPow(a, d, n);
  if (x === 1n || x === n - 1n) return true;
  for (let i = 0; i < s - 1; i++) {
    x = (x * x) % n;
    if (x === n - 1n) return true;
    if (x === 1n) return false;
  }
  return false;
}

function trialDivision(n: bigint): boolean | null {
  for (const p of SMALL_PRIMES) {
    if (n === p) return true;
    if (n % p === 0n) return false;
  }
  return null;
}

function bytesToBigInt(b: Uint8Array): bigint {
  let n = 0n;
  for (const byte of b) n = (n << 8n) | BigInt(byte);
  return n;
}

export function isPrime(n: bigint, rounds = 40, rng: Rng = defaultRng): boolean {
  if (n < 2n) return false;
  const td = trialDivision(n);
  if (td !== null) return td;
  if (n < DET_BOUND) {
    for (const a of DET_WITNESSES) {
      if (a >= n) continue;
      if (!millerRabinWitness(n, a)) return false;
    }
    return true;
  }
  for (let i = 0; i < rounds; i++) {
    const len = Math.max(8, Math.ceil(bitLength(n) / 8));
    const a = (bytesToBigInt(rng(len)) % (n - 3n)) + 2n;
    if (!millerRabinWitness(n, a)) return false;
  }
  return true;
}

function bitLength(n: bigint): number {
  let bits = 0;
  let v = n < 0n ? -n : n;
  while (v > 0n) {
    bits++;
    v >>= 1n;
  }
  return bits;
}

export function samplePrimeCongruent3Mod4(bits: number, rng: Rng = defaultRng): bigint {
  if (!Number.isInteger(bits) || bits < 8 || bits > 4096) {
    throw new Error('bit size must be an integer in [8, 4096]');
  }
  const byteLen = Math.ceil(bits / 8);
  const topBit = 1n << BigInt(bits - 1);
  const mask = (1n << BigInt(bits)) - 1n;
  for (let attempt = 0; attempt < 200000; attempt++) {
    let n = bytesToBigInt(rng(byteLen)) & mask;
    n |= topBit;
    n = (n & ~3n) | 3n;
    if (isPrime(n, 40, rng)) return n;
  }
  throw new Error('failed to sample prime ≡ 3 (mod 4)');
}

export function hashToPrime(seed: Uint8Array, bits: number): bigint {
  if (!Number.isInteger(bits) || bits < 16 || bits > 4096) {
    throw new Error('hashToPrime bits must be an integer in [16, 4096]');
  }
  const byteLen = Math.ceil(bits / 8);
  const topBit = 1n << BigInt(bits - 1);
  const mask = (1n << BigInt(bits)) - 1n;
  const dst = new TextEncoder().encode('SSS3/vdf-fs/hashprime');
  const limit = 1n << 40n;
  for (let counter = 0n; counter < limit; counter++) {
    const ctrBytes = new Uint8Array(8);
    new DataView(ctrBytes.buffer).setBigUint64(0, counter, false);
    let acc = new Uint8Array(0);
    let block = 0;
    while (acc.length < byteLen) {
      const blkIdx = new Uint8Array(4);
      new DataView(blkIdx.buffer).setUint32(0, block, false);
      const input = new Uint8Array(dst.length + seed.length + ctrBytes.length + blkIdx.length);
      let o = 0;
      input.set(dst, o);
      o += dst.length;
      input.set(seed, o);
      o += seed.length;
      input.set(ctrBytes, o);
      o += ctrBytes.length;
      input.set(blkIdx, o);
      const out = sha256(input);
      const next = new Uint8Array(acc.length + out.length);
      next.set(acc, 0);
      next.set(out, acc.length);
      acc = next;
      block++;
    }
    let n = bytesToBigInt(acc.subarray(0, byteLen)) & mask;
    n |= topBit;
    n |= 1n;
    if (isPrime(n)) return n;
  }
  throw new Error('hashToPrime exhausted counter space');
}

function modPositive(a: bigint, m: bigint): bigint {
  const r = a % m;
  return r < 0n ? r + m : r;
}

/** Tonelli-Shanks: square root of n mod p (p odd prime). Returns null if n is not a QR. */
export function sqrtModPrime(n: bigint, p: bigint): bigint | null {
  const a = modPositive(n, p);
  if (a === 0n) return 0n;
  if (p === 2n) return a;
  // Euler's criterion: a^((p-1)/2) mod p = 1 iff QR, p-1 iff NR.
  const legendre = modPow(a, (p - 1n) / 2n, p);
  if (legendre === p - 1n) return null;
  if (legendre !== 1n) return null;
  if (p % 4n === 3n) {
    return modPow(a, (p + 1n) / 4n, p);
  }
  // Tonelli-Shanks general case
  let q = p - 1n;
  let s = 0n;
  while ((q & 1n) === 0n) {
    q >>= 1n;
    s++;
  }
  // Find a non-residue z
  let z = 2n;
  while (modPow(z, (p - 1n) / 2n, p) !== p - 1n) z++;
  let m = s;
  let c = modPow(z, q, p);
  let t = modPow(a, q, p);
  let r = modPow(a, (q + 1n) / 2n, p);
  while (true) {
    if (t === 1n) return r;
    let i = 0n;
    let tmp = t;
    while (tmp !== 1n) {
      tmp = (tmp * tmp) % p;
      i++;
      if (i === m) return null;
    }
    const b = modPow(c, 1n << (m - i - 1n), p);
    m = i;
    c = (b * b) % p;
    t = (t * c) % p;
    r = (r * b) % p;
  }
}

export function discriminantFromPrime(p: bigint): bigint {
  if (p < 3n) throw new Error('prime too small for discriminant');
  if (p % 4n !== 3n) throw new Error('prime must be ≡ 3 (mod 4)');
  const delta = -p;
  const mod4 = ((delta % 4n) + 4n) % 4n;
  if (mod4 !== 1n) throw new Error(`discriminant must be ≡ 1 (mod 4); got ${mod4}`);
  return delta;
}
