import { sha256 } from '@noble/hashes/sha2.js';
import {
  compose,
  discriminant,
  equal,
  type Form,
  identity,
  pow,
  reduce,
  serializeForm,
  square,
} from './classgroup.js';
import {
  discriminantFromPrime,
  hashToPrime,
  isPrime,
  samplePrimeCongruent3Mod4,
  sqrtModPrime,
  type Rng,
} from './prime.js';

const defaultRng: Rng = (n) => {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
};

export const FS_PRIME_BITS = 128;

export type VdfProgress = (done: bigint, total: bigint) => void;

/** Deterministically hash a seed to a non-principal reduced form of the given discriminant.
 *
 * Strategy: iterate small odd primes a; pick the first one where Δ is a QR mod a (so
 * b² ≡ Δ (mod a) is solvable). Lift to mod 4a by ensuring b is odd, since for Δ ≡ 1
 * (mod 4) and odd b we have b² ≡ 1 ≡ Δ (mod 4). Skip a seed-derived number of valid
 * primes so different seeds produce different generators.
 */
export function hashToForm(seed: Uint8Array, delta: bigint): Form {
  const dst = new TextEncoder().encode('SSS3/vdf-htf');
  const seedInput = new Uint8Array(dst.length + seed.length);
  seedInput.set(dst, 0);
  seedInput.set(seed, dst.length);
  const seedHash = sha256(seedInput);
  let skipBudget = 0;
  for (let i = 0; i < 8; i++) skipBudget = (skipBudget << 8) | seedHash[i]!;
  skipBudget = (skipBudget >>> 0) % 64;
  let p = 3n;
  for (let attempt = 0; attempt < 100000; attempt++) {
    while (!isPrime(p)) p += 2n;
    if (delta % p !== 0n) {
      const deltaModP = ((delta % p) + p) % p;
      const sqrt = sqrtModPrime(deltaModP, p);
      if (sqrt !== null) {
        if (skipBudget > 0) {
          skipBudget--;
        } else {
          let b = sqrt;
          if ((b & 1n) === 0n) b = b + p;
          const c = (b * b - delta) / (4n * p);
          return reduce({ a: p, b, c });
        }
      }
    }
    p += 2n;
    if (p > 1000000n) throw new Error('hashToForm: exhausted small-prime search');
  }
  throw new Error('hashToForm: no candidate found');
}

export function sampleDiscriminant(discriminantBits: number, rng: Rng = defaultRng): bigint {
  const p = samplePrimeCongruent3Mod4(discriminantBits, rng);
  return discriminantFromPrime(p);
}

// Pick a progress / cancellation interval that emits ~32 callbacks across the
// loop, clamped so tiny T still gets per-step cancellation checks and huge T
// doesn't flood the main thread with postMessage. Workers raise cancellation
// by throwing from inside the callback, so the cadence here is also the
// cancellation latency upper bound.
function progressInterval(total: bigint): bigint {
  let interval = total / 32n;
  if (interval < 1n) interval = 1n;
  if (interval > 16384n) interval = 16384n;
  return interval;
}

export function vdfEval(g: Form, T: bigint, onProgress?: VdfProgress): Form {
  if (T < 0n) throw new Error('T must be non-negative');
  let y = reduce(g);
  if (T === 0n) {
    if (onProgress) onProgress(0n, 0n);
    return y;
  }
  const interval = progressInterval(T);
  for (let i = 0n; i < T; i++) {
    y = square(y);
    if (onProgress && i % interval === 0n) onProgress(i, T);
  }
  if (onProgress) onProgress(T, T);
  return y;
}

export function vdfProve(
  g: Form,
  y: Form,
  T: bigint,
  primeBits: number = FS_PRIME_BITS,
  onProgress?: VdfProgress,
): Form {
  if (T < 0n) throw new Error('T must be non-negative');
  if (discriminant(g) !== discriminant(y)) throw new Error('g and y must share discriminant');
  const ell = hashToPrime(fsTranscript(g, y, T), primeBits);
  const power = (1n << T) / ell;
  return powWithProgress(g, power, onProgress);
}

// Like classgroup's pow(), but with an optional progress / cancellation hook
// that fires roughly progressInterval(bitLength) times across the loop.
function powWithProgress(f: Form, e: bigint, onProgress?: VdfProgress): Form {
  if (e < 0n) throw new Error('negative exponent not supported');
  const delta = discriminant(f);
  if (e === 0n) {
    if (onProgress) onProgress(0n, 0n);
    return reduce(identity(delta));
  }
  if (e === 1n) {
    if (onProgress) onProgress(1n, 1n);
    return reduce(f);
  }
  const total = BigInt(e.toString(2).length);
  const interval = progressInterval(total);
  let result: Form | null = null;
  let base = reduce(f);
  let exp = e;
  let i = 0n;
  while (exp > 0n) {
    if (exp & 1n) result = result === null ? base : compose(result, base);
    exp >>= 1n;
    if (exp > 0n) base = square(base);
    i++;
    if (onProgress && i % interval === 0n) onProgress(i, total);
  }
  if (onProgress) onProgress(total, total);
  return result!;
}

export function vdfVerify(
  g: Form,
  y: Form,
  pi: Form,
  T: bigint,
  primeBits: number = FS_PRIME_BITS,
): boolean {
  if (T < 0n) return false;
  if (discriminant(g) !== discriminant(y) || discriminant(g) !== discriminant(pi)) return false;
  const ell = hashToPrime(fsTranscript(g, y, T), primeBits);
  const r = (1n << T) % ell;
  const left = compose(pow(pi, ell), pow(g, r));
  return equal(reduce(left), reduce(y));
}

function fsTranscript(g: Form, y: Form, T: bigint): Uint8Array {
  const sg = serializeForm(g);
  const sy = serializeForm(y);
  const sT = new Uint8Array(8);
  new DataView(sT.buffer).setBigUint64(0, T, false);
  const out = new Uint8Array(sg.length + sy.length + sT.length);
  out.set(sg, 0);
  out.set(sy, sg.length);
  out.set(sT, sg.length + sy.length);
  return out;
}
