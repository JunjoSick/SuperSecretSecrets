// Local VDF profiling. Run with:
//   npx vite-node scripts/vdf-bench.ts
//
// Captures timings at production-like discriminant sizes (128-bit prime, so |Δ|
// ~ 2^128) for square / compose / full vdfEval. Used as a baseline before
// NUDUPL/NUCOMP land and to compare the optimized path apples-to-apples.

import { performance } from 'node:perf_hooks';
import {
  compose,
  composeReference,
  square,
  squareReference,
  type Form,
} from '../src/crypto/vdf/classgroup';
import { discriminantFromPrime, samplePrimeCongruent3Mod4 } from '../src/crypto/vdf/prime';
import { hashToForm, vdfEval } from '../src/crypto/vdf/wesolowski';
import { vdfLockShare, vdfUnlockShare } from '../src/crypto/vdf/timelock';

const enc = new TextEncoder();

function fmt(ms: number): string {
  if (ms < 1) return `${(ms * 1000).toFixed(1)}μs`;
  if (ms < 1000) return `${ms.toFixed(2)}ms`;
  return `${(ms / 1000).toFixed(2)}s`;
}

function bench<T>(label: string, fn: () => T, iters: number): { total: number; perOp: number; result: T } {
  // Warmup
  for (let i = 0; i < Math.min(iters, 8); i++) fn();
  const start = performance.now();
  let last!: T;
  for (let i = 0; i < iters; i++) last = fn();
  const total = performance.now() - start;
  const perOp = total / iters;
  console.log(`  ${label.padEnd(40)} ${iters.toString().padStart(7)} iters  ${fmt(total).padStart(10)} total  ${fmt(perOp).padStart(10)} / op`);
  return { total, perOp, result: last };
}

function makeRng(seed = 0xc0ffee) {
  let state = seed >>> 0;
  return (n: number) => {
    const out = new Uint8Array(n);
    for (let i = 0; i < n; i++) {
      state = (state * 1664525 + 1013904223) >>> 0;
      out[i] = (state >>> 16) & 0xff;
    }
    return out;
  };
}

async function main() {
  const rng = makeRng();
  const p = samplePrimeCongruent3Mod4(128, rng);
  const delta = discriminantFromPrime(p);
  console.log(`# Δ = -p where p is a 128-bit prime ≡ 3 (mod 4)`);
  console.log(`# bit length of |Δ| = ${delta.toString(2).length - 1}`);
  console.log();

  // Generate a corpus of reduced same-discriminant forms. We warm up by
  // squaring a hashed-to-form generator several times so the corpus reflects
  // steady-state coefficient sizes (a ≈ b ≈ sqrt(|Δ|/3)) rather than the tiny
  // a values hashToForm initially produces.
  const corpusSize = 64;
  const corpus: Form[] = [];
  let warm = hashToForm(enc.encode('bench-warm'), delta);
  for (let i = 0; i < 64; i++) warm = square(warm);
  corpus.push(warm);
  for (let i = 1; i < corpusSize; i++) {
    corpus.push(square(corpus[i - 1]!));
  }

  // Sanity check: count primitive vs non-primitive forms in the corpus.
  // (gcd(a,b) check is what duplicatePrimitive() uses.)
  let primitive = 0;
  for (const f of corpus) {
    let x = f.a < 0n ? -f.a : f.a;
    let y = f.b < 0n ? -f.b : f.b;
    while (y > 0n) [x, y] = [y, x % y];
    if (x === 1n) primitive++;
  }
  console.log(`# corpus: ${corpusSize} reduced forms, primitive (gcd(a,b)=1): ${primitive}/${corpusSize}`);
  console.log();

  console.log('## square()');
  let idx = 0;
  bench('squareReference', () => squareReference(corpus[idx++ % corpusSize]!), 2000);
  idx = 0;
  bench('square (current fast path)', () => square(corpus[idx++ % corpusSize]!), 2000);
  console.log();

  console.log('## compose()');
  let i1 = 0;
  let i2 = 17;
  bench('composeReference', () => composeReference(corpus[i1++ % corpusSize]!, corpus[i2++ % corpusSize]!), 2000);
  i1 = 0; i2 = 17;
  bench('compose (current)', () => compose(corpus[i1++ % corpusSize]!, corpus[i2++ % corpusSize]!), 2000);
  console.log();

  console.log('## vdfEval (squaring chain) at production T values');
  const g = corpus[0]!;
  for (const Texp of [10n, 12n, 14n, 16n]) {
    const T = 1n << Texp;
    const start = performance.now();
    vdfEval(g, T);
    const elapsed = performance.now() - start;
    const sps = Number(T) / (elapsed / 1000);
    console.log(`  T = 2^${Texp.toString().padStart(2)} = ${T.toString().padStart(8)}  ${fmt(elapsed).padStart(10)}  ${sps.toFixed(0).padStart(10)} sq/s`);
  }
  console.log();

  console.log('## end-to-end: vdfLockShare / vdfUnlockShare');
  const payload = enc.encode('bench-payload-256-bytes-' + 'x'.repeat(232));
  for (const Texp of [12n, 14n, 16n]) {
    const T = 1n << Texp;
    const shareSeed = enc.encode('bench-share-0');

    const lockStart = performance.now();
    const { ciphertext, lock, proof } = vdfLockShare(payload, { delta, T }, shareSeed, rng);
    const lockMs = performance.now() - lockStart;

    const unlockStart = performance.now();
    const decoded = vdfUnlockShare(ciphertext, { delta, T }, lock, undefined, proof);
    const unlockMs = performance.now() - unlockStart;

    if (decoded.length !== payload.length) throw new Error('payload length mismatch');
    for (let i = 0; i < payload.length; i++) if (decoded[i] !== payload[i]) throw new Error('payload mismatch');

    console.log(`  T = 2^${Texp.toString().padStart(2)}  lock ${fmt(lockMs).padStart(10)}  unlock ${fmt(unlockMs).padStart(10)}`);
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
