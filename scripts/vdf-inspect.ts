// Inspect the actual a/b/c magnitudes during a real VDF squaring chain.
// This shows whether duplicatePrimitive's modInverse is over small or large numbers,
// which informs where NUDUPL would help most.

import { square, type Form } from '../src/crypto/vdf/classgroup';
import { discriminantFromPrime, samplePrimeCongruent3Mod4 } from '../src/crypto/vdf/prime';
import { hashToForm } from '../src/crypto/vdf/wesolowski';

const enc = new TextEncoder();

function bits(n: bigint): number {
  if (n === 0n) return 0;
  return (n < 0n ? -n : n).toString(2).length;
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

const p = samplePrimeCongruent3Mod4(128, makeRng());
const delta = discriminantFromPrime(p);
console.log(`# |Δ| ~ 2^${bits(delta) - 1}`);

let f: Form = hashToForm(enc.encode('inspect'), delta);
console.log(`# initial form bits: a=${bits(f.a)} b=${bits(f.b)} c=${bits(f.c)}`);

const aSamples: number[] = [];
const bSamples: number[] = [];
const cSamples: number[] = [];
for (let i = 0; i < 1000; i++) {
  f = square(f);
  aSamples.push(bits(f.a));
  bSamples.push(bits(f.b));
  cSamples.push(bits(f.c));
}

function stats(name: string, arr: number[]) {
  const sorted = [...arr].sort((a, b) => a - b);
  const min = sorted[0]!;
  const max = sorted[sorted.length - 1]!;
  const median = sorted[Math.floor(sorted.length / 2)]!;
  const mean = arr.reduce((s, v) => s + v, 0) / arr.length;
  console.log(`  ${name}: min=${min} median=${median} mean=${mean.toFixed(1)} max=${max}`);
}

console.log('# coefficient bit lengths over 1000 squarings:');
stats('a', aSamples);
stats('b', bSamples);
stats('c', cSamples);
