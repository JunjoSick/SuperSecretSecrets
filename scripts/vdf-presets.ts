// Run the in-app VDF benchmark and print the estimates it would feed to the
// preset-cap logic, so we can sanity-check that 'Slow' isn't silently enabled
// when it would freeze recovery.
//
//   npx vite-node scripts/vdf-presets.ts

import {
  estimateVdfSeconds,
  formatVdfEstimate,
  shouldCapVdfPreset,
  vdfBenchmark,
} from '../src/crypto/vdf/benchmark';
import { vdfLockShare, vdfUnlockShare } from '../src/crypto/vdf/timelock';
import { discriminantFromPrime, samplePrimeCongruent3Mod4 } from '../src/crypto/vdf/prime';
import { performance } from 'node:perf_hooks';

const enc = new TextEncoder();
const PRESETS = [
  { label: 'light', T: 1n << 14n },
  { label: 'medium', T: 1n << 16n },
  { label: 'slow', T: 1n << 20n },
];

const result = vdfBenchmark();
console.log(`# vdfBenchmark: rounds=${result.rounds} elapsed=${result.elapsedMs.toFixed(1)}ms`);
console.log(`# squaringsPerSecond=${result.squaringsPerSecond.toFixed(0)}`);
console.log(`# mobileLikely=${result.mobileLikely}`);
console.log();

console.log('# Estimated lock time per preset (eval only):');
for (const p of PRESETS) {
  const sec = estimateVdfSeconds(p.T, result);
  const capped = shouldCapVdfPreset(p.T, result);
  console.log(
    `  ${p.label.padEnd(8)} T=2^${p.T.toString(2).length - 1}  ${formatVdfEstimate(p.T, result).padStart(10)}  (${sec.toFixed(1)}s)  capped=${capped}`,
  );
}

console.log();
console.log('# Measured end-to-end lock+unlock at the production discriminant width');
const p = samplePrimeCongruent3Mod4(128);
const delta = discriminantFromPrime(p);
const payload = enc.encode('preset-bench');
for (const p of PRESETS) {
  if (p.label === 'slow') {
    console.log(`  ${p.label.padEnd(8)} T=2^${p.T.toString(2).length - 1}  skipped (would take ~${formatVdfEstimate(p.T, result)})`);
    continue;
  }
  const seed = enc.encode(`preset-${p.label}`);
  const start = performance.now();
  const { ciphertext, lock, proof } = vdfLockShare(payload, { delta, T: p.T }, seed, () => new Uint8Array(12));
  const lockMs = performance.now() - start;
  const unlockStart = performance.now();
  vdfUnlockShare(ciphertext, { delta, T: p.T }, lock, undefined, proof);
  const unlockMs = performance.now() - unlockStart;
  const evalRatio = (lockMs / 1000) / estimateVdfSeconds(p.T, result);
  console.log(
    `  ${p.label.padEnd(8)} T=2^${p.T.toString(2).length - 1}  lock=${(lockMs / 1000).toFixed(2)}s  unlock=${(unlockMs / 1000).toFixed(2)}s  lock/eval-estimate=${evalRatio.toFixed(2)}x`,
  );
}
