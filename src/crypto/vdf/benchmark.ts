import { square } from './classgroup';
import { discriminantFromPrime } from './prime';
import { hashToForm, vdfEval } from './wesolowski';

export type VdfBenchmarkResult = {
  rounds: number;
  elapsedMs: number;
  squaringsPerSecond: number;
  mobileLikely: boolean;
};

const enc = new TextEncoder();
// Mersenne prime M127 = 2^127 - 1, which is ≡ 3 (mod 4). Using a 128-bit prime
// keeps the benchmark's bigint coefficient sizes representative of production
// (which uses 128-bit discriminants by default); a 64-bit prime previously
// underestimated per-square cost by roughly 2-4×.
const BENCHMARK_DELTA = discriminantFromPrime((1n << 127n) - 1n);
const BENCHMARK_SEED = enc.encode('SSS3/vdf-benchmark');
// Squarings before timing starts so the chain reaches the steady-state
// coefficient distribution (a, b, c near sqrt(|Δ|/3)) and V8 has had time to
// optimise the squaring loop. Too small a warmup leaves the benchmark averaged
// over a phase where a is still tiny and squarings are unrealistically cheap.
const BENCHMARK_WARMUP = 256;

export function vdfBenchmark(rounds = 2048): VdfBenchmarkResult {
  // 2048 rounds is enough for the timed window to land in the ~30-80ms range on
  // typical hardware — long enough that timer jitter is negligible, short
  // enough that the UI can run this on demand without jank. Callers passing a
  // smaller value still get a result, just a noisier one.
  const safeRounds = Math.max(16, Math.trunc(rounds));
  let g = hashToForm(BENCHMARK_SEED, BENCHMARK_DELTA);
  for (let i = 0; i < BENCHMARK_WARMUP; i++) g = square(g);
  const start = performance.now();
  vdfEval(g, BigInt(safeRounds));
  const elapsedMs = Math.max(performance.now() - start, 0.001);
  return {
    rounds: safeRounds,
    elapsedMs,
    squaringsPerSecond: safeRounds / (elapsedMs / 1000),
    mobileLikely: isLikelyMobile(),
  };
}

// Encoding a VDF-locked share runs vdfEval (≈T squarings) followed by vdfProve
// (a pow over a (T - FS_PRIME_BITS)-bit exponent ≈ T squarings + ~T/2 composes).
// With our optimised compose/square cost ratio, prove costs roughly 1.6× a bare
// eval, so total lock ≈ 2.6× eval. We treat the benchmark's squaringsPerSecond
// as the eval-only rate and apply this multiplier so the UI estimate tracks the
// full lock latency the user actually waits for.
const LOCK_EVAL_MULTIPLIER = 2.6;

export function estimateVdfSeconds(T: bigint, benchmark: VdfBenchmarkResult): number {
  const evalSeconds = Number(T) / Math.max(benchmark.squaringsPerSecond, 1);
  return evalSeconds * LOCK_EVAL_MULTIPLIER;
}

export function shouldCapVdfPreset(T: bigint, benchmark: VdfBenchmarkResult): boolean {
  if (benchmark.mobileLikely && T > (1n << 16n)) return true;
  return estimateVdfSeconds(T, benchmark) > 10 * 60;
}

export function formatVdfEstimate(T: bigint, benchmark: VdfBenchmarkResult): string {
  return formatDuration(estimateVdfSeconds(T, benchmark));
}

export function isLikelyMobile(): boolean {
  if (typeof navigator === 'undefined') return false;
  const ua = navigator.userAgent.toLowerCase();
  return (
    /android|iphone|ipad|ipod|mobile/.test(ua) ||
    (navigator.maxTouchPoints > 1 && /macintosh/.test(ua))
  );
}

function formatDuration(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds < 0) return 'unknown';
  if (seconds < 1) return '<1 s';
  if (seconds < 90) return `${Math.round(seconds)} s`;
  if (seconds < 90 * 60) return `${Math.round(seconds / 60)} min`;
  return `${Math.round(seconds / 3600)} h`;
}
