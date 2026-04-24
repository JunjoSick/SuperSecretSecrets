export const DRAND_QUICKNET_CHAIN_HASH =
  '52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971';

export const TIMELOCK_SECURITY_NOTICE = [
  'Time-locked shares are not post-quantum.',
  'Unlock depends on drand quicknet threshold honesty.',
  'Unlock needs network access or imported beacon data for the target round.',
] as const;

export type TimeLockInfo = {
  network: 'quicknet';
  chainHash: string;
  round: number;
  scheme: 'drand-tlock';
  security: typeof TIMELOCK_SECURITY_NOTICE;
};

export type TimeLockOptions = {
  round: number;
  adapter: TimeLockAdapter;
  chainHash?: string;
};

export type TimeLockAdapter = {
  lock(plaintext: Uint8Array, info: TimeLockInfo): Uint8Array;
  unlock(ciphertext: Uint8Array, info: TimeLockInfo): Uint8Array;
};

const enc = new TextEncoder();
const dec = new TextDecoder();

export function normalizeTimeLockInfo(opts: Omit<TimeLockOptions, 'adapter'>): TimeLockInfo {
  if (!Number.isInteger(opts.round) || opts.round < 1) throw new Error('time-lock round must be a positive integer');
  return {
    network: 'quicknet',
    chainHash: opts.chainHash ?? DRAND_QUICKNET_CHAIN_HASH,
    round: opts.round,
    scheme: 'drand-tlock',
    security: TIMELOCK_SECURITY_NOTICE,
  };
}

export function lockSharePayload(
  payload: Uint8Array,
  opts: TimeLockOptions,
): { ciphertext: Uint8Array; info: TimeLockInfo } {
  const info = normalizeTimeLockInfo(opts);
  return { ciphertext: opts.adapter.lock(payload, info), info };
}

export function unlockSharePayload(
  ciphertext: Uint8Array,
  info: TimeLockInfo,
  adapter: TimeLockAdapter,
): Uint8Array {
  return adapter.unlock(ciphertext, info);
}

export function encodeTimeLockInfo(info: TimeLockInfo): Uint8Array {
  return enc.encode(JSON.stringify(info));
}

export function decodeTimeLockInfo(raw: Uint8Array): TimeLockInfo {
  const parsed = JSON.parse(dec.decode(raw)) as TimeLockInfo;
  if (parsed.network !== 'quicknet') throw new Error('unsupported drand network');
  if (parsed.chainHash !== DRAND_QUICKNET_CHAIN_HASH) throw new Error('unsupported drand chain hash');
  if (parsed.scheme !== 'drand-tlock') throw new Error('unsupported time-lock scheme');
  if (!Number.isInteger(parsed.round) || parsed.round < 1) throw new Error('invalid time-lock round');
  return {
    network: 'quicknet',
    chainHash: parsed.chainHash,
    round: parsed.round,
    scheme: 'drand-tlock',
    security: TIMELOCK_SECURITY_NOTICE,
  };
}
