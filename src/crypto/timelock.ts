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

export const VDF_TIMELOCK_SECURITY_NOTICE = [
  'VDF time-locks are not post-quantum.',
  'Encoder waits the same T sequential squarings as the unlocker.',
  'ASIC attackers may evaluate sequential squarings 3-10× faster than browser JS.',
] as const;

export type VdfTimeLockInfo = {
  scheme: 'wesolowski-classgroup';
  discriminantBits: number;
  T: bigint;
  paramsTlvDigest: Uint8Array;
  security: typeof VDF_TIMELOCK_SECURITY_NOTICE;
};

export type VdfTimeLockAdapter = {
  lock(plaintext: Uint8Array, info: VdfTimeLockInfo): Uint8Array;
  unlock(ciphertext: Uint8Array, info: VdfTimeLockInfo): Uint8Array;
};

function hex(bytes: Uint8Array): string {
  let out = '';
  for (const b of bytes) out += b.toString(16).padStart(2, '0');
  return out;
}

function unhex(s: string): Uint8Array {
  if (s.length % 2 !== 0) throw new Error('hex string must have even length');
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = parseInt(s.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) throw new Error('invalid hex character');
    out[i] = byte;
  }
  return out;
}

export function encodeVdfTimeLockInfo(info: VdfTimeLockInfo): Uint8Array {
  if (info.scheme !== 'wesolowski-classgroup') throw new Error('unsupported VDF scheme');
  if (!Number.isInteger(info.discriminantBits) || info.discriminantBits < 64) {
    throw new Error('discriminantBits must be a positive integer ≥ 64');
  }
  if (info.T < 0n) throw new Error('T must be non-negative');
  if (info.paramsTlvDigest.length !== 32) throw new Error('paramsTlvDigest must be 32 bytes');
  return enc.encode(
    JSON.stringify({
      scheme: info.scheme,
      discriminantBits: info.discriminantBits,
      T: info.T.toString(),
      paramsTlvDigest: hex(info.paramsTlvDigest),
    }),
  );
}

export function decodeVdfTimeLockInfo(raw: Uint8Array): VdfTimeLockInfo {
  const parsed = JSON.parse(dec.decode(raw));
  if (parsed.scheme !== 'wesolowski-classgroup') throw new Error('unsupported VDF scheme');
  if (!Number.isInteger(parsed.discriminantBits) || parsed.discriminantBits < 64) {
    throw new Error('discriminantBits must be ≥ 64');
  }
  if (typeof parsed.T !== 'string') throw new Error('T must be a decimal string');
  const T = BigInt(parsed.T);
  if (T < 0n) throw new Error('T must be non-negative');
  if (typeof parsed.paramsTlvDigest !== 'string') throw new Error('paramsTlvDigest must be hex string');
  const digest = unhex(parsed.paramsTlvDigest);
  if (digest.length !== 32) throw new Error('paramsTlvDigest must be 32 bytes');
  return {
    scheme: 'wesolowski-classgroup',
    discriminantBits: parsed.discriminantBits,
    T,
    paramsTlvDigest: digest,
    security: VDF_TIMELOCK_SECURITY_NOTICE,
  };
}
