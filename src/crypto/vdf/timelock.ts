import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { aeadDecrypt, aeadEncrypt } from '../aead.js';
import { type Form, parseForm, serializeForm } from './classgroup.js';
import { hashToForm, vdfEval, vdfProve, vdfVerify, type VdfProgress } from './wesolowski.js';

const enc = new TextEncoder();
const dec = new TextDecoder();
const AEAD_NONCE_LEN = 12;

export type VdfParams = {
  delta: bigint;
  T: bigint;
};

export type VdfShareLockData = {
  g: Form;
  nonce: Uint8Array;
};

export type VdfShareProofData = {
  pi: Form;
};

export function encodeVdfParams(p: VdfParams): Uint8Array {
  if (p.T < 0n) throw new Error('T must be non-negative');
  return enc.encode(
    JSON.stringify({
      scheme: 'wesolowski-classgroup',
      delta: p.delta.toString(),
      T: p.T.toString(),
    }),
  );
}

export function decodeVdfParams(raw: Uint8Array): VdfParams {
  const parsed = JSON.parse(dec.decode(raw));
  if (parsed.scheme !== 'wesolowski-classgroup') throw new Error('unsupported VDF scheme');
  if (typeof parsed.delta !== 'string' || typeof parsed.T !== 'string') {
    throw new Error('VDF params must use decimal strings for delta and T');
  }
  const delta = BigInt(parsed.delta);
  const T = BigInt(parsed.T);
  if (T < 0n) throw new Error('T must be non-negative');
  return { delta, T };
}

function hex(b: Uint8Array): string {
  let out = '';
  for (const v of b) out += v.toString(16).padStart(2, '0');
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

export function encodeVdfShareLock(data: VdfShareLockData): Uint8Array {
  if (data.nonce.length !== AEAD_NONCE_LEN) throw new Error(`nonce must be ${AEAD_NONCE_LEN} bytes`);
  return enc.encode(
    JSON.stringify({
      g: { a: data.g.a.toString(), b: data.g.b.toString(), c: data.g.c.toString() },
      nonce: hex(data.nonce),
    }),
  );
}

export function decodeVdfShareLock(raw: Uint8Array): VdfShareLockData {
  const parsed = JSON.parse(dec.decode(raw));
  const a = BigInt(parsed.g.a);
  const b = BigInt(parsed.g.b);
  const c = BigInt(parsed.g.c);
  const nonce = unhex(parsed.nonce);
  if (nonce.length !== AEAD_NONCE_LEN) throw new Error(`nonce must be ${AEAD_NONCE_LEN} bytes`);
  return { g: { a, b, c }, nonce };
}

export function encodeVdfProof(data: VdfShareProofData): Uint8Array {
  return serializeForm(data.pi);
}

export function decodeVdfProof(raw: Uint8Array): VdfShareProofData {
  return { pi: parseForm(raw) };
}

function deriveAeadKey(y: Form): Uint8Array {
  return hkdf(sha256, serializeForm(y), new Uint8Array(0), enc.encode('SSS3/vdf-key'), 32);
}

export function vdfLockShare(
  payload: Uint8Array,
  params: VdfParams,
  shareSeed: Uint8Array,
  rng: (n: number) => Uint8Array,
  onProgress?: VdfProgress,
): { ciphertext: Uint8Array; lock: VdfShareLockData; proof: VdfShareProofData } {
  // The caller passes bundleId || shareIdx here so each share gets a distinct
  // public VDF generator; decoding rejects locks that do not match that seed.
  const g = hashToForm(shareSeed, params.delta);
  // Lock work is split between vdfEval (T squarings) and vdfProve (~T-bit
  // exponent pow ≈ another T squarings + T/2 composes). We model this as a
  // single 0..2T range so the worker sees continuously increasing progress
  // and cancellation is checked throughout both phases instead of only eval.
  const grandTotal = params.T * 2n;
  const evalProgress: VdfProgress | undefined = onProgress
    ? (done) => onProgress(done, grandTotal)
    : undefined;
  const y = vdfEval(g, params.T, evalProgress);
  const proveProgress: VdfProgress | undefined = onProgress
    ? (done, total) => {
        // Map prove's [0..bits] onto [T..2T]. We use a linear scale on the
        // prove total rather than the exact bit count because the latter is
        // only known after sampling ell, and the discrepancy is bounded by
        // FS_PRIME_BITS (128) — invisible at the UI's progress-bar granularity.
        if (total === 0n) {
          onProgress(grandTotal, grandTotal);
          return;
        }
        const offset = (done * params.T) / total;
        onProgress(params.T + offset, grandTotal);
      }
    : undefined;
  const proof = { pi: vdfProve(g, y, params.T, undefined, proveProgress) };
  const key = deriveAeadKey(y);
  const nonce = rng(AEAD_NONCE_LEN);
  const ciphertext = aeadEncrypt('aes-256-gcm', key, nonce, payload);
  key.fill(0);
  return { ciphertext, lock: { g, nonce }, proof };
}

export function vdfUnlockShare(
  ciphertext: Uint8Array,
  params: VdfParams,
  lock: VdfShareLockData,
  onProgress?: VdfProgress,
  proof?: VdfShareProofData,
): Uint8Array {
  const y = vdfEval(lock.g, params.T, onProgress);
  if (proof && !vdfVerify(lock.g, y, proof.pi, params.T)) {
    throw new Error('VDF proof does not verify against computed output');
  }
  const key = deriveAeadKey(y);
  try {
    return aeadDecrypt('aes-256-gcm', key, lock.nonce, ciphertext);
  } finally {
    key.fill(0);
  }
}
