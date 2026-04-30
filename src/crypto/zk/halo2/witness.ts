import type { DecryptionProofWitnessV1 } from '../decryption-proof-prover';
import {
  ML_KEM_SEED_BYTES,
  VAULT_ROOT_KEY_BYTES,
} from '../decryption-proof-relations';

export const HALO2_WITNESS_DOMAIN = 'SSS/v3/decryption-proof/witness/v1';
export const HALO2_WITNESS_VERSION = 1;
export const HALO2_WITNESS_V1_BYTES = ML_KEM_SEED_BYTES + VAULT_ROOT_KEY_BYTES;

export type Halo2WasmVerifier = {
  verify_decryption_proof_v1(
    proofBytes: Uint8Array,
    encodedPublicInputs: Uint8Array,
    verifyingKeyBytes: Uint8Array,
    srsBytes: Uint8Array,
  ): boolean;
};

export type Halo2WasmProverSecureApi = {
  allocate_witness_buffer(len: number): number;
  free_witness_buffer(ptr: number, len: number): void;
  prove_decryption_proof_v1_from_witness_ptr(
    encodedPublicInputsPtr: number,
    encodedPublicInputsLen: number,
    witnessPtr: number,
    witnessLen: number,
    provingKeyPtr: number,
    provingKeyLen: number,
    srsPtr: number,
    srsLen: number,
  ): Uint8Array;
};

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();
const DOMAIN_BYTES = textEncoder.encode(HALO2_WITNESS_DOMAIN);

export function encodeDecryptionProofWitnessV1(witness: DecryptionProofWitnessV1): Uint8Array {
  validateDecryptionProofWitnessV1(witness);
  return concat(
    u16LengthPrefixed(DOMAIN_BYTES),
    new Uint8Array([HALO2_WITNESS_VERSION]),
    encodeField(0x01, witness.kemSeed),
    encodeField(0x02, witness.vaultRootKey),
  );
}

export function decodeDecryptionProofWitnessV1(encoded: Uint8Array): DecryptionProofWitnessV1 {
  let offset = 0;
  const domainLen = readU16(encoded, offset, 'witness domain length');
  offset += 2;
  const domain = readBytes(encoded, offset, domainLen, 'witness domain');
  offset += domainLen;
  if (textDecoder.decode(domain) !== HALO2_WITNESS_DOMAIN) {
    throw new Error('unsupported decryption proof witness domain');
  }
  const version = readU8(encoded, offset, 'witness version');
  offset += 1;
  if (version !== HALO2_WITNESS_VERSION) {
    throw new Error('unsupported decryption proof witness version');
  }

  const kemSeed = readExpectedField(encoded, 0x01, offset);
  offset = kemSeed.nextOffset;
  const vaultRootKey = readExpectedField(encoded, 0x02, offset);
  offset = vaultRootKey.nextOffset;
  if (offset !== encoded.length) throw new Error('trailing bytes after decryption proof witness');

  const witness = {
    kemSeed: kemSeed.value,
    vaultRootKey: vaultRootKey.value,
  };
  validateDecryptionProofWitnessV1(witness);
  return witness;
}

export function validateDecryptionProofWitnessV1(witness: DecryptionProofWitnessV1): void {
  assertBytes(witness.kemSeed, 'KEM seed');
  assertBytes(witness.vaultRootKey, 'vault root key');
  if (witness.kemSeed.length !== ML_KEM_SEED_BYTES) {
    throw new Error(`decryption proof KEM seed must be ${ML_KEM_SEED_BYTES} bytes`);
  }
  if (witness.vaultRootKey.length !== VAULT_ROOT_KEY_BYTES) {
    throw new Error(`decryption proof vault root key must be ${VAULT_ROOT_KEY_BYTES} bytes`);
  }
}

export function zeroizeBytes(bytes: Uint8Array): void {
  bytes.fill(0);
}

export function zeroizeDecryptionProofWitnessV1(witness: DecryptionProofWitnessV1): void {
  zeroizeBytes(witness.kemSeed);
  zeroizeBytes(witness.vaultRootKey);
}

export function encodeAndZeroizeDecryptionProofWitnessV1(
  witness: DecryptionProofWitnessV1,
): Uint8Array {
  try {
    return encodeDecryptionProofWitnessV1(witness);
  } finally {
    zeroizeDecryptionProofWitnessV1(witness);
  }
}

export function copyWitnessToWasmMemory(args: {
  memory: WebAssembly.Memory;
  ptr: number;
  witness: DecryptionProofWitnessV1;
}): void {
  validateDecryptionProofWitnessV1(args.witness);
  const region = wasmMemoryRegion(args.memory, args.ptr, HALO2_WITNESS_V1_BYTES);
  region.set(args.witness.kemSeed, 0);
  region.set(args.witness.vaultRootKey, ML_KEM_SEED_BYTES);
}

export function zeroizeWasmMemoryRegion(memory: WebAssembly.Memory, ptr: number, len: number): void {
  wasmMemoryRegion(memory, ptr, len).fill(0);
}

function wasmMemoryRegion(memory: WebAssembly.Memory, ptr: number, len: number): Uint8Array {
  if (!Number.isInteger(ptr) || ptr < 0) throw new Error('WASM memory pointer out of range');
  if (!Number.isInteger(len) || len < 0) throw new Error('WASM memory length out of range');
  if (ptr + len > memory.buffer.byteLength) throw new Error('WASM memory region out of bounds');
  return new Uint8Array(memory.buffer, ptr, len);
}

function readExpectedField(
  encoded: Uint8Array,
  expectedTag: number,
  offset: number,
): { value: Uint8Array; nextOffset: number } {
  const tag = readU8(encoded, offset, 'witness field tag');
  offset += 1;
  if (tag !== expectedTag) {
    if (tag < expectedTag) throw new Error('duplicate or out-of-order decryption proof witness field');
    throw new Error(`missing decryption proof witness field 0x${expectedTag.toString(16).padStart(2, '0')}`);
  }
  const len = readU32(encoded, offset, 'witness field length');
  offset += 4;
  const value = readBytes(encoded, offset, len, 'witness field value');
  return { value, nextOffset: offset + len };
}

function encodeField(tag: number, value: Uint8Array): Uint8Array {
  if (!Number.isInteger(tag) || tag < 0 || tag > 0xff) throw new Error('witness field tag out of range');
  const out = new Uint8Array(1 + 4 + value.length);
  out[0] = tag;
  writeU32(out, 1, value.length);
  out.set(value, 5);
  return out;
}

function u16LengthPrefixed(bytes: Uint8Array): Uint8Array {
  if (bytes.length > 0xffff) throw new Error('witness domain too long');
  const out = new Uint8Array(2 + bytes.length);
  out[0] = (bytes.length >>> 8) & 0xff;
  out[1] = bytes.length & 0xff;
  out.set(bytes, 2);
  return out;
}

function writeU32(out: Uint8Array, offset: number, value: number): void {
  if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) {
    throw new Error('witness integer out of range');
  }
  out[offset] = (value >>> 24) & 0xff;
  out[offset + 1] = (value >>> 16) & 0xff;
  out[offset + 2] = (value >>> 8) & 0xff;
  out[offset + 3] = value & 0xff;
}

function readU8(buf: Uint8Array, offset: number, label: string): number {
  if (offset + 1 > buf.length) throw new Error(`truncated ${label}`);
  return buf[offset]!;
}

function readU16(buf: Uint8Array, offset: number, label: string): number {
  if (offset + 2 > buf.length) throw new Error(`truncated ${label}`);
  return ((buf[offset]! << 8) | buf[offset + 1]!) >>> 0;
}

function readU32(buf: Uint8Array, offset: number, label: string): number {
  if (offset + 4 > buf.length) throw new Error(`truncated ${label}`);
  return (
    (buf[offset]! * 0x1000000) +
    ((buf[offset + 1]! << 16) | (buf[offset + 2]! << 8) | buf[offset + 3]!)
  ) >>> 0;
}

function readBytes(buf: Uint8Array, offset: number, length: number, label: string): Uint8Array {
  if (offset + length > buf.length) throw new Error(`truncated ${label}`);
  return buf.slice(offset, offset + length);
}

function assertBytes(value: unknown, label: string): asserts value is Uint8Array {
  if (!(value instanceof Uint8Array)) throw new Error(`decryption proof ${label} must be a Uint8Array`);
}

function concat(...chunks: Uint8Array[]): Uint8Array {
  const len = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const out = new Uint8Array(len);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}
