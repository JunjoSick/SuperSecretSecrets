import { bn254_Fr } from '@noble/curves/bn254.js';
import { sha256 } from '@noble/hashes/sha2.js';

export const POSEIDON2_BN254_HASH_ID = 'poseidon2';
export const POSEIDON2_BN254_FIELD_ID = 'bn254-scalar';
export const POSEIDON2_BN254_PARAMS_ID = 'sss-v3-poseidon2-bn254-v1';
export const POSEIDON2_BN254_FIELD_BYTES = 32;
export const POSEIDON2_BN254_VECTOR_MANIFEST_DOMAIN =
  'SSS/v3/poseidon2-bn254/vector-manifest/v1';
export const POSEIDON2_BN254_UNAVAILABLE_MESSAGE =
  'Poseidon2-BN254 commitment backend is not bundled; provide an audited TS/WASM implementation and shared test vectors';

export const BN254_SCALAR_FIELD_ORDER = bn254_Fr.ORDER;

export type Poseidon2Bn254Vector = {
  name: string;
  domain: string;
  inputsHex: readonly string[];
  outputHex: string;
};

export type Poseidon2Bn254VectorManifest = {
  hash: typeof POSEIDON2_BN254_HASH_ID;
  field: typeof POSEIDON2_BN254_FIELD_ID;
  paramsId: typeof POSEIDON2_BN254_PARAMS_ID;
  width: string;
  rate: string;
  capacity: string;
  roundsFull: string;
  roundsPartial: string;
  mdsMatrixDigest: string;
  roundConstantsDigest: string;
  vectors: readonly Poseidon2Bn254Vector[];
};

export type Poseidon2Bn254Implementation = {
  paramsId: typeof POSEIDON2_BN254_PARAMS_ID;
  vectorManifestDigest: Uint8Array;
  hash(inputs: readonly bigint[], domain: string): bigint | Uint8Array;
};

export type Poseidon2Bn254Backend = {
  paramsId: typeof POSEIDON2_BN254_PARAMS_ID;
  hash(inputs: readonly bigint[], domain: string): bigint | Uint8Array;
};

const textEncoder = new TextEncoder();
const MANIFEST_DOMAIN_BYTES = textEncoder.encode(POSEIDON2_BN254_VECTOR_MANIFEST_DOMAIN);

export function validatePoseidon2Bn254VectorManifest(
  manifest: unknown,
): asserts manifest is Poseidon2Bn254VectorManifest {
  if (!isRecord(manifest)) throw new Error('Poseidon2-BN254 vector manifest must be an object');
  if (manifest.hash !== POSEIDON2_BN254_HASH_ID) {
    throw new Error('Poseidon2-BN254 vector manifest hash must be poseidon2');
  }
  if (manifest.field !== POSEIDON2_BN254_FIELD_ID) {
    throw new Error('Poseidon2-BN254 vector manifest field must be bn254-scalar');
  }
  if (manifest.paramsId !== POSEIDON2_BN254_PARAMS_ID) {
    throw new Error('Poseidon2-BN254 vector manifest paramsId mismatch');
  }

  assertPositiveDecimalString(manifest.width, 'Poseidon2-BN254 width');
  assertPositiveDecimalString(manifest.rate, 'Poseidon2-BN254 rate');
  assertPositiveDecimalString(manifest.capacity, 'Poseidon2-BN254 capacity');
  assertPositiveDecimalString(manifest.roundsFull, 'Poseidon2-BN254 full rounds');
  assertPositiveDecimalString(manifest.roundsPartial, 'Poseidon2-BN254 partial rounds');
  hexToBytes32(manifest.mdsMatrixDigest, 'Poseidon2-BN254 MDS matrix digest');
  hexToBytes32(manifest.roundConstantsDigest, 'Poseidon2-BN254 round constants digest');

  if (!Array.isArray(manifest.vectors) || manifest.vectors.length === 0) {
    throw new Error('Poseidon2-BN254 vector manifest must include vectors');
  }
  for (const [index, vector] of manifest.vectors.entries()) {
    validatePoseidon2Bn254Vector(vector, index);
  }
}

export function digestPoseidon2Bn254VectorManifest(manifest: unknown): Uint8Array {
  validatePoseidon2Bn254VectorManifest(manifest);
  return sha256(encodePoseidon2Bn254VectorManifest(manifest));
}

export function createPoseidon2Bn254Implementation(args: {
  manifest: unknown;
  backend: Poseidon2Bn254Backend;
}): Poseidon2Bn254Implementation {
  validatePoseidon2Bn254VectorManifest(args.manifest);
  if (!isRecord(args.backend)) throw new Error('Poseidon2-BN254 backend must be an object');
  if (args.backend.paramsId !== POSEIDON2_BN254_PARAMS_ID) {
    throw new Error('Poseidon2-BN254 backend paramsId mismatch');
  }
  if (typeof args.backend.hash !== 'function') {
    throw new Error('Poseidon2-BN254 backend hash function is required');
  }

  for (const vector of args.manifest.vectors) {
    const inputs = vector.inputsHex.map((inputHex) =>
      bytesToBn254Scalar(hexToFieldBytes(inputHex, 'Poseidon2-BN254 vector input')),
    );
    const actual = normalizePoseidon2Bn254Output(args.backend.hash(inputs, vector.domain));
    const expected = hexToFieldBytes(vector.outputHex, 'Poseidon2-BN254 vector output');
    if (!constantTimeEqual(actual, expected)) {
      throw new Error(`Poseidon2-BN254 vector mismatch: ${vector.name}`);
    }
  }

  return {
    paramsId: POSEIDON2_BN254_PARAMS_ID,
    vectorManifestDigest: digestPoseidon2Bn254VectorManifest(args.manifest),
    hash(inputs, domain) {
      return args.backend.hash([...inputs], domain);
    },
  };
}

export function bytesToBn254Scalar(bytes: Uint8Array): bigint {
  if (!(bytes instanceof Uint8Array) || bytes.length !== POSEIDON2_BN254_FIELD_BYTES) {
    throw new Error('BN254 scalar bytes must be exactly 32 bytes');
  }
  const value = bytesToBigEndianBigInt(bytes);
  assertBn254Scalar(value, 'BN254 scalar');
  return value;
}

export function bn254ScalarToBytes(value: bigint): Uint8Array {
  assertBn254Scalar(value, 'BN254 scalar');
  const out = new Uint8Array(POSEIDON2_BN254_FIELD_BYTES);
  let remaining = value;
  for (let index = out.length - 1; index >= 0; index--) {
    out[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return out;
}

export function assertBn254Scalar(value: bigint, label = 'BN254 scalar'): void {
  if (typeof value !== 'bigint' || value < 0n || value >= BN254_SCALAR_FIELD_ORDER) {
    throw new Error(`${label} must be in the BN254 scalar field`);
  }
}

export function poseidon2Bn254Hash(
  inputs: readonly bigint[],
  implementation?: Poseidon2Bn254Implementation,
  domain = '',
): Uint8Array {
  if (!implementation) throw new Error(POSEIDON2_BN254_UNAVAILABLE_MESSAGE);
  validatePoseidon2Bn254Implementation(implementation);
  if (typeof domain !== 'string') throw new Error('Poseidon2-BN254 domain must be a string');
  for (const [index, input] of inputs.entries()) {
    assertBn254Scalar(input, `Poseidon2-BN254 input ${index}`);
  }
  const output = implementation.hash([...inputs], domain);
  return normalizePoseidon2Bn254Output(output);
}

export function commitPoseidon2Bn254FieldElements(args: {
  domain: string;
  inputs: readonly bigint[];
  implementation?: Poseidon2Bn254Implementation;
}): Uint8Array {
  return poseidon2Bn254Hash(args.inputs, args.implementation, args.domain);
}

function validatePoseidon2Bn254Implementation(implementation: Poseidon2Bn254Implementation): void {
  if (implementation.paramsId !== POSEIDON2_BN254_PARAMS_ID) {
    throw new Error('Poseidon2-BN254 implementation paramsId mismatch');
  }
  if (
    !(implementation.vectorManifestDigest instanceof Uint8Array) ||
    implementation.vectorManifestDigest.length !== 32
  ) {
    throw new Error('Poseidon2-BN254 implementation vector manifest digest must be 32 bytes');
  }
  if (typeof implementation.hash !== 'function') {
    throw new Error('Poseidon2-BN254 implementation hash function is required');
  }
}

function normalizePoseidon2Bn254Output(output: bigint | Uint8Array): Uint8Array {
  if (typeof output === 'bigint') return bn254ScalarToBytes(output);
  if (!(output instanceof Uint8Array)) {
    throw new Error('Poseidon2-BN254 implementation returned an invalid output');
  }
  bytesToBn254Scalar(output);
  return output.slice();
}

function encodePoseidon2Bn254VectorManifest(manifest: Poseidon2Bn254VectorManifest): Uint8Array {
  const chunks: Uint8Array[] = [
    u16LengthPrefixed(MANIFEST_DOMAIN_BYTES),
    stringField(manifest.hash),
    stringField(manifest.field),
    stringField(manifest.paramsId),
    stringField(manifest.width),
    stringField(manifest.rate),
    stringField(manifest.capacity),
    stringField(manifest.roundsFull),
    stringField(manifest.roundsPartial),
    hexToBytes32(manifest.mdsMatrixDigest, 'Poseidon2-BN254 MDS matrix digest'),
    hexToBytes32(manifest.roundConstantsDigest, 'Poseidon2-BN254 round constants digest'),
    u32(manifest.vectors.length),
  ];
  for (const vector of manifest.vectors) {
    chunks.push(
      stringField(vector.name),
      stringField(vector.domain),
      u32(vector.inputsHex.length),
    );
    for (const inputHex of vector.inputsHex) {
      chunks.push(hexToFieldBytes(inputHex, 'Poseidon2-BN254 vector input'));
    }
    chunks.push(hexToFieldBytes(vector.outputHex, 'Poseidon2-BN254 vector output'));
  }
  return concat(...chunks);
}

function validatePoseidon2Bn254Vector(value: unknown, index: number): asserts value is Poseidon2Bn254Vector {
  if (!isRecord(value)) {
    throw new Error(`Poseidon2-BN254 vector ${index} must be an object`);
  }
  if (typeof value.name !== 'string' || value.name.length === 0) {
    throw new Error(`Poseidon2-BN254 vector ${index} name is required`);
  }
  if (typeof value.domain !== 'string' || value.domain.length === 0) {
    throw new Error(`Poseidon2-BN254 vector ${index} domain is required`);
  }
  if (!Array.isArray(value.inputsHex)) {
    throw new Error(`Poseidon2-BN254 vector ${index} inputsHex must be an array`);
  }
  for (const [inputIndex, inputHex] of value.inputsHex.entries()) {
    hexToFieldBytes(inputHex, `Poseidon2-BN254 vector ${index} input ${inputIndex}`);
  }
  hexToFieldBytes(value.outputHex, `Poseidon2-BN254 vector ${index} output`);
}

function assertPositiveDecimalString(value: unknown, label: string): void {
  if (typeof value !== 'string' || !/^[1-9][0-9]*$/.test(value)) {
    throw new Error(`${label} must be a positive decimal string`);
  }
}

function stringField(value: string): Uint8Array {
  return u16LengthPrefixed(textEncoder.encode(value));
}

function hexToBytes32(value: unknown, label: string): Uint8Array {
  if (typeof value !== 'string' || !/^[0-9a-fA-F]{64}$/.test(value)) {
    throw new Error(`${label} must be 32 bytes of hex`);
  }
  const out = new Uint8Array(32);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(value.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function hexToFieldBytes(value: unknown, label: string): Uint8Array {
  const bytes = hexToBytes32(value, label);
  bytesToBn254Scalar(bytes);
  return bytes;
}

function bytesToBigEndianBigInt(bytes: Uint8Array): bigint {
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  return value;
}

function u16LengthPrefixed(bytes: Uint8Array): Uint8Array {
  if (bytes.length > 0xffff) throw new Error('Poseidon2-BN254 manifest component too long');
  const out = new Uint8Array(2 + bytes.length);
  out[0] = (bytes.length >>> 8) & 0xff;
  out[1] = bytes.length & 0xff;
  out.set(bytes, 2);
  return out;
}

function u32(value: number): Uint8Array {
  if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) {
    throw new Error('Poseidon2-BN254 manifest integer out of range');
  }
  return new Uint8Array([
    (value >>> 24) & 0xff,
    (value >>> 16) & 0xff,
    (value >>> 8) & 0xff,
    value & 0xff,
  ]);
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

function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}
