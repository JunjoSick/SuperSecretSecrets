import { sha256 } from '@noble/hashes/sha2.js';
import {
  AES_256_GCM_NONCE_BYTES,
  AES_256_GCM_TAG_BYTES,
  BN254_TRANSCRIPT_DIGEST_BYTES,
  BN254_TRANSCRIPT_DIGEST_LIMB_BYTES,
  ML_KEM_768_CIPHERTEXT_BYTES,
  PROOF_AEAD_ID_AES_256_GCM,
  PROOF_COMMITMENT_HASH_ID_POSEIDON2_BN254,
  PROOF_KDF_ID_HKDF_SHA256,
  PROOF_KEM_ID_ML_KEM_768,
  TRANSCRIPT_V1_DOMAIN,
  getSupportedDecryptionProofRelation,
} from './decryption-proof-relations';
import { VERSION_V3, type HeaderChunkQr } from '../codec';

export const DECRYPTION_PROOF_PUBLIC_INPUTS_VERSION = 1;
export const DECRYPTION_PROOF_BUNDLE_ID_BYTES = 8;
export const DECRYPTION_PROOF_COMMITMENT_BYTES = 32;

export type DecryptionProofPublicInputsV1 = {
  bundleId: Uint8Array;
  payloadKind: 'vault-root';

  kemAlgId: typeof PROOF_KEM_ID_ML_KEM_768;
  kdfAlgId: typeof PROOF_KDF_ID_HKDF_SHA256;
  aeadAlgId: typeof PROOF_AEAD_ID_AES_256_GCM;
  commitmentHashId: typeof PROOF_COMMITMENT_HASH_ID_POSEIDON2_BN254;
  passphraseFlag: false;

  argon2TCost: 0;
  argon2MemLog2KiB: 0;
  argon2Parallelism: 0;

  policyCommitment: Uint8Array;
  plaintextCommitment: Uint8Array;
  vaultTreeRoot: Uint8Array;
  kemCiphertext: Uint8Array;
  aeadNonce: Uint8Array;
  aeadCiphertextAndTag: Uint8Array;
};

export type TranscriptDigestBn254PublicInputs = {
  high128: bigint;
  low128: bigint;
};

export type DecryptionProofPublicInputBuilderArgsV1 = {
  firstHeader: HeaderChunkQr;
  fullHeaderPayload: Uint8Array;
  payloadKind: string;
  policyCommitment: Uint8Array;
  plaintextCommitment: Uint8Array;
  vaultTreeRoot?: Uint8Array | null;
};

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();
const TRANSCRIPT_DOMAIN_BYTES = textEncoder.encode(TRANSCRIPT_V1_DOMAIN);
const PAYLOAD_KIND_VAULT_ROOT_BYTES = textEncoder.encode('vault-root');

export function encodeDecryptionProofPublicInputsV1(
  input: DecryptionProofPublicInputsV1,
): Uint8Array {
  validatePublicInputs(input);
  const fields = [
    encodeField(0x01, input.bundleId),
    encodeField(0x02, PAYLOAD_KIND_VAULT_ROOT_BYTES),
    encodeField(
      0x03,
      new Uint8Array([
        input.kemAlgId,
        input.kdfAlgId,
        input.aeadAlgId,
        input.commitmentHashId,
        input.passphraseFlag ? 1 : 0,
      ]),
    ),
    encodeField(0x04, u32Triplet(input.argon2TCost, input.argon2MemLog2KiB, input.argon2Parallelism)),
    encodeField(0x05, input.policyCommitment),
    encodeField(0x06, input.plaintextCommitment),
    encodeField(0x07, input.vaultTreeRoot),
    encodeField(0x08, input.kemCiphertext),
    encodeField(0x09, input.aeadNonce),
    encodeField(0x0a, input.aeadCiphertextAndTag),
  ];
  return concat(u16LengthPrefixed(TRANSCRIPT_DOMAIN_BYTES), new Uint8Array([DECRYPTION_PROOF_PUBLIC_INPUTS_VERSION]), ...fields);
}

export function decodeDecryptionProofPublicInputsV1(
  encoded: Uint8Array,
): DecryptionProofPublicInputsV1 {
  let offset = 0;
  const domainLen = readU16(encoded, offset, 'transcript domain length');
  offset += 2;
  const domain = readBytes(encoded, offset, domainLen, 'transcript domain');
  offset += domainLen;
  if (textDecoder.decode(domain) !== TRANSCRIPT_V1_DOMAIN) {
    throw new Error('unsupported decryption proof transcript domain');
  }
  const transcriptVersion = readU8(encoded, offset, 'transcript version');
  offset += 1;
  if (transcriptVersion !== DECRYPTION_PROOF_PUBLIC_INPUTS_VERSION) {
    throw new Error('unsupported decryption proof transcript version');
  }

  const fields = new Map<number, Uint8Array>();
  for (let expectedTag = 0x01; expectedTag <= 0x0a; expectedTag++) {
    if (offset >= encoded.length) {
      throw new Error(`missing decryption proof transcript field 0x${expectedTag.toString(16).padStart(2, '0')}`);
    }
    const tag = readU8(encoded, offset, 'transcript field tag');
    offset += 1;
    if (tag !== expectedTag) {
      if (tag < expectedTag) {
        throw new Error('duplicate or out-of-order decryption proof transcript field');
      }
      throw new Error(`missing decryption proof transcript field 0x${expectedTag.toString(16).padStart(2, '0')}`);
    }
    const length = readU32(encoded, offset, 'transcript field length');
    offset += 4;
    const value = readBytes(encoded, offset, length, 'transcript field value');
    offset += length;
    fields.set(tag, value);
  }
  if (offset !== encoded.length) throw new Error('trailing bytes after decryption proof transcript');

  const bundleId = requiredField(fields, 0x01);
  const payloadKind = textDecoder.decode(requiredField(fields, 0x02));
  const algorithmTuple = requiredField(fields, 0x03);
  const argon2Tuple = requiredField(fields, 0x04);
  const policyCommitment = requiredField(fields, 0x05);
  const plaintextCommitment = requiredField(fields, 0x06);
  const vaultTreeRoot = requiredField(fields, 0x07);
  const kemCiphertext = requiredField(fields, 0x08);
  const aeadNonce = requiredField(fields, 0x09);
  const aeadCiphertextAndTag = requiredField(fields, 0x0a);

  if (algorithmTuple.length !== 5) throw new Error('decryption proof algorithm tuple must be 5 bytes');
  if (argon2Tuple.length !== 12) throw new Error('decryption proof Argon2 tuple must be 12 bytes');
  if (algorithmTuple[4] !== 0) {
    throw new Error('decryption proof passphrase flag must be false');
  }

  const input: DecryptionProofPublicInputsV1 = {
    bundleId,
    payloadKind: payloadKind as 'vault-root',
    kemAlgId: algorithmTuple[0] as typeof PROOF_KEM_ID_ML_KEM_768,
    kdfAlgId: algorithmTuple[1] as typeof PROOF_KDF_ID_HKDF_SHA256,
    aeadAlgId: algorithmTuple[2] as typeof PROOF_AEAD_ID_AES_256_GCM,
    commitmentHashId: algorithmTuple[3] as typeof PROOF_COMMITMENT_HASH_ID_POSEIDON2_BN254,
    passphraseFlag: false,
    argon2TCost: readU32(argon2Tuple, 0, 'Argon2 tCost') as 0,
    argon2MemLog2KiB: readU32(argon2Tuple, 4, 'Argon2 memLog2KiB') as 0,
    argon2Parallelism: readU32(argon2Tuple, 8, 'Argon2 parallelism') as 0,
    policyCommitment,
    plaintextCommitment,
    vaultTreeRoot,
    kemCiphertext,
    aeadNonce,
    aeadCiphertextAndTag,
  };
  validatePublicInputs(input);
  return input;
}

export function digestDecryptionProofPublicInputsV1(
  input: DecryptionProofPublicInputsV1,
): Uint8Array {
  return sha256(encodeDecryptionProofPublicInputsV1(input));
}

export function splitTranscriptDigestForBn254PublicInputs(
  digest: Uint8Array,
): TranscriptDigestBn254PublicInputs {
  if (digest.length !== BN254_TRANSCRIPT_DIGEST_BYTES) {
    throw new Error('transcript digest must be 32 bytes');
  }
  return {
    high128: bytesToBigEndianBigInt(digest.slice(0, BN254_TRANSCRIPT_DIGEST_LIMB_BYTES)),
    low128: bytesToBigEndianBigInt(digest.slice(BN254_TRANSCRIPT_DIGEST_LIMB_BYTES)),
  };
}

export function buildDecryptionProofPublicInputsFromDecodedHeaderV1(
  args: DecryptionProofPublicInputBuilderArgsV1,
): DecryptionProofPublicInputsV1 {
  const { firstHeader, fullHeaderPayload, payloadKind, policyCommitment, plaintextCommitment } = args;
  if (firstHeader.version !== VERSION_V3) throw new Error('decryption proof public inputs require a v3 header');
  const support = getSupportedDecryptionProofRelation({
    formatVersion: firstHeader.version,
    payloadKind,
    kemAlg: firstHeader.kemAlg,
    kdfAlg: firstHeader.kdfAlg,
    aeadAlg: firstHeader.aeadAlg,
    passphrase: firstHeader.flags.passphrase,
  });
  if (!support.supported) throw new Error(support.reason);
  if (
    firstHeader.argon2.tCost !== 0 ||
    firstHeader.argon2.memLog2KiB !== 0 ||
    firstHeader.argon2.parallelism !== 0
  ) {
    throw new Error('no-passphrase decryption proof relation requires zero Argon2 params');
  }

  const kemCiphertext = fullHeaderPayload.slice(0, ML_KEM_768_CIPHERTEXT_BYTES);
  const nonceOffset = ML_KEM_768_CIPHERTEXT_BYTES;
  const aeadOffset = nonceOffset + AES_256_GCM_NONCE_BYTES;
  const input: DecryptionProofPublicInputsV1 = {
    bundleId: firstHeader.bundleId,
    payloadKind: 'vault-root',
    kemAlgId: PROOF_KEM_ID_ML_KEM_768,
    kdfAlgId: PROOF_KDF_ID_HKDF_SHA256,
    aeadAlgId: PROOF_AEAD_ID_AES_256_GCM,
    commitmentHashId: PROOF_COMMITMENT_HASH_ID_POSEIDON2_BN254,
    passphraseFlag: false,
    argon2TCost: 0,
    argon2MemLog2KiB: 0,
    argon2Parallelism: 0,
    policyCommitment,
    plaintextCommitment,
    vaultTreeRoot: args.vaultTreeRoot ?? new Uint8Array(0),
    kemCiphertext,
    aeadNonce: fullHeaderPayload.slice(nonceOffset, aeadOffset),
    aeadCiphertextAndTag: fullHeaderPayload.slice(aeadOffset),
  };
  validatePublicInputs(input);
  return input;
}

function validatePublicInputs(input: DecryptionProofPublicInputsV1): void {
  assertBytes(input.bundleId, 'bundleId');
  assertBytes(input.policyCommitment, 'policyCommitment');
  assertBytes(input.plaintextCommitment, 'plaintextCommitment');
  assertBytes(input.vaultTreeRoot, 'vaultTreeRoot');
  assertBytes(input.kemCiphertext, 'kemCiphertext');
  assertBytes(input.aeadNonce, 'aeadNonce');
  assertBytes(input.aeadCiphertextAndTag, 'aeadCiphertextAndTag');

  if (input.bundleId.length !== DECRYPTION_PROOF_BUNDLE_ID_BYTES) {
    throw new Error('decryption proof bundleId must be 8 bytes');
  }
  if (input.payloadKind !== 'vault-root') {
    throw new Error('decryption proof payload kind must be vault-root');
  }
  if (input.kemAlgId !== PROOF_KEM_ID_ML_KEM_768) {
    throw new Error('decryption proof KEM id must be ML-KEM-768');
  }
  if (input.kdfAlgId !== PROOF_KDF_ID_HKDF_SHA256) {
    throw new Error('decryption proof KDF id must be HKDF-SHA256');
  }
  if (input.aeadAlgId !== PROOF_AEAD_ID_AES_256_GCM) {
    throw new Error('decryption proof AEAD id must be AES-256-GCM');
  }
  if (input.commitmentHashId !== PROOF_COMMITMENT_HASH_ID_POSEIDON2_BN254) {
    throw new Error('decryption proof commitment hash id must be Poseidon2-BN254');
  }
  if (input.passphraseFlag !== false) {
    throw new Error('decryption proof passphrase flag must be false');
  }
  if (input.argon2TCost !== 0 || input.argon2MemLog2KiB !== 0 || input.argon2Parallelism !== 0) {
    throw new Error('no-passphrase decryption proof relation requires zero Argon2 params');
  }
  if (input.policyCommitment.length !== DECRYPTION_PROOF_COMMITMENT_BYTES) {
    throw new Error('decryption proof policy commitment must be 32 bytes');
  }
  if (input.plaintextCommitment.length !== DECRYPTION_PROOF_COMMITMENT_BYTES) {
    throw new Error('decryption proof plaintext commitment must be 32 bytes');
  }
  if (input.kemCiphertext.length !== ML_KEM_768_CIPHERTEXT_BYTES) {
    throw new Error('decryption proof KEM ciphertext must be 1088 bytes');
  }
  if (input.aeadNonce.length !== AES_256_GCM_NONCE_BYTES) {
    throw new Error('decryption proof AEAD nonce must be 12 bytes');
  }
  if (input.aeadCiphertextAndTag.length < AES_256_GCM_TAG_BYTES) {
    throw new Error('decryption proof AEAD ciphertext and tag must include at least a 16-byte tag');
  }
}

function assertBytes(value: unknown, label: string): asserts value is Uint8Array {
  if (!(value instanceof Uint8Array)) {
    throw new Error(`decryption proof ${label} must be a Uint8Array`);
  }
}

function requiredField(fields: Map<number, Uint8Array>, tag: number): Uint8Array {
  const value = fields.get(tag);
  if (!value) throw new Error(`missing decryption proof transcript field 0x${tag.toString(16).padStart(2, '0')}`);
  return value;
}

function encodeField(tag: number, value: Uint8Array): Uint8Array {
  if (!Number.isInteger(tag) || tag < 0 || tag > 0xff) throw new Error('transcript field tag out of range');
  const out = new Uint8Array(1 + 4 + value.length);
  out[0] = tag;
  writeU32(out, 1, value.length);
  out.set(value, 5);
  return out;
}

function u16LengthPrefixed(bytes: Uint8Array): Uint8Array {
  if (bytes.length > 0xffff) throw new Error('transcript domain too long');
  const out = new Uint8Array(2 + bytes.length);
  out[0] = (bytes.length >>> 8) & 0xff;
  out[1] = bytes.length & 0xff;
  out.set(bytes, 2);
  return out;
}

function u32Triplet(a: number, b: number, c: number): Uint8Array {
  const out = new Uint8Array(12);
  writeU32(out, 0, a);
  writeU32(out, 4, b);
  writeU32(out, 8, c);
  return out;
}

function writeU32(out: Uint8Array, offset: number, value: number): void {
  if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) {
    throw new Error('decryption proof transcript integer out of range');
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

function bytesToBigEndianBigInt(bytes: Uint8Array): bigint {
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  return value;
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
