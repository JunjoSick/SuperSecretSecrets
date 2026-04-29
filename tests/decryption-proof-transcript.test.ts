import { describe, expect, it } from 'vitest';
import {
  KIND_HEADER,
  VERSION_V3,
  type HeaderChunkQr,
} from '../src/crypto/codec';
import {
  ML_KEM_768_CIPHERTEXT_BYTES,
  TRANSCRIPT_V1_DOMAIN,
} from '../src/crypto/zk/decryption-proof-relations';
import {
  buildDecryptionProofPublicInputsFromDecodedHeaderV1,
  decodeDecryptionProofPublicInputsV1,
  digestDecryptionProofPublicInputsV1,
  encodeDecryptionProofPublicInputsV1,
  splitTranscriptDigestForBn254PublicInputs,
  type DecryptionProofPublicInputsV1,
} from '../src/crypto/zk/decryption-proof-transcript';

const DOMAIN_LEN = new TextEncoder().encode(TRANSCRIPT_V1_DOMAIN).length;

describe('decryption proof public-input transcript', () => {
  it('round-trips through the canonical binary codec', () => {
    const input = samplePublicInputs();
    expect(decodeDecryptionProofPublicInputsV1(encodeDecryptionProofPublicInputsV1(input))).toEqual(input);
  });

  it('produces deterministic digests and changes for public byte-field mutations', () => {
    const base = samplePublicInputs();
    const baseDigest = digestDecryptionProofPublicInputsV1(base);
    expect(digestDecryptionProofPublicInputsV1(samplePublicInputs())).toEqual(baseDigest);

    const mutations: Array<[string, (input: DecryptionProofPublicInputsV1) => void]> = [
      ['bundleId', (input) => { input.bundleId[0]! ^= 1; }],
      ['policyCommitment', (input) => { input.policyCommitment[0]! ^= 1; }],
      ['plaintextCommitment', (input) => { input.plaintextCommitment[0]! ^= 1; }],
      ['vaultTreeRoot', (input) => { input.vaultTreeRoot[0]! ^= 1; }],
      ['kemCiphertext', (input) => { input.kemCiphertext[0]! ^= 1; }],
      ['aeadNonce', (input) => { input.aeadNonce[0]! ^= 1; }],
      ['aeadCiphertextAndTag', (input) => { input.aeadCiphertextAndTag[0]! ^= 1; }],
    ];

    for (const [name, mutate] of mutations) {
      const changed = samplePublicInputs();
      mutate(changed);
      expect(digestDecryptionProofPublicInputsV1(changed), name).not.toEqual(baseDigest);
    }
  });

  it('rejects field order, duplicate, missing, and trailing-byte mutations', () => {
    const encoded = encodeDecryptionProofPublicInputsV1(samplePublicInputs());
    const { prefix, fields } = splitEncodedTranscript(encoded);

    expect(() => decodeDecryptionProofPublicInputsV1(concat(prefix, fields[1]!, fields[0]!, ...fields.slice(2)))).toThrow();
    expect(() => decodeDecryptionProofPublicInputsV1(concat(prefix, fields[0]!, fields[0]!, ...fields.slice(1)))).toThrow();
    expect(() => decodeDecryptionProofPublicInputsV1(concat(prefix, ...fields.filter((field) => field[0] !== 0x07)))).toThrow();
    expect(() => decodeDecryptionProofPublicInputsV1(concat(encoded, new Uint8Array([0])))).toThrow();
  });

  it('rejects malformed tuple lengths and tuple values', () => {
    const encoded = encodeDecryptionProofPublicInputsV1(samplePublicInputs());

    expect(() => decodeDecryptionProofPublicInputsV1(replaceField(encoded, 0x03, new Uint8Array([1, 1, 1, 1])))).toThrow(
      /algorithm tuple/,
    );
    expect(() => decodeDecryptionProofPublicInputsV1(replaceField(encoded, 0x04, new Uint8Array(8)))).toThrow(
      /Argon2 tuple/,
    );
    expect(() => decodeDecryptionProofPublicInputsV1(replaceField(encoded, 0x03, new Uint8Array([1, 1, 1, 2, 0])))).toThrow(
      /commitment hash/,
    );
    expect(() => decodeDecryptionProofPublicInputsV1(replaceField(encoded, 0x03, new Uint8Array([1, 1, 1, 1, 2])))).toThrow(
      /passphrase flag/,
    );
    const argon2 = new Uint8Array(12);
    argon2[11] = 1;
    expect(() => decodeDecryptionProofPublicInputsV1(replaceField(encoded, 0x04, argon2))).toThrow(/Argon2/);
  });

  it('validates canonical relation-specific lengths and zero passphrase parameters', () => {
    expect(() => encodeDecryptionProofPublicInputsV1({ ...samplePublicInputs(), bundleId: bytes(7, 1) })).toThrow(/bundleId/);
    expect(() =>
      encodeDecryptionProofPublicInputsV1({
        ...samplePublicInputs(),
        payloadKind: 'secret' as 'vault-root',
      }),
    ).toThrow(/payload kind/);
    expect(() =>
      encodeDecryptionProofPublicInputsV1({
        ...samplePublicInputs(),
        passphraseFlag: true as false,
      }),
    ).toThrow(/passphrase flag/);
    expect(() =>
      encodeDecryptionProofPublicInputsV1({
        ...samplePublicInputs(),
        argon2TCost: 1 as 0,
      }),
    ).toThrow(/Argon2/);
    expect(() =>
      encodeDecryptionProofPublicInputsV1({
        ...samplePublicInputs(),
        policyCommitment: bytes(31, 1),
      }),
    ).toThrow(/policy commitment/);
    expect(() =>
      encodeDecryptionProofPublicInputsV1({
        ...samplePublicInputs(),
        plaintextCommitment: bytes(31, 1),
      }),
    ).toThrow(/plaintext commitment/);
    expect(() =>
      encodeDecryptionProofPublicInputsV1({
        ...samplePublicInputs(),
        kemCiphertext: bytes(ML_KEM_768_CIPHERTEXT_BYTES - 1, 1),
      }),
    ).toThrow(/KEM ciphertext/);
    expect(() => encodeDecryptionProofPublicInputsV1({ ...samplePublicInputs(), aeadNonce: bytes(11, 1) })).toThrow(
      /nonce/,
    );
    expect(() =>
      encodeDecryptionProofPublicInputsV1({ ...samplePublicInputs(), aeadCiphertextAndTag: bytes(15, 1) }),
    ).toThrow(/ciphertext and tag/);
  });

  it('keeps vaultTreeRoot optional only at the builder boundary', () => {
    expect(() =>
      encodeDecryptionProofPublicInputsV1({
        ...samplePublicInputs(),
        vaultTreeRoot: undefined as unknown as Uint8Array,
      }),
    ).toThrow(/vaultTreeRoot/);
    expect(() =>
      encodeDecryptionProofPublicInputsV1({
        ...samplePublicInputs(),
        vaultTreeRoot: null as unknown as Uint8Array,
      }),
    ).toThrow(/vaultTreeRoot/);

    const built = buildDecryptionProofPublicInputsFromDecodedHeaderV1({
      firstHeader: sampleHeader(),
      fullHeaderPayload: sampleHeaderPayload(),
      payloadKind: 'vault-root',
      policyCommitment: bytes(32, 5),
      plaintextCommitment: bytes(32, 6),
      vaultTreeRoot: null,
    });
    expect(built.vaultTreeRoot.length).toBe(0);
    const encoded = encodeDecryptionProofPublicInputsV1(built);
    const field = splitEncodedTranscript(encoded).fields.find((candidate) => candidate[0] === 0x07);
    expect(field?.slice(1, 5)).toEqual(new Uint8Array([0, 0, 0, 0]));
  });

  it('builder slices the header payload with the hardcoded ML-KEM-768 boundaries', () => {
    const fullHeaderPayload = sampleHeaderPayload();
    const built = buildDecryptionProofPublicInputsFromDecodedHeaderV1({
      firstHeader: sampleHeader(),
      fullHeaderPayload,
      payloadKind: 'vault-root',
      policyCommitment: bytes(32, 5),
      plaintextCommitment: bytes(32, 6),
      vaultTreeRoot: bytes(32, 7),
    });
    expect(built.kemCiphertext).toEqual(fullHeaderPayload.slice(0, 1088));
    expect(built.aeadNonce).toEqual(fullHeaderPayload.slice(1088, 1100));
    expect(built.aeadCiphertextAndTag).toEqual(fullHeaderPayload.slice(1100));
  });

  it('builder rejects mutated no-passphrase Argon2 header values', () => {
    expect(() =>
      buildDecryptionProofPublicInputsFromDecodedHeaderV1({
        firstHeader: { ...sampleHeader(), argon2: { tCost: 1, memLog2KiB: 0, parallelism: 0 } },
        fullHeaderPayload: sampleHeaderPayload(),
        payloadKind: 'vault-root',
        policyCommitment: bytes(32, 5),
        plaintextCommitment: bytes(32, 6),
      }),
    ).toThrow(/Argon2/);
  });

  it('splits SHA-256 transcript digests into two big-endian BN254-safe limbs', () => {
    const digest = Uint8Array.from({ length: 32 }, (_, index) => index);
    expect(splitTranscriptDigestForBn254PublicInputs(digest)).toEqual({
      high128: 0x000102030405060708090a0b0c0d0e0fn,
      low128: 0x101112131415161718191a1b1c1d1e1fn,
    });
    expect(() => splitTranscriptDigestForBn254PublicInputs(bytes(31, 1))).toThrow(/32 bytes/);
  });
});

function samplePublicInputs(): DecryptionProofPublicInputsV1 {
  return {
    bundleId: bytes(8, 1),
    payloadKind: 'vault-root',
    kemAlgId: 1,
    kdfAlgId: 1,
    aeadAlgId: 1,
    commitmentHashId: 1,
    passphraseFlag: false,
    argon2TCost: 0,
    argon2MemLog2KiB: 0,
    argon2Parallelism: 0,
    policyCommitment: bytes(32, 2),
    plaintextCommitment: bytes(32, 3),
    vaultTreeRoot: bytes(32, 4),
    kemCiphertext: bytes(ML_KEM_768_CIPHERTEXT_BYTES, 5),
    aeadNonce: bytes(12, 6),
    aeadCiphertextAndTag: bytes(48, 7),
  };
}

function sampleHeaderPayload(): Uint8Array {
  return concat(bytes(ML_KEM_768_CIPHERTEXT_BYTES, 5), bytes(12, 6), bytes(48, 7));
}

function sampleHeader(): HeaderChunkQr {
  return {
    kind: KIND_HEADER,
    version: VERSION_V3,
    bundleId: bytes(8, 1),
    kemAlg: 'ml-kem-768',
    aeadAlg: 'aes-256-gcm',
    kdfAlg: 'hkdf-sha256',
    flags: { passphrase: false },
    argon2: { tCost: 0, memLog2KiB: 0, parallelism: 0 },
    t: 2,
    n: 3,
    chunkIdx: 0,
    chunkTotal: 1,
    payload: sampleHeaderPayload(),
  };
}

function replaceField(encoded: Uint8Array, tag: number, value: Uint8Array): Uint8Array {
  const { prefix, fields } = splitEncodedTranscript(encoded);
  return concat(prefix, ...fields.map((field) => (field[0] === tag ? fieldBytes(tag, value) : field)));
}

function splitEncodedTranscript(encoded: Uint8Array): { prefix: Uint8Array; fields: Uint8Array[] } {
  const prefixLen = 2 + DOMAIN_LEN + 1;
  const fields: Uint8Array[] = [];
  let offset = prefixLen;
  while (offset < encoded.length) {
    const length =
      encoded[offset + 1]! * 0x1000000 +
      ((encoded[offset + 2]! << 16) | (encoded[offset + 3]! << 8) | encoded[offset + 4]!);
    const end = offset + 5 + length;
    fields.push(encoded.slice(offset, end));
    offset = end;
  }
  return { prefix: encoded.slice(0, prefixLen), fields };
}

function fieldBytes(tag: number, value: Uint8Array): Uint8Array {
  const out = new Uint8Array(5 + value.length);
  out[0] = tag;
  out[1] = (value.length >>> 24) & 0xff;
  out[2] = (value.length >>> 16) & 0xff;
  out[3] = (value.length >>> 8) & 0xff;
  out[4] = value.length & 0xff;
  out.set(value, 5);
  return out;
}

function bytes(length: number, seed: number): Uint8Array {
  return Uint8Array.from({ length }, (_, index) => (seed + index) & 0xff);
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
