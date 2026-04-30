import { describe, expect, it } from 'vitest';
import {
  HALO2_WITNESS_DOMAIN,
  HALO2_WITNESS_V1_BYTES,
  copyWitnessToWasmMemory,
  decodeDecryptionProofWitnessV1,
  encodeAndZeroizeDecryptionProofWitnessV1,
  encodeDecryptionProofWitnessV1,
  zeroizeBytes,
  zeroizeDecryptionProofWitnessV1,
  zeroizeWasmMemoryRegion,
} from '../src/crypto/zk/halo2/witness';
import type { DecryptionProofWitnessV1 } from '../src/crypto/zk/decryption-proof-prover';

const DOMAIN_LEN = new TextEncoder().encode(HALO2_WITNESS_DOMAIN).length;

describe('Halo2 witness codec and memory-boundary helpers', () => {
  it('round-trips deterministic binary witness encoding', () => {
    const witness = sampleWitness();
    const encoded = encodeDecryptionProofWitnessV1(witness);
    expect(encoded[0]).toBe(0);
    expect(encoded[1]).toBe(DOMAIN_LEN);
    expect(new TextDecoder().decode(encoded.slice(2, 2 + DOMAIN_LEN))).toBe(HALO2_WITNESS_DOMAIN);
    expect(encoded[2 + DOMAIN_LEN]).toBe(1);
    expect(decodeDecryptionProofWitnessV1(encoded)).toEqual(witness);
  });

  it('rejects wrong witness lengths, field order, missing fields, and trailing bytes', () => {
    expect(() => encodeDecryptionProofWitnessV1({ ...sampleWitness(), kemSeed: bytes(63, 1) })).toThrow(/KEM seed/);
    expect(() => encodeDecryptionProofWitnessV1({ ...sampleWitness(), vaultRootKey: bytes(31, 1) })).toThrow(
      /vault root key/,
    );

    const encoded = encodeDecryptionProofWitnessV1(sampleWitness());
    const { prefix, fields } = splitEncodedWitness(encoded);
    expect(() => decodeDecryptionProofWitnessV1(concat(prefix, fields[1]!, fields[0]!))).toThrow();
    expect(() => decodeDecryptionProofWitnessV1(concat(prefix, fields[0]!))).toThrow(/truncated|missing/);
    expect(() => decodeDecryptionProofWitnessV1(concat(encoded, new Uint8Array([0])))).toThrow(/trailing/);
  });

  it('zeroizes JS witness buffers explicitly', () => {
    const witness = sampleWitness();
    zeroizeDecryptionProofWitnessV1(witness);
    expect(witness.kemSeed).toEqual(new Uint8Array(64));
    expect(witness.vaultRootKey).toEqual(new Uint8Array(32));
  });

  it('zeroizes witness buffers after compatibility encoding', () => {
    const witness = sampleWitness();
    const encoded = encodeAndZeroizeDecryptionProofWitnessV1(witness);
    expect(decodeDecryptionProofWitnessV1(encoded)).toEqual(sampleWitness());
    expect(witness.kemSeed).toEqual(new Uint8Array(64));
    expect(witness.vaultRootKey).toEqual(new Uint8Array(32));
  });

  it('copies witness material to WASM memory and zeroizes observable regions', () => {
    const witness = sampleWitness();
    const memory = new WebAssembly.Memory({ initial: 1 });
    const ptr = 128;
    copyWitnessToWasmMemory({ memory, ptr, witness });
    const region = new Uint8Array(memory.buffer, ptr, HALO2_WITNESS_V1_BYTES);
    expect(region.slice(0, 64)).toEqual(witness.kemSeed);
    expect(region.slice(64)).toEqual(witness.vaultRootKey);

    zeroizeWasmMemoryRegion(memory, ptr, HALO2_WITNESS_V1_BYTES);
    expect(region).toEqual(new Uint8Array(HALO2_WITNESS_V1_BYTES));
  });

  it('rejects out-of-bounds WASM memory regions', () => {
    const memory = new WebAssembly.Memory({ initial: 1 });
    expect(() => zeroizeWasmMemoryRegion(memory, memory.buffer.byteLength - 4, 8)).toThrow(/out of bounds/);
  });

  it('zeroizeBytes is explicit best-effort JS buffer hygiene', () => {
    const value = bytes(8, 1);
    zeroizeBytes(value);
    expect(value).toEqual(new Uint8Array(8));
  });
});

function sampleWitness(): DecryptionProofWitnessV1 {
  return {
    kemSeed: bytes(64, 1),
    vaultRootKey: bytes(32, 100),
  };
}

function splitEncodedWitness(encoded: Uint8Array): { prefix: Uint8Array; fields: Uint8Array[] } {
  const prefixLen = 2 + DOMAIN_LEN + 1;
  const fields: Uint8Array[] = [];
  let offset = prefixLen;
  while (offset < encoded.length) {
    const len =
      encoded[offset + 1]! * 0x1000000 +
      ((encoded[offset + 2]! << 16) | (encoded[offset + 3]! << 8) | encoded[offset + 4]!);
    const end = offset + 5 + len;
    fields.push(encoded.slice(offset, end));
    offset = end;
  }
  return { prefix: encoded.slice(0, prefixLen), fields };
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
