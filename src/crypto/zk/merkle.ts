import { sha256 } from '@noble/hashes/sha2.js';

export const HASH_LEN = 32;

export type MerkleProof = {
  index: number;
  leafCount: number;
  siblings: Uint8Array[];
};

const enc = new TextEncoder();

function leafHash(domain: string, leaf: Uint8Array): Uint8Array {
  const dst = enc.encode(domain);
  const buf = new Uint8Array(1 + dst.length + leaf.length);
  buf[0] = 0x00;
  buf.set(dst, 1);
  buf.set(leaf, 1 + dst.length);
  return sha256(buf);
}

function nodeHash(domain: string, left: Uint8Array, right: Uint8Array): Uint8Array {
  const dst = enc.encode(domain);
  const buf = new Uint8Array(1 + dst.length + HASH_LEN * 2);
  buf[0] = 0x01;
  buf.set(dst, 1);
  buf.set(left, 1 + dst.length);
  buf.set(right, 1 + dst.length + HASH_LEN);
  return sha256(buf);
}

export function merkleRoot(leaves: Uint8Array[], domain: string): Uint8Array {
  if (leaves.length === 0) throw new Error('merkle tree requires at least one leaf');
  return merkleRootFromHashes(leaves.map((leaf) => leafHash(domain, leaf)), domain);
}

export function merkleProof(leaves: Uint8Array[], index: number, domain: string): MerkleProof {
  if (leaves.length === 0) throw new Error('merkle tree requires at least one leaf');
  if (!Number.isInteger(index) || index < 0 || index >= leaves.length) {
    throw new Error('index out of range');
  }
  const hashes = leaves.map((leaf) => leafHash(domain, leaf));
  const siblings: Uint8Array[] = [];
  collectProof(hashes, index, domain, siblings);
  return { index, leafCount: leaves.length, siblings };
}

export function merkleVerify(
  leaf: Uint8Array,
  proof: MerkleProof,
  root: Uint8Array,
  domain: string,
): boolean {
  if (root.length !== HASH_LEN) return false;
  if (!Number.isInteger(proof.index) || !Number.isInteger(proof.leafCount)) return false;
  if (proof.index < 0 || proof.leafCount < 1 || proof.index >= proof.leafCount) return false;
  const directions = proofDirections(proof.leafCount, proof.index);
  if (directions.length !== proof.siblings.length) return false;
  let cur = leafHash(domain, leaf);
  for (let i = proof.siblings.length - 1; i >= 0; i--) {
    const sibling = proof.siblings[i]!;
    if (sibling.length !== HASH_LEN) return false;
    cur = directions[i] === 'left' ? nodeHash(domain, cur, sibling) : nodeHash(domain, sibling, cur);
  }
  return constantTimeEqual(cur, root);
}

export function encodeMerkleProof(proof: MerkleProof): Uint8Array {
  if (proof.siblings.length > 0xff) throw new Error('merkle proof too deep');
  const out = new Uint8Array(4 + 4 + 1 + proof.siblings.length * HASH_LEN);
  const view = new DataView(out.buffer);
  view.setUint32(0, proof.index >>> 0, false);
  view.setUint32(4, proof.leafCount >>> 0, false);
  out[8] = proof.siblings.length;
  let o = 9;
  for (const s of proof.siblings) {
    if (s.length !== HASH_LEN) throw new Error('sibling must be 32 bytes');
    out.set(s, o);
    o += HASH_LEN;
  }
  return out;
}

export function decodeMerkleProof(raw: Uint8Array): MerkleProof {
  if (raw.length < 9) throw new Error('truncated merkle proof');
  const view = new DataView(raw.buffer, raw.byteOffset, raw.byteLength);
  const index = view.getUint32(0, false);
  const leafCount = view.getUint32(4, false);
  const depth = raw[8]!;
  if (raw.length !== 9 + depth * HASH_LEN) throw new Error('merkle proof length mismatch');
  const siblings: Uint8Array[] = [];
  for (let i = 0; i < depth; i++) siblings.push(raw.slice(9 + i * HASH_LEN, 9 + (i + 1) * HASH_LEN));
  return { index, leafCount, siblings };
}

function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

function splitPoint(n: number): number {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

function merkleRootFromHashes(hashes: Uint8Array[], domain: string): Uint8Array {
  if (hashes.length === 1) return hashes[0]!;
  const k = splitPoint(hashes.length);
  return nodeHash(
    domain,
    merkleRootFromHashes(hashes.slice(0, k), domain),
    merkleRootFromHashes(hashes.slice(k), domain),
  );
}

function collectProof(hashes: Uint8Array[], index: number, domain: string, siblings: Uint8Array[]): void {
  if (hashes.length === 1) return;
  const k = splitPoint(hashes.length);
  if (index < k) {
    siblings.push(merkleRootFromHashes(hashes.slice(k), domain));
    collectProof(hashes.slice(0, k), index, domain, siblings);
  } else {
    siblings.push(merkleRootFromHashes(hashes.slice(0, k), domain));
    collectProof(hashes.slice(k), index - k, domain, siblings);
  }
}

function proofDirections(leafCount: number, index: number): Array<'left' | 'right'> {
  if (leafCount === 1) return [];
  const k = splitPoint(leafCount);
  if (index < k) return ['left', ...proofDirections(k, index)];
  return ['right', ...proofDirections(leafCount - k, index - k)];
}
