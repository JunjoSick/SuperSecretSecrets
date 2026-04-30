import { sha256 } from '@noble/hashes/sha2.js';
import type { VaultEntry } from '../vault/index.js';
import { merkleProof, merkleRoot, merkleVerify, type MerkleProof } from './merkle.js';

const VAULT_LEAF_DOMAIN = 'vault-leaf';

const enc = new TextEncoder();

function entryLeaf(entry: VaultEntry): Uint8Array {
  const dst = enc.encode('SSS3/vault-leaf-input');
  const idBytes = enc.encode(entry.id);
  const nameBytes = enc.encode(entry.name);
  const ctBytes = enc.encode(entry.contentType ?? '');
  const dataDigest = sha256(entry.data);
  const buf = new Uint8Array(
    dst.length + 4 + idBytes.length + 4 + nameBytes.length + 4 + ctBytes.length + dataDigest.length,
  );
  let o = 0;
  buf.set(dst, o);
  o += dst.length;
  const view = new DataView(buf.buffer);
  view.setUint32(o, idBytes.length, false);
  o += 4;
  buf.set(idBytes, o);
  o += idBytes.length;
  view.setUint32(o, nameBytes.length, false);
  o += 4;
  buf.set(nameBytes, o);
  o += nameBytes.length;
  view.setUint32(o, ctBytes.length, false);
  o += 4;
  buf.set(ctBytes, o);
  o += ctBytes.length;
  buf.set(dataDigest, o);
  return sha256(buf);
}

export function vaultTreeRoot(entries: VaultEntry[]): Uint8Array {
  if (entries.length === 0) throw new Error('vault must contain at least one entry');
  return merkleRoot(entries.map(entryLeaf), VAULT_LEAF_DOMAIN);
}

export function proveVaultEntry(
  entries: VaultEntry[],
  index: number,
): { leaf: Uint8Array; proof: MerkleProof } {
  if (entries.length === 0) throw new Error('vault must contain at least one entry');
  const leaf = entryLeaf(entries[index]!);
  const proof = merkleProof(entries.map(entryLeaf), index, VAULT_LEAF_DOMAIN);
  return { leaf, proof };
}

export function verifyVaultEntry(
  entry: VaultEntry,
  proof: MerkleProof,
  root: Uint8Array,
): boolean {
  const leaf = entryLeaf(entry);
  return merkleVerify(leaf, proof, root, VAULT_LEAF_DOMAIN);
}
