import { sha256 } from '@noble/hashes/sha2.js';
import type { PolicyManifest, PolicyManifestNode } from '../policy.js';
import { merkleRoot } from './merkle.js';

const MANIFEST_LEAF_DOMAIN = 'manifest-leaf';

const enc = new TextEncoder();

function nodeLeafBytes(node: PolicyManifestNode): Uint8Array {
  const childrenSorted = (node.children ?? []).slice().sort();
  const payload = JSON.stringify({
    id: node.id,
    type: node.type,
    custodianId: node.custodianId ?? null,
    threshold: node.threshold ?? null,
    children: childrenSorted,
  });
  return sha256(enc.encode(payload));
}

function manifestLeaves(manifest: PolicyManifest): Uint8Array[] {
  const ids = Object.keys(manifest.nodes).sort();
  const root = sha256(
    enc.encode(
      JSON.stringify({
        version: manifest.version,
        kind: manifest.kind,
        rootNodeId: manifest.rootNodeId,
        threshold: manifest.threshold,
        totalPoints: manifest.totalPoints,
        custodians: manifest.custodians
          .slice()
          .sort((a, b) => a.id.localeCompare(b.id))
          .map((c) => ({ id: c.id, shareIdx: c.shareIdx, weight: c.weight })),
      }),
    ),
  );
  const leaves: Uint8Array[] = [root];
  for (const id of ids) leaves.push(nodeLeafBytes(manifest.nodes[id]!));
  return leaves;
}

export function commitPolicyManifest(manifest: PolicyManifest): Uint8Array {
  return merkleRoot(manifestLeaves(manifest), MANIFEST_LEAF_DOMAIN);
}

export function verifyPolicyManifestCommitment(
  manifest: PolicyManifest,
  expectedRoot: Uint8Array,
): boolean {
  const actual = commitPolicyManifest(manifest);
  if (actual.length !== expectedRoot.length) return false;
  let diff = 0;
  for (let i = 0; i < actual.length; i++) diff |= actual[i]! ^ expectedRoot[i]!;
  return diff === 0;
}
