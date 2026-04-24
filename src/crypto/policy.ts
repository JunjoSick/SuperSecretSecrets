import { split, combine } from './shamir';
import type { ShareMetadata } from './metadata';

export const POLICY_ROOT_NODE_ID = 'root';
export const POLICY_COMPONENTS_FORMAT = 1;

export type Custodian = {
  id: string;
  name?: string;
  weight?: number;
  metadata?: ShareMetadata;
};

export type PolicyNode =
  | { type: 'LEAF'; id?: string; custodianId: string }
  | { type: 'OR'; id?: string; children: PolicyNode[] }
  | { type: 'AND'; id?: string; children: PolicyNode[] }
  | { type: 'THRESHOLD'; id?: string; threshold: number; children: PolicyNode[] };

export type ShareComponent = {
  id: string;
  nodeId: string;
  custodianId: string;
  value: Uint8Array;
};

export type CustodianShare = {
  custodian: Custodian;
  shareIdx: number;
  components: ShareComponent[];
};

export type PolicyManifestNode = {
  id: string;
  type: PolicyNode['type'];
  custodianId?: string;
  threshold?: number;
  children?: string[];
};

export type PolicyManifest = {
  version: 2;
  kind: 'flat' | 'tree';
  rootNodeId: string;
  threshold: number;
  totalPoints: number;
  custodians: Array<{ id: string; shareIdx: number; weight: number; name?: string }>;
  nodes: Record<string, PolicyManifestNode>;
};

export type CompiledPolicy = {
  manifest: PolicyManifest;
  shares: CustodianShare[];
};

export type PolicyProgress = {
  satisfied: boolean;
  available: number;
  required: number;
  total: number;
};

const enc = new TextEncoder();
const dec = new TextDecoder();

export function compileFlatPolicy(
  secret: Uint8Array,
  threshold: number,
  custodians: Custodian[],
  rng?: (n: number) => Uint8Array,
): CompiledPolicy {
  const normalized = normalizeCustodians(custodians);
  const totalPoints = normalized.reduce((sum, c) => sum + weightOf(c), 0);
  if (totalPoints > 255) throw new Error('weighted point count must be <= 255');
  if (threshold < 2 || threshold > totalPoints) {
    throw new Error('flat policy threshold must be between 2 and total weighted points');
  }

  const points = split(secret, threshold, totalPoints, rng);
  let pointOffset = 0;
  const shares: CustodianShare[] = normalized.map((custodian, idx) => {
    const components: ShareComponent[] = [];
    for (let i = 0; i < weightOf(custodian); i++) {
      const point = points[pointOffset++]!;
      components.push({
        id: `${POLICY_ROOT_NODE_ID}:${point[0]!}`,
        nodeId: POLICY_ROOT_NODE_ID,
        custodianId: custodian.id,
        value: point,
      });
    }
    return { custodian, shareIdx: idx + 1, components };
  });

  return {
    manifest: {
      version: 2,
      kind: 'flat',
      rootNodeId: POLICY_ROOT_NODE_ID,
      threshold,
      totalPoints,
      custodians: manifestCustodians(shares),
      nodes: {
        [POLICY_ROOT_NODE_ID]: {
          id: POLICY_ROOT_NODE_ID,
          type: 'THRESHOLD',
          threshold,
          children: [],
        },
      },
    },
    shares,
  };
}

export function compileTreePolicy(
  secret: Uint8Array,
  policy: PolicyNode,
  custodiansIn: Custodian[],
  rng?: (n: number) => Uint8Array,
): CompiledPolicy {
  const custodians = normalizeCustodians(custodiansIn);
  const byCustodian = new Map(custodians.map((c) => [c.id, c]));
  const nodes: Record<string, PolicyManifestNode> = {};
  const shareComponents = new Map<string, ShareComponent[]>();
  let generated = 0;
  let componentCount = 0;

  function nodeId(node: PolicyNode, fallback: string): string {
    return node.id ?? fallback;
  }

  function assign(node: PolicyNode, nodeSecret: Uint8Array, path: string): string {
    const id = nodeId(node, path === '' ? POLICY_ROOT_NODE_ID : path);
    if (nodes[id]) throw new Error(`duplicate policy node id ${id}`);
    switch (node.type) {
      case 'LEAF': {
        if (!byCustodian.has(node.custodianId)) throw new Error(`unknown custodian ${node.custodianId}`);
        nodes[id] = { id, type: 'LEAF', custodianId: node.custodianId };
        const component: ShareComponent = {
          id: `${id}:${++generated}`,
          nodeId: id,
          custodianId: node.custodianId,
          value: nodeSecret,
        };
        shareComponents.set(node.custodianId, [...(shareComponents.get(node.custodianId) ?? []), component]);
        componentCount++;
        return id;
      }
      case 'OR': {
        assertChildren(node.children, id);
        const childIds = node.children.map((child, idx) => assign(child, nodeSecret, `${id}.${idx + 1}`));
        nodes[id] = { id, type: 'OR', children: childIds };
        return id;
      }
      case 'AND':
      case 'THRESHOLD': {
        assertChildren(node.children, id);
        const threshold = node.type === 'AND' ? node.children.length : node.threshold;
        if (!Number.isInteger(threshold) || threshold < 2 || threshold > node.children.length) {
          throw new Error(`invalid threshold at policy node ${id}`);
        }
        const childShares = split(nodeSecret, threshold, node.children.length, rng);
        const childIds = node.children.map((child, idx) => assign(child, childShares[idx]!, `${id}.${idx + 1}`));
        nodes[id] = { id, type: node.type, threshold, children: childIds };
        return id;
      }
    }
  }

  const rootNodeId = assign(policy, secret, POLICY_ROOT_NODE_ID);
  if (componentCount > 255) throw new Error('policy component count must be <= 255');

  const shares = custodians
    .map((custodian, idx) => ({
      custodian,
      shareIdx: idx + 1,
      components: shareComponents.get(custodian.id) ?? [],
    }))
    .filter((share) => share.components.length > 0);

  return {
    manifest: {
      version: 2,
      kind: 'tree',
      rootNodeId,
      threshold: policyThreshold(nodes[rootNodeId]!),
      totalPoints: componentCount,
      custodians: manifestCustodians(shares),
      nodes,
    },
    shares,
  };
}

export function encodePolicyManifest(manifest: PolicyManifest): Uint8Array {
  return enc.encode(JSON.stringify(manifest));
}

export function decodePolicyManifest(raw: Uint8Array): PolicyManifest {
  const parsed = JSON.parse(dec.decode(raw)) as PolicyManifest;
  if (parsed.version !== 2) throw new Error('unsupported policy manifest version');
  if (parsed.kind !== 'flat' && parsed.kind !== 'tree') throw new Error('unknown policy manifest kind');
  if (!parsed.nodes?.[parsed.rootNodeId]) throw new Error('policy manifest missing root node');
  return parsed;
}

export function encodeShareComponents(components: ShareComponent[]): Uint8Array {
  if (components.length > 255) throw new Error('too many components in one share');
  const chunks: Uint8Array[] = [new Uint8Array([POLICY_COMPONENTS_FORMAT, components.length])];
  for (const component of components) {
    const id = enc.encode(component.id);
    const custodianId = enc.encode(component.custodianId);
    const nodeId = enc.encode(component.nodeId);
    if (id.length > 255 || custodianId.length > 255 || nodeId.length > 255) {
      throw new Error('policy component identifiers must be <= 255 bytes');
    }
    if (component.value.length > 0xffff) throw new Error('policy component value too long');
    chunks.push(
      new Uint8Array([id.length]),
      id,
      new Uint8Array([custodianId.length]),
      custodianId,
      new Uint8Array([nodeId.length]),
      nodeId,
      u16(component.value.length),
      component.value,
    );
  }
  return concat(...chunks);
}

export function decodeShareComponents(raw: Uint8Array): ShareComponent[] {
  if (raw.length < 2) throw new Error('truncated policy component payload');
  if (raw[0] !== POLICY_COMPONENTS_FORMAT) throw new Error('unknown policy component payload format');
  const count = raw[1]!;
  let o = 2;
  const components: ShareComponent[] = [];
  for (let i = 0; i < count; i++) {
    const id = readString(raw, o);
    o = id.next;
    const custodianId = readString(raw, o);
    o = custodianId.next;
    const nodeId = readString(raw, o);
    o = nodeId.next;
    if (o + 2 > raw.length) throw new Error('truncated policy component value length');
    const valueLen = (raw[o]! << 8) | raw[o + 1]!;
    o += 2;
    if (o + valueLen > raw.length) throw new Error('truncated policy component value');
    const value = raw.slice(o, o + valueLen);
    o += valueLen;
    components.push({
      id: id.value,
      custodianId: custodianId.value,
      nodeId: nodeId.value,
      value,
    });
  }
  if (o !== raw.length) throw new Error('trailing bytes after policy component payload');
  return components;
}

export function recoverPolicySecret(
  manifest: PolicyManifest,
  shares: Array<{ components: ShareComponent[] }>,
): { secret: Uint8Array | null; progress: PolicyProgress } {
  const componentsByNode = new Map<string, ShareComponent[]>();
  for (const share of shares) {
    for (const component of share.components) {
      componentsByNode.set(component.nodeId, [...(componentsByNode.get(component.nodeId) ?? []), component]);
    }
  }

  if (manifest.kind === 'flat') {
    const rootComponents = dedupeByComponentId(componentsByNode.get(manifest.rootNodeId) ?? []);
    const progress = {
      satisfied: rootComponents.length >= manifest.threshold,
      available: rootComponents.length,
      required: manifest.threshold,
      total: manifest.totalPoints,
    };
    if (!progress.satisfied) return { secret: null, progress };
    const chosen = rootComponents
      .sort((a, b) => shareX(a.value) - shareX(b.value))
      .slice(0, manifest.threshold)
      .map((component) => component.value);
    return { secret: combine(chosen), progress };
  }

  const recovered = recoverNode(manifest.rootNodeId);
  const root = manifest.nodes[manifest.rootNodeId]!;
  const childStates = nodeSatisfaction(root);
  const progress = {
    satisfied: recovered !== null,
    available: childStates.available,
    required: childStates.required,
    total: childStates.total,
  };
  return { secret: recovered, progress };

  function recoverNode(nodeId: string): Uint8Array | null {
    const node = manifest.nodes[nodeId];
    if (!node) throw new Error(`policy manifest references missing node ${nodeId}`);
    switch (node.type) {
      case 'LEAF':
        return (componentsByNode.get(nodeId) ?? [])[0]?.value ?? null;
      case 'OR':
        for (const childId of node.children ?? []) {
          const value = recoverNode(childId);
          if (value) return value;
        }
        return null;
      case 'AND':
      case 'THRESHOLD': {
        const threshold = policyThreshold(node);
        const values: Uint8Array[] = [];
        for (const childId of node.children ?? []) {
          const value = recoverNode(childId);
          if (value) values.push(value);
        }
        if (values.length < threshold) return null;
        return combine(values.slice(0, threshold));
      }
    }
  }

  function nodeSatisfaction(node: PolicyManifestNode): PolicyProgress {
    if (node.type === 'LEAF') {
      const present = (componentsByNode.get(node.id) ?? []).length > 0;
      return { satisfied: present, available: present ? 1 : 0, required: 1, total: 1 };
    }
    const children = (node.children ?? []).map((id) => nodeSatisfaction(manifest.nodes[id]!));
    if (node.type === 'OR') {
      return {
        satisfied: children.some((c) => c.satisfied),
        available: children.filter((c) => c.satisfied).length,
        required: 1,
        total: children.length,
      };
    }
    const required = policyThreshold(node);
    const available = children.filter((c) => c.satisfied).length;
    return { satisfied: available >= required, available, required, total: children.length };
  }
}

function normalizeCustodians(custodians: Custodian[]): Custodian[] {
  if (custodians.length === 0) throw new Error('at least one custodian is required');
  const ids = new Set<string>();
  return custodians.map((custodian, idx) => {
    const id = custodian.id || `custodian-${idx + 1}`;
    if (ids.has(id)) throw new Error(`duplicate custodian id ${id}`);
    ids.add(id);
    return { ...custodian, id, weight: weightOf(custodian) };
  });
}

function manifestCustodians(shares: CustodianShare[]): PolicyManifest['custodians'] {
  return shares.map((share) => {
    const item: PolicyManifest['custodians'][number] = {
      id: share.custodian.id,
      shareIdx: share.shareIdx,
      weight: weightOf(share.custodian),
    };
    if (share.custodian.name) item.name = share.custodian.name;
    return item;
  });
}

function policyThreshold(node: PolicyManifestNode): number {
  if (node.type === 'OR') return 1;
  if (node.type === 'AND') return node.children?.length ?? 0;
  if (node.type === 'THRESHOLD') return node.threshold ?? 0;
  return 1;
}

function assertChildren(children: PolicyNode[], id: string): void {
  if (children.length === 0) throw new Error(`policy node ${id} must have children`);
  if (children.length > 255) throw new Error(`policy node ${id} has too many children`);
}

function weightOf(custodian: Custodian): number {
  const weight = custodian.weight ?? 1;
  if (!Number.isInteger(weight) || weight < 1) throw new Error(`invalid weight for custodian ${custodian.id}`);
  return weight;
}

function dedupeByComponentId(components: ShareComponent[]): ShareComponent[] {
  const seen = new Set<string>();
  const out: ShareComponent[] = [];
  for (const component of components) {
    if (seen.has(component.id)) continue;
    seen.add(component.id);
    out.push(component);
  }
  return out;
}

function shareX(value: Uint8Array): number {
  return value[0] ?? 0;
}

function readString(raw: Uint8Array, offset: number): { value: string; next: number } {
  if (offset >= raw.length) throw new Error('truncated policy component string length');
  const len = raw[offset]!;
  const start = offset + 1;
  const end = start + len;
  if (end > raw.length) throw new Error('truncated policy component string');
  return { value: dec.decode(raw.slice(start, end)), next: end };
}

function u16(value: number): Uint8Array {
  return new Uint8Array([(value >>> 8) & 0xff, value & 0xff]);
}

function concat(...chunks: Uint8Array[]): Uint8Array {
  const len = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const out = new Uint8Array(len);
  let o = 0;
  for (const chunk of chunks) {
    out.set(chunk, o);
    o += chunk.length;
  }
  return out;
}
