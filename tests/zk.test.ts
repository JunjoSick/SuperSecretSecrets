import { describe, expect, it } from 'vitest';
import {
  G,
  ORDER,
  hashToPoint,
  hashToScalar,
  pointFromBytes,
  pointToBytes,
  randomScalar,
  scalarFromBytes,
  scalarToBytes,
} from '../src/crypto/zk/curve';
import {
  decodeMerkleProof,
  encodeMerkleProof,
  merkleProof,
  merkleRoot,
  merkleVerify,
} from '../src/crypto/zk/merkle';
import {
  commitmentFromBytes,
  commitmentToBytes,
  H,
  pedersenCommit,
  valueScalar,
} from '../src/crypto/zk/pedersen';
import {
  decodeSchnorrProof,
  encodeSchnorrProof,
  schnorrProveCommit,
  schnorrVerifyCommit,
  SCHNORR_PROOF_LEN,
} from '../src/crypto/zk/schnorr';

const utf8 = (s: string) => new TextEncoder().encode(s);

describe('curve', () => {
  it('exposes ristretto255 base and prime-order scalar field', () => {
    expect(G.equals(G)).toBe(true);
    expect(ORDER).toBeGreaterThan(2n ** 251n);
    expect(ORDER).toBeLessThan(2n ** 253n);
  });

  it('round-trips scalars through bytes', () => {
    const s = randomScalar();
    expect(scalarFromBytes(scalarToBytes(s))).toBe(s);
  });

  it('round-trips points through bytes', () => {
    const p = G.multiply(42n);
    const back = pointFromBytes(pointToBytes(p));
    expect(back.equals(p)).toBe(true);
  });

  it('hashToScalar is deterministic and domain-separated', () => {
    const a = hashToScalar('test', utf8('hello'));
    const b = hashToScalar('test', utf8('hello'));
    const c = hashToScalar('other', utf8('hello'));
    expect(a).toBe(b);
    expect(a).not.toBe(c);
  });

  it('hashToPoint is deterministic and domain-separated', () => {
    const a = hashToPoint('test', utf8('hello'));
    const b = hashToPoint('test', utf8('hello'));
    const c = hashToPoint('other', utf8('hello'));
    expect(a.equals(b)).toBe(true);
    expect(a.equals(c)).toBe(false);
  });
});

describe('Pedersen commitments', () => {
  it('H is independent of G (no known DLOG relation by construction)', () => {
    expect(H().equals(G)).toBe(false);
    expect(H().equals(H())).toBe(true);
  });

  it('binds value: same blinding, different value → different commitment', () => {
    const r = randomScalar();
    const c1 = pedersenCommit(7n, r);
    const c2 = pedersenCommit(8n, r);
    expect(c1.equals(c2)).toBe(false);
  });

  it('hides value: same value, different blinding → different commitment', () => {
    const c1 = pedersenCommit(7n, randomScalar());
    const c2 = pedersenCommit(7n, randomScalar());
    expect(c1.equals(c2)).toBe(false);
  });

  it('homomorphic: C(v1,r1) + C(v2,r2) = C(v1+v2, r1+r2)', () => {
    const v1 = 11n;
    const r1 = 22n;
    const v2 = 33n;
    const r2 = 44n;
    const lhs = pedersenCommit(v1, r1).add(pedersenCommit(v2, r2));
    const rhs = pedersenCommit(v1 + v2, r1 + r2);
    expect(lhs.equals(rhs)).toBe(true);
  });

  it('round-trips commitments through bytes', () => {
    const c = pedersenCommit(123n, 456n);
    expect(commitmentFromBytes(commitmentToBytes(c)).equals(c)).toBe(true);
  });

  it('valueScalar is deterministic for the same payload', () => {
    const a = valueScalar('share-value', utf8('payload'));
    const b = valueScalar('share-value', utf8('payload'));
    expect(a).toBe(b);
  });
});

describe('Schnorr PoK of commitment opening', () => {
  it('honestly produced proofs verify', () => {
    const v = valueScalar('share-value', utf8('share bytes'));
    const r = randomScalar();
    const C = pedersenCommit(v, r);
    const ctx = utf8('bundle/0');
    const proof = schnorrProveCommit(v, r, C, ctx);
    expect(schnorrVerifyCommit(C, proof, ctx)).toBe(true);
  });

  it('rejects tampered C', () => {
    const v = 5n;
    const r = randomScalar();
    const C = pedersenCommit(v, r);
    const ctx = utf8('ctx');
    const proof = schnorrProveCommit(v, r, C, ctx);
    const Cprime = pedersenCommit(6n, r);
    expect(schnorrVerifyCommit(Cprime, proof, ctx)).toBe(false);
  });

  it('rejects tampered context', () => {
    const v = 5n;
    const r = randomScalar();
    const C = pedersenCommit(v, r);
    const proof = schnorrProveCommit(v, r, C, utf8('ctx-A'));
    expect(schnorrVerifyCommit(C, proof, utf8('ctx-B'))).toBe(false);
  });

  it('rejects forged proof with random A and z values', () => {
    const v = 5n;
    const r = randomScalar();
    const C = pedersenCommit(v, r);
    const ctx = utf8('ctx');
    const fake = {
      A: G.multiply(randomScalar()),
      z1: randomScalar(),
      z2: randomScalar(),
    };
    expect(schnorrVerifyCommit(C, fake, ctx)).toBe(false);
  });

  it('rejects proofs that flip a single byte in the encoded form', () => {
    const v = 9n;
    const r = randomScalar();
    const C = pedersenCommit(v, r);
    const ctx = utf8('ctx');
    const proof = schnorrProveCommit(v, r, C, ctx);
    const encoded = encodeSchnorrProof(proof);
    expect(encoded.length).toBe(SCHNORR_PROOF_LEN);
    const tampered = encoded.slice();
    tampered[0]! ^= 0x01;
    let parsed: ReturnType<typeof decodeSchnorrProof> | null = null;
    try {
      parsed = decodeSchnorrProof(tampered);
    } catch {
      parsed = null;
    }
    if (parsed) expect(schnorrVerifyCommit(C, parsed, ctx)).toBe(false);
  });

  it('encodes and decodes proofs', () => {
    const v = 17n;
    const r = randomScalar();
    const C = pedersenCommit(v, r);
    const ctx = utf8('ctx');
    const proof = schnorrProveCommit(v, r, C, ctx);
    const enc = encodeSchnorrProof(proof);
    const dec = decodeSchnorrProof(enc);
    expect(schnorrVerifyCommit(C, dec, ctx)).toBe(true);
  });
});

describe('Merkle tree', () => {
  const leaves = [utf8('alpha'), utf8('beta'), utf8('gamma'), utf8('delta'), utf8('epsilon')];
  const domain = 'test-tree';

  it('produces deterministic root', () => {
    const r1 = merkleRoot(leaves, domain);
    const r2 = merkleRoot(leaves, domain);
    expect(r1).toEqual(r2);
  });

  it('domain separates roots', () => {
    const r1 = merkleRoot(leaves, 'A');
    const r2 = merkleRoot(leaves, 'B');
    expect(r1).not.toEqual(r2);
  });

  it('does not duplicate the final odd leaf into the tree shape', () => {
    const three = merkleRoot([utf8('a'), utf8('b'), utf8('c')], domain);
    const four = merkleRoot([utf8('a'), utf8('b'), utf8('c'), utf8('c')], domain);
    expect(three).not.toEqual(four);
  });

  it('verifies inclusion proofs for every leaf', () => {
    const root = merkleRoot(leaves, domain);
    for (let i = 0; i < leaves.length; i++) {
      const proof = merkleProof(leaves, i, domain);
      expect(merkleVerify(leaves[i]!, proof, root, domain)).toBe(true);
    }
  });

  it('rejects proof with wrong index', () => {
    const root = merkleRoot(leaves, domain);
    const proof = merkleProof(leaves, 1, domain);
    expect(merkleVerify(leaves[2]!, proof, root, domain)).toBe(false);
  });

  it('rejects proof with tampered sibling', () => {
    const root = merkleRoot(leaves, domain);
    const proof = merkleProof(leaves, 2, domain);
    if (proof.siblings.length > 0) proof.siblings[0]![0]! ^= 0xff;
    expect(merkleVerify(leaves[2]!, proof, root, domain)).toBe(false);
  });

  it('rejects proof against wrong root', () => {
    const proof = merkleProof(leaves, 0, domain);
    const wrongRoot = merkleRoot([utf8('x'), utf8('y')], domain);
    expect(merkleVerify(leaves[0]!, proof, wrongRoot, domain)).toBe(false);
  });

  it('rejects proof against different domain', () => {
    const root = merkleRoot(leaves, domain);
    const proof = merkleProof(leaves, 0, domain);
    expect(merkleVerify(leaves[0]!, proof, root, 'other')).toBe(false);
  });

  it('handles single-leaf trees', () => {
    const single = [utf8('only')];
    const root = merkleRoot(single, domain);
    const proof = merkleProof(single, 0, domain);
    expect(proof.siblings).toHaveLength(0);
    expect(merkleVerify(single[0]!, proof, root, domain)).toBe(true);
  });

  it('round-trips proofs through encode/decode', () => {
    const root = merkleRoot(leaves, domain);
    const proof = merkleProof(leaves, 3, domain);
    const enc = encodeMerkleProof(proof);
    const dec = decodeMerkleProof(enc);
    expect(dec.index).toBe(proof.index);
    expect(dec.leafCount).toBe(proof.leafCount);
    expect(dec.siblings.length).toBe(proof.siblings.length);
    expect(merkleVerify(leaves[3]!, dec, root, domain)).toBe(true);
  });

  it('rejects truncated encoded proofs', () => {
    const proof = merkleProof(leaves, 0, domain);
    const enc = encodeMerkleProof(proof);
    expect(() => decodeMerkleProof(enc.slice(0, enc.length - 1))).toThrow();
  });
});
