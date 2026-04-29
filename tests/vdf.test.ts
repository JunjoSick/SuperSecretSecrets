import { describe, expect, it } from 'vitest';
import {
  discriminantFromPrime,
  hashToPrime,
  isPrime,
  samplePrimeCongruent3Mod4,
  sqrtModPrime,
} from '../src/crypto/vdf/prime';
import { hashToForm } from '../src/crypto/vdf/wesolowski';
import {
  compose,
  composeReference,
  discriminant,
  equal,
  identity,
  inverse,
  isReduced,
  parseForm,
  pow,
  reduce,
  serializeForm,
  square,
  squareReference,
  type Form,
} from '../src/crypto/vdf/classgroup';
import qfbVectors from './fixtures/qfb-vectors.json';

const utf8 = (s: string) => new TextEncoder().encode(s);

type FormJson = { a: string; b: string; c: string };

function formFromJson(form: FormJson): Form {
  return {
    a: BigInt(form.a),
    b: BigInt(form.b),
    c: BigInt(form.c),
  };
}

describe('isPrime', () => {
  it('classifies small known primes correctly', () => {
    for (const p of [2n, 3n, 5n, 7n, 11n, 13n, 9999999967n, 100000000003n]) {
      expect(isPrime(p)).toBe(true);
    }
  });

  it('classifies small known composites correctly', () => {
    for (const n of [1n, 4n, 6n, 9n, 15n, 25n, 49n, 91n, 121n, 9999999969n]) {
      expect(isPrime(n)).toBe(false);
    }
  });

  it('rejects negatives and zero', () => {
    expect(isPrime(0n)).toBe(false);
    expect(isPrime(1n)).toBe(false);
    expect(isPrime(-7n)).toBe(false);
  });
});

describe('samplePrimeCongruent3Mod4', () => {
  it('returns a prime ≡ 3 (mod 4) with the requested bit length', () => {
    for (let trial = 0; trial < 4; trial++) {
      const p = samplePrimeCongruent3Mod4(64);
      expect(p % 4n).toBe(3n);
      expect(isPrime(p)).toBe(true);
      expect(p >= 1n << 63n).toBe(true);
      expect(p < 1n << 64n).toBe(true);
    }
  });

  it('is reproducible under a deterministic RNG', () => {
    const makeRng = (initial: number) => {
      let state = initial >>> 0;
      return (n: number) => {
        const out = new Uint8Array(n);
        for (let i = 0; i < n; i++) {
          state = ((state * 1664525) + 1013904223) >>> 0;
          out[i] = (state >>> 16) & 0xff;
        }
        return out;
      };
    };
    const a = samplePrimeCongruent3Mod4(64, makeRng(42));
    const b = samplePrimeCongruent3Mod4(64, makeRng(42));
    expect(a).toBe(b);
  });
});

describe('hashToPrime', () => {
  it('is deterministic for the same seed', () => {
    const a = hashToPrime(utf8('hello'), 128);
    const b = hashToPrime(utf8('hello'), 128);
    expect(a).toBe(b);
    expect(isPrime(a)).toBe(true);
  });

  it('is sensitive to seed input', () => {
    const a = hashToPrime(utf8('hello'), 128);
    const b = hashToPrime(utf8('world'), 128);
    expect(a).not.toBe(b);
  });

  it('respects the requested bit length', () => {
    const p = hashToPrime(utf8('test'), 96);
    expect(p < 1n << 96n).toBe(true);
    expect(p >= 1n << 95n).toBe(true);
    expect(p & 1n).toBe(1n);
  });
});

describe('discriminantFromPrime', () => {
  it('returns -p for p ≡ 3 (mod 4) and asserts -p ≡ 1 (mod 4)', () => {
    const p = 23n;
    const delta = discriminantFromPrime(p);
    expect(delta).toBe(-23n);
    expect(((delta % 4n) + 4n) % 4n).toBe(1n);
  });

  it('rejects p ≡ 1 (mod 4)', () => {
    expect(() => discriminantFromPrime(13n)).toThrow();
  });

  it('rejects very small primes', () => {
    expect(() => discriminantFromPrime(3n)).not.toThrow();
    expect(() => discriminantFromPrime(2n)).toThrow();
  });
});

describe('class group: identity / discriminant / equality', () => {
  it('principal form is reduced and has the requested discriminant', () => {
    for (const p of [23n, 47n, 67n, 103n, 163n, 211n]) {
      const delta = discriminantFromPrime(p);
      const id = identity(delta);
      expect(discriminant(id)).toBe(delta);
      expect(isReduced(id)).toBe(true);
    }
  });

  it('equality requires all three coefficients to match', () => {
    const f: Form = { a: 1n, b: 1n, c: 6n };
    const g: Form = { a: 1n, b: 1n, c: 6n };
    const h: Form = { a: 1n, b: -1n, c: 6n };
    expect(equal(f, g)).toBe(true);
    expect(equal(f, h)).toBe(false);
  });
});

describe('class group: reduction', () => {
  it('preserves discriminant', () => {
    const cases: Form[] = [
      { a: 5n, b: 11n, c: 7n },
      { a: 3n, b: 5n, c: 4n },
      { a: 7n, b: 9n, c: 5n },
      { a: 11n, b: 13n, c: 7n },
      { a: 100n, b: 1n, c: 6n },
    ];
    for (const f of cases) {
      const r = reduce(f);
      expect(discriminant(r)).toBe(discriminant(f));
      expect(isReduced(r)).toBe(true);
    }
  });

  it('reduces a known non-reduced form to a known reduced form (Δ=-19)', () => {
    const r = reduce({ a: 5n, b: 11n, c: 7n });
    expect(equal(r, { a: 1n, b: 1n, c: 5n })).toBe(true);
  });

  it('reduces another known case (Δ=-23)', () => {
    const r = reduce({ a: 3n, b: 5n, c: 4n });
    expect(equal(r, { a: 2n, b: 1n, c: 3n })).toBe(true);
  });

  it('is idempotent', () => {
    const f: Form = { a: 5n, b: 11n, c: 7n };
    const r1 = reduce(f);
    const r2 = reduce(r1);
    expect(equal(r1, r2)).toBe(true);
  });

  it('enumerates the 3 reduced forms of class group of disc -23', () => {
    const delta = -23n;
    const candidates: Form[] = [
      { a: 1n, b: 1n, c: 6n },
      { a: 2n, b: 1n, c: 3n },
      { a: 2n, b: -1n, c: 3n },
    ];
    for (const f of candidates) {
      expect(discriminant(f)).toBe(delta);
      expect(isReduced(f)).toBe(true);
      expect(equal(reduce(f), f)).toBe(true);
    }
  });

  it('rejects non-positive leading coefficient', () => {
    expect(() => reduce({ a: 0n, b: 0n, c: 0n })).toThrow();
    expect(() => reduce({ a: -1n, b: 0n, c: 23n })).toThrow();
  });
});

describe('class group: composition', () => {
  const delta23 = -23n;
  const id23: Form = { a: 1n, b: 1n, c: 6n };
  const g: Form = { a: 2n, b: 1n, c: 3n };
  const gInv: Form = { a: 2n, b: -1n, c: 3n };

  it('preserves discriminant', () => {
    const r = compose(g, gInv);
    expect(discriminant(r)).toBe(delta23);
    expect(isReduced(r)).toBe(true);
  });

  it('identity law: compose(f, identity) = f', () => {
    expect(equal(compose(g, id23), g)).toBe(true);
    expect(equal(compose(id23, g), g)).toBe(true);
    expect(equal(compose(gInv, id23), gInv)).toBe(true);
  });

  it('inverse law: compose(f, inverse(f)) = identity', () => {
    expect(equal(compose(g, inverse(g)), id23)).toBe(true);
    expect(equal(compose(gInv, inverse(gInv)), id23)).toBe(true);
  });

  it('squaring: g² = (2, -1, 3) for disc -23', () => {
    expect(equal(square(g), gInv)).toBe(true);
    expect(equal(square(gInv), g)).toBe(true);
  });

  it('order 3: g³ = identity for disc -23', () => {
    const g3 = compose(square(g), g);
    expect(equal(g3, id23)).toBe(true);
  });

  it('square via compose matches dedicated square', () => {
    expect(equal(square(g), compose(g, g))).toBe(true);
    expect(equal(square(gInv), compose(gInv, gInv))).toBe(true);
  });

  it('fast square stays equivalent to the reference square oracle', () => {
    const deltas = [-23n, -47n, -9223372036854775783n];
    for (const delta of deltas) {
      for (let i = 0; i < 16; i++) {
        const f = hashToForm(utf8(`square-${delta}-${i}`), delta);
        expect(equal(square(f), squareReference(f))).toBe(true);
      }
    }
  });

  it('fast square matches reference along a long squaring chain (128-bit Δ)', () => {
    // hashToForm produces small-a generators; chain-state forms have a/b/c
    // near sqrt(|Δ|/3) and exercise the cheap-C path on full-width bigints.
    // 9223372036854775783 is a 64-bit prime ≡ 3 (mod 4) so |Δ| has 64 bits;
    // we extend by chaining many squarings to hit the steady-state coefficient
    // distribution this commit's optimisation targets.
    const delta = -9223372036854775783n;
    let fast = hashToForm(utf8('chain-seed'), delta);
    let ref = fast;
    for (let i = 0; i < 200; i++) {
      fast = square(fast);
      ref = squareReference(ref);
      expect(equal(fast, ref), `chain step ${i}`).toBe(true);
    }
  });

  it('fast compose matches reference for random same-discriminant pairs', () => {
    const delta = -9223372036854775783n;
    const corpus: Form[] = [];
    let f = hashToForm(utf8('compose-seed'), delta);
    for (let i = 0; i < 32; i++) {
      f = squareReference(f);
      corpus.push(f);
    }
    for (let i = 0; i < corpus.length; i++) {
      for (let j = 0; j < corpus.length; j++) {
        const left = corpus[i]!;
        const right = corpus[j]!;
        expect(equal(compose(left, right), composeReference(left, right)), `pair ${i},${j}`).toBe(true);
      }
    }
  });

  it('compose falls back to reference (non-coprime path) for non-primitive squarings', () => {
    // Δ = -23 has h = 3 with reduced forms { (1,1,6), (2,1,3), (2,-1,3) }.
    // Squaring (2,1,3) hits gcd(a1,a2) = 2 ≠ 1, exercising findCoprimeForm.
    // Both compose and composeReference must agree on the result.
    const f: Form = { a: 2n, b: 1n, c: 3n };
    const g: Form = { a: 2n, b: -1n, c: 3n };
    expect(equal(compose(f, f), composeReference(f, f))).toBe(true);
    expect(equal(compose(g, g), composeReference(g, g))).toBe(true);
    expect(equal(compose(f, g), composeReference(f, g))).toBe(true);
  });

  it('associativity: (f * g) * h = f * (g * h)', () => {
    const lhs = compose(compose(g, gInv), g);
    const rhs = compose(g, compose(gInv, g));
    expect(equal(lhs, rhs)).toBe(true);
  });

  it('rejects forms with mismatched discriminant', () => {
    const f23 = id23;
    const f19: Form = { a: 1n, b: 1n, c: 5n };
    expect(() => compose(f23, f19)).toThrow();
  });

  it('matches pinned QFB vectors and the reference composition oracle', () => {
    for (const vector of qfbVectors.cases) {
      const left = formFromJson(vector.left);
      const right = formFromJson(vector.right);
      const expected = formFromJson(vector.compose);
      const composed = compose(left, right);
      expect(discriminant(left).toString()).toBe(vector.discriminants.left);
      expect(discriminant(right).toString()).toBe(vector.discriminants.right);
      expect(discriminant(composed).toString()).toBe(vector.delta);
      expect(equal(composeReference(left, right), expected), vector.name).toBe(true);
      expect(equal(composed, expected), vector.name).toBe(true);
      expect(equal(square(left), formFromJson(vector.squareLeft)), vector.name).toBe(true);
      expect(equal(inverse(left), formFromJson(vector.inverseLeft)), vector.name).toBe(true);
      expect(equal(pow(left, 13n), formFromJson(vector.powLeft13)), vector.name).toBe(true);
    }
  });
});

describe('class group: pow', () => {
  const id23: Form = { a: 1n, b: 1n, c: 6n };
  const g: Form = { a: 2n, b: 1n, c: 3n };
  const gInv: Form = { a: 2n, b: -1n, c: 3n };

  it('pow(f, 0) = identity', () => {
    expect(equal(pow(g, 0n), id23)).toBe(true);
  });

  it('pow(f, 1) = f', () => {
    expect(equal(pow(g, 1n), g)).toBe(true);
  });

  it('pow(f, 2) = square(f)', () => {
    expect(equal(pow(g, 2n), square(g))).toBe(true);
  });

  it('pow respects group order: g^3 = identity, g^4 = g, g^7 = g (since order 3)', () => {
    expect(equal(pow(g, 3n), id23)).toBe(true);
    expect(equal(pow(g, 4n), g)).toBe(true);
    expect(equal(pow(g, 7n), g)).toBe(true);
  });

  it('pow(f, n) * pow(f, m) = pow(f, n+m)', () => {
    for (const [n, m] of [[2n, 5n], [7n, 11n], [13n, 1n]] as const) {
      const lhs = compose(pow(g, n), pow(g, m));
      const rhs = pow(g, n + m);
      expect(equal(lhs, rhs)).toBe(true);
    }
  });

  it('pow with large exponent terminates', () => {
    // g has order 3 so g^large should be one of {id, g, gInv}
    const e = (1n << 64n) + 7n;
    const r = pow(g, e);
    expect([id23, g, gInv].some((f) => equal(r, f))).toBe(true);
  });

  it('rejects negative exponents', () => {
    expect(() => pow(g, -1n)).toThrow();
  });
});

describe('class group: inverse', () => {
  it('inverse of identity is identity', () => {
    const id23: Form = { a: 1n, b: 1n, c: 6n };
    expect(equal(inverse(id23), id23)).toBe(true);
  });

  it('inverse is involutive', () => {
    const g: Form = { a: 2n, b: 1n, c: 3n };
    expect(equal(inverse(inverse(g)), g)).toBe(true);
  });

  it('inverse(f) reduces to (a, -b, c)', () => {
    const g: Form = { a: 2n, b: 1n, c: 3n };
    expect(equal(inverse(g), { a: 2n, b: -1n, c: 3n })).toBe(true);
  });
});

describe('sqrtModPrime', () => {
  it('returns 0 for n = 0', () => {
    expect(sqrtModPrime(0n, 7n)).toBe(0n);
  });

  it('finds square roots for known QRs (p ≡ 3 mod 4)', () => {
    for (const [n, p] of [[2n, 7n], [4n, 11n], [9n, 23n], [25n, 47n]] as const) {
      const r = sqrtModPrime(n, p);
      if (r === null) throw new Error(`expected QR for ${n} mod ${p}`);
      expect((r * r) % p).toBe(n % p);
    }
  });

  it('finds square roots for QRs (p ≡ 1 mod 4, full Tonelli-Shanks)', () => {
    for (const [n, p] of [[4n, 13n], [9n, 17n], [16n, 29n], [25n, 37n]] as const) {
      const r = sqrtModPrime(n, p);
      if (r === null) throw new Error(`expected QR for ${n} mod ${p}`);
      expect((r * r) % p).toBe(n % p);
    }
  });

  it('returns null for non-residues', () => {
    expect(sqrtModPrime(2n, 5n)).toBe(null); // 2 is NR mod 5
    expect(sqrtModPrime(3n, 7n)).toBe(null); // 3 is NR mod 7
  });

  it('handles negative n correctly (p ≡ 1 mod 4 so -1 is QR)', () => {
    const p = 13n;
    const r = sqrtModPrime(-1n, p);
    if (r === null) throw new Error('expected QR');
    expect((r * r) % p).toBe((p - 1n) % p);
  });
});

describe('hashToForm', () => {
  it('produces a reduced form of the requested discriminant', () => {
    const delta = -23n;
    const f = hashToForm(new TextEncoder().encode('seed'), delta);
    expect(discriminant(f)).toBe(delta);
    expect(isReduced(f)).toBe(true);
  });

  it('is deterministic for the same seed', () => {
    const delta = -163n;
    const a = hashToForm(new TextEncoder().encode('seed'), delta);
    const b = hashToForm(new TextEncoder().encode('seed'), delta);
    expect(equal(a, b)).toBe(true);
  });

  it('different seeds may produce different forms', () => {
    const delta = -163n;
    const f1 = hashToForm(new TextEncoder().encode('seed-A'), delta);
    const f2 = hashToForm(new TextEncoder().encode('seed-B'), delta);
    // Both must have the right disc but they may collide for tiny class groups.
    // For -163 (h=1), they collide. For -23 (h=3), often differ.
    expect(discriminant(f1)).toBe(delta);
    expect(discriminant(f2)).toBe(delta);
  });

  it('produces a non-principal form for class groups of order > 1 with most seeds', () => {
    const delta = -23n; // h(-23) = 3
    const id = identity(delta);
    let nonPrincipal = 0;
    for (let i = 0; i < 16; i++) {
      const seed = new TextEncoder().encode(`seed-${i}`);
      const f = hashToForm(seed, delta);
      if (!equal(f, id)) nonPrincipal++;
    }
    expect(nonPrincipal).toBeGreaterThan(0);
  });
});

describe('Wesolowski VDF (disc -23)', () => {
  const g: Form = { a: 2n, b: 1n, c: 3n };
  const gInv: Form = { a: 2n, b: -1n, c: 3n };

  it('vdfEval(g, 0) = g', async () => {
    const { vdfEval } = await import('../src/crypto/vdf/wesolowski');
    expect(equal(vdfEval(g, 0n), g)).toBe(true);
  });

  it('vdfEval(g, T) = g^(2^T) for small T (order 3)', async () => {
    const { vdfEval } = await import('../src/crypto/vdf/wesolowski');
    // 2^0=1: g^1=g; 2^1=2: g^2=gInv; 2^2=4≡1 mod 3: g^4=g; 2^3=8≡2 mod 3: g^8=gInv
    expect(equal(vdfEval(g, 1n), gInv)).toBe(true);
    expect(equal(vdfEval(g, 2n), g)).toBe(true);
    expect(equal(vdfEval(g, 3n), gInv)).toBe(true);
    expect(equal(vdfEval(g, 4n), g)).toBe(true);
  });

  it('vdfEval streams progress', async () => {
    const { vdfEval } = await import('../src/crypto/vdf/wesolowski');
    let lastDone = -1n;
    let lastTotal = -1n;
    vdfEval(g, 5n, (done, total) => {
      lastDone = done;
      lastTotal = total;
    });
    expect(lastDone).toBe(5n);
    expect(lastTotal).toBe(5n);
  });

  it('vdfProve / vdfVerify round-trip succeeds for honest input', async () => {
    const { vdfEval, vdfProve, vdfVerify } = await import('../src/crypto/vdf/wesolowski');
    for (const T of [4n, 5n, 8n, 16n]) {
      const y = vdfEval(g, T);
      const pi = vdfProve(g, y, T, 24);
      expect(vdfVerify(g, y, pi, T, 24)).toBe(true);
    }
  });

  it('vdfVerify rejects tampered y', async () => {
    const { vdfEval, vdfProve, vdfVerify } = await import('../src/crypto/vdf/wesolowski');
    const T = 8n;
    const y = vdfEval(g, T);
    const pi = vdfProve(g, y, T, 24);
    const tamperedY = equal(y, g) ? gInv : g;
    expect(vdfVerify(g, tamperedY, pi, T, 24)).toBe(false);
  });

  it('vdfVerify rejects tampered T', async () => {
    const { vdfEval, vdfProve, vdfVerify } = await import('../src/crypto/vdf/wesolowski');
    const T = 8n;
    const y = vdfEval(g, T);
    const pi = vdfProve(g, y, T, 24);
    expect(vdfVerify(g, y, pi, T + 1n, 24)).toBe(false);
    expect(vdfVerify(g, y, pi, T - 1n, 24)).toBe(false);
  });

  it('vdfVerify rejects tampered π', async () => {
    const { vdfEval, vdfProve, vdfVerify } = await import('../src/crypto/vdf/wesolowski');
    const T = 8n;
    const y = vdfEval(g, T);
    const pi = vdfProve(g, y, T, 24);
    const tamperedPi: Form = { a: pi.a + 2n, b: pi.b, c: pi.c };
    expect(vdfVerify(g, y, tamperedPi, T, 24)).toBe(false);
  });

  it('vdfVerify rejects mismatched discriminant', async () => {
    const { vdfEval, vdfVerify } = await import('../src/crypto/vdf/wesolowski');
    const T = 4n;
    const y = vdfEval(g, T);
    const wrongDiscPi: Form = { a: 1n, b: 1n, c: 5n }; // disc -19
    expect(vdfVerify(g, y, wrongDiscPi, T, 24)).toBe(false);
  });

  it('vdfProve rejects forms with mismatched discriminant', async () => {
    const { vdfProve } = await import('../src/crypto/vdf/wesolowski');
    const wrongDisc: Form = { a: 1n, b: 1n, c: 5n };
    expect(() => vdfProve(g, wrongDisc, 4n, 24)).toThrow();
  });

  it('vdfLockShare progress is monotonically non-decreasing across eval and prove', async () => {
    const { vdfLockShare } = await import('../src/crypto/vdf/timelock');
    const { discriminantFromPrime } = await import('../src/crypto/vdf/prime');
    const delta = discriminantFromPrime((1n << 127n) - 1n);
    const T = 1n << 8n;
    const events: Array<{ done: bigint; total: bigint }> = [];
    vdfLockShare(
      new Uint8Array(8),
      { delta, T },
      utf8('cancel-test'),
      (n) => new Uint8Array(n),
      (done, total) => {
        events.push({ done, total });
      },
    );
    // Two phases (eval, prove) are remapped to a single [0, 2T] range.
    expect(events.length).toBeGreaterThan(2);
    const total = events[0]!.total;
    expect(total).toBe(T * 2n);
    expect(events.every((e) => e.total === total)).toBe(true);
    for (let i = 1; i < events.length; i++) {
      expect(events[i]!.done >= events[i - 1]!.done, `regress at ${i}`).toBe(true);
    }
    expect(events[events.length - 1]!.done).toBe(total);
  });

  it('vdfLockShare propagates a callback throw to abort the lock mid-flight', async () => {
    const { vdfLockShare } = await import('../src/crypto/vdf/timelock');
    const { discriminantFromPrime } = await import('../src/crypto/vdf/prime');
    const delta = discriminantFromPrime((1n << 127n) - 1n);
    const T = 1n << 10n;
    let calls = 0;
    expect(() =>
      vdfLockShare(
        new Uint8Array(8),
        { delta, T },
        utf8('cancel-mid'),
        (n) => new Uint8Array(n),
        () => {
          calls++;
          if (calls >= 2) throw new Error('cancelled');
        },
      ),
    ).toThrow('cancelled');
    // The throw must come from inside the eval loop, not after it completes.
    // With the dynamic progress interval (T/32), eval alone emits ~32 events,
    // so cancelling on the second event proves we don't run the entire eval.
    expect(calls).toBeLessThan(20);
  });
});

describe('class group: serialization', () => {
  it('round-trips reduced forms through bytes', () => {
    const cases: Form[] = [
      { a: 1n, b: 1n, c: 6n },
      { a: 2n, b: -1n, c: 3n },
      { a: 1n, b: 1n, c: (1n - -163n) / 4n },
      { a: 12345678901234567890n, b: -98765n, c: 99999n },
      identity(-163n),
    ];
    for (const f of cases) {
      const enc = serializeForm(f);
      const dec = parseForm(enc);
      expect(equal(dec, f)).toBe(true);
    }
  });

  it('round-trips negative b correctly', () => {
    const f: Form = { a: 7n, b: -3n, c: 11n };
    expect(equal(parseForm(serializeForm(f)), f)).toBe(true);
  });

  it('rejects trailing bytes', () => {
    const enc = serializeForm({ a: 1n, b: 1n, c: 6n });
    const padded = new Uint8Array(enc.length + 1);
    padded.set(enc, 0);
    expect(() => parseForm(padded)).toThrow();
  });

  it('rejects truncated input', () => {
    const enc = serializeForm({ a: 1n, b: 1n, c: 6n });
    expect(() => parseForm(enc.slice(0, enc.length - 1))).toThrow();
  });
});
