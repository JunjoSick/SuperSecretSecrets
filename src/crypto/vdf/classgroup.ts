export type Form = { a: bigint; b: bigint; c: bigint };

export function discriminant(f: Form): bigint {
  return f.b * f.b - 4n * f.a * f.c;
}

export function identity(delta: bigint): Form {
  const mod4 = ((delta % 4n) + 4n) % 4n;
  if (mod4 === 1n) {
    const c = (1n - delta) / 4n;
    return { a: 1n, b: 1n, c };
  }
  if (mod4 === 0n) {
    const c = -delta / 4n;
    return { a: 1n, b: 0n, c };
  }
  throw new Error(`discriminant must be ≡ 0 or 1 (mod 4); got ${mod4}`);
}

export function equal(f: Form, g: Form): boolean {
  return f.a === g.a && f.b === g.b && f.c === g.c;
}

export function isReduced(f: Form): boolean {
  const { a, b, c } = f;
  if (a <= 0n) return false;
  if (a > c) return false;
  const negA = -a;
  if (b <= negA || b > a) return false;
  if (a === c && b < 0n) return false;
  return true;
}

function floorDiv(a: bigint, b: bigint): bigint {
  if (b === 0n) throw new Error('division by zero');
  const q = a / b;
  const r = a % b;
  if (r !== 0n && (a < 0n) !== (b < 0n)) return q - 1n;
  return q;
}

function gcd(a: bigint, b: bigint): bigint {
  let x = a < 0n ? -a : a;
  let y = b < 0n ? -b : b;
  while (y > 0n) [x, y] = [y, x % y];
  return x;
}

function extgcd(a: bigint, b: bigint): { g: bigint; x: bigint; y: bigint } {
  let oldR = a;
  let r = b;
  let oldS = 1n;
  let s = 0n;
  let oldT = 0n;
  let t = 1n;
  while (r !== 0n) {
    const q = floorDiv(oldR, r);
    [oldR, r] = [r, oldR - q * r];
    [oldS, s] = [s, oldS - q * s];
    [oldT, t] = [t, oldT - q * t];
  }
  if (oldR < 0n) return { g: -oldR, x: -oldS, y: -oldT };
  return { g: oldR, x: oldS, y: oldT };
}

function modInverse(a: bigint, m: bigint): bigint {
  if (m <= 0n) throw new Error('modulus must be positive');
  if (m === 1n) return 0n;
  const aReduced = ((a % m) + m) % m;
  const eg = extgcd(aReduced, m);
  if (eg.g !== 1n) throw new Error(`no modular inverse: gcd(${a}, ${m}) = ${eg.g}`);
  return ((eg.x % m) + m) % m;
}

function transformByMatrix(f: Form, p: bigint, q: bigint, r: bigint, s: bigint): Form {
  const newA = f.a * p * p + f.b * p * q + f.c * q * q;
  const newB = 2n * f.a * p * r + f.b * (p * s + q * r) + 2n * f.c * q * s;
  const newC = f.a * r * r + f.b * r * s + f.c * s * s;
  return { a: newA, b: newB, c: newC };
}

function findCoprimeForm(f: Form, m: bigint): Form {
  const absM = m < 0n ? -m : m;
  if (absM <= 1n || gcd(f.a, absM) === 1n) return f;
  for (let n = 1n; n <= 200n; n++) {
    for (let q = 0n; q <= n; q++) {
      for (let pAbs = 0n; pAbs <= n; pAbs++) {
        if (pAbs + q !== n) continue;
        for (const pSign of [1n, -1n]) {
          if (pAbs === 0n && pSign === -1n) continue;
          const p = pAbs * pSign;
          const absP = pAbs;
          const absQ = q;
          if (absP === 0n && absQ === 0n) continue;
          if (gcd(absP, absQ) !== 1n) continue;
          const newA = f.a * p * p + f.b * p * q + f.c * q * q;
          const candidate = newA < 0n ? -newA : newA;
          if (candidate <= 0n) continue;
          if (gcd(candidate, absM) !== 1n) continue;
          const eg = extgcd(p, q);
          if (eg.g !== 1n) continue;
          const sx = eg.x;
          const ry = -eg.y;
          if (p * sx - q * ry !== 1n) continue;
          return transformByMatrix(f, p, q, ry, sx);
        }
      }
    }
  }
  throw new Error('failed to find coprime equivalent form');
}

function simpleCompose(f1: Form, f2: Form, delta: bigint): Form {
  const { a: a1, b: b1 } = f1;
  const { a: a2, b: b2 } = f2;
  if (a2 === 1n) {
    const A = a1;
    const B = b1;
    const C = (B * B - delta) / (4n * A);
    return reduce({ a: A, b: B, c: C });
  }
  const a1Inv = modInverse(((a1 % a2) + a2) % a2, a2);
  const halfDiff = (b2 - b1) / 2n;
  const halfMod = ((halfDiff % a2) + a2) % a2;
  const t = (halfMod * a1Inv) % a2;
  const B = b1 + 2n * a1 * t;
  const A = a1 * a2;
  const C = (B * B - delta) / (4n * A);
  return reduce({ a: A, b: B, c: C });
}

export function composeReference(f1: Form, f2: Form): Form {
  const d1 = discriminant(f1);
  const d2 = discriminant(f2);
  if (d1 !== d2) throw new Error('forms must share discriminant');
  if (gcd(f1.a, f2.a) === 1n) return simpleCompose(f1, f2, d1);
  const transformed = findCoprimeForm(f1, f2.a);
  if (discriminant(transformed) !== d1) throw new Error('transform broke discriminant');
  return simpleCompose(transformed, f2, d1);
}

// Fast composition for the coprime case. Computes the same form as
// simpleCompose but skips the 2n-bit B*B multiplication used to derive C.
//
// Derivation: B = b1 + 2*a1*t and Δ = b1² - 4*a1*c1, so
//   B² - Δ = 4*a1*(t*b1 + a1*t² + c1)
//   (B² - Δ) / (4*a1*a2) = (t*b1 + a1*t² + c1) / a2
// which gives C as a quotient of n-bit values rather than 2n-bit ones.
function simpleComposeFast(f1: Form, f2: Form): Form {
  const { a: a1, b: b1, c: c1 } = f1;
  const { a: a2, b: b2 } = f2;
  if (a2 === 1n) return reduce({ a: a1, b: b1, c: c1 });
  const a1Inv = modInverse(((a1 % a2) + a2) % a2, a2);
  const halfDiff = (b2 - b1) / 2n;
  const halfMod = ((halfDiff % a2) + a2) % a2;
  const t = (halfMod * a1Inv) % a2;
  const a1t = a1 * t;
  const C = (t * b1 + a1t * t + c1) / a2;
  const B = b1 + a1t + a1t;
  const A = a1 * a2;
  return reduce({ a: A, b: B, c: C });
}

export function compose(f1: Form, f2: Form): Form {
  const d1 = discriminant(f1);
  const d2 = discriminant(f2);
  if (d1 !== d2) throw new Error('forms must share discriminant');
  if (gcd(f1.a, f2.a) === 1n) return simpleComposeFast(f1, f2);
  const transformed = findCoprimeForm(f1, f2.a);
  if (discriminant(transformed) !== d1) throw new Error('transform broke discriminant');
  return simpleComposeFast(transformed, f2);
}

function duplicatePrimitive(f: Form): Form | null {
  const reduced = reduce(f);
  const { a, b, c } = reduced;
  if (gcd(a, b) !== 1n) return null;
  const t = a === 1n ? 0n : (((-c % a) + a) * modInverse(b, a)) % a;
  // Same algebraic shortcut as simpleComposeFast specialised to f1 = f2 = (a,b,c):
  //   B = b + 2*a*t and B² - Δ = 4*a*(b*t + a*t² + c), so
  //   C = (b*t + a*t² + c) / a, avoiding the big B*B multiply.
  const at = a * t;
  const numC = b * t + at * t + c;
  if (numC % a !== 0n) return null;
  const B = b + at + at;
  const A = a * a;
  return reduce({ a: A, b: B, c: numC / a });
}

export function squareReference(f: Form): Form {
  return composeReference(f, f);
}

export function square(f: Form): Form {
  return duplicatePrimitive(f) ?? squareReference(f);
}

export function pow(f: Form, e: bigint): Form {
  if (e < 0n) throw new Error('negative exponent not supported');
  const delta = discriminant(f);
  if (e === 0n) return reduce(identity(delta));
  if (e === 1n) return reduce(f);
  let result: Form | null = null;
  let base = reduce(f);
  let exp = e;
  while (exp > 0n) {
    if (exp & 1n) result = result === null ? base : compose(result, base);
    exp >>= 1n;
    if (exp > 0n) base = square(base);
  }
  return result!;
}

export function inverse(f: Form): Form {
  return reduce({ a: f.a, b: -f.b, c: f.c });
}

export function reduce(f: Form): Form {
  let { a, b, c } = f;
  if (a <= 0n) throw new Error('form must have positive leading coefficient');
  for (let guard = 0; guard < 1000000; guard++) {
    if (b > a || b < -a) {
      const twoA = 2n * a;
      const q = floorDiv(b + a, twoA);
      const newB = b - q * twoA;
      const newC = c - q * b + q * q * a;
      b = newB;
      c = newC;
      continue;
    }
    if (a > c) {
      [a, c] = [c, a];
      b = -b;
      continue;
    }
    if (a === c && b < 0n) {
      b = -b;
      continue;
    }
    if (b === -a) {
      b = a;
      continue;
    }
    return { a, b, c };
  }
  throw new Error('reduction did not converge');
}

function encodeSignedBigInt(n: bigint): Uint8Array {
  const negative = n < 0n;
  let v = negative ? -n : n;
  const magBytes: number[] = [];
  if (v === 0n) magBytes.push(0);
  while (v > 0n) {
    magBytes.unshift(Number(v & 0xffn));
    v >>= 8n;
  }
  if (magBytes.length > 0xffff) throw new Error('integer too large to serialize');
  const out = new Uint8Array(2 + 1 + magBytes.length);
  out[0] = (magBytes.length >>> 8) & 0xff;
  out[1] = magBytes.length & 0xff;
  out[2] = negative ? 1 : 0;
  for (let i = 0; i < magBytes.length; i++) out[3 + i] = magBytes[i]!;
  return out;
}

function decodeSignedBigInt(buf: Uint8Array, offset: number): { value: bigint; next: number } {
  if (buf.length < offset + 3) throw new Error('truncated signed bigint header');
  const len = (buf[offset]! << 8) | buf[offset + 1]!;
  if (buf.length < offset + 3 + len) throw new Error('truncated signed bigint body');
  const sign = buf[offset + 2]!;
  if (sign !== 0 && sign !== 1) throw new Error('invalid sign byte');
  let v = 0n;
  for (let i = 0; i < len; i++) v = (v << 8n) | BigInt(buf[offset + 3 + i]!);
  return { value: sign === 1 ? -v : v, next: offset + 3 + len };
}

export function serializeForm(f: Form): Uint8Array {
  const a = encodeSignedBigInt(f.a);
  const b = encodeSignedBigInt(f.b);
  const c = encodeSignedBigInt(f.c);
  const out = new Uint8Array(a.length + b.length + c.length);
  out.set(a, 0);
  out.set(b, a.length);
  out.set(c, a.length + b.length);
  return out;
}

export function parseForm(raw: Uint8Array): Form {
  const a = decodeSignedBigInt(raw, 0);
  const b = decodeSignedBigInt(raw, a.next);
  const c = decodeSignedBigInt(raw, b.next);
  if (c.next !== raw.length) throw new Error('trailing bytes in serialized form');
  return { a: a.value, b: b.value, c: c.value };
}
