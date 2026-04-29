# C0 Shared Arithmetization Architecture

This document is the C0 gate for the SSS v3 Halo2 decryption-proof backend.
It exists to prevent the AES-GCM, HKDF-SHA256, and ML-KEM gadgets from being
implemented as isolated circuits that cannot compose inside browser WASM.

Current implemented relation:

```text
sss-v3-poseidon2bn254-vaultroot-only-v1
```

The current relation proves only the Poseidon2-BN254 vault-root plaintext
commitment and binds the proof to the canonical public-input transcript digest.
It does not claim the full ML-KEM/HKDF/AES relation.

Future full relation:

```text
sss-v3-mlkem768-hkdfsha256-aes256gcm-poseidon2bn254-vaultroot-nopass-v1
```

The future relation remains blocked until the component row/memory estimates
below are replaced with measured gadget counts and reviewed.

## Field

The circuit field is the BN254 scalar field used by `halo2-axiom`:

```text
p = 21888242871839275222246405745257275088548364400416034343698204186575808495617
  = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
```

Public byte strings are never reduced modulo `p`. Values are represented as
fixed-width big-endian limbs:

```text
u8      -> one range-checked field element in [0, 255]
u16     -> two u8 limbs, reconstructed big-endian
u32     -> four u8 limbs, reconstructed big-endian
u128    -> sixteen u8 limbs or one field element after range proof
bytes32 -> two u128 limbs
q3329   -> one coefficient field element constrained to [0, 3328]
```

The transcript digest is represented as two public instances:

```text
digestHigh128 = digest[0..16]  as big-endian u128
digestLow128  = digest[16..32] as big-endian u128
```

The current circuit instance layout is:

```text
0: bundleId
1: plaintextCommitment
2: transcriptDigestHigh128
3: transcriptDigestLow128
```

## Shared Tables

All byte-oriented gadgets must use one shared table family rather than
allocating private lookup tables per gadget.

Required tables:

```text
byte_table(x)                      x in [0, 255]
u4_table(x)                        x in [0, 15]
q3329_table(x)                     x in [0, 3328]
aes_sbox_table(x, sbox(x))         x in [0, 255]
xor_table(a, b, a xor b)           a,b in [0, 255]
and_table(a, b, a and b)           a,b in [0, 255]
```

If table size becomes impractical, the fallback is a compressed lookup design
with packed nibbles for bitwise operations. Do not add separate AES, SHA, and
ML-KEM byte tables.

## SHA-256 / HKDF Plan

HKDF-SHA256 must be exact for the future full relation.

Representation:

```text
message bytes -> shared byte table
u32 words     -> four bytes, big-endian reconstruction
rotates       -> bit/nibble decomposition reused from shared tables
Ch, Maj       -> xor/and lookup strategy or packed bit constraints
additions     -> 32-bit limb addition with carry range checks
```

Only implement the SHA-256 work required for:

```text
HKDF-Extract(salt = bundleId, ikm = sharedSecret)
HKDF-Expand(info = "SSS/AEAD/v1", L = 32)
```

Do not introduce SHA-256 proof-facing commitments. Public transcript and
artifact digests remain outside the circuit.

## Poseidon2 Commitments

Proof-facing commitments use Poseidon2 over BN254 with:

```text
paramsId = sss-v3-poseidon2-bn254-v1
width = 4
rate = 3
capacity = 1
full rounds = 8
partial rounds = 56
```

The shared vector manifest is:

```text
tests/fixtures/poseidon2-bn254-vectors.json
```

The TypeScript implementation and Rust/Halo2 helper must continue to match this
manifest. Relation digests must change if the Poseidon2 params id or vector
manifest changes.

## AES-256-GCM Plan

The AES-GCM gadget must prove:

```text
AES-256-GCM.decrypt(aeadKey, nonce, ciphertextAndTag) = vaultRootKey
```

Required layout:

```text
AES key schedule       shared byte table + aes_sbox_table
AES rounds             byte state, SubBytes lookup, ShiftRows wiring, MixColumns
GHASH                  GF(2^128) multiplication with bit decomposition
tag check              constant-time equality constraints against public tag
nonce                  public transcript bytes constrained through digest limbs
```

Preliminary row estimate:

```text
AES-256 block decrypt/key schedule: 20k-60k rows for one 32-byte plaintext path
GHASH and tag check:               20k-80k rows
AES-GCM subtotal:                  40k-140k rows
```

These are planning estimates, not acceptance numbers. The C3 milestone must
replace them with measured rows.

## ML-KEM-768 Plan

ML-KEM arithmetic over q = 3329 must be explicit. Coefficients are field
elements with a range proof into `[0, 3328]`; modular operations must constrain
both the unreduced value and the quotient/remainder relation.

Required components before integration:

```text
q3329 add/sub/mul tests
NTT/inverse NTT tests
compression/decompression tests
SHA3/SHAKE/XOF strategy and test vectors
keygenFromSeed vector matching
decapsulation vector matching
```

Forbidden:

```text
Do not emulate q=3329 arithmetic as unconstrained BN254 arithmetic.
Do not integrate ML-KEM before standalone q3329 and NTT tests pass.
```

Preliminary row estimate:

```text
q3329 and NTT arithmetic:        300k-900k rows
SHA3/SHAKE/XOF path:             500k-2M rows
decapsulation and reencrypt path 500k-2M rows
ML-KEM subtotal:                 1.3M-4.9M rows
```

These estimates make browser-WASM proving feasibility uncertain.

## Combined Feasibility Gate

Before implementing C5/C6, record measured rows and proving memory for:

```text
AES-256-GCM only
HKDF-SHA256 only
ML-KEM-768 decapsulation only
combined full relation
```

Go/no-go rule:

```text
If combined proving needs more than 1.5 GB browser WASM memory, or if proof
generation is not plausibly usable on a current laptop browser worker, stop and
redesign the first supported relation or proof architecture.
```

The current KZG proof size is expected to remain QR-feasible, but proving memory
and time are the gating risks.

## Merge Gate

Until C3-C7 are measured and reviewed:

```text
SUPPORTED_HALO2_RELATIONS must accept only the vaultroot-only relation.
The UI must not claim the full ML-KEM/HKDF/AES relation is proven.
Full-relation artifacts must be rejected by the Halo2 artifact loader.
```
