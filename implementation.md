# Implementation Notes: v2 to v3

This file is for a future Codex agent picking up SuperSecretSecrets after the
v3 proof-foundation work. Treat it as a map of what changed from v2 to v3, what
is already implemented, and what must remain true when doing the next slice.

## Current Branch State

- v2 remains supported. Decode accepts v2 and v3 frames through the shared
  `SSS2` magic with version byte `2` or `3`.
- v3 is the active extension path for ZK commitments, VDF-locked shares,
  selective vault disclosure, and auditor decryption proofs.
- The first real Halo2 proof relation is intentionally narrow:
  `sss-v3-poseidon2bn254-vaultroot-only-v1`.
- The full in-circuit ML-KEM/HKDF/AES proof relation is not shipped yet. Do not
  label the current vault-root-only artifact as the full relation.
- The encode UI has been polished around the v3 pipeline, but product wiring for
  automatic proof emission still needs a deliberate final pass.

## Wire Format Delta

v2 introduced the extensible QR frame shape. v3 keeps that container and adds
new critical/non-critical TLVs under version byte `3`.

Important codec files:

- `src/crypto/codec.ts`
- `src/crypto/index.ts`
- `tests/v2.test.ts`
- `tests/v3-codec.test.ts`
- `tests/v3-pipeline.test.ts`
- `tests/v3-fixture.test.ts`

New v3 TLVs:

- `0x08 TLV_POLICY_COMMITMENT`
- `0x09 TLV_PLAINTEXT_COMMITMENT`
- `0x0a TLV_VAULT_TREE_ROOT`
- `0x0b TLV_SHARE_COMMIT_PROOF`
- `0x0c TLV_VDF_PARAMS`
- `0x0d TLV_VDF_LOCK`
- `0x0e TLV_VDF_PROOF`
- `0x0f TLV_DECRYPTION_PROOF`

Rules to preserve:

- Unknown critical TLVs must fail decode.
- Unknown non-critical TLVs may warn but must not break normal recovery.
- `TLV_DECRYPTION_PROOF` is non-critical, but a present malformed/tampered proof
  claim is treated as a real audit claim and must fail closed.
- v3 header chunks can split when extension data is large. Tests already cover
  multi-header behavior; do not assume header chunk `0` is the whole header.

## v3 Commitments

v2 could recover secrets and vault blobs, but did not bind a proof-facing
commitment set. v3 adds commitments for policy, plaintext/vault-root, share
openings, and vault trees.

Important files:

- `src/crypto/zk/pedersen.ts`
- `src/crypto/zk/schnorr.ts`
- `src/crypto/zk/merkle.ts`
- `src/crypto/zk/vault-tree.ts`
- `src/crypto/zk/curve.ts`
- `tests/zk.test.ts`
- `tests/proof-facing-commitments.test.ts`
- `tests/poseidon2-bn254-commitment.test.ts`
- `tests/poseidon2-zkpassport.test.ts`

Security intent:

- The normal app behavior can still recover without a decryption proof.
- v3 commitments add integrity and audit surfaces; they are not confidentiality
  features by themselves.
- Proof-facing commitments use Poseidon2-BN254 where the Halo2 relation requires
  it. Do not silently mix SHA-256 commitment semantics into Halo2 public inputs.

## Vaults and Selective Disclosure

v2 vault support existed as encrypted blob recovery. v3 adds vault tree roots and
per-entry disclosure verification.

Important files:

- `src/crypto/index.ts`
- `src/crypto/zk/vault-tree.ts`
- `src/pages/Recover.tsx`
- `src/pages/Verify.tsx`
- `tests/png-upload.test.ts`
- `tests/v3-fixture.test.ts`

Behavior to preserve:

- Image payloads are represented as single-entry vault presets.
- Encode can strip image metadata by re-encoding the selected image before
  vaulting it.
- Recover renders image entries from object URLs and can export disclosure JSON.
- `/verify` verifies disclosure JSON against the v3 vault tree root.

## VDF Delta

v2 time locks used external drand-style availability assumptions. v3 adds
per-share local VDF locks using class-group Wesolowski proofs.

Important files:

- `src/crypto/vdf/`
- `src/workers/encode.worker.ts`
- `src/workers/decode.worker.ts`
- `src/workers/protocol.ts`
- `src/components/WorkerProgress.tsx`
- `tests/vdf.test.ts`
- `tests/v3-vdf.test.ts`

Behavior to preserve:

- VDF work runs off the UI thread.
- Progress and cancellation must work during both evaluation and proof phases.
- Preset runtime estimates are local heuristics, not hard security guarantees.
- VDF locks are not post-quantum and should not be described as such.

## Decryption Proof Foundation

The loose legacy helpers in `src/crypto/zk/decryption-proof.ts` are no longer
the authoritative spec surface. They remain for plaintext commitment helpers and
compatibility exports until old encode/decode tests are fully migrated.

The canonical proof surface is split across:

- `src/crypto/zk/decryption-proof-relations.ts`
- `src/crypto/zk/decryption-proof-transcript.ts`
- `src/crypto/zk/decryption-proof-envelope.ts`
- `src/crypto/zk/decryption-proof-prover.ts`
- `src/crypto/zk/decryption-proof-verifier.ts`
- `src/crypto/zk/halo2/artifact.ts`
- `src/crypto/zk/halo2/backend.ts`
- `src/crypto/zk/halo2/witness.ts`
- `src/crypto/zk/manifest.ts`

Tests:

- `tests/decryption-proof-relations.test.ts`
- `tests/decryption-proof-transcript.test.ts`
- `tests/decryption-proof-envelope.test.ts`
- `tests/decryption-proof-verifier.test.ts`
- `tests/decryption-proof-artifact.test.ts`
- `tests/decryption-proof-halo2-backend.test.ts`
- `tests/decryption-proof-halo2-real-artifact.test.ts`
- `tests/decryption-proof-halo2-vaultroot-only.test.ts`
- `tests/decryption-proof-memory-boundary.test.ts`
- `tests/v3-decryption-proof-integration.test.ts`
- `tests/helpers/decryption-proof-mock.ts`

### Relation IDs

Do not reuse app codec IDs inside proof circuits. Proof-local IDs are hardcoded
as `0x01` for the first supported algorithm tuple:

- ML-KEM-768
- HKDF-SHA256
- AES-256-GCM
- Poseidon2-BN254 commitment
- no passphrase

The ML-KEM-768 ciphertext length is fixed at `1088` bytes in
`decryption-proof-relations.ts`; tests assert this agrees with the dependency.

There are two relation strings to understand:

- `RELATION_V1_ID`
  Full intended relation:
  `sss-v3-mlkem768-hkdfsha256-aes256gcm-poseidon2bn254-vaultroot-nopass-v1`.
  This is not implemented as a Halo2 circuit yet.
- `RELATION_V1_VAULTROOT_ONLY_ID`
  Current shipped Halo2 relation:
  `sss-v3-poseidon2bn254-vaultroot-only-v1`.
  This constrains the vault-root commitment plus transcript digest public
  instances. This honest narrow relation is the only one in
  `SUPPORTED_HALO2_RELATIONS`.

Relation digest formula:

```text
sha256(u16_be(domain_len) || domain || u16_be(relation_id_len) || relation_id)
```

The known current vault-root-only digest is:

```text
9f2973dbcdd6d997c7b6190b4b906babc82a53560038b756b43820924573aa32
```

### Public Input Transcript

The canonical transcript is in `decryption-proof-transcript.ts`.

Encoding:

```text
u16_be domainLen
domain bytes
u8 version
field 0x01
field 0x02
...
field 0x0a
```

Each field is:

```text
u8 tag || u32_be length || bytes
```

Important constraints:

- Tags must appear in strict increasing order, `0x01` through `0x0a`.
- Missing, duplicate, out-of-order, or trailing fields must throw.
- Field `0x03` is exactly 5 bytes.
- Field `0x04` is exactly 12 bytes.
- `vaultTreeRoot` is always present. The builder normalizes `undefined` and
  `null` to zero-length bytes; the low-level encoder rejects optional/null.
- No-passphrase relation requires zero Argon2 params.
- KEM ciphertext must be exactly 1088 bytes.
- AES-GCM nonce must be exactly 12 bytes.
- Digest is SHA-256 over the canonical transcript bytes.
- BN254 public inputs split the 32-byte digest into two big-endian 128-bit
  limbs: `high128`, `low128`.

Why the transcript limbs matter:

The Halo2 verifier must bind public-instance limbs for the transcript digest.
Without this, a valid vault-root proof could be reused after changing the KEM
ciphertext, nonce, or algorithm identifiers. This has already been fixed; do
not remove those public instances from the Rust circuit, artifact manifest, or
TS verifier checks.

### Envelope Codec

The spec envelope lives in `decryption-proof-envelope.ts`.

Fields:

- version
- schemeId
- flags
- relationId
- relationDigest
- verifierArtifactDigest
- transcriptDigest
- proofBytes

Rules:

- Reject reserved flags.
- Reject empty `relationId`.
- Reject empty `proofBytes`.
- Enforce 32-byte digests.
- Enforce no trailing bytes.
- Enforce hard proof-size maximum.

Size thresholds:

- ideal: `2500` bytes
- warning: `5000` bytes
- hard: `10000` bytes

Known flags:

- `DECRYPTION_PROOF_FLAG_TEST_ONLY`
- `DECRYPTION_PROOF_FLAG_TRUSTED_SETUP`
- `DECRYPTION_PROOF_FLAG_EXTERNAL_ARTIFACT`

Production modules know the test-only flag so they can reject it where needed,
but production code must not emit mock proofs.

### Prover and Verifier Registry

Interfaces:

- `DecryptionProofProver`
- `DecryptionProofVerifier`

Registry key:

```text
schemeId + relationDigest + verifierArtifactDigest
```

Verification wrapper behavior:

- Check envelope version.
- Recompute/check transcript digest.
- Match verifier by scheme, relation digest, and verifier artifact digest.
- Await the verifier.
- Return one of: `verified`, `unsupported`, `failed`.

## Halo2 Workspace

Rust workspace:

- `crates/halo2-decryption-proof/circuit`
- `crates/halo2-decryption-proof/wasm`
- `crates/halo2-decryption-proof/keygen`

Rust README:

- `crates/halo2-decryption-proof/README.md`

Current status:

- Poseidon2-BN254 reference implementation matches `@zkpassport/poseidon2`.
- TLV decoder for `DecryptionProofPublicInputsV1` exists.
- Owned witness type exists.
- `VaultRootCommitmentCircuit` exists.
- Transcript digest public-instance binding exists.
- Keygen emits manifest + `srs.bin` + `pk.bin` + `vk.bin`.
- WASM exports real prove/verify entry points.
- TS has artifact loading/validation and an end-to-end real-artifact test.
- Deterministic dev SRS is gated and must never be used for production claims.

Memory safety note:

- WASM prove/verify boundaries must catch Rust panics before returning to JS.
- Sensitive witness buffers must be zeroized/freeable even if proving fails.
- Do not introduce a direct panic path that can trap the WASM instance before JS
  cleanup runs.

Artifact rules:

- `schemeId` for Halo2/KZG is `0x01`.
- Mock tests use `schemeId = 0x7f` and live under `tests/`, not `src/`.
- A manifest using deterministic dev SRS must be rejected unless the caller has
  explicitly opted into dev artifacts.
- A production claim requires ceremony-backed BN254/KZG parameters.

## Encode/Decode Behavior

Encode:

- v3 commitments can be emitted.
- VDF locks can be emitted.
- A decryption proof can be emitted only through an explicit async prover path
  for a supported v3 vault-root bundle.
- Proof emission must not happen unless local verification accepts the proof
  before QR export.

Decode:

- v2/v3 decode remains compatible.
- Unsupported proof relation/scheme should be surfaced as unsupported/warning.
- Malformed or invalid present proof data must fail closed.
- Async proof verification belongs in worker-level or async decode flow; do not
  block the synchronous decode path with async WASM assumptions.

## Frontend Delta

The v3 UI moved from a plain encoder to an instrument-style pipeline interface.

Important files:

- `src/pages/Encode.tsx`
- `src/pages/Recover.tsx`
- `src/pages/Verify.tsx`
- `src/components/SettingsPanel.tsx`
- `src/components/QrCard.tsx`
- `src/components/WorkerProgress.tsx`
- `src/App.tsx`
- `src/styles/globals.css`

Recent encode polish:

- Responsive header/nav fixes.
- Operation strip and operation digest.
- Staged encode breadcrumbs.
- Payload composer with plaintext/vault mode selection.
- Better image payload drop zone and selected-image state.
- Better threshold card and pipeline preview.
- Bundle integrity strip in generated output.
- Text wrapping/min-width fixes for chips, buttons, cards, and QR labels.

Frontend constraints to keep:

- Text must not overflow boxes on mobile or desktop.
- Use the existing dark, precise, mono instrument style.
- Avoid nested cards and decorative one-note palettes.
- Keep controls usable first; do not turn operational pages into landing pages.

## GitHub Pages

Deployment is already configured:

- `.github/workflows/pages.yml`
- `vite.config.ts`
- `src/router.tsx`
- `scripts/spa-404.mjs`

The workflow builds on push to `main`, sets `VITE_BASE` from
`actions/configure-pages`, uploads `dist`, and deploys through GitHub Pages.
React Router uses `import.meta.env.BASE_URL` as `basename`.

After merge, the repo settings still need GitHub Pages source set to GitHub
Actions if it is not already.

## Future Work

High priority:

- Wire the real Halo2 prover into the encode UX deliberately.
- Wire async proof verification into recover/decode UX deliberately.
- Add manual browser checks for encode/recover/verify after proof UX wiring.
- Replace any production-facing use of deterministic dev SRS with
  ceremony-backed parameters.

Deferred protocol work:

- Full in-circuit relation for ML-KEM-768 decapsulation, HKDF-SHA256,
  AES-256-GCM decrypt/authenticate, and Poseidon2-BN254 vault-root commitment.
- Optional passphrase relation.
- ChaCha20-Poly1305 relation.
- ML-KEM-512/1024 relation variants if product support requires them.

Before claiming v3 complete:

- Run `npm run typecheck`.
- Run `npm test`.
- Run `npm run build`.
- Run `git diff --check`.
- Run `cargo test --workspace` in `crates/halo2-decryption-proof`.
- Re-check README and SECURITY for exact shipped claims.

