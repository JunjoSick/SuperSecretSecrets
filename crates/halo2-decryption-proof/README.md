# halo2-decryption-proof

Real Halo2 + WASM artifact pipeline for the SSS v3 decryption proof.

This workspace targets the `sss-v3-poseidon2bn254-vaultroot-only-v1`
relation as the first deliverable — a strict subset of the full
`RELATION_V1_ID` that only constrains the Poseidon2-BN254 commitment of
the vault-root key. The full ML-KEM-768 + HKDF-SHA256 + AES-GCM in-circuit
relation is a future milestone tracked in
`../../supersecretsecrets_v3_decryption_proof_spec_updated_v3.md` §13.

## Layout

| Crate | Path | Purpose |
|---|---|---|
| `halo2-decryption-proof-circuit` | `circuit/` | Reference Poseidon2-BN254 sponge (matches `@zkpassport/poseidon2`), TLV decoder for the public-inputs blob, owned witness type, and `VaultRootCommitmentCircuit`. |
| `halo2-decryption-proof-wasm` | `wasm/` | `wasm-bindgen` exports that satisfy the `Halo2WasmProver` / `Halo2WasmVerifier` contract from `src/crypto/zk/halo2/witness.ts`. |
| `halo2-decryption-proof-keygen` | `keygen/` | Bin that emits `srs.bin`, `pk.bin`, `vk.bin`, `trusted-setup-id.txt`, and a JSON sidecar consumed by `validateHalo2VerifierArtifact`. It can include WASM build bytes when supplied. |

## Build & test

```sh
# Native tests, including the Poseidon2-BN254 cross-language vector check.
cargo test --workspace

# Generate a local artifact bundle under target/halo2-vaultroot-only-artifact.
cargo run -p halo2-decryption-proof-keygen -- --allow-dev-srs

# Options:
#   --out DIR       output directory
#   --k K           circuit size, default 11
#   --srs-in FILE   load a serialized KZG SRS
#   --allow-dev-srs generate a deterministic local-development SRS
#   --wasm FILE     include compiled WASM bytes in the manifest hash
```

The vector test reads
`SuperSecretSecrets/tests/fixtures/poseidon2-bn254-vectors.json` and runs
every entry through the Rust port. Mismatch = parameter drift.

Keygen refuses to emit a deterministic development SRS unless
`--allow-dev-srs` is present. That path is only for reproducible tests and
local artifacts. Production artifacts must be generated with
ceremony-backed BN254/KZG parameters via `--srs-in`; the TypeScript loader
also rejects deterministic-dev manifests unless explicitly allowed by the
caller.

## Wasm build (target wasm32-unknown-unknown)

```sh
rustup target add wasm32-unknown-unknown
cargo build -p halo2-decryption-proof-wasm --release --target wasm32-unknown-unknown
```

The WASM exports are wired to the same Halo2/KZG prover and verifier used
by the native tests. Both paths require the generated `srs.bin` alongside
`pk.bin` or `vk.bin`.

## Status

| Milestone | Status |
|---|---|
| Workspace + Cargo manifests | done |
| Poseidon2-BN254 reference impl | done (passes existing TS vectors) |
| TLV decoder for `DecryptionProofPublicInputsV1` | done |
| Witness layout (`HALO2_WITNESS_V1_BYTES`) | done |
| Vault-root plaintext commitment helper | done |
| In-circuit `VaultRootCommitmentCircuit` (halo2 chip) | done (MockProver tests) |
| KZG SRS / PK / VK generation in `keygen` | done (artifact bundle + manifest; dev SRS behind explicit flag) |
| Real `verify_decryption_proof_v1` / `prove_…_v1_from_witness_ptr` | done (native-tested; browser build requires wasm32 target) |
| End-to-end TS test against the real artifact | done (keygen manifest + pk/vk/srs loader + dev-SRS gate) |

## Why split out a `vaultroot-only` relation?

The `RELATION_V1_ID` digest is bound to the full
`mlkem768-hkdfsha256-aes256gcm-poseidon2bn254-vaultroot-nopass`
construction. Shipping a circuit that only constrains the Poseidon2
commitment under that id would lie about its semantics. The new id
(`sss-v3-poseidon2bn254-vaultroot-only-v1`) is plumbed through
`SUPPORTED_HALO2_RELATIONS` in `decryption-proof-relations.ts`, so the
TS verifier accepts artifacts under either relation but the envelope
carries the honest one.
