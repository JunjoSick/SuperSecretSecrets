//! Reference + (in progress) in-circuit primitives for the SSS v3
//! `sss-v3-poseidon2bn254-vaultroot-only-v1` decryption proof relation.
//!
//! The TypeScript wrapper in `src/crypto/zk/halo2/` defines the verifier
//! contract that this crate must match. The crate is split into:
//!
//! - [`relation`]: stable string ids and 32-byte digests that mirror
//!   `decryption-proof-relations.ts`.
//! - [`witness`]: byte layout for the WASM-owned witness buffer used by
//!   `prove_decryption_proof_v1_from_witness_ptr`.
//! - [`transcript`]: TLV codec for the public inputs blob handed to the
//!   verifier; the wasm wrapper decodes this to extract the BN254 instance
//!   values.
//! - [`poseidon2`]: out-of-circuit Poseidon2-BN254 sponge that matches
//!   `@zkpassport/poseidon2`. The Halo2 chip reuses the same constants and
//!   matrix from [`poseidon2::params`].
//! - [`commitment`]: the `bindPoseidon2Bn254VaultRootPlaintextCommitment`
//!   binding that the TS encoder uses; the circuit must constrain the same
//!   value.
//! - [`circuit`]: the `VaultRootCommitmentCircuit` used by key generation.

#![deny(rust_2018_idioms)]
#![forbid(unsafe_code)]

pub mod artifacts;
pub mod circuit;
pub mod commitment;
pub mod poseidon2;
pub mod relation;
pub mod transcript;
pub mod witness;

pub use commitment::{
    bind_vault_root_plaintext_commitment, BUNDLE_ID_BYTES, COMMITMENT_BYTES, VAULT_ROOT_KEY_BYTES,
};
pub use relation::{
    relation_digest, RELATION_DIGEST_DOMAIN, RELATION_V1_VAULTROOT_ONLY_DIGEST,
    RELATION_V1_VAULTROOT_ONLY_ID,
};

/// Re-export the BN254 scalar field used by the circuit so downstream
/// crates do not have to depend on `halo2curves` directly.
pub use halo2_axiom::halo2curves::bn256::Fr as Bn254Scalar;
