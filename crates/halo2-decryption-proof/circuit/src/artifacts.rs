//! Pinned proof-artifact identity for production Halo2/KZG bundles.
//!
//! Digest values are placeholders until ceremony-backed artifacts are
//! generated. Production release gates must replace every zero digest before
//! accepting an artifact set.

use crate::relation::RELATION_V1_FULL_ID;

pub const RELATION_ID: &str = RELATION_V1_FULL_ID;
pub const CIRCUIT_VERSION: &str = "v1";
pub const PUBLIC_INPUT_SCHEMA_VERSION: &str = "v1";

pub const EXPECTED_K: u32 = 14;

pub const EXPECTED_SRS_SHA256: [u8; 32] = [
    0xea, 0x72, 0x57, 0xf0, 0xea, 0x1f, 0x78, 0x4d, 0x62, 0x91, 0xef, 0x5a, 0x55, 0x85, 0xc7, 0x59,
    0xc8, 0xdd, 0x17, 0x85, 0x92, 0x9a, 0xd9, 0xe7, 0xe9, 0xda, 0x51, 0xae, 0xd2, 0x22, 0x6a, 0x64,
];
pub const EXPECTED_PK_SHA256: [u8; 32] = [0u8; 32]; // TODO: sha256(assets/pk_v1.bin)
pub const EXPECTED_VK_SHA256: [u8; 32] = [0u8; 32]; // TODO: sha256(assets/vk_v1.bin)
pub const PUBLIC_INPUT_SCHEMA_SHA256: [u8; 32] = [0u8; 32]; // TODO: sha256(canonical public input schema)
pub const PROOF_ARTIFACT_DIGEST: [u8; 32] = [0u8; 32]; // TODO: sha256(proof_artifact_manifest.v1.json)

pub fn has_placeholder_digests() -> bool {
    EXPECTED_SRS_SHA256 == [0u8; 32]
        || EXPECTED_PK_SHA256 == [0u8; 32]
        || EXPECTED_VK_SHA256 == [0u8; 32]
        || PUBLIC_INPUT_SCHEMA_SHA256 == [0u8; 32]
        || PROOF_ARTIFACT_DIGEST == [0u8; 32]
}
