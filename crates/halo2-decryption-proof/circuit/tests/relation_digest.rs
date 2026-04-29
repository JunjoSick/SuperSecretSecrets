//! Lock the Rust relation digest against the well-known TS digest. If
//! `RELATION_V1_VAULTROOT_ONLY_ID` ever changes on either side, this test
//! fires before the wasm artifact ships.

use halo2_decryption_proof_circuit::relation::{
    relation_digest, relation_v1_vaultroot_only_digest, RELATION_V1_FULL_ID,
    RELATION_V1_VAULTROOT_ONLY_ID,
};

#[test]
fn relation_v1_vaultroot_only_digest_matches_id() {
    let digest = relation_v1_vaultroot_only_digest();
    assert_eq!(digest, relation_digest(RELATION_V1_VAULTROOT_ONLY_ID));
    assert_ne!(digest, relation_digest(RELATION_V1_FULL_ID));
    assert_ne!(digest, relation_digest("changed"));
}
