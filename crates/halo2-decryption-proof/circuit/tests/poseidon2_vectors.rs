//! Cross-language correctness gate: runs every vector in
//! `tests/fixtures/poseidon2-bn254-vectors.json` (consumed by the
//! TypeScript test suite) and asserts that the Rust port of Poseidon2
//! produces the same output bytes.

use std::path::PathBuf;

use halo2_axiom::halo2curves::bn256::Fr;
use halo2_decryption_proof_circuit::commitment::{fr_to_be_bytes, parse_hex_fr};
use halo2_decryption_proof_circuit::poseidon2;
use serde::Deserialize;

#[derive(Deserialize)]
struct Manifest {
    hash: String,
    field: String,
    #[serde(rename = "paramsId")]
    params_id: String,
    width: String,
    rate: String,
    capacity: String,
    #[serde(rename = "roundsFull")]
    rounds_full: String,
    #[serde(rename = "roundsPartial")]
    rounds_partial: String,
    vectors: Vec<Vector>,
}

#[derive(Deserialize)]
struct Vector {
    name: String,
    domain: String,
    #[serde(rename = "inputsHex")]
    inputs_hex: Vec<String>,
    #[serde(rename = "outputHex")]
    output_hex: String,
}

fn fixture_path() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("../../../tests/fixtures/poseidon2-bn254-vectors.json");
    path
}

#[test]
fn poseidon2_bn254_matches_typescript_vectors() {
    let raw = std::fs::read_to_string(fixture_path()).expect("read poseidon2 vector fixture");
    let manifest: Manifest = serde_json::from_str(&raw).expect("parse vector manifest");

    assert_eq!(manifest.hash, "poseidon2");
    assert_eq!(manifest.field, "bn254-scalar");
    assert_eq!(manifest.params_id, "sss-v3-poseidon2-bn254-v1");
    assert_eq!(manifest.width, "4");
    assert_eq!(manifest.rate, "3");
    assert_eq!(manifest.capacity, "1");
    assert_eq!(manifest.rounds_full, "8");
    assert_eq!(manifest.rounds_partial, "56");
    assert!(!manifest.vectors.is_empty());

    for vector in &manifest.vectors {
        let inputs: Vec<Fr> = vector
            .inputs_hex
            .iter()
            .map(|hex_str| parse_hex_fr(hex_str).expect("vector input is a valid BN254 scalar"))
            .collect();

        let domain_tag = halo2_decryption_proof_circuit::commitment::domain_tag(&vector.domain);
        let mut tagged = Vec::with_capacity(inputs.len() + 1);
        tagged.push(domain_tag);
        tagged.extend_from_slice(&inputs);

        let output = poseidon2::hash_to_field(&tagged);
        let actual = hex::encode(fr_to_be_bytes(&output));
        assert_eq!(
            actual.as_str(),
            vector.output_hex.as_str(),
            "Poseidon2 vector mismatch: {}",
            vector.name
        );
    }
}
